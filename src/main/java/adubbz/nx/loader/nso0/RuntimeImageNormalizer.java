package adubbz.nx.loader.nso0;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.Msg;

/**
 * Restores NSOs captured from a running process (e.g. a CodeFS memory session) to the layout
 * of an unrelocated image. Such a capture differs from a normal NSO in two ways:
 *  - DT_RELR slots already hold runtime pointers, which the loader would rebase a second time.
 *  - Its segments follow page permissions, so RELRO sits at the end of .rodata rather than the
 *    start of .data, where the analyzers expect vtables and type_info objects.
 *
 * Images are only changed when every DT_RELR slot is a runtime pointer and the runtime base is
 * confirmed. An unrelocated slot holds an offset inside the image, so normal NSOs never qualify.
 */
public final class RuntimeImageNormalizer
{
    private static final long DT_INIT_ARRAY = 25;
    private static final long DT_RELRSZ = 35;
    private static final long DT_RELR = 36;

    private static final long PAGE_SIZE = 0x1000L;
    private static final int MOD0_MAGIC = 0x30444F4D;

    // A base needs this many distinct type names, and twice the votes of any other base.
    private static final int MIN_BASE_VOTES = 8;

    public record Result(long runtimeBase, long rodataSize, long dataOffset, long dataSize) {}

    private RuntimeImageNormalizer() {}

    /**
     * Normalizes the image in place if it is a runtime capture.
     *
     * @return the corrected layout, or null if the image was left unchanged
     */
    public static Result normalize(byte[] image, long textOffset, long rodataOffset, long rodataSize,
                                   long dataOffset, long dataSize, long bssSize)
    {
        ByteBuffer buffer = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        List<Integer> slots;
        long initArray;

        try
        {
            int mod0 = Math.toIntExact(Integer.toUnsignedLong(buffer.getInt(Math.toIntExact(textOffset + 4))));

            if (buffer.getInt(mod0) != MOD0_MAGIC)
                return null;

            int dynamic = Math.addExact(mod0, buffer.getInt(mod0 + 4));

            // aarch32 dynamic entries read as oversized values; DT_RELR support here is 64-bit only.
            if (Long.compareUnsigned(buffer.getLong(dynamic), 0xFFFFFFFFL) > 0
                || Long.compareUnsigned(buffer.getLong(dynamic + 0x10), 0xFFFFFFFFL) > 0)
                return null;

            long relr = -1;
            long relrSize = -1;
            initArray = -1;

            for (int off = dynamic; buffer.getLong(off) != 0; off += 0x10)
            {
                long tag = buffer.getLong(off);
                long value = buffer.getLong(off + 8);

                if (tag == DT_RELR)
                    relr = value;
                else if (tag == DT_RELRSZ)
                    relrSize = value;
                else if (tag == DT_INIT_ARRAY)
                    initArray = value;
            }

            if (relr < 0 || relrSize <= 0)
                return null;

            slots = expandRelr(buffer, Math.toIntExact(relr), Math.toIntExact(relrSize));
        }
        catch (IndexOutOfBoundsException | ArithmeticException e)
        {
            return null; // Not a layout we can reason about, so leave it to the normal path
        }

        long imageSize = image.length + bssSize;
        long minValue = -1;
        long maxValue = 0;

        for (int slot : slots)
        {
            long value = buffer.getLong(slot);

            if (Long.compareUnsigned(value, imageSize) < 0)
                return null;

            if (minValue == -1 || Long.compareUnsigned(value, minValue) < 0)
                minValue = value;

            if (Long.compareUnsigned(value, maxValue) > 0)
                maxValue = value;
        }

        if (slots.isEmpty() || Long.compareUnsigned(maxValue - minValue, imageSize) >= 0)
            return null;

        long runtimeBase = findRuntimeBase(buffer, image, slots, minValue, maxValue, imageSize, rodataOffset, rodataSize);

        if (runtimeBase == -1)
        {
            Msg.warn(RuntimeImageNormalizer.class, "Image looks like a runtime capture, but its runtime base could not be confirmed. Importing it unchanged; pointers will be wrong.");
            return null;
        }

        for (int slot : slots)
            buffer.putLong(slot, buffer.getLong(slot) - runtimeBase);

        Msg.info(RuntimeImageNormalizer.class, String.format("Normalized runtime capture: rebased %d DT_RELR slots from base 0x%X", slots.size(), runtimeBase));

        long rodataEnd = rodataOffset + rodataSize;
        boolean splitRelro = initArray > rodataOffset && initArray < rodataEnd
            && initArray % PAGE_SIZE == 0 && rodataEnd == dataOffset;

        if (!splitRelro)
            return new Result(runtimeBase, rodataSize, dataOffset, dataSize);

        Msg.info(RuntimeImageNormalizer.class, String.format("Normalized runtime capture: moved .rodata/.data boundary from 0x%X to 0x%X", dataOffset, initArray));
        return new Result(runtimeBase, initArray - rodataOffset, initArray, dataOffset + dataSize - initArray);
    }

    private static List<Integer> expandRelr(ByteBuffer buffer, int relr, int relrSize)
    {
        List<Integer> slots = new ArrayList<>();
        long where = 0;

        for (int off = relr; off < relr + relrSize; off += 8)
        {
            long entry = buffer.getLong(off);

            if ((entry & 1) == 0)
            {
                addSlot(buffer, slots, entry);
                where = entry + 8;
            }
            else
            {
                for (int bit = 0; bit < 63; bit++)
                {
                    if (((entry >>> (bit + 1)) & 1) != 0)
                        addSlot(buffer, slots, where + bit * 8L);
                }

                where += 63 * 8L;
            }
        }

        return slots;
    }

    private static void addSlot(ByteBuffer buffer, List<Integer> slots, long slot)
    {
        int index = Math.toIntExact(slot);
        buffer.getLong(index); // Throws if the slot lies outside the image
        slots.add(index);
    }

    /**
     * ASLR bases can't be read off the lowest pointer, as the lowest target is rarely the image
     * start. Instead, each pointer votes for the base that would place it on a mangled type name,
     * since those are the one kind of target that can be recognized from the bytes alone.
     */
    private static long findRuntimeBase(ByteBuffer buffer, byte[] image, List<Integer> slots, long minValue, long maxValue,
                                        long imageSize, long rodataOffset, long rodataSize)
    {
        long lowest = (maxValue - imageSize + PAGE_SIZE) & -PAGE_SIZE;
        long highest = minValue & -PAGE_SIZE;

        if (Long.compareUnsigned(lowest, highest) > 0)
            return -1;

        int[] votes = new int[Math.toIntExact((highest - lowest) / PAGE_SIZE + 1)];
        int[] lastVoter = new int[votes.length];
        List<Long> names = findTypeNames(image, rodataOffset, rodataSize);

        // Each name votes once per base. A function pointer shared by many vtables would otherwise
        // outvote the true base by landing repeatedly on the one string it happens to line up with.
        for (int i = 0; i < names.size(); i++)
        {
            long name = names.get(i);

            for (int slot : slots)
            {
                long base = buffer.getLong(slot) - name;

                if ((base & (PAGE_SIZE - 1)) != 0 || Long.compareUnsigned(base, lowest) < 0 || Long.compareUnsigned(base, highest) > 0)
                    continue;

                int index = (int)((base - lowest) / PAGE_SIZE);

                if (lastVoter[index] != i + 1)
                {
                    lastVoter[index] = i + 1;
                    votes[index]++;
                }
            }
        }

        int best = 0;
        int runnerUp = 0;
        long bestBase = -1;

        for (int i = 0; i < votes.length; i++)
        {
            if (votes[i] > best)
            {
                runnerUp = best;
                best = votes[i];
                bestBase = lowest + i * PAGE_SIZE;
            }
            else if (votes[i] > runnerUp)
            {
                runnerUp = votes[i];
            }
        }

        return best >= MIN_BASE_VOTES && best > runnerUp * 2 ? bestBase : -1;
    }

    private static List<Long> findTypeNames(byte[] image, long rodataOffset, long rodataSize)
    {
        List<Long> names = new ArrayList<>();
        int end = Math.toIntExact(rodataOffset + rodataSize);

        for (int start = Math.toIntExact(rodataOffset); start < end; start++)
        {
            if (start > 0 && image[start - 1] != 0)
                continue;

            int stop = start;

            while (stop < end && isMangledNameChar(image[stop]))
                stop++;

            if (stop < end && image[stop] == 0 && isTypeName(image, start, stop))
                names.add((long)start);
        }

        return names;
    }

    private static boolean isMangledNameChar(byte b)
    {
        return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '_';
    }

    private static boolean isTypeName(byte[] image, int start, int stop)
    {
        if (stop - start < 4)
            return false;

        if (image[start] == 'N')
            return image[stop - 1] == 'E';

        // A source name: its decimal length prefix must fit in what follows
        int length = 0;
        int pos = start;

        while (pos < stop && image[pos] >= '0' && image[pos] <= '9' && length < 0x1000)
            length = length * 10 + (image[pos++] - '0');

        return pos > start && length > 0 && pos + length <= stop;
    }
}
