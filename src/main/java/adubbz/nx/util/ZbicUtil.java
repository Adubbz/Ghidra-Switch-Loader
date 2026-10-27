/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.util;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import adubbz.nx.common.ZbicException;
import com.github.luben.zstd.Zstd;

/**
 * Pure-Java ZBIC -> standard zstd frame converter.
 *
 * Nintendo ZBIC (firmware 22.0.0+) is zstd with two changes:
 *   1. Magic 0x4349425A ("ZBIC") instead of 0xFD2FB528
 *   2. FSE normalized-count tables use Binary Interpolative Coding
 *      (FSE_readNCount_bic) instead of the usual bit-packed format
 *
 * This class rewrites ZBIC frames into ordinary zstd frames so that a
 * stock zstd implementation (zstd-jni) can decompress them. Direct,
 * line-for-line port of the reference zbic.py.
 */
public final class ZbicUtil
{
    private ZbicUtil() {}

    public static final byte[] ZSTD_MAGIC = { (byte) 0x28, (byte) 0xB5, (byte) 0x2F, (byte) 0xFD };
    public static final byte[] ZBIC_MAGIC = { (byte) 0x5A, (byte) 0x42, (byte) 0x49, (byte) 0x43 }; // "ZBIC"

    private static final int FSE_MIN_TABLELOG = 5;
    // private static final int FSE_MAX_TABLELOG = 12; // unused, kept for parity with zbic.py

    // Precomputed (middle, first, last) index triples. Copied from
    // Atmosphere / kinnay zstd.c BIC_table[0x300].
    private static final int[] BIC_TABLE = {
        0x080, 0x000, 0x100, 0x0C0, 0x080, 0x100, 0x0E0, 0x0C0,
        0x100, 0x0F0, 0x0E0, 0x100, 0x0F8, 0x0F0, 0x100, 0x0FC,
        0x0F8, 0x100, 0x0FE, 0x0FC, 0x100, 0x0FF, 0x0FE, 0x100,
        0x0FD, 0x0FC, 0x0FE, 0x0FA, 0x0F8, 0x0FC, 0x0FB, 0x0FA,
        0x0FC, 0x0F9, 0x0F8, 0x0FA, 0x0F4, 0x0F0, 0x0F8, 0x0F6,
        0x0F4, 0x0F8, 0x0F7, 0x0F6, 0x0F8, 0x0F5, 0x0F4, 0x0F6,
        0x0F2, 0x0F0, 0x0F4, 0x0F3, 0x0F2, 0x0F4, 0x0F1, 0x0F0,
        0x0F2, 0x0E8, 0x0E0, 0x0F0, 0x0EC, 0x0E8, 0x0F0, 0x0EE,
        0x0EC, 0x0F0, 0x0EF, 0x0EE, 0x0F0, 0x0ED, 0x0EC, 0x0EE,
        0x0EA, 0x0E8, 0x0EC, 0x0EB, 0x0EA, 0x0EC, 0x0E9, 0x0E8,
        0x0EA, 0x0E4, 0x0E0, 0x0E8, 0x0E6, 0x0E4, 0x0E8, 0x0E7,
        0x0E6, 0x0E8, 0x0E5, 0x0E4, 0x0E6, 0x0E2, 0x0E0, 0x0E4,
        0x0E3, 0x0E2, 0x0E4, 0x0E1, 0x0E0, 0x0E2, 0x0D0, 0x0C0,
        0x0E0, 0x0D8, 0x0D0, 0x0E0, 0x0DC, 0x0D8, 0x0E0, 0x0DE,
        0x0DC, 0x0E0, 0x0DF, 0x0DE, 0x0E0, 0x0DD, 0x0DC, 0x0DE,
        0x0DA, 0x0D8, 0x0DC, 0x0DB, 0x0DA, 0x0DC, 0x0D9, 0x0D8,
        0x0DA, 0x0D4, 0x0D0, 0x0D8, 0x0D6, 0x0D4, 0x0D8, 0x0D7,
        0x0D6, 0x0D8, 0x0D5, 0x0D4, 0x0D6, 0x0D2, 0x0D0, 0x0D4,
        0x0D3, 0x0D2, 0x0D4, 0x0D1, 0x0D0, 0x0D2, 0x0C8, 0x0C0,
        0x0D0, 0x0CC, 0x0C8, 0x0D0, 0x0CE, 0x0CC, 0x0D0, 0x0CF,
        0x0CE, 0x0D0, 0x0CD, 0x0CC, 0x0CE, 0x0CA, 0x0C8, 0x0CC,
        0x0CB, 0x0CA, 0x0CC, 0x0C9, 0x0C8, 0x0CA, 0x0C4, 0x0C0,
        0x0C8, 0x0C6, 0x0C4, 0x0C8, 0x0C7, 0x0C6, 0x0C8, 0x0C5,
        0x0C4, 0x0C6, 0x0C2, 0x0C0, 0x0C4, 0x0C3, 0x0C2, 0x0C4,
        0x0C1, 0x0C0, 0x0C2, 0x0A0, 0x080, 0x0C0, 0x0B0, 0x0A0,
        0x0C0, 0x0B8, 0x0B0, 0x0C0, 0x0BC, 0x0B8, 0x0C0, 0x0BE,
        0x0BC, 0x0C0, 0x0BF, 0x0BE, 0x0C0, 0x0BD, 0x0BC, 0x0BE,
        0x0BA, 0x0B8, 0x0BC, 0x0BB, 0x0BA, 0x0BC, 0x0B9, 0x0B8,
        0x0BA, 0x0B4, 0x0B0, 0x0B8, 0x0B6, 0x0B4, 0x0B8, 0x0B7,
        0x0B6, 0x0B8, 0x0B5, 0x0B4, 0x0B6, 0x0B2, 0x0B0, 0x0B4,
        0x0B3, 0x0B2, 0x0B4, 0x0B1, 0x0B0, 0x0B2, 0x0A8, 0x0A0,
        0x0B0, 0x0AC, 0x0A8, 0x0B0, 0x0AE, 0x0AC, 0x0B0, 0x0AF,
        0x0AE, 0x0B0, 0x0AD, 0x0AC, 0x0AE, 0x0AA, 0x0A8, 0x0AC,
        0x0AB, 0x0AA, 0x0AC, 0x0A9, 0x0A8, 0x0AA, 0x0A4, 0x0A0,
        0x0A8, 0x0A6, 0x0A4, 0x0A8, 0x0A7, 0x0A6, 0x0A8, 0x0A5,
        0x0A4, 0x0A6, 0x0A2, 0x0A0, 0x0A4, 0x0A3, 0x0A2, 0x0A4,
        0x0A1, 0x0A0, 0x0A2, 0x090, 0x080, 0x0A0, 0x098, 0x090,
        0x0A0, 0x09C, 0x098, 0x0A0, 0x09E, 0x09C, 0x0A0, 0x09F,
        0x09E, 0x0A0, 0x09D, 0x09C, 0x09E, 0x09A, 0x098, 0x09C,
        0x09B, 0x09A, 0x09C, 0x099, 0x098, 0x09A, 0x094, 0x090,
        0x098, 0x096, 0x094, 0x098, 0x097, 0x096, 0x098, 0x095,
        0x094, 0x096, 0x092, 0x090, 0x094, 0x093, 0x092, 0x094,
        0x091, 0x090, 0x092, 0x088, 0x080, 0x090, 0x08C, 0x088,
        0x090, 0x08E, 0x08C, 0x090, 0x08F, 0x08E, 0x090, 0x08D,
        0x08C, 0x08E, 0x08A, 0x088, 0x08C, 0x08B, 0x08A, 0x08C,
        0x089, 0x088, 0x08A, 0x084, 0x080, 0x088, 0x086, 0x084,
        0x088, 0x087, 0x086, 0x088, 0x085, 0x084, 0x086, 0x082,
        0x080, 0x084, 0x083, 0x082, 0x084, 0x081, 0x080, 0x082,
        0x040, 0x000, 0x080, 0x060, 0x040, 0x080, 0x070, 0x060,
        0x080, 0x078, 0x070, 0x080, 0x07C, 0x078, 0x080, 0x07E,
        0x07C, 0x080, 0x07F, 0x07E, 0x080, 0x07D, 0x07C, 0x07E,
        0x07A, 0x078, 0x07C, 0x07B, 0x07A, 0x07C, 0x079, 0x078,
        0x07A, 0x074, 0x070, 0x078, 0x076, 0x074, 0x078, 0x077,
        0x076, 0x078, 0x075, 0x074, 0x076, 0x072, 0x070, 0x074,
        0x073, 0x072, 0x074, 0x071, 0x070, 0x072, 0x068, 0x060,
        0x070, 0x06C, 0x068, 0x070, 0x06E, 0x06C, 0x070, 0x06F,
        0x06E, 0x070, 0x06D, 0x06C, 0x06E, 0x06A, 0x068, 0x06C,
        0x06B, 0x06A, 0x06C, 0x069, 0x068, 0x06A, 0x064, 0x060,
        0x068, 0x066, 0x064, 0x068, 0x067, 0x066, 0x068, 0x065,
        0x064, 0x066, 0x062, 0x060, 0x064, 0x063, 0x062, 0x064,
        0x061, 0x060, 0x062, 0x050, 0x040, 0x060, 0x058, 0x050,
        0x060, 0x05C, 0x058, 0x060, 0x05E, 0x05C, 0x060, 0x05F,
        0x05E, 0x060, 0x05D, 0x05C, 0x05E, 0x05A, 0x058, 0x05C,
        0x05B, 0x05A, 0x05C, 0x059, 0x058, 0x05A, 0x054, 0x050,
        0x058, 0x056, 0x054, 0x058, 0x057, 0x056, 0x058, 0x055,
        0x054, 0x056, 0x052, 0x050, 0x054, 0x053, 0x052, 0x054,
        0x051, 0x050, 0x052, 0x048, 0x040, 0x050, 0x04C, 0x048,
        0x050, 0x04E, 0x04C, 0x050, 0x04F, 0x04E, 0x050, 0x04D,
        0x04C, 0x04E, 0x04A, 0x048, 0x04C, 0x04B, 0x04A, 0x04C,
        0x049, 0x048, 0x04A, 0x044, 0x040, 0x048, 0x046, 0x044,
        0x048, 0x047, 0x046, 0x048, 0x045, 0x044, 0x046, 0x042,
        0x040, 0x044, 0x043, 0x042, 0x044, 0x041, 0x040, 0x042,
        0x020, 0x000, 0x040, 0x030, 0x020, 0x040, 0x038, 0x030,
        0x040, 0x03C, 0x038, 0x040, 0x03E, 0x03C, 0x040, 0x03F,
        0x03E, 0x040, 0x03D, 0x03C, 0x03E, 0x03A, 0x038, 0x03C,
        0x03B, 0x03A, 0x03C, 0x039, 0x038, 0x03A, 0x034, 0x030,
        0x038, 0x036, 0x034, 0x038, 0x037, 0x036, 0x038, 0x035,
        0x034, 0x036, 0x032, 0x030, 0x034, 0x033, 0x032, 0x034,
        0x031, 0x030, 0x032, 0x028, 0x020, 0x030, 0x02C, 0x028,
        0x030, 0x02E, 0x02C, 0x030, 0x02F, 0x02E, 0x030, 0x02D,
        0x02C, 0x02E, 0x02A, 0x028, 0x02C, 0x02B, 0x02A, 0x02C,
        0x029, 0x028, 0x02A, 0x024, 0x020, 0x028, 0x026, 0x024,
        0x028, 0x027, 0x026, 0x028, 0x025, 0x024, 0x026, 0x022,
        0x020, 0x024, 0x023, 0x022, 0x024, 0x021, 0x020, 0x022,
        0x010, 0x000, 0x020, 0x018, 0x010, 0x020, 0x01C, 0x018,
        0x020, 0x01E, 0x01C, 0x020, 0x01F, 0x01E, 0x020, 0x01D,
        0x01C, 0x01E, 0x01A, 0x018, 0x01C, 0x01B, 0x01A, 0x01C,
        0x019, 0x018, 0x01A, 0x014, 0x010, 0x018, 0x016, 0x014,
        0x018, 0x017, 0x016, 0x018, 0x015, 0x014, 0x016, 0x012,
        0x010, 0x014, 0x013, 0x012, 0x014, 0x011, 0x010, 0x012,
        0x008, 0x000, 0x010, 0x00C, 0x008, 0x010, 0x00E, 0x00C,
        0x010, 0x00F, 0x00E, 0x010, 0x00D, 0x00C, 0x00E, 0x00A,
        0x008, 0x00C, 0x00B, 0x00A, 0x00C, 0x009, 0x008, 0x00A,
        0x004, 0x000, 0x008, 0x006, 0x004, 0x008, 0x007, 0x006,
        0x008, 0x005, 0x004, 0x006, 0x002, 0x000, 0x004, 0x003,
        0x002, 0x004, 0x001, 0x000, 0x002, 0x000, 0x000, 0x001,
    };

    static
    {
        if (BIC_TABLE.length != 0x300)
            throw new ExceptionInInitializerError("BIC_TABLE must have 0x300 entries");
    }

    // -----------------------------------------------------------------
    // Small internal value holders (stand-ins for zbic.py's tuple returns)
    // -----------------------------------------------------------------
    static final class Pulled
    {
        final long acc;
        final int rds;

        Pulled(long acc, int rds)
        {
            this.acc = acc;
            this.rds = rds;
        }
    }

    static final class NCountResult
    {
        final int[] normalized;
        final int maxSymbolValue;
        final int tableLog;
        final int bytesConsumed;

        NCountResult(int[] normalized, int maxSymbolValue, int tableLog, int bytesConsumed)
        {
            this.normalized = normalized;
            this.maxSymbolValue = maxSymbolValue;
            this.tableLog = tableLog;
            this.bytesConsumed = bytesConsumed;
        }
    }

    private static final class Section
    {
        final byte[] bytes;
        final int pos;

        Section(byte[] bytes, int pos)
        {
            this.bytes = bytes;
            this.pos = pos;
        }
    }

    private static int u8(byte[] a, int idx)
    {
        return a[idx] & 0xFF;
    }

    // -----------------------------------------------------------------
    // BIC NCount decoder (port of FSE_readNCount_bic)
    // -----------------------------------------------------------------

    /**
     * Match the C for-loop over U64:
     *   for (acc = init; rawDataSize; acc = *(ip + rawDataSize--) | (acc &lt;&lt; 8))
     *       if (((acc &gt;&gt; 32) &amp; 0xFFFFFFFF) &gt;= 0x100) break;
     * Body checks high bits *before* the increment consumes another byte.
     * Java longs wrap the same way C's u64 does for +, -, *, and &lt;&lt;, so no
     * explicit 64-bit masking is required beyond using &gt;&gt;&gt; for the unsigned
     * right shift below.
     */
    static Pulled pull(byte[] payload, long acc, int rds)
    {
        while (rds != 0)
        {
            if (((acc >>> 32) & 0xFFFFFFFFL) >= 0x100L)
                break;
            rds -= 1;
            acc = Byte.toUnsignedLong(payload[rds + 1]) | (acc << 8);
        }
        return new Pulled(acc, rds);
    }

    /**
     * Decode a BIC-encoded FSE NCount header.
     */
    static NCountResult fseReadNCountBic(byte[] header, int maxSymbolValue)
    {
        if (header.length == 0)
            throw new ZbicException("empty NCount header");

        int bit0 = u8(header, 0);
        int rawDataSize = bit0 & 0x7F;
        int useLowProb = bit0 >>> 7;
        if (rawDataSize >= header.length)
            throw new ZbicException(String.format("NCount rawDataSize %d >= buffer %d", rawDataSize, header.length));
        int dataSize = rawDataSize + 1;
        if (dataSize > header.length)
            throw new ZbicException(String.format("NCount dataSize %d > buffer %d", dataSize, header.length));

        byte[] payload = Arrays.copyOf(header, dataSize);

        int rds = rawDataSize;
        Pulled p = pull(payload, 0L, rds);
        long i = p.acc;
        rds = p.rds;

        long encodedCharTable = Long.divideUnsigned(i, 0x34L);
        long j = Long.remainderUnsigned(i, 0x34L);
        p = pull(payload, encodedCharTable, rds);
        encodedCharTable = p.acc;
        rds = p.rds;

        int charNum = (int) j + 1;
        if (charNum > maxSymbolValue)
            throw new ZbicException(String.format("charNum too large (%d > %d)", charNum, maxSymbolValue));

        long charTable = encodedCharTable >>> 3;
        int k = (int) (encodedCharTable & 0x7L);
        p = pull(payload, charTable, rds);
        charTable = p.acc;
        rds = p.rds;

        int tableLog = k + 5;
        int remaining = 1 << tableLog;

        long l = Long.divideUnsigned(charTable, remaining);
        p = pull(payload, l, rds);
        l = p.acc;
        rds = p.rds;

        int charLast = (int) Long.remainderUnsigned(charTable, remaining) + 1;
        if (useLowProb != 0)
            charLast = charNum + (int) Long.remainderUnsigned(charTable, remaining) + 2;

        int n = charNum;
        n |= n >>> 1;
        n |= n >>> 2;
        n |= n >>> 4;
        n |= n >>> 8;
        n |= n >>> 16;
        int charNumNextPow2 = n + 1;
        if (charNumNextPow2 > 0xFF)
            throw new ZbicException("charNumNextPow2 overflow");

        int[] bicCounter = new int[257];
        bicCounter[charNumNextPow2] = charLast;

        if (charNumNextPow2 != 0xFF)
        {
            int bicCount = 0;
            while (bicCount < charNumNextPow2)
            {
                int off = 3 * (bicCount - charNumNextPow2 + 0x100);
                int mid = BIC_TABLE[off];
                int first = BIC_TABLE[off + 1];
                int last = BIC_TABLE[off + 2];
                int bcFirst = bicCounter[first];
                int bcLast = bicCounter[last];

                if (bcFirst == bcLast)
                {
                    for (int idx = first + 1; idx < last; idx++)
                        bicCounter[idx] = bcFirst;
                }
                else
                {
                    int denom = bcLast - bcFirst + 1;
                    long lNext = Long.divideUnsigned(l, denom);
                    long lEntry = Long.remainderUnsigned(l, denom);
                    l = lNext;
                    p = pull(payload, l, rds);
                    l = p.acc;
                    rds = p.rds;
                    bicCounter[mid] = (int) lEntry + bcFirst;
                }

                bicCount += 1;
            }
        }

        int[] normalized = new int[charNum + 1];
        if (charNum != 0xFF)
        {
            int acc2 = 0;
            int rem = remaining;
            for (int s = 0; s <= charNum; s++)
            {
                // Match C: short bcCount = *(short *)bc++ (LE low 16 bits, signed)
                int bc = bicCounter[s + 1] & 0xFFFF;
                if (bc >= 0x8000)
                    bc -= 0x10000;
                int dist = bc - acc2;
                int count = dist - useLowProb;
                acc2 += dist;
                normalized[s] = count;
                rem -= Math.abs(count);
            }
            if (rem != 0)
            {
                throw new ZbicException(String.format(
                    "NCount remaining mismatch (%d) tableLog=%d charNum=%d useLowProb=%d dataSize=%d",
                    rem, tableLog, charNum, useLowProb, dataSize));
            }
        }

        if (rds != 0)
            throw new ZbicException(String.format("NCount trailing data rds=%d dataSize=%d", rds, dataSize));

        return new NCountResult(normalized, charNum, tableLog, dataSize);
    }

    // -----------------------------------------------------------------
    // Standard FSE NCount encoder (port of FSE_writeNCount_generic)
    // -----------------------------------------------------------------
    static byte[] fseWriteNCount(int[] normalized, int tableLog)
    {
        int maxSv = normalized.length - 1;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        long bitStream = 0;
        int bitCount = 0;

        bitStream += ((long) (tableLog - FSE_MIN_TABLELOG)) << bitCount;
        bitCount += 4;

        int tableSize = 1 << tableLog;
        int remaining = tableSize + 1;
        int threshold = tableSize;
        int nbBits = tableLog + 1;
        int symbol = 0;
        int alphabet = maxSv + 1;
        int previousIs0 = 0;

        while (symbol < alphabet && remaining > 1)
        {
            if (previousIs0 != 0)
            {
                int start = symbol;
                while (symbol < alphabet && normalized[symbol] == 0)
                    symbol += 1;
                if (symbol == alphabet)
                    break; // only trailing zeroes

                while (symbol >= start + 24)
                {
                    start += 24;
                    bitStream += 0xFFFFL << bitCount;
                    bitCount += 16;
                    if (bitCount > 16)
                    {
                        out.write((int) (bitStream & 0xFF));
                        out.write((int) ((bitStream >>> 8) & 0xFF));
                        bitStream >>>= 16;
                        bitCount -= 16;
                    }
                }
                while (symbol >= start + 3)
                {
                    start += 3;
                    bitStream += 3L << bitCount;
                    bitCount += 2;
                }
                bitStream += ((long) (symbol - start)) << bitCount;
                bitCount += 2;
                // Flush as upstream does, so up to 16 bits of repeat codes
                // never pile up past the 64-bit accumulator or the final flush.
                if (bitCount > 16)
                {
                    out.write((int) (bitStream & 0xFF));
                    out.write((int) ((bitStream >>> 8) & 0xFF));
                    bitStream >>>= 16;
                    bitCount -= 16;
                }
                previousIs0 = 0;
            }

            int count = normalized[symbol];
            symbol += 1;
            int maxv = (2 * threshold - 1) - remaining;
            remaining -= (count < 0 ? -count : count);
            count += 1; // +1 for extra accuracy
            if (count >= threshold)
                count += maxv;
            bitStream += ((long) count) << bitCount;
            bitCount += nbBits;
            bitCount -= (count < maxv) ? 1 : 0;
            previousIs0 = (count == 1) ? 1 : 0;
            if (remaining < 1)
                throw new ZbicException("writeNCount remaining < 1");
            while (remaining < threshold)
            {
                nbBits -= 1;
                threshold >>>= 1;
            }
            if (bitCount > 16)
            {
                out.write((int) (bitStream & 0xFF));
                out.write((int) ((bitStream >>> 8) & 0xFF));
                bitStream >>>= 16;
                bitCount -= 16;
            }
        }

        if (remaining != 1)
            throw new ZbicException("writeNCount remaining != 1 (got " + remaining + ")");

        // Final flush: write enough bytes for the remaining bits.
        int finalBytes = (bitCount + 7) / 8;
        for (int i = 0; i < finalBytes; i++)
            out.write((int) ((bitStream >>> (8 * i)) & 0xFF));

        return out.toByteArray();
    }

    /** BIC NCount header -> standard FSE NCount header. */
    static byte[] convertNCount(byte[] header, int maxSv)
    {
        NCountResult r = fseReadNCountBic(header, maxSv);
        return fseWriteNCount(r.normalized, r.tableLog);
    }

    // -----------------------------------------------------------------
    // Frame / block helpers
    // -----------------------------------------------------------------
    private static int readLe24(byte[] data, int off)
    {
        return u8(data, off) | (u8(data, off + 1) << 8) | (u8(data, off + 2) << 16);
    }

    private static byte[] writeLe24(int val)
    {
        return new byte[] { (byte) (val & 0xFF), (byte) ((val >>> 8) & 0xFF), (byte) ((val >>> 16) & 0xFF) };
    }

    /** Advance past Frame_Header; pos points at Frame_Header_Descriptor. */
    private static int skipFrameHeader(byte[] data, int pos)
    {
        int fhd = u8(data, pos);
        pos += 1;
        // Window_Descriptor present when Single_Segment_flag is clear
        if ((fhd & 0x20) == 0)
            pos += 1;
        // Dictionary_ID
        int[] didLens = { 0, 1, 2, 4 };
        pos += didLens[fhd & 3];
        // Frame_Content_Size
        int fcsBits = fhd >>> 6;
        if ((fhd & 0x20) != 0 && fcsBits == 0)
            pos += 1;
        else
        {
            int[] fcsLens = { 0, 2, 4, 8 };
            pos += fcsLens[fcsBits];
        }
        return pos;
    }

    /**
     * Rewrite the Literals_Section starting at pos.
     *
     * Only rewrites when an FSE/BIC Huffman weight table is present and
     * converted; otherwise the original bytes are copied unchanged so we
     * cannot introduce size-field encoding bugs.
     */
    private static Section rewriteLiteralsSection(byte[] src, int pos)
    {
        int litHdr = u8(src, pos);
        int litType = litHdr & 3; // 0=Raw 1=RLE 2=Compressed 3=Treeless
        int sizeFmt = (litHdr >>> 2) & 3;
        int start = pos;
        pos += 1;

        if (litType == 0 || litType == 1) // Raw / RLE - no FSE tables
        {
            int regenSize;
            // Raw/RLE size_format encoding (different from Compressed!)
            if (sizeFmt == 0 || sizeFmt == 2)
            {
                regenSize = litHdr >>> 3;
            }
            else if (sizeFmt == 1)
            {
                regenSize = (litHdr >>> 4) | (u8(src, pos) << 4);
                pos += 1;
            }
            else
            {
                regenSize = (litHdr >>> 4) | (u8(src, pos) << 4) | (u8(src, pos + 1) << 12);
                pos += 2;
            }
            pos += (litType == 1) ? 1 : regenSize;
            return new Section(Arrays.copyOfRange(src, start, pos), pos);
        }

        // Compressed or Treeless - header encodes both regenerated_size and
        // compressed_size. Per zstd format / ZSTD_decodeLiteralsBlock:
        //   size_format 00/01: 3-byte header, 10+10 bit sizes
        //                      (00 = single stream, 01 = 4 streams)
        //   size_format 10:    4-byte header, 14+14 bit sizes
        //   size_format 11:    5-byte header, 18+18 bit sizes
        long lhc = u8(src, start) | (u8(src, start + 1) << 8) | (u8(src, start + 2) << 16);
        if (start + 3 < src.length)
            lhc |= ((long) u8(src, start + 3)) << 24;

        int lhSize;
        long cSize;
        if (sizeFmt <= 1)
        {
            lhSize = 3;
            cSize = (lhc >>> 14) & 0x3FF;
        }
        else if (sizeFmt == 2)
        {
            lhSize = 4;
            cSize = lhc >>> 18;
        }
        else
        {
            lhSize = 5;
            cSize = (lhc >>> 22) + ((start + 4 < src.length) ? (((long) u8(src, start + 4)) << 10) : 0);
        }

        int payloadStart = start + lhSize;
        int sectionEnd = payloadStart + (int) cSize;
        pos = sectionEnd;

        // Treeless has no tree; Compressed may have FSE-compressed weights.
        // HUF_readStats layout when headerByte < 128:
        //   payload[0]           = iSize  (size of FSE-compressed weight block)
        //   payload[1:1+iSize]   = FSE block = NCount header + weight bitstream
        //   payload[1+iSize:]    = jump table (optional) + literal streams
        // We must convert only the NCount and keep the weight bitstream intact.
        if (litType != 2)
            return new Section(Arrays.copyOfRange(src, start, sectionEnd), sectionEnd);

        byte[] payload = Arrays.copyOfRange(src, payloadStart, sectionEnd);
        if (payload.length == 0 || u8(payload, 0) >= 128)
        {
            // Direct weights or empty - nothing to convert
            return new Section(Arrays.copyOfRange(src, start, sectionEnd), sectionEnd);
        }

        int iSize = u8(payload, 0);
        if (1 + iSize > payload.length)
            throw new ZbicException("Huffman FSE weight table truncated");
        byte[] fseBlock = Arrays.copyOfRange(payload, 1, 1 + iSize);
        byte[] rest = Arrays.copyOfRange(payload, 1 + iSize, payload.length);

        // Split FSE block into BIC NCount + remaining weight bitstream
        NCountResult ncr;
        try
        {
            ncr = fseReadNCountBic(fseBlock, 12);
        }
        catch (ZbicException e)
        {
            // Leave the original bytes untouched if the weight table doesn't
            // parse as BIC-encoded.
            return new Section(Arrays.copyOfRange(src, start, sectionEnd), sectionEnd);
        }

        byte[] newNc = fseWriteNCount(ncr.normalized, ncr.tableLog);
        byte[] weightBitstream = Arrays.copyOfRange(fseBlock, ncr.bytesConsumed, fseBlock.length);
        ByteArrayOutputStream newFseBlockStream = new ByteArrayOutputStream();
        newFseBlockStream.write(newNc, 0, newNc.length);
        newFseBlockStream.write(weightBitstream, 0, weightBitstream.length);
        byte[] newFseBlock = newFseBlockStream.toByteArray();
        if (newFseBlock.length >= 128)
            throw new ZbicException("converted Huffman FSE block too large for hSize field");

        ByteArrayOutputStream newPayloadStream = new ByteArrayOutputStream();
        newPayloadStream.write(newFseBlock.length);
        newPayloadStream.write(newFseBlock, 0, newFseBlock.length);
        newPayloadStream.write(rest, 0, rest.length);
        byte[] newPayload = newPayloadStream.toByteArray();
        long newCSize = newPayload.length;

        if (newCSize == cSize && Arrays.equals(newPayload, payload))
            return new Section(Arrays.copyOfRange(src, start, sectionEnd), sectionEnd);

        // Size changed - rebuild Literals_Section_Header keeping regenerated_size
        // and encoding the new compressed_size with the same size_format.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (sizeFmt <= 1)
        {
            // 3-byte: [type:2][szfmt:2][regen:10][csize:10]
            long regen = (lhc >>> 4) & 0x3FF;
            if (newCSize > 0x3FF)
                throw new ZbicException(String.format("new c_size %d too large for size_fmt %d", newCSize, sizeFmt));
            long packed = litType | (sizeFmt << 2) | (regen << 4) | (newCSize << 14);
            out.write((int) (packed & 0xFF));
            out.write((int) ((packed >>> 8) & 0xFF));
            out.write((int) ((packed >>> 16) & 0xFF));
        }
        else if (sizeFmt == 2)
        {
            // 4-byte: [type:2][szfmt:2][regen:14][csize:14]
            long regen = (lhc >>> 4) & 0x3FFF;
            if (newCSize > 0x3FFF)
                throw new ZbicException(String.format("new c_size %d too large for size_fmt 2", newCSize));
            long packed = litType | (sizeFmt << 2) | (regen << 4) | (newCSize << 18);
            out.write((int) (packed & 0xFF));
            out.write((int) ((packed >>> 8) & 0xFF));
            out.write((int) ((packed >>> 16) & 0xFF));
            out.write((int) ((packed >>> 24) & 0xFF));
        }
        else
        {
            // 5-byte: [type:2][szfmt:2][regen:18][csize:18]
            long regen = (lhc >>> 4) & 0x3FFFF;
            if (newCSize > 0x3FFFF)
                throw new ZbicException(String.format("new c_size %d too large for size_fmt 3", newCSize));
            // first 4 bytes hold type+szfmt+regen(18)+csize low 10 bits; 5th has csize high 8
            long packed = litType | (sizeFmt << 2) | (regen << 4) | ((newCSize & 0x3FF) << 22);
            out.write((int) (packed & 0xFF));
            out.write((int) ((packed >>> 8) & 0xFF));
            out.write((int) ((packed >>> 16) & 0xFF));
            out.write((int) ((packed >>> 24) & 0xFF));
            out.write((int) ((newCSize >>> 10) & 0xFF));
        }

        out.write(newPayload, 0, newPayload.length);
        return new Section(out.toByteArray(), sectionEnd);
    }

    /** Rewrite Sequences_Section starting at pos. */
    private static Section rewriteSequencesSection(byte[] src, int pos, int blockEnd)
    {
        int start = pos;
        if (pos >= blockEnd)
            return new Section(new byte[0], pos);

        // Number_of_Sequences
        int seq0 = u8(src, pos);
        pos += 1;
        int nbSeq;
        if (seq0 < 128)
        {
            nbSeq = seq0;
        }
        else if (seq0 < 255)
        {
            nbSeq = ((seq0 - 128) << 8) + u8(src, pos);
            pos += 1;
        }
        else
        {
            nbSeq = u8(src, pos) + (u8(src, pos + 1) << 8) + 0x7F00;
            pos += 2;
        }

        if (nbSeq == 0)
            return new Section(Arrays.copyOfRange(src, start, pos), pos);

        int modes = u8(src, pos);
        pos += 1;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(src, start, pos - start); // keep nbSeq + modes bytes as-is

        String[] tableNames = { "LL", "OF", "ML" };
        int[] shifts = { 6, 4, 2 };
        int[] maxSvs = { 35, 31, 52 };

        for (int ti = 0; ti < 3; ti++)
        {
            int mode = (modes >>> shifts[ti]) & 3;
            if (mode == 2) // FSE_Compressed -> BIC NCount
            {
                // Only the remainder of THIS block is valid input - do not
                // let the BIC decoder read into the next block.
                if (pos >= blockEnd)
                    throw new ZbicException("seq " + tableNames[ti] + " FSE NCount starts past block end");
                byte[] available = Arrays.copyOfRange(src, pos, blockEnd);
                byte[] newNc = convertNCount(available, maxSvs[ti]);
                NCountResult r = fseReadNCountBic(available, maxSvs[ti]);
                int oldSz = r.bytesConsumed;
                if (oldSz > available.length)
                {
                    throw new ZbicException(String.format(
                        "seq %s FSE NCount size %d exceeds block remainder %d", tableNames[ti], oldSz, available.length));
                }
                out.write(newNc, 0, newNc.length);
                pos += oldSz;
            }
            else if (mode == 1) // RLE
            {
                if (pos >= blockEnd)
                    throw new ZbicException("seq " + tableNames[ti] + " RLE past block end");
                out.write(u8(src, pos));
                pos += 1;
            }
            // mode 0 (Predef) / 3 (Repeat): nothing to copy here
        }

        // remainder of the block is the bit-packed sequences bitstream
        out.write(src, pos, blockEnd - pos);
        return new Section(out.toByteArray(), blockEnd);
    }

    /** Return a rewritten compressed-block body (no 3-byte header). */
    private static byte[] rewriteCompressedBlock(byte[] src, int blockStart, int blockSize)
    {
        int pos = blockStart;
        int end = blockStart + blockSize;

        Section lit = rewriteLiteralsSection(src, pos);
        pos = lit.pos;
        Section seq = rewriteSequencesSection(src, pos, end);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(lit.bytes, 0, lit.bytes.length);
        out.write(seq.bytes, 0, seq.bytes.length);
        return out.toByteArray();
    }

    // -----------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------

    /** True if the buffer starts with the ZBIC magic. */
    public static boolean isZbicFrame(byte[] data)
    {
        if (data == null || data.length < ZBIC_MAGIC.length)
            return false;
        for (int i = 0; i < ZBIC_MAGIC.length; i++)
        {
            if (data[i] != ZBIC_MAGIC[i])
                return false;
        }
        return true;
    }

    /**
     * Convert a ZBIC frame into a standard zstd frame.
     *
     * @throws ZbicException on malformed input.
     */
    public static byte[] zbicToZstd(byte[] compressed)
    {
        if (!isZbicFrame(compressed))
        {
            byte[] head = Arrays.copyOf(compressed, Math.min(4, compressed.length));
            StringBuilder hex = new StringBuilder();
            for (byte b : head)
                hex.append(String.format("%02x", b));
            throw new ZbicException("not a ZBIC frame (bad magic " + hex + ")");
        }
        if (compressed.length < 6)
            throw new ZbicException("frame too short");

        byte[] src = compressed;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(ZSTD_MAGIC, 0, ZSTD_MAGIC.length);

        // Frame header (unchanged aside from magic)
        int pos = 4;
        int hdrEnd = skipFrameHeader(src, pos);
        out.write(src, pos, hdrEnd - pos);
        pos = hdrEnd;

        // Blocks
        while (pos + 3 <= src.length)
        {
            int bh = readLe24(src, pos);
            int last = bh & 1;
            int btype = (bh >>> 1) & 3;
            int bsize = bh >>> 3;
            pos += 3;

            if (btype == 0) // Raw
            {
                out.write(writeLe24(bh), 0, 3);
                out.write(src, pos, bsize);
                pos += bsize;
            }
            else if (btype == 1) // RLE
            {
                out.write(writeLe24(bh), 0, 3);
                out.write(src, pos, 1);
                pos += 1;
            }
            else if (btype == 2) // Compressed
            {
                byte[] body = rewriteCompressedBlock(src, pos, bsize);
                pos += bsize;
                int newBh = (body.length << 3) | (btype << 1) | last;
                out.write(writeLe24(newBh), 0, 3);
                out.write(body, 0, body.length);
            }
            else
            {
                throw new ZbicException("reserved block type " + btype);
            }

            if (last != 0)
                break;
        }

        // Optional content checksum (4 bytes) - copy remaining
        if (pos < src.length)
            out.write(src, pos, src.length - pos);

        return out.toByteArray();
    }

    /**
     * Convenience: convert ZBIC -&gt; zstd, then decompress with zstd-jni.
     *
     * @throws ZbicException on malformed input, or if the frame's content
     *                       size is unknown (streaming decompression is not
     *                       implemented here).
     */
    public static byte[] decompress(byte[] compressed)
    {
        byte[] frame = zbicToZstd(compressed);
        long size = Zstd.getFrameContentSize(frame);
        if (size < 0)
            throw new ZbicException("zstd frame content size unknown or invalid (" + size + ")");
        if (size > Integer.MAX_VALUE)
            throw new ZbicException("zstd frame content size too large: " + size);

        // Zstd.decompress(byte[], int) throws ZstdException internally on error.
        return Zstd.decompress(frame, (int) size);
    }
}
