package adubbz.nx.util;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;

import java.io.IOException;

public class LegacyByteProviderWrapper extends ByteProviderWrapper {

    public LegacyByteProviderWrapper(ByteProvider provider, long subOffset, long subLength) {
        super(provider, subOffset, subLength);
    }

    @Override
    public boolean isValidIndex(long index) {
        return (0 <= index && subOffset + index < subLength) && provider.isValidIndex(subOffset + index);
    }

    @Override
    public byte readByte(long index) throws IOException {
        if (index < 0 || subOffset + index >= subLength) {
            throw new IOException("Invalid index: " + index);
        }
        return provider.readByte(subOffset + index);
    }

    @Override
    public byte[] readBytes(long index, long length) throws IOException {
        if (index < 0 || subOffset + index >= subLength) {
            throw new IOException("Invalid index: " + index);
        }
        if (subOffset + index + length > subLength) {
            throw new IOException("Unable to read past EOF: " + index + ", " + length);
        }
        return provider.readBytes(subOffset + index, length);
    }
}
