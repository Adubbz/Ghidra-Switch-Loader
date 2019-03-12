package adubbz.switchloader.common;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.MemoryBlockUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class InitializedSectionManager 
{
    private TaskMonitor monitor;
    private MemoryBlockUtil mbu;
    private AddressSpace addressSpace;
    private long baseAddress;
    private List<Section> sections = new ArrayList<>();
    
    private boolean isFinalized = false;
    
    public InitializedSectionManager(TaskMonitor monitor, MemoryBlockUtil mbu, AddressSpace addressSpace, long baseAddress)
    {
        this.monitor = monitor;
        this.mbu = mbu;
        this.addressSpace = addressSpace;
        this.baseAddress = baseAddress;
    }
    
    public void addSection(String name, long addressOffset, InputStream dataInput, long dataSize, boolean read, boolean write, boolean execute)
    {
        if (this.isFinalized)
            throw new RuntimeException("Attempted to add a new section when they are already finalized!");
        
        Section newSection = new Section(name, addressOffset, dataInput, dataSize, read, write, execute);
        
        // Go through all previous sections and adjust them
        for (Section section : this.sections)
        {
            if (section.overlaps(newSection).isEmpty())
                continue;
            
            section.accomodate(newSection);
        }
        
        this.sections.add(newSection);
    }
    
    public void addSectionInheritPerms(String name, long addressOffset, InputStream dataInput, long dataSize)
    {
        if (this.isFinalized)
            throw new RuntimeException("Attempted to add a new section when they are already finalized!");
        
        Section newSection = new Section(name, addressOffset, dataInput, dataSize, false, false, false);
        
        // Go through all previous sections and adjust them
        for (Section section : this.sections)
        {
            if (section.overlaps(newSection).isEmpty())
                continue;

            section.accomodate(newSection);
            newSection.read = section.read;
            newSection.write = section.write;
            newSection.execute = section.execute;
        }
        
        this.sections.add(newSection);
    }
    
    public void finalizeSections() throws IOException, AddressOverflowException
    {
        if (this.isFinalized)
            throw new RuntimeException("Sections are already finalized!");
        
        this.isFinalized = true;
        
        this.sections.sort((section1, section2) ->
        {
          return section1.originalAddressRange.getMinAddress().compareTo(section2.originalAddressRange.getMinAddress());  
        });
        
        for (Section section : this.sections)
        {
            for (int i = 0; i < section.addresses.size(); i++)
            {
                String suffix = i == 0 ? "" : "." + i;
                AddressRange range = section.addresses.get(i);
                
                Msg.info(this, String.format("Finalizing block %s 0x%X-0x%X", (section.name + suffix), range.getMinAddress().getUnsignedOffset(), range.getMinAddress().getUnsignedOffset() + range.getLength() - 1));
                section.dataInput.mark(Integer.MAX_VALUE);
                section.dataInput.skip(range.getMinAddress().getUnsignedOffset() - section.originalAddressRange.getMinAddress().getUnsignedOffset());
                this.mbu.createInitializedBlock(section.name + suffix, range.getMinAddress(), section.dataInput, range.getLength() - 1, "", null, section.read, section.write, section.execute, this.monitor);
                section.dataInput.reset();
            }
        }
    }
    
    private class Section
    {
        private String name;
        private InputStream dataInput;
        private long dataSize;
        private boolean read;
        private boolean write;
        private boolean execute;
        
        private AddressRange originalAddressRange;
        private List<AddressRange> addresses = new ArrayList<>();
        
        public Section(String name, long addressOffset, InputStream dataInput, long dataSize, boolean read, boolean write, boolean execute)
        {
            this.name = name;
            this.dataInput = dataInput;
            this.dataSize = dataSize;
            this.read = read;
            this.write = write;
            this.execute = execute;
            
            long baseAddress = InitializedSectionManager.this.baseAddress;
            Address startAddress = InitializedSectionManager.this.addressSpace.getAddress(baseAddress + addressOffset);
            Address endAddress = startAddress.add(dataSize);
            
            this.originalAddressRange = new AddressRangeImpl(startAddress, endAddress);
            this.addresses.add(this.originalAddressRange);
        }
        
        /***
         * Find overlapping addresses between this range and another range.
         * @param section
         * @return a map of this section's address ranges to a list of overlapping ranges in
         * the provided section.
         */
        public Map<AddressRange, List<AddressRange>> overlaps(Section section)
        {
            Map<AddressRange, List<AddressRange>> overlapMap = new HashMap<>();
            
            for (AddressRange addr1 : this.addresses)
            {
                for (AddressRange addr2 : section.addresses)
                {
                    if (addr1.intersects(addr2))
                    {
                        if (!overlapMap.containsKey(addr1))
                            overlapMap.put(addr1, new ArrayList<>());
                            
                        List<AddressRange> overlapList = overlapMap.get(addr1);
                        overlapList.add(addr2);
                    }
                }
            }
            
            // Merge overlapping ranges together for sanity
            for (var entry : overlapMap.entrySet())
            {
               overlapMap.put(entry.getKey(), this.mergeOverlappingRanges(entry.getValue()));
               
               /*for (AddressRange overlapRange : entry.getValue())
               {
                   Msg.info(this, String.format("Overlap between %s 0x%X-0x%X and %s 0x%X-0x%X", this.name, entry.getKey().getMinAddress().getUnsignedOffset(), entry.getKey().getMaxAddress().getUnsignedOffset(), section.name, overlapRange.getMinAddress().getUnsignedOffset(), overlapRange.getMaxAddress().getUnsignedOffset()));   
               }*/
            }
            
            return overlapMap;
        }
        
        /***
         * Adjust address ranges to remove overlap with the
         * provided section
         * @param section
         */
        public void accomodate(Section section)
        {
            Map<AddressRange, List<AddressRange>> overlapMap = this.overlaps(section);
            AddressSpace addrSpace = InitializedSectionManager.this.addressSpace;
            
            //Msg.info(this, this.name + " pre-accomodation " + this.addresses.size() + " address ranges.");
            
            for (var entry : overlapMap.entrySet())
            {
                AddressRange overlappedRange = entry.getKey();
                List<AddressRange> overlaps = entry.getValue();
                List<AddressRange> newAddressRanges = new ArrayList<>();
                
                long startOffset = overlappedRange.getMinAddress().getUnsignedOffset();
                
                while (!overlaps.isEmpty())
                {
                    long endOffset = overlappedRange.getMaxAddress().getUnsignedOffset();
                    AddressRange firstOverlapRange = null;
                    
                    for (AddressRange overlap : overlaps)
                    {
                        if (overlap.getMinAddress().getUnsignedOffset() <= addrSpace.getAddress(endOffset).getUnsignedOffset())
                        {
                            // End before the overlap
                            endOffset = overlap.getMinAddress().getUnsignedOffset();
                            firstOverlapRange = overlap;
                        }
                    }
                    
                    if (firstOverlapRange == null)
                        throw new RuntimeException("Failed to find smallest overlap start range");
                    
                    if (endOffset - startOffset > 0)
                    {
                        newAddressRanges.add(new AddressRangeImpl(addrSpace.getAddress(startOffset), addrSpace.getAddress(endOffset)));
                    }
                    
                    // Start again after the overlap
                    startOffset = firstOverlapRange.getMaxAddress().getUnsignedOffset();
                    overlaps.remove(firstOverlapRange);
                }
                
                // Add on the data after the last overlap
                if (startOffset < overlappedRange.getMaxAddress().getUnsignedOffset())
                {
                    newAddressRanges.add(new AddressRangeImpl(addrSpace.getAddress(startOffset), overlappedRange.getMaxAddress()));
                }
                
                // Remove the overlapped range and insert our new ones
                this.addresses.remove(overlappedRange);
                this.addresses.addAll(newAddressRanges);
            }
            
            this.addresses.sort((addr1, addr2) ->
            {
                return addr1.compareTo(addr2);
            });
            
            //Msg.info(this, this.name + " post-accomodation " + this.addresses.size() + " address ranges.");
        }
        
        private List<AddressRange> mergeOverlappingRanges(List<AddressRange> in)
        {
            if (in.size() <= 1)
                return in;
            
            List<AddressRange> out = new ArrayList<>();
            
            for (AddressRange inRange : in)
            {
                if (out.isEmpty())
                {
                    out.add(inRange);
                    continue;
                }
                
                var itr = out.listIterator();
                
                // Go through all existing output and check for intersections
                while (itr.hasNext())
                {
                    AddressRange outRange = itr.next();
                    
                    // Create a new merged range
                    if (inRange.intersects(outRange))
                    {
                        itr.remove();
                        Address newRangeStart = inRange.getMinAddress().getUnsignedOffset() < outRange.getMinAddress().getUnsignedOffset() ? inRange.getMinAddress() : outRange.getMinAddress();
                        Address newRangeEnd = inRange.getMaxAddress().getUnsignedOffset() > outRange.getMaxAddress().getUnsignedOffset() ? inRange.getMaxAddress() : outRange.getMaxAddress();
                        itr.add(new AddressRangeImpl(newRangeStart, newRangeEnd));
                    }
                }
            }
            
            return out;
        }
    }
}
