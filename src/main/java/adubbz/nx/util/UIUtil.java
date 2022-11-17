/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package adubbz.nx.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.exception.NotFoundException;

public class UIUtil 
{
    private static final int SORT_BY_NAME = 1;
    private static final int SORT_BY_ADDRESS = 2;
    
    private static final GroupComparator ADDR_COMPARATOR = new GroupComparator(SORT_BY_ADDRESS);
    
    public static void sortProgramTree(Program program)
    {
        ProgramDB db = (ProgramDB)program;
        ProgramModule programTreeModule = db.getTreeManager().getRootModule("Program Tree");
        
        if (programTreeModule == null)
            return;
        
        try 
        {
            sortModule(programTreeModule);
        } 
        catch (NotFoundException ignored)
        {
        }
    }
    
    private static void sortModule(ProgramModule parent) throws NotFoundException
    {
        List<Group> list = new ArrayList<>();
        Group[] kids = parent.getChildren();

        for (Group kid : kids) {
            list.add(kid);
            if (kid instanceof ProgramModule) {
                sortModule((ProgramModule) kid);
            }
        }

        list.sort(ADDR_COMPARATOR);

        for (int i = 0; i < list.size(); i++) 
        {
            Group group = list.get(i);
            parent.moveChild(group.getName(), i);
        }
    }
    
    private static class GroupComparator implements Comparator<Group> 
    {
        private int sortType;

        GroupComparator(int sortType) 
        {
            this.sortType = sortType;
        }

        @Override
        public int compare(Group g1, Group g2) 
        {
            if (sortType == SORT_BY_ADDRESS) 
            {
                Address addr1;
                Address addr2;
                if (g1 instanceof ProgramFragment) {
                    addr1 = ((ProgramFragment) g1).getMinAddress();
                }
                else {
                    ProgramModule m = (ProgramModule) g1;
                    addr1 = m.getAddressSet().getMinAddress();
                }
                if (g2 instanceof ProgramFragment) {
                    addr2 = ((ProgramFragment) g2).getMinAddress();
                }
                else {
                    ProgramModule m = (ProgramModule) g2;
                    addr2 = m.getAddressSet().getMinAddress();
                }
                if (addr1 == null && addr2 == null) {
                    return 0;
                }
                if (addr1 != null && addr2 == null) {
                    return -1;
                }
                if (addr1 == null) {
                    return 1;
                }
                return addr1.compareTo(addr2);
            }
            return g1.getName().compareTo(g2.getName());
        }

    }
}
