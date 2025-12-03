public static String demangleIpcSymbol(Program program, String mangled)
    {
        // Needed by the demangler
        if (!mangled.startsWith("_Z"))
            mangled = "_Z" + mangled;
     
        String out = mangled;
        DemangledObject demangledObj = DemanglerUtil.demangle(program, mangled);
        
        // Where possible, replace the mangled symbol with a demangled one
        if (demangledObj != null)
        {
            StringBuilder builder = new StringBuilder(demangledObj.toString());
            int templateLevel = 0;
            
            //De-Ghidrify-template colons
            for (int i = 0; i < builder.length(); ++i) 
            {
                char ch = builder.charAt(i);
                
                if (ch == '<') 
                {
                    ++templateLevel;
                }
                else if (ch == '>' && templateLevel != 0) 
                {
                    --templateLevel;
                }

                if (templateLevel > 0 && ch == '-') 
                    builder.setCharAt(i, ':');
            }
            
            out = builder.toString();
        }            
        
        return out;
    }
