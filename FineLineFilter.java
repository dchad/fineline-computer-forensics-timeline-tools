/*  Copyright 2014 Derek Chadwick
 
    This file is part of the FineLine Computer Forensics Timeline Tools.

    FineLine is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FineLine is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with FineLine.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Project: FineLine Computer Forensics Timeline Tools
 * Author : Derek Chadwick
 * Date   : 16/1/2014
 * Class  : FineLineFilter
 * 
 * Description: A class for importing FineLine event records into existing projects.
 *              
 *              
 * 
 */



package FineLineGUI;

import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import javax.swing.filechooser.FileFilter;

/**
 *
 * @author Derek
 */
class FineLineFilter extends InputFilter {
    private RandomAccessFile file_input;
    private String filename;
    private FileInputFilter filter;
    private FineLineConfig flc;

    public FineLineFilter(FineLineConfig flConfig) 
    {
        if(filter == null) filter = new FileInputFilter(null, null);
        flConfig = flc;      
    }

    @Override
    public File init(String location, Component parent) 
    {
        try {
	    //	    file_input = new BufferedReader(new FileReader(filename));
	    file_input = new RandomAccessFile(filename, "r");
	}
	catch (FileNotFoundException ioe) {
	    return null;
	}

	return new File(filename);
    }

    @Override
    public FineLineEvent getNextEvent() 
    {
    	String line;
	
        while (true)
        {
	   try {
	    line = file_input.readLine();
	   }
	   catch (IOException ioe) {
	    return null;
	   }
           if (line.startsWith("<event>"))
           {
               return(new FineLineEvent(line));
           }
	}   
    }

    @Override
    public FileFilter getFileFilter() 
    {
        return(filter);
    }

    @Override
    public String getName() 
    {
        return("FineLine Event Filter");
    }

    @Override
    public String getDescription() 
    {
        return("Reads event files created by the FineLine Computer Forensic Timeline Tools");
    }

    @Override
    public long getExactCount() 
    {
        return(0);
    }

    @Override
    public long getTotalCount() 
    {
        try {
	    return file_input.length();
	}
	catch (IOException ie) {
	    return 0;
	}
    }

    @Override
    public long getProcessedCount() 
    {
	try {
	    return file_input.getFilePointer();
	}
	catch (IOException ie) {
	    return 0;
	}        
    }
    
}
