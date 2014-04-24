/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package FineLineGUI;

/********************************************************************

This file is part of Zeitline: a forensic timeline editor

Written by Florian Buchholz and Courtney Falk.

Copyright (c) 2004,2005 Florian Buchholz, Courtney Falk, Purdue
University. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal with the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:
 
Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimers.
Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimers in the
documentation and/or other materials provided with the distribution.
Neither the names of Florian Buchholz, Courtney Falk, CERIAS, Purdue
University, nor the names of its contributors may be used to endorse
or promote products derived from this Software without specific prior
written permission.
 
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NON-INFRINGEMENT.  IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE
SOFTWARE.

**********************************************************************/

import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.RandomAccessFile;
import java.io.IOException;
import java.util.Calendar;
import java.util.LinkedList;
import javax.swing.filechooser.FileFilter;

public class FLSFilter extends InputFilter 
{

    protected RandomAccessFile file_input;
    private static FileFilter filter;

    protected String filename;
    protected Calendar mtime;
    protected Calendar atime;
    protected Calendar ctime;
    protected int user_id;
    protected int group_id;
    protected int mode;
    protected int permissions;
    protected long size;
    protected int type;
    FineLineConfig flConfig;

    public FLSFilter(FineLineConfig flc) 
    {
        if(filter == null) filter = new FileInputFilter(".fls", "*.fls");
        flConfig = flc;
    } // FLSFilter

    public File init(String filename, Component parent) 
    {

	try {
	    //	    file_input = new BufferedReader(new FileReader(filename));
	    file_input = new RandomAccessFile(filename, "r");
	}
	catch (FileNotFoundException ioe) {
	    return null;
	}

	return new File(filename);
    } // init

    public FineLineEvent getNextEvent() 
    {

	String line;
	String[] fields;
	    
	    while (true) {

		try {
		    line = file_input.readLine();
		}
		catch (IOException ioe) {
		    return null;
		}
		
		if (line == null) return null;

		fields = line.split("\\|");	    
		
		if (fields.length < 16)
		    System.err.println("FLSFilter.getNextEvent() <ERROR> Line not in proper format: " + line);
		else
		    break;

	    }
		  

	    // get timestamps, we have second granularity but need to
	    // convert to ms
            String name = fields[1];
            try {
                mtime = Calendar.getInstance();
                mtime.setTimeInMillis(Long.decode(fields[12]).intValue() * (long)1000);
                atime = Calendar.getInstance();
                atime.setTimeInMillis(Long.decode(fields[11]).intValue() * (long)1000);
                ctime = Calendar.getInstance();
                ctime.setTimeInMillis(Long.decode(fields[13]).intValue() * (long)1000);

                user_id = Integer.decode(fields[7]).intValue();
                group_id = Integer.decode(fields[8]).intValue();
                mode = Integer.decode(fields[4]).intValue();
                size = Long.decode(fields[10]).intValue();
            } catch (NumberFormatException ex) {
                System.out.println("FLSFilter.getNextEvent() <ERROR> Number format exception.");
            }

           return(new MACTimeEvent(name, mtime, atime, ctime, user_id, group_id, mode, size, MACTimeEvent.TYPE_MAC, flConfig));
    } // getNextEvent

    public FileFilter getFileFilter() {
	return filter;
    } // getFileFilter

    public String getName() {
        return "FLS Filter";
    } // getName
    
    public String getDescription() {
        return "Reads in MAC times as output by Brian Carrier's FLS tool.";
    } // getDescription

    public long getExactCount() {
	return 0;
    } // getExactCount

    public long getTotalCount() {
	try {
	    return file_input.length();
	}
	catch (IOException ie) {
	    return 0;
	}
    } // getTotalCount

    public long getProcessedCount() {
	try {
	    return file_input.getFilePointer();
	}
	catch (IOException ie) {
	    return 0;
	}
    } // getProcessedCount

} // FLSFilter
