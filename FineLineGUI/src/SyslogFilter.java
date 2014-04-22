

package FineLineGUI;

/********************************************************************

This file is part of Zeitline: a forensic timeline editor

Written by Florian Buchholz and Courtney Falk.

Copyright (c) 2004-2006 Florian Buchholz, Courtney Falk, Purdue
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
import java.io.RandomAccessFile;
import java.io.IOException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.text.NumberFormat;
import javax.swing.filechooser.FileFilter;
import javax.swing.JComponent;
import javax.swing.JFormattedTextField;

public class SyslogFilter extends InputFilter {
    protected RandomAccessFile file_input;
    private static FileFilter filter;
    protected int current_year;
    protected int last_month;
    protected GregorianCalendar now;
    private JComponent[] parameter_fields;
    private String[] parameter_names;
    private static final int CURRENT_YEAR;
    private FineLineConfig flConfig;
    
    static {
	    Calendar cal = Calendar.getInstance();
	    CURRENT_YEAR = cal.get(Calendar.YEAR);
       
    }
    
    
    public SyslogFilter(FineLineConfig flc) 
    {
        if(filter == null) filter = new FileInputFilter(null, null);
	parameter_fields = new JComponent[1]; 
	NumberFormat nf = NumberFormat.getIntegerInstance();
	nf.setGroupingUsed(false);
	JFormattedTextField ftf = new JFormattedTextField(nf);
	ftf.setValue(new Integer(CURRENT_YEAR));
	parameter_fields[0] = ftf;
	parameter_names = new String[1];
	parameter_names[0] = new String("Start year: ");
        flConfig = flc;
    } // SyslogFilter

    public File init(String filename, Component parent) 
    {
	try {
	    file_input = new RandomAccessFile(filename, "r");
	}
	catch (IOException ioe) {
	    return null;
        }
	
	current_year = ((Integer)((JFormattedTextField)parameter_fields[0]).getValue()).intValue();
	
	last_month = -1;
	now = new GregorianCalendar();
	now.clear();

	return new File(filename);
    } // init

    public FineLineEvent getNextEvent() 
    {

	String line;
	String[] fields;
	
	try {
	    line = file_input.readLine();
	}
	catch (IOException ioe) {
	    return null;
	}
	
	if (line == null) return null;

	// Pattern to match: <timestamp> <hostname/IP> [<generating instance>] <message>
	// timestamp: <three-character month> <day> <hh:mm:ss>
	// hostname: <non-whitespace sequence>
	// generating instance: (<non-colon sequence>|<non-colon sequence>[digits]):
	// message: remainder of line
	
	Pattern p = Pattern.compile("(...)\\s+(\\d+)\\s+(\\d\\d):(\\d\\d):(\\d\\d)\\s+(\\S+)\\s+([^:]*)\\[(\\d+)\\]:\\s(.+)");
	Matcher m = p.matcher(line);

	if (m.matches()) {
		int month = getMonth(m.group(1));
		if (month < last_month)
			current_year++;
		last_month = month;
		now.set(current_year, month, 
		    (new Integer(m.group(2))).intValue(), 
		    (new Integer(m.group(3))).intValue(), 
		    (new Integer(m.group(4))).intValue(), 
		    (new Integer(m.group(5))).intValue());
		
		return new SyslogEvent(now, m.group(6), m.group(7), new Integer(m.group(8)), m.group(9), flConfig);
	}

	p = Pattern.compile("(...)\\s+(\\d+)\\s+(\\d\\d):(\\d\\d):(\\d\\d)\\s+(\\S+)\\s+([^:]*):\\s(.+)");
	m = p.matcher(line);

	if (m.matches()) {
		int month = getMonth(m.group(1));
		if (month < last_month)
			current_year++;
		last_month = month;
		now.set(current_year, month, 
		    (new Integer(m.group(2))).intValue(), 
		    (new Integer(m.group(3))).intValue(), 
		    (new Integer(m.group(4))).intValue(), 
		    (new Integer(m.group(5))).intValue());

//		System.out.println("Host: " + m.group(6) + " Generator: " + m.group(7));
		    
		return new SyslogEvent(now, m.group(6), m.group(7), 0, m.group(8), flConfig);
//		return new GeneralEvent(m.group(8), "", new Calendar(now.getTime().getTime()));
	}
	
	System.err.println("No match for line: " + line);
	return null;
    } // getNextEvent

    public FileFilter getFileFilter() {
	return filter;
    } // getFileFilter

    public String getName() {
        return "Syslog Filter";
    } // getName
    
    public String getDescription() {
        return "Linux syslog event filter";
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

    public String[] getParameterLabels() {
	return parameter_names;
    }
    
    public JComponent[] getParameterFields() {
	return parameter_fields;
    }
    
    protected int getMonth(String name) {

	if (name.equals("Jan"))
	    return 0;
	if (name.equals("Feb"))
	    return 1;
	if (name.equals("Mar"))
	    return 2;
	if (name.equals("Apr"))
	    return 3;
	if (name.equals("May"))
	    return 4;
	if (name.equals("Jun"))
	    return 5;
	if (name.equals("Jul"))
	    return 6;
	if (name.equals("Aug"))
	    return 7;
	if (name.equals("Sep"))
	    return 8;
	if (name.equals("Oct"))
	    return 9;
	if (name.equals("Nov"))
	    return 10;
	if (name.equals("Dec"))
	    return 11;

	return 0;

    }

} // SyslogFilter
