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
 * Date   : 1/12/2013
 * Class  : FineLineEventLogLoader
 * 
 * Description: A runnable class for loading events from a project/case file.
 * 
 * 
 */

package FineLineGUI;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;


/**
 *
 * @author Derek
 */
public class FineLineEventLogLoader implements Runnable 
{
    private File eventFile;
    private BufferedReader in;
    private long fileLength = 0;
    private long charCount = 0;
    private long percentage = 0;
    private long eventCount = 0;
    private FineLineGraphViewPanel flGraph;
    private FineLineTextViewPanel flText;
    private FineLineMainFrame flMain;
    private int days = 0;
    private Boolean running;
    private ProgressDialog flpd;
    private JProgressBar progress;
    

        
    public FineLineEventLogLoader(FineLineMainFrame parent, FineLineGraphViewPanel gvp, File eventLogFile)
    {
        eventFile = eventLogFile;
        try {
            in = new BufferedReader(new FileReader(eventFile));
        } catch (FileNotFoundException ex) {
            System.out.println("FineLineEventLog <ERROR> Could not open event log file.");
        }
        fileLength = eventFile.length();
        flGraph = gvp;
        flMain = parent;
        flText = flMain.getTextPanel();
    }
        
    public String readLine()
    {
        String event = null;
        try {
            event = in.readLine();
            charCount = charCount + event.length();
            percentage = (charCount / fileLength) * 100;
        } catch (IOException ex) {
            System.out.println("FineLineEventLog <ERROR> Could not read event log file.");
        }
        return event;
    }
    
    public void saveAs()
    {
        //TODO: save the event log as another file
    }
    
    public long getFileSize()
    {
        return(fileLength);
    }
    
    public long getPercentage()
    {
        return(percentage);
    }

    @Override
    public void run() 
    {
        running = true;
        flpd = new ProgressDialog(flMain, "Opening project", this);
        flpd.setVisible(true);
        loadEventLog();
        flGraph.finishedEventLoad(days);
        flpd.setVisible(false);
        System.out.println("FineLineEventLogLoader: loaded days = " + days);
        try {
            in.close();
        } catch (IOException ex) {
            System.out.println("FineLineEventLogLoader <ERROR> Could not close project file.");
        }
    }

    public void stop()
    {
        running = false;
    }
    
    private void loadEventLog() 
    {
        String event;
        int day = 0;    //calender day
        int seqDay = 0; //sequence of 24 hour periods, there is at least one 24 hour period given a single event.
        progress = flpd.getProgressBar();

        if(progress != null) 
        {
            progress.setString("Loading (" + percentage + "%)");
            progress.setMaximum((int)fileLength);
            progress.setValue(0);
        }

        flpd.setStatus("Parsing event file");
        try {
            while (running && ((event = in.readLine()) != null))
            {
                if (event.startsWith("<event>")) //only process the event records, skip the project header etc...
                {
                   FineLineEvent evt = new FineLineEvent(event);
                   if (evt.getDay() != day) //we have a new 24 hour period so increment the day sequence
                   {
                       seqDay++;
                       day = evt.getDay();
                   }
                   evt.setDaySequence(seqDay); //set the timeline sequential day for x positioning (range = 1 to number of days in event log)
                  flGraph.addEvent(evt);
                  flText.addEvent(evt.getTime() + " " + evt.getSummary());
                  charCount = charCount + event.length();
                  eventCount++;
                  if(progress != null) 
                  {
                    progress.setValue((int)charCount);
                    percentage = (long)(((double)charCount / (double)fileLength) * 100.0);
                    progress.setString("Loading (" + percentage + "%)");
                  }
                }
            }
        } catch (IOException ex) {
            System.out.println("FineLineEventLogLoader: IO exception reading log file.");
        }
        System.out.println("Processed events: " + eventCount);
        days = seqDay++;
    }
    
    public class ProgressDialog extends JDialog implements ActionListener 
    {

    private Thread thread;
    private JLabel status;
    private JProgressBar progressBar;
    private JButton cancelButton;
    private FineLineEventLogLoader runner;

    public ProgressDialog(JFrame owner, String title, FineLineEventLogLoader run) 
    {
        super(owner, title, true);
                
	runner = run;
        
	JPanel pane = (JPanel) getContentPane();
        pane.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
	
        pane.setLayout(new GridLayout(3,1));
	
	status = new JLabel("Adding events to the timeline", JLabel.CENTER);
	pane.add(status);
	
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        pane.add(progressBar);

        cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(this);
        pane.add(cancelButton);
        
        setResizable(false);
        pack();
        setLocationRelativeTo(owner);
        this.setModal(false); //make sure the dialog does not block on display
    } 
    
    public void actionPerformed(ActionEvent e) 
    {
        Object source = e.getSource();
        
        if(source == cancelButton) 
        {
            runner.stop();
	    setVisible(false);
        }
    } // actionPerformed
    
    public JProgressBar getProgressBar() 
    {
        return progressBar;
    } // getProgressBar
    
    public void setStatus(String newStatus) 
    {
	    status.setText(newStatus);
    }
    
    public void setVisible(boolean visible) 
    {
        if(visible) 
        {
            // setting visible to true causes control to be given to the dialog
            super.setVisible(true);
        }
        else 
        {
            super.setVisible(false);
        }
    }
} 

}
