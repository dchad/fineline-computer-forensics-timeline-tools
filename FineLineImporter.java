
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
 * Date   : 02/01/2014
 * Class  : FineLineImporter
 * 
 * Description: runnable class responsible for initiating and controlling imports
 *              of various event formats such as MACTIME/FLS, SYSLOG and FineLine files.
 *              Based on the importer class from Zeitline by Florian Buchholz and Courtney Falk.
 */


package FineLineGUI;

import java.io.File;
import javax.swing.JFrame;
import javax.swing.JProgressBar;

/**
 *
 * @author Derek
 */
public class FineLineImporter implements Runnable
{
        private boolean running;
        private JProgressBar progress_bar;
        private FineLineProgressDialog flpd;
        private InputFilter input_filter;
        private File importFile;
        private JFrame frame;
        private FineLineGraphViewPanel flGraph;
        private FineLineTextViewPanel flText;
        private FineLineConfig flConfig;

        public FineLineImporter(JFrame parent, FineLineGraphViewPanel flg, FineLineTextViewPanel flt, FineLineConfig flc) 
        {
            this.running = false;
            this.progress_bar = null;
            frame = parent;
            flGraph = flg;
            flText = flt;
            flConfig = flc;
        } 

        private boolean initImport() 
        {
            FineLineImportDialog idlg = new FineLineImportDialog(frame);
            if(idlg.showDialog(frame) == idlg.CANCEL_OPTION) return(false);
       
            int importType = idlg.getImportFilterType();

            //now obtain the import filter selected from the import filter list in the dialogue
            switch(importType)
            {
                case 0: input_filter = new FLSFilter(flConfig); break;
                case 1: input_filter = new SyslogFilter(flConfig); break;
                case 2: input_filter = new FineLineFilter(flConfig); break;
                //TODO: case 3: input_filter = new Log2Timeline(); break;
                default: System.out.println("Unknown import filter type."); return(false);
            }
            importFile = input_filter.init(idlg.getFileName(), frame);
            if(importFile == null) 
                return(false);
            flpd = new FineLineProgressDialog(frame, "Importing Events", this);
            flpd.setVisible(true);
            return(true);
	} 
        
        public void stop() 
        {
            running = false;
        }
        
	public void run() 
        {
            if (!initImport())
                return;

            progress_bar = flpd.getProgressBar();
            // enable thread execution
            running = true;
            
            String filter_name = input_filter.getName();
            int percent_done = 0;
            double total_size = 0;
            int eventCount = 0;
            
            if(progress_bar != null) 
            {
                progress_bar.setString(filter_name + " (" + percent_done + "%)");
                progress_bar.setMaximum(new Long(input_filter.getTotalCount()).intValue());
                progress_bar.setValue(0);
                total_size = new Long(input_filter.getTotalCount()).doubleValue();
            }
	    
            flpd.setStatus("Parsing import file");
            int value = 0;
            int day = 0;
            int seqDay = 0;
            FineLineEvent evt;
	    while(running && ((evt = input_filter.getNextEvent()) != null)) {
		
               //add the event obtained to a list of fine line events
               //System.out.println("FineLineImporter.run() <DEBUG> adding event: " + evt.getTime());
               eventCount++;
               if (evt.getDay() != day) //we have a new 24 hour period so increment the day sequence
               {
                   seqDay++;
                   day = evt.getDay();
               }
               evt.setDaySequence(seqDay); //set the timeline sequential day for x positioning (range = 1 to number of days in event log)
               flGraph.addEvent(evt);
               flText.addEvent(evt.getTime() + " " + evt.getSummary());
                // update the progress bar
               if(progress_bar != null) 
               {
                    value = new Long(input_filter.getProcessedCount()).intValue();
                    progress_bar.setValue(value);
                    
                    percent_done = new Double(new Long(input_filter.getProcessedCount()).doubleValue() / total_size * 100.0).intValue();
                    progress_bar.setString(filter_name + " (" + percent_done + "%)");
               }
	    }

            // make sure the import wasn't canceled
            if(running) 
            {
		// change progress bar to undetermined time
		flpd.setStatus("Adding events to the timeline");
		progress_bar.setIndeterminate(true);
            }
            
            // close the progress dialog
            flpd.setVisible(false);
            flGraph.finishedEventLoad(seqDay);
            System.out.println("FineLineImporter.run() <INFO> Processed events = " + eventCount);
	} // run


    } 

