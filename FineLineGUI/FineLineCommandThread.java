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
 * Class  : FineLineCommandThread
 * 
 * Description: a class for running and contolling the command line tools.
 * 
 */

package FineLineGUI;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 *
 * @author Derek
 */
public class FineLineCommandThread implements Runnable 
{
    private Process toolProcess;
    String[] execStr;
    FineLineFilterViewPanel flfvp;
    private boolean terminateTool;
    
    public FineLineCommandThread(FineLineFilterViewPanel parent)
    {
        flfvp = parent;
        execStr = new String[10];
    }

    @Override
    public void run() 
    {
       startTool();
    }
    
    public void startTool()
    {
       String tmp;
       int i = 0;
       File toolFile;
       
       tmp = flfvp.getCommand();
       if (tmp.length() > 0)
       {
          execStr[i] = tmp;
          i++;
          execStr[i] = "-d";
          i++;
       }
       else
       {
           flfvp.putMessage("Invalid command.\n");
           return;
       }
       toolFile = new File(tmp);
       
       tmp = flfvp.getFilter();
       if (tmp.length() > 0)
       {
          execStr[i] = "-f";
          i++;
          execStr[i] = tmp;
          i++;
       }
       tmp = flfvp.getOutputFile();
       if (tmp.length() > 0)
       {
          execStr[i] = "-o";
          i++;
          execStr[i] = tmp;
          i++;
       }
       tmp = flfvp.getGUIAddress();
       if (tmp.length() > 0)
       {
           execStr[i] = "-a";
           i++;
           execStr[i] = tmp;
           i++;        
       }
       
       
       // Now get the checkbox values
       /* DEPRECATED: unnecessary
       if (flfvp.getFileGeneration())
       {
           execStr[i] = "-d";
           i++;
       }
       if (flfvp.getSendEvents())
       {
           execStr[i] = "-g";
           i++;
           //TODO: get ip address for GUI
       }
       if (flfvp.getUseFilter())
       {
           
       }
       */
       
      if (toolFile.exists())
      {
        //Debug.debug("WLCPThread.start(): starting WLCP: ", execStr);
         flfvp.putMessage("Starting command line tool...\n");
         try 
         {   
            toolProcess = Runtime.getRuntime().exec(execStr); //go the process
         } catch (IOException ex) {
            flfvp.putMessage("IO exception while starting process.\n");
            return;
         }
         try 
         {
            //now connect to the process and display the output
            monitorToolThread();
         } catch (IOException ex) {
            flfvp.putMessage("IO exception while monitoring tool process.\n");
         }
         
      }
      else
      {
         flfvp.putMessage("Could not find tool file.\n");
      }
            
    }
    
    private void monitorToolThread() throws IOException
   {
      //lets go!
      Boolean running = true;
      terminateTool = false;
      
      BufferedReader toolOutput = new BufferedReader(new InputStreamReader(toolProcess.getInputStream()));

      while(running)
      {
         String inStr = null;
         try 
         {
            Thread.sleep(250); //have a little rest while waiting for WLCP to do something
         } catch (InterruptedException ex) {
            //Debug.debug("WLCPThread.monitorWLCPThread() - Thread.sleep() interrupted.");
         }
         if (toolOutput.ready())
         {
             inStr = toolOutput.readLine();
         }
         else
         {
            int ev = -1;
            try
            {
               Thread.sleep(1000); //have another little rest while waiting for WLCP to do something
            } catch (InterruptedException ex) {
               //Debug.debug("WLCPThread.monitorWLCPThread() - Thread.sleep() interrupted.");
            }
            try
            {
               ev = toolProcess.exitValue();
            } catch (IllegalThreadStateException ex) { } //do nothing as tool is still running 
            if (ev >= 0)  //WARNING: exit value is system dependent, have to check this on cross-platform tests!!!
            {
               terminateTool = true;
               //if (Config.DEBUG)
               //   Debug.debug("WLCPThread.monitorWLCPThread() - Exit value is: ", ev);
            }
         }
         
         if (inStr != null)
         {
            flfvp.putMessage(inStr);
         }
                 
         if (terminateTool)  // for the cancel button if the user gets sick of waiting
         {
            toolProcess.destroy();
            running = false;
            flfvp.putMessage("Tool completed.\n");
         }
      }

      toolOutput.close(); // we are all done
      
  }
    
  public synchronized void setTerminateTool()
  {
     terminateTool = true;
  }
  
}
