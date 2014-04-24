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
 * Class  : FineLineProject
 * 
 * Description: A class for reading and writing FineLine project files. It reads in a header record
 *              for a fineline project and if successful starts a FineLineEventLogLoader thread to
 *              read in the event records. FineLine generated event files have a default project
 *              header at the beginning of the file, followed by the events in time sequence order.
 */



package FineLineGUI;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;

/**
 *
 * @author Derek
 */
public class FineLineProject
{
    private String projectName;
    private String projectFileName;
    private String projectInvestigator;
    private String projectSummary;
    private String projectDescription;
    private String projectStartDate;
    private String projectEndDate;
    private File flProjectFile;
    private final FineLineGraphViewPanel flGraph;
    private long eventRecordCount;
    private long fileLength;
    private FineLineEventLogLoader flLoader;
    private Boolean open;
    private Boolean modified;
    private BufferedReader in;
    //private FineLineInfoPane flInfo;
    
    public FineLineProject(FineLineGraphViewPanel parent, File projFile)
    {
        flGraph = parent;
        flProjectFile = projFile;
        open = false;
        modified = false;
        //flInfo = new FineLineInfoPane((JFrame) JFrame.getFrames()[0]);
    }
    
    public void open()
    {
        if (flProjectFile == null)
            return;
        //flInfo.show("Loading events...");
        if (!flProjectFile.exists())
        {
                JOptionPane.showMessageDialog(flGraph, "Project file does not exist.", "Project file does not exist.", JOptionPane.OK_OPTION);
                System.out.println("FineLineProject <ERROR> Could not create project file.");
                return;
        }
       
          try {
            in = new BufferedReader(new FileReader(flProjectFile));
            readProjectHeader();
            flGraph.loadProject(this, flProjectFile);
          } catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(flGraph, "Could not open project file.", "Could not open project file.", JOptionPane.OK_OPTION);
            System.out.println("FineLineProject <ERROR> Could not open project file.");
            return;
          }
          fileLength = flProjectFile.length();

          try {
            in.close();
          } catch (IOException ex) {
            System.out.println("FineLineProject <ERROR> Could not close project file.");
          }
          open = true;
    }

    private void readProjectHeader() 
    {
        String phdr = null;
        try {
            phdr = in.readLine();
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(flGraph, "Could not read project header.", "Could not read project header.", JOptionPane.OK_OPTION);
            System.out.println("FineLineProject: could not read project header.");
        }
        //Extract the following fields:
        //<project><name></name><investigator></investigator><summary></summary><startdate></startdate><enddate></enddate><description></description></project>
        // 1. projectName
        // 2. projectInvestigator
        // 3. projectSummary
        // 4. projectStartDate
        // 5. projectEndDate
        // 6. projectDescription
        
        Pattern p = Pattern.compile("<name>(.*)</name>", Pattern.DOTALL);
        Matcher m = p.matcher(phdr);
        if (m.find()) 
        {
           //System.out.println(m.group(1)); 
            projectName = m.group(1);
        }
        p = Pattern.compile("<investigator>(.*)</investigator>", Pattern.DOTALL);
        m = p.matcher(phdr);
        if (m.find()) 
        {
           //System.out.println(m.group(1));
            projectInvestigator = m.group(1);
        }
        p = Pattern.compile("<summary>(.*)</summary>", Pattern.DOTALL);
        m = p.matcher(phdr);
        if (m.find()) 
        {
           //System.out.println(m.group(1)); 
            projectSummary = m.group(1);
        }
        p = Pattern.compile("<startdate>(.*)</startdate>", Pattern.DOTALL);
        m = p.matcher(phdr);
        if (m.find()) 
        {
           //System.out.println(m.group(1)); 
            projectStartDate = m.group(1);
        }
        p = Pattern.compile("<enddate>(.*)</enddate>", Pattern.DOTALL);
        m = p.matcher(phdr);
        if (m.find()) 
        {
           //System.out.println(m.group(1)); 
            projectEndDate = m.group(1);
        }
        p = Pattern.compile("<description>(.*)</description>", Pattern.DOTALL);
        m = p.matcher(phdr);
        if (m.find()) 
        {
           //System.out.println(m.group(1)); 
            projectDescription = m.group(1);
        }
    }

    private void loadEventList() 
    {
         //flLoader = new FineLineEventLogLoader(flGraph, flProjectFile);
         //Thread t = new Thread(flLoader);
         //t.start();
    }

    public void save() 
    {
        //write out the project header then get the event list from the graph panel and write it out
        //flInfo.show("Saving events...");
        if (!flProjectFile.exists())
        {
            try {
                flProjectFile.createNewFile();
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(flGraph, "Could not create project file.", "Could not create project file.", JOptionPane.OK_OPTION);
                System.out.println("FineLineProject <ERROR> Could not create project file.");
                return;
            }
        }
        PrintWriter out = null;
        try {
            out = new PrintWriter(flProjectFile);
        } catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(flGraph, "Could not open project file.", "Could not open project file.", JOptionPane.OK_OPTION);
            System.out.println("FineLineProject.save() <ERROR> opening project file.");
            return;
        }
        String projHeader = "<project><name>" + projectName +"</name><investigator>" + projectInvestigator + "</investigator><summary>" + projectSummary + "</summary><startdate>" + projectStartDate + "</startdate><enddate>" + projectEndDate + "</enddate><description>" + projectDescription + "</description></project>";
        out.println(projHeader);
        System.out.println("Saved project: " + projHeader);
        //Now serialize the event list and print out
        //TODO: put in a runnable so large event files do not freeze the gui
        flGraph.serializeEventList(out);
        out.flush();
        out.close();
        modified = false;
        //flInfo.hide();
    }
    
    public Boolean active()
    {
        return(open);
    }
    
    public Boolean modified()
    {
        return(modified);
    }

    public void setModified()
    {
        modified = true;
    }
    
    public void eventChange()
    {
        modified = true;
    }
    
    void saveAs(File pf) 
    {
        flProjectFile = pf;
        save();
    }
    
    /*
    Getter/Setter methods
    */
    public String getProjectName()
    {
        return(projectName);
    }
    public String getProjectFileName()
    {
       return(projectFileName);   
    }
    public String getProjectInvestigator()
    {
       return(projectInvestigator);
    }
    public String getProjectSummary()
    {
       return(projectSummary); 
    }
    public String getProjectDescription()
    {
       return(projectDescription);
    }
    public String getProjectStartDate()
    {
        return(projectStartDate);
    }
    public String getProjectEndDate()
    {
        return(projectEndDate);
    }
    public void setProjectName(String pn)
    {
        projectName = pn;
        modified = true;
    }
    public void setProjectFileName(String pfn)
    {
       projectFileName = pfn; 
       modified = true;
    }
    public void setProjectInvestigator(String pi)
    {
       projectInvestigator = pi;
       modified = true;
    }
    public void setProjectSummary(String ps)
    {
       projectSummary = ps; 
       modified = true;
    }
    public void setProjectDescription(String pd)
    {
       projectDescription = pd;
       modified = true;
    }
    public void setProjectStartDate(String sd)
    {
        projectStartDate = sd;
        modified = true;
    }
    public void setProjectEndDate(String ed)
    {
        projectEndDate = ed;
        modified = true;
    }

}
