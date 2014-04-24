/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/*
 * Class: FineLineTimeLine
 * Purpose: Implements the timeline project or case file using a hasmap to store the event/evidence records.
 * Date: 01/01/2014
 * Author: Derek Chadwick
 */
package FineLineGUI;

import java.util.HashMap;

/**
 *
 * @author Derek
 */

//import java.util.Date;
//TODO: DEPRECATED - JDK 8 will use java.time.*
//import java.time.ZoneId;
//import java.time.ZoneOffset;
//import java.time.ZonedDateTime;
//import java.time.LocalDateTime;

import java.util.TimeZone;
import java.util.SimpleTimeZone;
import java.util.Calendar;
import java.util.GregorianCalendar;

public class FineLineTimeLine 
{
    //Key value is the date and time string from the event record
    private final HashMap<String, FineLineEventRecord> flEventMap;
    //TODO: add project properties and methods for managing project
    String eventFile;
    String projectFile;
    
    TimeZone timeZone;
    SimpleTimeZone simpleTimeZone;
    GregorianCalendar startDate;
    Calendar endDate;

    public FineLineTimeLine(String prjFile) 
    {
        this.flEventMap = new HashMap<>();
        projectFile = prjFile;
        //open the project file and load the events into the hashmap, 
        //if it is a new project then get the event file and load the 
        //events into the hash map
        
        startDate = new GregorianCalendar();
        startDate.set(2001, 1, 1, 12, 0, 0); // 01/01/2001 12:00
        timeZone.setID("Australia/Perth");
    
    }
    
    public void openEventFile(String evtFile)
    {
        
    }
    
    public void openProjectFile(String projectFile)
    {
        
    }
    
    public void saveProjectFile()
    {
        
    }
    
    public FineLineEventRecord getEvent(String event)
    {
        return(flEventMap.get(event));
    }
    
    public void putEvent(FineLineEventRecord fler)
    {
        //get date and time then add key/value pair to the hashmap
    }
}
