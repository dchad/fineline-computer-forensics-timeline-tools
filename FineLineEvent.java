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
 * Class  : FineLineEvent
 * 
 * Description: A single event or item of evidence to be displayed on the timeline.
 * 
 * 
 */

package FineLineGUI;

import java.awt.Color;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.util.Calendar;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author Derek
 */
public class FineLineEvent
{
    private int xPos;
    private int yPos;
    private int width;
    private int height;
    private String eventID;
    private String evidenceNumber;
    private String eventType;
    private String eventTime;
    private String eventDescription;
    private Color  eventColor;
    private String eventSummary;
    private String eventDate; //DD/MM/YYYY
    private Boolean magnified;
    private String eventDisplayTime;
    private String filePath;
    private String userName;
    private int eventHour;
    private int eventMinute;
    private int eventDay;
    private int eventMonth;
    private int eventYear;
    private int eventDaySequence;
    private int iconXPos;
    private int iconYPos;
    private Color iconColour;
    private Color iconMagnifyColour;
    private int eventTypeNumber;
    private Boolean spread;
    private Boolean marked;
    private Boolean hiddenEvent;
    private Boolean hiddenText;
    private Boolean pinned;
    private FineLineConfig flConfig;
    String eventData;

    public FineLineEvent()
    {
        xPos = 1;
        yPos = 1;
        width = 10;
        height = 10;
        magnified = false;
        eventType = "MANUAL"; //only useful for fineline generated events
        eventTypeNumber = FineLineConfig.FL_MANUAL_EVIDENCE_EVENT;
        filePath = "NONE";
        evidenceNumber = "0000";
        eventData = "NONE";
        userName = "NONE";
        spread = false;
        marked = false;
        hiddenEvent = false;
        hiddenText = false;
        pinned = false;
        setIconColour();    
    }
    
    public FineLineEvent(String filename, Calendar cal, FineLineConfig flc)
    {
        //Constructor for MACTIME/FLS GENERATED EVENTS
        flConfig = flc;
        xPos = 1;
        yPos = 1;
        width = 10;
        height = 10;
        eventID = "0000";
        eventSummary = filename;
        eventYear = cal.get(Calendar.YEAR);
        eventMonth = cal.get(Calendar.MONTH);
        eventDay = cal.get(Calendar.DAY_OF_MONTH);
        eventHour = cal.get(Calendar.HOUR);
        eventMinute = cal.get(Calendar.MINUTE);
        eventDate = String.format("%02d/%02d/%02d", eventDay, eventMonth, eventYear);
        eventDisplayTime = String.format("%02d:%02d", eventHour, eventMinute);
        eventTime = String.format("%s %s", eventDate, eventDisplayTime);
        magnified = false;
        eventType = "MACTIME/FLS";
        eventTypeNumber = FineLineConfig.FL_MACTIME_FLS_EVENT;
        filePath = "NONE";
        evidenceNumber = "0000";
        eventData = "NONE";
        userName = "NONE";
        spread = false;
        marked = false;
        hiddenEvent = false;
        hiddenText = false;
        pinned = false;
        setIconColour();
    }
    
    public FineLineEvent(String process, int pid, Calendar cal, FineLineConfig flc)
    {
        //Event imported from a Linux SYSLOG file
        xPos = 1;
        yPos = 1;
        width = 10;
        height = 10;
        magnified = false;
        eventID = "0000";
        eventSummary = String.format("%d %s", pid, process);
        eventYear = cal.get(Calendar.YEAR);
        eventMonth = cal.get(Calendar.MONTH);
        eventDay = cal.get(Calendar.DAY_OF_MONTH);
        eventHour = cal.get(Calendar.HOUR);
        eventMinute = cal.get(Calendar.MINUTE);
        eventDate = String.format("%02d/%02d/%02d", eventDay, eventMonth, eventYear);
        eventDisplayTime = String.format("%02d:%02d", eventHour, eventMinute);
        eventTime = String.format("%s %s", eventDate, eventDisplayTime);
        eventType = "SYSLOG";
        eventTypeNumber = FineLineConfig.FL_SYSLOG_EVENT;
        filePath = "NONE";
        evidenceNumber = "0000";
        eventData = "NONE";
        userName = "NONE";
        spread = false;
        marked = false;
        hiddenEvent = false;
        hiddenText = false;
        pinned = false;
        setIconColour();
    }
    
    public FineLineEvent(String evt)
    {
        //FINELINE GENERATED EVENT FILES
        xPos = 1;
        yPos = 1;
        width = 10;
        height = 10;
        magnified = false;
        filePath = "NONE";
        evidenceNumber = "0000";
        userName = "NONE";
        eventSummary = "NONE";
        spread = false;
        marked = false;
        hiddenEvent = false;
        hiddenText = false;
        pinned = false;
        
        Pattern p = Pattern.compile("<id>(.*)</id>", Pattern.DOTALL);
        Matcher m = p.matcher(evt);
        if (m.find()) 
        {
           eventID = m.group(1); 
        }
        
        p = Pattern.compile("<evidencenumber>(.*)</evidencenumber>", Pattern.DOTALL);
        m = p.matcher(evt);
        if (m.find()) 
        {
           evidenceNumber = m.group(1); 
        }
        
        p = Pattern.compile("<time>(.*)</time>", Pattern.DOTALL);
        m = p.matcher(evt);
        if (m.find()) 
        {
           eventTime = m.group(1); // DD/MM/YYYY HH:MM:SS
        }
        
        p = Pattern.compile("<type>(.*)</type>", Pattern.DOTALL);
        m = p.matcher(evt);
        if (m.find()) 
        {
           eventType = m.group(1); 
        }
        if ("Information".equals(eventType))
            eventTypeNumber = FineLineConfig.FL_WIN_INFORMATION;
        else if ("Verbose".equals(eventType))
            eventTypeNumber = FineLineConfig.FL_WIN_VERBOSE;
        else if ("Warning".equals(eventType))
            eventTypeNumber = FineLineConfig.FL_WIN_WARNING;
        else if ("Error".equals(eventType))
            eventTypeNumber = FineLineConfig.FL_WIN_ERROR;
        else if ("Critical".equals(eventType))
            eventTypeNumber = FineLineConfig.FL_WIN_CRITICAL;
        else if ("SYSLOG".equals(eventType))
            eventTypeNumber = FineLineConfig.FL_SYSLOG_EVENT;
        else if ("MACTIME/FLS".equals(eventType))
            eventTypeNumber = FineLineConfig.FL_MACTIME_FLS_EVENT;
        else
            eventTypeNumber = FineLineConfig.FL_MANUAL_EVIDENCE_EVENT;
        
        p = Pattern.compile("<summary>(.*)</summary>", Pattern.DOTALL);
        m = p.matcher(evt);
        if (m.find()) 
        {
           eventSummary = m.group(1); 
        }
        
        p = Pattern.compile("<data>(.*)</data>", Pattern.DOTALL);
        m = p.matcher(evt);
        if (m.find()) 
        {
           eventData = m.group(1); 
           if (eventID.equalsIgnoreCase("4648") || eventID.equalsIgnoreCase("4624"))
           {
              p = Pattern.compile("<mstring5>(.*)</mstring5>", Pattern.DOTALL);
              m = p.matcher(eventData);
              if (m.find())
              {
                  userName = m.group(1);
                  if (!eventSummary.contains(userName))
                  {
                     eventSummary = eventSummary + " (" + userName + ")";
                  }
              }
           }
           if (eventID.equalsIgnoreCase("4634") || eventID.equalsIgnoreCase("4647"))
           {
              p = Pattern.compile("<mstring1>(.*)</mstring1>", Pattern.DOTALL);
              m = p.matcher(eventData);
              if (m.find())
              {
                 userName = m.group(1);
                 if (!eventSummary.contains(userName))
                 {
                    eventSummary = eventSummary + " (" + userName + ")";
                 }
              }
           }
        }     

        p = Pattern.compile("<hiddenevent>(.*)</hiddenevent>", Pattern.DOTALL);
        m = p.matcher(evt);
        if (m.find()) 
        {
           hiddenEvent = Boolean.valueOf(m.group(1)); 
        }     
 
        p = Pattern.compile("<hiddentext>(.*)</hiddentext>", Pattern.DOTALL);
        m = p.matcher(evt);
        if (m.find()) 
        {
           hiddenText = Boolean.valueOf(m.group(1)); 
        }     

        p = Pattern.compile("<marked>(.*)</marked>", Pattern.DOTALL);
        m = p.matcher(evt);
        if (m.find()) 
        {
           marked = Boolean.valueOf(m.group(1)); 
        }     

        p = Pattern.compile("<pinned>(.*)</pinned>", Pattern.DOTALL);
        m = p.matcher(evt);
        if (m.find()) 
        {
           pinned = Boolean.valueOf(m.group(1)); 
        }     
        
        p = Pattern.compile("<ypos>(.*)</ypos>", Pattern.DOTALL);
        m = p.matcher(evt);
        if (m.find()) 
        {
           yPos = Integer.parseInt(m.group(1)); 
           iconYPos = yPos - (height/2);
        }     
        
        //extract hour and minute from time field for xpos/ypos
        eventDate = eventTime.substring(0, 10); // DD/MM/YYYY
        //System.out.println("Event Date: " + eventDate); 
        
        eventDay = Integer.parseInt(eventDate.substring(0,2));
        eventMonth = Integer.parseInt(eventDate.substring(3,5));
        eventYear = Integer.parseInt(eventDate.substring(6,10));
        
        int beg = eventTime.indexOf(" ");
        int end = eventTime.indexOf(":");
        eventDisplayTime = eventTime.substring(beg+1, beg+6);
        String tempStr = eventTime.substring(beg+1, end);
        
        eventHour = Integer.parseInt(tempStr);
        tempStr = eventTime.substring(end+1, end+3);
        eventMinute = Integer.parseInt(tempStr);
        
        setIconColour();
    }
    
    public void setX(int xPos)
    { 
        this.xPos = xPos;
        this.iconXPos = xPos - (width/2);
    }

    public int getX()
    {
        return (int) xPos;
    }

    public void setY(int yPos)
    {
        this.yPos = yPos;
        this.iconYPos = yPos - (height/2);
    }

    public int getY()
    {
        return yPos;
    }

    public int getWidth()
    {
        return width;
    } 

    public int getHeight()
    {
        return height;
    }
    
    public String getTime()
    {
        return eventTime;
    }
    public void setPos(int x, int y)
    {
        xPos = x;
        iconXPos = (int) (xPos - (width/2));
        if (yPos < 1)
        {
           yPos = y;
           iconYPos = yPos - (height/2);
        }
    }

    public int getHour()
    {
        return eventHour;
    }
    public int getMinute()
    {
        return eventMinute;
    }
    public int getDay()
    {
        return eventDay;
    }
    public int getMonth()
    {
        return eventMonth;
    }
    public int getYear()
    {
        return eventYear;
    }
    public String getDate()
    {
        return eventDate;
    }
    public void setDaySequence(int day)
    {
        eventDaySequence = day;
    }
    public int getDaySequence()
    {
        return eventDaySequence;
    }
    public final void magnify(int multi)
    {
        width = width * multi;
        height = height * multi;
        iconXPos = (xPos - (width/2));
        iconYPos = yPos - (height/2);
        magnified = true;

    }
    
    public void demagnify (int multi)
    {
        width = width / multi;
        height = height / multi;
        iconXPos = (xPos - (width/2));
        iconYPos = yPos - (height/2);  
        magnified = false;
    }
    
    public void spread(int y)
    {
        spread = true;
        yPos = y;
        width = 4;
        height = 4;
        iconXPos = (int) (xPos - (width/2));
        iconYPos = yPos - (height/2);
        hiddenText = true;
    }
    
    public Boolean getSpread()
    {
        return(spread);
    }
    
    public void mark()
    {
        marked = true;
    }
    public void unmark()
    {
        marked = false;
    }
    public Boolean marked ()
    {
        return(marked);
    }
    public void hideEvent()
    {
        if (!pinned)
           hiddenEvent = true;
    }
    public void unhideEvent()
    {
        hiddenEvent = false;
    }
    public Boolean hiddenEvent()
    {
        return(hiddenEvent);
    }
    public void hideText()
    {
        if (!pinned)
          hiddenText = true;
    }
    public void unhideText()
    {
        hiddenText = false;
    }
    public Boolean hiddenText()
    {
        return(hiddenText);
    }
    public void pinEvent()
    {
        pinned = true;
    }
    public Boolean getPinned()
    {
        return(pinned);
    }
    public void unPinEvent()
    {
        pinned = false;
    }
    public String getEventType()
    {
        return(eventType);
    }
    public void setEventType(String evtTypeString)
    {
        eventType = evtTypeString;
    }
    public void drawLine(Graphics g, int ribbonY)
    {
        if (hiddenEvent)
            return;
        if (!spread)
        {
           g.drawLine(xPos, yPos + (height/2), xPos, ribbonY);
        }
    }
    
    public Boolean getMagnifiedState()
    {
        return (magnified);
    }
    
    public void paintEvent(Graphics g)
    {
        if (hiddenEvent)
            return;

        FontMetrics fm = g.getFontMetrics();
        int timeStringWidth = fm.stringWidth(eventDisplayTime);
        int sumStringWidth = fm.stringWidth(eventSummary);
        int stringHeight = fm.getHeight();
        if (!magnified)
           g.setColor(iconColour);
        else
           g.setColor(iconMagnifyColour);
        
        if (!spread || pinned)
        {
           g.fillRect(iconXPos,iconYPos,width,height);
        }
        g.setColor(Color.GRAY);
        g.drawRect(iconXPos,iconYPos,width,height);  
        
        if (marked)
        {
            g.setColor(Color.BLACK);
            //g.drawLine(iconXPos - 2, yPos - 2, iconXPos + width - 2, yPos - 2);
            //g.drawLine(xPos - 2, iconYPos - 2, xPos - 2, yPos + height - 2);
            g.drawOval(xPos - 2, yPos - 2, 4, 4);
        }
                 
        if (hiddenText && !magnified && !pinned)
              return; 
        
        
        g.setColor(Color.DARK_GRAY);
        //g.clearRect(xPos - (timeStringWidth/2), iconYPos - (stringHeight + 2), timeStringWidth, stringHeight);
        g.drawString(eventDisplayTime, (xPos - (timeStringWidth/2)), iconYPos - (stringHeight+2));
        //g.clearRect(xPos - (sumStringWidth/2), iconYPos - 2, sumStringWidth, stringHeight);
        g.drawString(eventSummary, (xPos - (sumStringWidth/2)), iconYPos - 2);

    }

    public String getEventID() 
    {
       return(eventID);
    }

    public String getSummary()
    {
        return(eventSummary);
    }
    
    private void setIconColour() 
    {
        switch(eventTypeNumber)
        {
            case FineLineConfig.FL_WIN_VERBOSE             : iconColour = Color.WHITE; iconMagnifyColour = Color.PINK; break;
            case FineLineConfig.FL_WIN_CRITICAL            : iconColour = FineLineConfig.FL_BRICK_RED; iconMagnifyColour = FineLineConfig.FL_PINK; break;
            case FineLineConfig.FL_WIN_ERROR               : iconColour = Color.RED; iconMagnifyColour = Color.PINK; break;
            case FineLineConfig.FL_WIN_INFORMATION         : iconColour = FineLineConfig.FL_DARK_BLUE; iconMagnifyColour = FineLineConfig.FL_LIGHT_BLUE; break;
            case FineLineConfig.FL_WIN_WARNING             : iconColour = FineLineConfig.FL_ROSE; iconMagnifyColour = FineLineConfig.FL_PINK; break;
            case FineLineConfig.FL_EVENT_FILE_CLEARED_EVENT: iconColour = FineLineConfig.FL_BRICK_RED; iconMagnifyColour = FineLineConfig.FL_PINK; break;
            case FineLineConfig.FL_BOOT_EVENT              : iconColour = FineLineConfig.FL_MID_GREEN; iconMagnifyColour = FineLineConfig.FL_LIGHT_GREEN; break;
            case FineLineConfig.FL_SHUTDOWN_EVENT          : iconColour = FineLineConfig.FL_DARK_RED; iconMagnifyColour = FineLineConfig.FL_PINK; break;
            case FineLineConfig.FL_USER_LOGIN_EVENT        : iconColour = FineLineConfig.FL_DARK_BLUE; iconMagnifyColour = FineLineConfig.FL_SKY_BLUE; break;
            case FineLineConfig.FL_USER_LOGOUT_EVENT       : iconColour = FineLineConfig.FL_DARK_GOLD; iconMagnifyColour = FineLineConfig.FL_YELLOW; break;
            case FineLineConfig.FL_TIME_CHANGE_EVENT       : iconColour = FineLineConfig.FL_LIGHT_GREEN; iconMagnifyColour = FineLineConfig.FL_MID_GREEN; break;
            case FineLineConfig.FL_TIMEZONE_CHANGE_EVENT   : iconColour = FineLineConfig.FL_LIGHT_GREEN; iconMagnifyColour = FineLineConfig.FL_MID_GREEN; break;
            case FineLineConfig.FL_FILE_DELETED_EVENT      : iconColour = FineLineConfig.FL_BRICK_RED; iconMagnifyColour = FineLineConfig.FL_PINK; break;
            case FineLineConfig.FL_FILE_CREATED_EVENT      : iconColour = FineLineConfig.FL_BRICK_RED; iconMagnifyColour = FineLineConfig.FL_PINK; break;
            case FineLineConfig.FL_FILE_MODIFIED_EVENT     : iconColour = FineLineConfig.FL_BRICK_RED; iconMagnifyColour = FineLineConfig.FL_PINK; break;
            case FineLineConfig.FL_MANUAL_EVIDENCE_EVENT   : iconColour = FineLineConfig.FL_ROSE; iconMagnifyColour = FineLineConfig.FL_PINK; break;
            case FineLineConfig.FL_MACTIME_FLS_EVENT       : iconColour = FineLineConfig.FL_ROSE; iconMagnifyColour = FineLineConfig.FL_PINK; break;
            case FineLineConfig.FL_SYSLOG_EVENT            : iconColour = FineLineConfig.FL_MID_GREEN; iconMagnifyColour = FineLineConfig.FL_LIGHT_GREEN; break;
            case FineLineConfig.FL_UNKNOWN_EVENT           : iconColour = Color.BLACK; iconMagnifyColour = Color.DARK_GRAY; break;
            default: iconColour = Color.GRAY; iconMagnifyColour = Color.LIGHT_GRAY; break;
        }
    }
    
    @Override
    public String toString()
    {
        String temp = "<event><id>" + eventID + "</id><time>" + eventTime + "</time><type>" + eventType + "</type><summary>" + eventSummary + "</summary>";
        temp = temp + "<hiddenevent>" + hiddenEvent.toString() + "</hiddenevent><hiddentext>" + hiddenText.toString() + "</hiddentext><marked>" + marked.toString() + "</marked>";
        temp = temp + "<ypos>" + Integer.toString(yPos) + "</ypos><evidencenumber>" + evidenceNumber + "</evidencenumber>";
        temp = temp + "<pinned>" + pinned.toString() + "</pinned><data>" + eventData + "</data></event>"; 
       
        return(temp);
    }

    public void print(Graphics g)
    {
        //do some pretty text formatting
    }
    
    public String getDisplayTime() 
    {
       return(eventDisplayTime);
    }

    public String getEvidenceNumber() 
    {
       return(evidenceNumber);
    }

    public String getData() 
    {
       return(eventData);
    }

    void setSummary(String text) 
    {
        eventSummary = text;
    }

    void setDate(String text) 
    {
        eventDate = text;
        eventDay = Integer.parseInt(eventDate.substring(0,2));
        eventMonth = Integer.parseInt(eventDate.substring(3,5));
        eventYear = Integer.parseInt(eventDate.substring(6,10));
    }

    void setDisplayTime(String text) 
    {
        eventDisplayTime = text;
        String tempStr = eventDisplayTime.substring(0, 2);
        eventHour = Integer.parseInt(tempStr);
        tempStr = eventDisplayTime.substring(3);
        eventMinute = Integer.parseInt(tempStr);
        //TODO: need time format validation on this string
    }

    void setEvidenceNumber(String text) 
    {
        evidenceNumber = text;
    }

    void setData(String text) 
    {
        eventData = text;
    }

    void setEventID(int i) 
    {
        eventID = Integer.toString(i);
    }

    void setTime(String text) 
    {
        eventTime = text;
    }
    
}
