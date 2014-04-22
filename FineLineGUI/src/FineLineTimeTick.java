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
 * Class  : FineLineTimeTick
 * 
 * Description: A class for maintaining and painting time and date information on the timeline ribbon.
 * 
 * 
 */

package FineLineGUI;

import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Image;

/**
 *
 * @author Derek
 */
public class FineLineTimeTick 
{
    private final long minutes; //(0 to end of event log minutes (day * hour * 60)
    private int tickHour;       //(0 to 23)
    private int tickDay;        //(1 to end of event log days)
    private String date;        //(DD/MM/YYYY)
    private String time;        //(HH:MM)
    private Boolean midnight;   //time tick is midnight
    private int scaleFactor;    //ratio of minutes in a day to timeline screen width
    private int screenShape;    //1 = square, 2 = circle, 3 = triangle
    private Image screenIcon;
    private int xPos;
    private int yPos;
    private int length;
    
    public FineLineTimeTick(int hour, int day, int initX, int initY)
    {
        minutes = day * hour * 60;
        tickDay = day;
        tickHour = hour;
        if (hour < 10)
        {
           time = "0"+hour+":00";
        }
        else
        {
           time = hour+":00";
        }
        if (minutes == 0)
        {
            midnight = true;
        }
        else
        {
            midnight = false;
        }
        xPos = initX;
        yPos = initY;
        
    }
    public void setParameters(int hour, int day, int x, int y)
    {
        tickHour = hour;
        tickDay = day;
        time = hour+":00";
        if (hour == 0)
        {
            midnight = true;
        }
        else
        {
            midnight = false;
        }
        xPos = x;
        yPos = y;
    }
    public long getMinute()
    {
        return(minutes);
    }
    public Boolean isMidnight()
    {
        return(midnight);
    }
    public String getTimeString()
    {
        return time;
    }
    public int getX()
    {
        return(xPos);
    }
    public void setX(int x)
    {
        xPos = x;
    }
    public void setY(int y)
    {
        yPos = y;
    }
    public int getHour()
    {
        return(tickHour);
    }
    public void setDaySequence(int day)
    {
        tickDay = day;
    }
    public int getDaySequence()
    {
        return(tickDay);
    }
    public void paintTick(Graphics g)
    {
      FontMetrics fm = g.getFontMetrics();
      int w = fm.stringWidth(time);
      g.drawLine((int)xPos, yPos, (int)xPos, yPos + 5);
      g.drawString(time, (int) (xPos - (w/2)), yPos + 20);
      if (midnight)
      {
         g.drawOval(xPos - 2, yPos + 5, 4, 4);
      }
      else
      {
         g.drawOval(xPos - 1, yPos + 5, 2, 2);
      }        
      if (tickHour == 12) //Draw the date DD/MM/YYYY under midday timetick
      {
          w = fm.stringWidth(date);
          g.drawString(date, (int) (xPos - (w/2)), yPos + 40);
      }
    }

    void setDate(int get) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    void setDate(int day, int month, int year) 
    {
        month++; //Calendar months start at 0 so increment to get real month
        date = String.format("%02d/%02d/%4d", day, month, year);
    }
}
