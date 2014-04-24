package FineLineGUI;

import java.awt.Graphics;

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
 * Class  : FineLineNote
 * 
 * Description: class for storing and displaying annotations on the timeline.
 *          
 * 
 */



/**
 *
 * @author Derek
 */
public class FineLineNote 
{
    String noteText;
    int xPos;
    int yPos;
    int width;
    int height;
    int day;
    int month;
    int year;
    int hour;
    int minute;
    Boolean hidden;
    
    public FineLineNote(String txt)
    {
        noteText = txt;
        yPos = 20;
    }
    
    public void setPos(int x, int y)
    {
        xPos = x;
        yPos = y;
    }
    
    public void drawNote(Graphics g)
    {
        //First draw a note icon, then draw the text to the left of the icon.
    }
}
