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
 * Class  : FineLinePrinter
 * 
 * Description: A class for printing the currently displayed timeline or the text of the event list.
 * 
 * 
 */

package FineLineGUI;

import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.print.PageFormat;
import java.awt.print.Printable;
import java.awt.print.PrinterException;
import javax.swing.JFrame;

/**
 *
 * @author Derek
 */
public class FineLinePrinter implements Printable 
{
    private FineLineGraphViewPanel flGraph;
    private FineLineTextViewPanel flText;
    private FineLineEvent flEvent;
    int printJobType;
    
    public FineLinePrinter(JFrame parent, FineLineGraphViewPanel flgvp)
    {
        flGraph = flgvp;
        flText = null;
        flEvent = null;
        printJobType = 0;
    }

    public FineLinePrinter(JFrame parent, FineLineTextViewPanel fltvp)
    {
        flGraph = null;
        flText = fltvp;
        flEvent = null;
        printJobType = 1;
    }
    public FineLinePrinter(JFrame parent, FineLineEvent fle) 
    {
       flGraph = null;
       flText = null;
       flEvent = fle;
       printJobType = 2;
    }

    @Override
    public int print(Graphics g, PageFormat pageFormat, int pageIndex) throws PrinterException 
    {
        if (pageIndex > 0) 
        {
            return NO_SUCH_PAGE;
        }

        Graphics2D g2d = (Graphics2D)g;
        g2d.translate(pageFormat.getImageableX(), pageFormat.getImageableY());

        switch(printJobType)
        {
            case 0: flGraph.printAll(g); break; //TODO: do the graph 
            case 1: flText.printAll(g); break; //TODO: this will only print displayed text???
            case 2: flEvent.print(g); break; //TODO: implement a print function in FineLineEvent to nicely format the event text
            default: System.out.println("FineLinePrinter() <ERROR> Unknown print job type.");
                     return(NO_SUCH_PAGE);
        }
        g.drawString("Hello world!", 100, 100);
        
        return PAGE_EXISTS;
    }
    
}
