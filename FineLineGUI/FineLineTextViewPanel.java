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
 * Class  : FineLineTextViewPanel
 * 
 * Description: the panel for display the text listing of the currently loaded event file.
 *             
 * 
 */



package FineLineGUI;

import java.awt.Dimension;
import java.awt.print.PrinterException;
import java.awt.print.PrinterJob;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JViewport;
import javax.swing.SwingConstants;

/**
 *
 * @author Derek
 */
public class FineLineTextViewPanel extends JPanel
{
    private JTextArea eventList;
    private JScrollPane listScroller;
    private JViewport listView;
    JFrame flMain;
   
    public FineLineTextViewPanel(final JTabbedPane pane, JFrame parent, FineLineConfig flc)
    {
      setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
      setPreferredSize(new Dimension(1000,600));
      setBorder(BorderFactory.createTitledBorder("Event List"));
      
      flMain = parent;
      
      eventList = new JTextArea(100,80); //(rows,columns)
      eventList.setEditable(false);
      
      listScroller = new JScrollPane();
      listView = listScroller.getViewport();
      listScroller.getViewport().add(eventList);
      add(listScroller);
      
      Box separatorBox = Box.createVerticalBox();
      separatorBox.add(Box.createVerticalStrut(10));
      add(separatorBox);
      
      Box buttonBox = Box.createHorizontalBox();
      JButton printButton = new JButton("Print");
      printButton.addActionListener(new java.awt.event.ActionListener() 
      {
         public void actionPerformed(java.awt.event.ActionEvent evt) 
         {
            printEventList();
         }
      });
      buttonBox.add(Box.createHorizontalGlue());
      buttonBox.add(printButton);
      buttonBox.add(Box.createHorizontalStrut(20));
      
      add(buttonBox);
    }
    
   public synchronized void addEvent(String event)
   {
      if (event != null)
      {
         eventList.append(event.concat(FineLineConfig.LINE_FEED));
         //eventList.setCaretPosition(eventList.getText().length());
      }
   }
   
   public void printEventList()
   {
        PrinterJob job = PrinterJob.getPrinterJob();
        job.setPrintable(new FineLinePrinter(flMain, this));
        boolean doPrint = job.printDialog();
        if (doPrint)
        {
           try {
              job.print();
           } catch (PrinterException e) {
              System.out.println("Could not print job.");
           }
        }
   }
}
