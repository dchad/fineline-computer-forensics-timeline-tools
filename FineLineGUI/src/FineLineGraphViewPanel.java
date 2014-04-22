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
 * Class  : FineLineGraphViewPanel
 * 
 * Description: the main container panel for drawing the timeline ribbon and event icons
 *              and processing user input for timeline and event manipulation functions.
 * 
 */

package FineLineGUI;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import static java.awt.RenderingHints.KEY_ANTIALIASING;
import static java.awt.RenderingHints.VALUE_ANTIALIAS_ON;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.io.File;
import java.io.PrintWriter;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import javax.swing.JPopupMenu;



/**
 *
 * @author Derek
 */

public class FineLineGraphViewPanel extends JPanel implements MouseListener, MouseMotionListener, MouseWheelListener, ActionListener
{
    private final JTabbedPane pane;
    private int ribbonX = 10;
    private int ribbonY = 100;
    private int ribbonW = 800;
    private int ribbonH = 50;
    private int maxEventHeight;
    private int paneWidth;
    private int paneHeight;
    private int ribbonWidth;
    private int timeTickOffset;         //distance to move ribbon left or right when dragged or scrolled
    private int timeTickScaleFactor;    //(hours displayed x 60 minutes) divided by panel width for event placement
    private int timeTickHoursDisplayed; //number of hours on screen according to zoom factor (4 to 48 hours)
    private int timeTickCounter;        //minute counter to stop scrolling at the start and end of the time period
    private int maxTimeTick;            //calculate the max scroll size for the end of the event record
    private List<FineLineEvent> flEventList = new ArrayList<>();
    private final List<FineLineTimeTick> flTickList = new ArrayList<>();
    private int mouseX;
    private int mouseY;
    private FineLineProject flProject;
    private int scrollDirection;
    JPopupMenu timeLinePopUp;
    private final Font ribbonFont;
    private final Font eventFont;
    private int displayPeriods;
    private int totalDays;
    private int startDay; // DD/MM/YYYY
    private int startMonth;
    private int startYear;
    private final FineLineMainFrame mainFrame;
    private FineLineEventListPopUpWindow eventListPopUp;
    private final FineLineConfig flConfig;
    
    public FineLineGraphViewPanel(final JTabbedPane pane, FineLineMainFrame parent, FineLineConfig flc) 
    {
        //unset default FlowLayout' gaps
        super(new FlowLayout(FlowLayout.CENTER, 0, 0));
        this.pane = pane;
        this.setPreferredSize(new Dimension(1000,600));
        mainFrame = parent;
        
        //make JLabel read titles from JTabbedPane
        //JLabel label;
        //label = new JLabel("<<< FineLine Graph View Panel >>> ");
        //add(label);
        flConfig = flc;
        
        Calendar date = GregorianCalendar.getInstance();
        startDay = date.get(Calendar.DAY_OF_MONTH);
        startMonth = date.get(Calendar.MONTH); // Calendar starts months at 0 so add one to get the real month
        startYear = date.get(Calendar.YEAR);
        
        initTimeLineExtents();
        
        initMenuComponents();

        //panelFont = new Font("Arial", Font.BOLD, 12);
        ribbonFont = new Font("Arial", Font.PLAIN, 10);
        eventFont = new Font("Arial", Font.PLAIN, 10);
        
        //eventListPopUpShowing = false;
        
        addMouseMotionListener(this);
        addMouseListener(this);
        addMouseWheelListener(this);

    }
 
    @Override
    public void paintComponent(Graphics g) 
    {
        super.paintComponent(g);       
        
        // If pane size has changed, recalculate the ribbon size and position based on the
        // panel extents, make the ribbon height 10% of the panel height
        // and place at one third of the panel height.
        
        if ((pane.getWidth() != paneWidth) || (pane.getHeight() != paneHeight))
        {
            resetTimeLineExtents();
            
        }
        
        // Draw Timeline ribbon, date, and hour ticks
        g.setColor(FineLineConfig.FL_LIGHT_BLUE);
        g.fillRect(ribbonX,ribbonY,paneWidth,ribbonH);

        drawTimeTicks(g);
        
        drawEvents(g);

    }  

    /*
    Name: updateTimeLineExtents
    Purpose: updates the time ticks and event icon x position
             if the time line ribbon is scrolled/dragged left or right.
    Caller: mouseDragged
    */
    private void updateTimeLineExtents()
    {
        for (int i = 0; i < flEventList.size(); i++)
        {
            FineLineEvent fle = (FineLineEvent)flEventList.get(i);
            fle.setX(fle.getX() + timeTickOffset);
        }
        for (int i = 0; i < flTickList.size(); i++)
        {
            FineLineTimeTick fltt = (FineLineTimeTick) flTickList.get(i);
            fltt.setX(fltt.getX() + timeTickOffset);
        }
    }
    
    /*
    Name: drawEvents
    Purpose: draws hour ticks on the timeline ribbon.
    Caller: paintComponent
    */
    private void drawEvents(Graphics g) 
    {
        Graphics2D g2 = (Graphics2D)g;
        g2.setFont(eventFont);
        g2.setRenderingHint(KEY_ANTIALIASING, VALUE_ANTIALIAS_ON);
        
        // Draw event icons
        if (!flEventList.isEmpty())
        {
           for (int i = 0; i < flEventList.size(); i++)
           {
              FineLineEvent fle = (FineLineEvent)flEventList.get(i);
              int posX = fle.getX();
              if ((posX > 1) && (posX < ribbonWidth))
              {
                 //g.drawLine(posX, posY + (fle.getHeight()/2), posX, ribbonY);
                 fle.paintEvent(g);
                 fle.drawLine(g, ribbonY);
              }
           }
        }
    }    
    /*
    Name: drawTimeTicks
    Purpose: draws hour ticks on the timeline ribbon.
    Caller: paintComponent
    */
    private void drawTimeTicks(Graphics g) 
    {
        Graphics2D g2 = (Graphics2D)g;
        g2.setFont(ribbonFont);
        g2.setRenderingHint(KEY_ANTIALIASING, VALUE_ANTIALIAS_ON);
        g.setColor(Color.black);              //TODO: potential buffer overun here!!!!!!!!!!!!!!!!!!!!!
        for (int i = 0; i < flTickList.size(); i++)
        {
              FineLineTimeTick flt = flTickList.get(i);
              int x = flt.getX();
              if ((x > 0) && (x < ribbonWidth))
              {
                  flt.paintTick(g);
              }
        }
    }
    
    /*
    Name: setTimeLineExtents
    Purpose: sets the dimensions for the timeline ribbon and event icons
             if the container panel is resized or the graph is zoomed in/out.
    Caller: paintComponent
    */    
    private void resetTimeLineExtents()
    {
        paneHeight = pane.getHeight();
        paneWidth = pane.getWidth();
        calculateRibbonWidth();
        ribbonX = 1;
        ribbonY = paneHeight - (paneHeight / 3);
        ribbonW = ribbonWidth;
        ribbonH = paneHeight/10;
        maxEventHeight = ribbonY - (paneHeight / 3);
        timeTickScaleFactor = (ribbonWidth/timeTickHoursDisplayed);
        timeTickCounter = timeTickCounter + timeTickScaleFactor;
        //timeTickCounter = 0; TODO: how to maintain current view point when zooming
        resetTimeTicks();
        resetEventExtents();

    }
        
    /*
    Name: initTimeLineExtents
    Purpose: initialises the dimensions for the timeline ribbon and event icons
             on startup.
    Caller: constructor
    */    
    private void initTimeLineExtents()
    {
        paneHeight = pane.getHeight();
        paneWidth = pane.getWidth();
        timeTickHoursDisplayed = 24; //default display is one day
        calculateRibbonWidth();
        ribbonX = 1;
        ribbonY = paneHeight - (paneHeight / 3);
        ribbonW = ribbonWidth;
        ribbonH = paneHeight/10;
        maxEventHeight = ribbonY - (paneHeight / 3);
        timeTickOffset = 0;
        timeTickScaleFactor = (ribbonWidth/timeTickHoursDisplayed);
        displayPeriods = 1;
        totalDays = 1; //some random default value
        
        initTimeTicks();
    }

    /*
    Name: scrollTimeLine
    Purpose: scrolls the timeline left or right based on button clicks.
    Caller: MainFrame.
    */  
    public synchronized void scrollTimeLine()
    {
          int OFFSET = 1;
          if ((scrollDirection == 1) && (timeTickCounter < maxTimeTick)) // scroll timeline forward
          {
             timeTickOffset = (-OFFSET);
             timeTickCounter = (timeTickCounter + OFFSET);
             updateTimeLineExtents();
             repaint();
             /**
             repaint(ribbonX, ribbonY, ribbonW, ribbonH);
             for (int i = 0; i < flEventList.size(); i++)
             {
                FineLineEvent fle = flEventList.get(i);
                int iXpos = fle.getX();
                if ((iXpos > 1) && (iXpos < ribbonWidth))
                {
                   repaint(fle.getX()-100, fle.getY()-50, fle.getWidth()*10, fle.getHeight()*10);
                }
             }   
              **/
          }
          if ((scrollDirection == 2) && (timeTickCounter > 0)) // scroll timeline backward
          {
             timeTickOffset = OFFSET;
             timeTickCounter = timeTickCounter - OFFSET;
             updateTimeLineExtents();
             repaint();
             /**
             repaint(ribbonX, ribbonY, ribbonW, ribbonH);
             for (int i = 0; i < flEventList.size(); i++)
             {
                FineLineEvent fle = flEventList.get(i);
                int iXpos = fle.getX();
                if ((iXpos > 1) && (iXpos < ribbonWidth))
                {
                   repaint(fle.getX()-100, fle.getY()-50, fle.getWidth()*10, fle.getHeight()*10);
                }
             }   
             * */
          }
    }

    @Override
    public void mouseDragged(MouseEvent e) 
    {
       int OFFSET = 1;
       int ymove = e.getY();
       int xmove = e.getX();
       if ((ymove > ribbonY) && (ymove < (ribbonY+ribbonH)))
       {
          if ((xmove < (mouseX-OFFSET)) && (timeTickCounter < maxTimeTick))  //mouse was dragged left
          {
             timeTickOffset = (-OFFSET);
             mouseX = xmove - OFFSET;
             timeTickCounter = (timeTickCounter + OFFSET);
             updateTimeLineExtents();
             repaint();
             /**
             repaint(ribbonX, ribbonY, ribbonW, ribbonH);
             for (int i = 0; i < flEventList.size(); i++)
             {
                FineLineEvent fle = flEventList.get(i);
                int iXpos = fle.getX();
                if ((iXpos > 1) && (iXpos < ribbonWidth))
                {
                   repaint(fle.getX()-100, fle.getY()-50, fle.getWidth()*10, fle.getHeight()*10);
                }
             }   
             * */
          }
          if ((xmove > (mouseX+OFFSET)) && (timeTickCounter > 0)) //mouse was dragged right
          {
             timeTickOffset = OFFSET;
             mouseX = xmove + OFFSET;
             timeTickCounter = timeTickCounter - OFFSET;
             updateTimeLineExtents();
             repaint();
             /**
             repaint(ribbonX, ribbonY, ribbonW, ribbonH);
             for (int i = 0; i < flEventList.size(); i++)
             {
                FineLineEvent fle = flEventList.get(i);
                int iXpos = fle.getX();
                if ((iXpos > 1) && (iXpos < ribbonWidth))
                {
                   repaint(fle.getX()-100, fle.getY()-50, fle.getWidth()*10, fle.getHeight()*10);
                }
             }   
             * */
          }
       }     
       else
       {
           for (int i = 0; i < flEventList.size(); i++)
           {
                FineLineEvent fle = flEventList.get(i);
                int iXpos = fle.getX();
                int iYpos = fle.getY();
                int iHeight = fle.getHeight()/2;
                int iWidth = fle.getWidth()/2;
                if ((xmove >= (iXpos - (iWidth)) && (xmove <= (iXpos + (iWidth)))) && (ymove >= (iYpos - (iHeight)) && (ymove <= (iYpos + (iHeight)))))
                {
                   if (ymove > (mouseY+OFFSET))
                   {
                      mouseY = ymove;
                      fle.setY(iYpos + 3);
                      repaint();
                      //repaint(iXpos-100, iYpos-50, iWidth*20, iHeight*20);                       
                   }
                   else if (ymove < (mouseY-OFFSET))
                   {
                      mouseY = ymove;
                      fle.setY(iYpos - 3);
                      repaint();
                      //repaint(iXpos-100, iYpos-50, iWidth*20, iHeight*20);
                   }
                   break;
                }
           }              
       }
    }

    @Override
    public void mouseMoved(MouseEvent e) 
    {
       int xPos = e.getX();
       int yPos = e.getY();
       if ((yPos > maxEventHeight) && (yPos < ribbonY))
       {
          //int eventCount = 0;
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             int tempX = fle.getX();
             if (tempX < 0)
                 continue;
             if (tempX < ribbonWidth)
             {
             
                 int tempW = fle.getWidth()/2;
                 int tempY = fle.getY();
                 int tempH = fle.getHeight()/2;
                 if ((xPos > (tempX - tempW)) && (xPos < (tempX + tempW)) && (yPos > (tempY - tempH)) && (yPos < (tempY + tempH)))
                 {
                    //eventCount++;
                    //if (eventCount > 1)
                    //{
                        //popup a window listing all the events in the same minute
                        //showEventListWindow(i);
                        //break;
                        //spreadEvents(i-1);
                        //repaint();
                    //}
                    //else
                    //{
                       if (!fle.getMagnifiedState())
                       {
                          fle.magnify(2);
                          repaint();
                       }
                    //}
                 }
                 else
                 {
                     if (fle.getMagnifiedState())
                     {
                         fle.demagnify(2);
                         repaint();
                     }
                 }
             }
             else
             {
                 break;
             }
          }
       }

    }

    void eventOutput(String eventDescription, MouseEvent e) 
    {
           /*
        textArea.append(eventDescription
                + " (" + e.getX() + "," + e.getY() + ")"
                + " detected on "
                + e.getComponent().getClass().getName()
                + NEWLINE);
        textArea.setCaretPosition(textArea.getDocument().getLength()); */
    }

    @Override
    public void mouseClicked(MouseEvent e) 
    {
        if (e.getButton() == MouseEvent.BUTTON3)
        {
            //show the popup menu when right mouse button clicked
            mouseX = e.getX(); //will need this later to find the selected event if editing is required
            mouseY = e.getY();
            timeLinePopUp.show(pane, mouseX, mouseY);
        }
        if (e.getButton() == MouseEvent.BUTTON2)
        {
            System.out.println("Mouse Button 2 clicked.");
        }
        if (e.getButton() == MouseEvent.BUTTON1)
        {
            System.out.println("Mouse Button 1 clicked.");
        }
        //System.out.println("Mouse button clicked.");
    }

    @Override
    public void mousePressed(MouseEvent e) 
    {
        //System.out.println("Mouse Pressed: x="+ e.getX() + " - " + "y=" + e.getY());
        mouseX = e.getX();
    }

    @Override
    public void mouseReleased(MouseEvent e) 
    {
        //System.out.println("Mouse Released: x="+ e.getX() + " - " + "y=" + e.getY());
        timeTickOffset = 0; //reset tick offset to prevent unwanted scrolling
    }

    @Override
    public void mouseEntered(MouseEvent e) 
    {
        //System.out.println("Mouse Entered: x="+ e.getX() + " - " + "y=" + e.getY()); 
    }

    @Override
    public void mouseExited(MouseEvent e) 
    {
        //System.out.println("Mouse Exited: x="+ e.getX() + " - " + "y=" + e.getY());
    }

    @Override
    public void mouseWheelMoved(MouseWheelEvent e) 
    {
        System.out.println("Mouse Wheel Moved: rotation="+ e.getWheelRotation());
    }

    private void initMenuComponents() 
    {
         //initialise the popup and main menu items
        timeLinePopUp = new JPopupMenu("MENU");
 
        javax.swing.JMenuItem newMenuItem = new javax.swing.JMenuItem("New Event");
        newMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpNewMenuActionPerformed(evt);
            }
        });
        timeLinePopUp.add(newMenuItem);
        
        javax.swing.JMenuItem editMenuItem = new javax.swing.JMenuItem("Edit Event");
        editMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpEditMenuActionPerformed(evt);
            }
        });
        timeLinePopUp.add(editMenuItem);
        
        javax.swing.JMenuItem copyMenuItem = new javax.swing.JMenuItem("Copy Event");
        copyMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpCopyMenuActionPerformed(evt);
            }
        });
        timeLinePopUp.add(copyMenuItem);
        
        javax.swing.JMenuItem pasteMenuItem = new javax.swing.JMenuItem("Paste Event");
        pasteMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpPasteMenuActionPerformed(evt);
            }
        });
        timeLinePopUp.add(pasteMenuItem);
        
        timeLinePopUp.addSeparator();
       
       javax.swing.JMenuItem markMenuItem = new javax.swing.JMenuItem("Mark Event");
        markMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpMarkMenuActionPerformed(evt);
            }
        });        
        timeLinePopUp.add(markMenuItem);
        
        javax.swing.JMenuItem unMarkMenuItem = new javax.swing.JMenuItem("Unmark Event");
        unMarkMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpUnMarkMenuActionPerformed(evt);
            }
        });        
        timeLinePopUp.add(unMarkMenuItem);
               
        javax.swing.JMenuItem unMarkAllMenuItem = new javax.swing.JMenuItem("Unmark All");
        unMarkAllMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpUnMarkAllMenuActionPerformed(evt);
            }
        });        
        timeLinePopUp.add(unMarkAllMenuItem);
        
        timeLinePopUp.addSeparator();
        
        javax.swing.JMenuItem hideEventMenuItem = new javax.swing.JMenuItem("Hide Event");
        hideEventMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpHideEventMenuActionPerformed(evt);
            }
        });            
        timeLinePopUp.add(hideEventMenuItem);
        
        javax.swing.JMenuItem hideEventTextMenuItem = new javax.swing.JMenuItem("Hide Text");
        hideEventTextMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpHideEventTextMenuActionPerformed(evt);
            }
        });            
        timeLinePopUp.add(hideEventTextMenuItem);
        
        javax.swing.JMenuItem showAllMenuItem = new javax.swing.JMenuItem("Unhide All");
        showAllMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpShowAllMenuActionPerformed(evt);
            }
        });            
        timeLinePopUp.add(showAllMenuItem);
        
        javax.swing.JMenuItem rehideAllMenuItem = new javax.swing.JMenuItem("Rehide All");
        rehideAllMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpRehideMenuActionPerformed();
            }
        });            
        timeLinePopUp.add(rehideAllMenuItem);
        
        timeLinePopUp.addSeparator();
        
        javax.swing.JMenuItem pinEventsMenuItem = new javax.swing.JMenuItem("Pin Event");
        pinEventsMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) 
            {
                pinEvent();
            }
        });            
        timeLinePopUp.add(pinEventsMenuItem);
        
        javax.swing.JMenuItem unpinEventsMenuItem = new javax.swing.JMenuItem("Unpin Event");
        unpinEventsMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) 
            {
                unpinEvent();
            }
        });            
        timeLinePopUp.add(unpinEventsMenuItem);        
        timeLinePopUp.addSeparator();
        
        javax.swing.JMenuItem deleteMenuItem = new javax.swing.JMenuItem("Delete Event");
        deleteMenuItem.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popUpDeleteMenuActionPerformed(evt);
            }
        });            
        timeLinePopUp.add(deleteMenuItem);
    }

    private void popUpNewMenuActionPerformed(ActionEvent evt) 
    {
       FineLineEventDialog fled = new FineLineEventDialog(mainFrame, this);
       fled.showDialog("New Event Dialog");
            
    }
                
    private void popUpEditMenuActionPerformed(ActionEvent evt) 
    {
       
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             int tempX = fle.getX();
             if (tempX < 0)
                 continue;
             if (tempX < ribbonWidth)
             {
                 int tempW = fle.getWidth()/2;
                 int tempY = fle.getY();
                 int tempH = fle.getHeight()/2;
                 if ((mouseX > (tempX - tempW)) && (mouseX < (tempX + tempW)) && (mouseY > (tempY - tempH)) && (mouseY < (tempY + tempH)))
                 {
                    FineLineEventDialog fled = new FineLineEventDialog(mainFrame, this, fle);
                    fled.showDialog("Edit Event Dialog");
                    break;
                 }
             }
             else
             {
                 break;
             }
          }
                         
    }
    private void popUpPasteMenuActionPerformed(ActionEvent evt) 
    {
       System.out.println("Paste Menu Clicked.");  
       //TODO: copy event data from the system buffer
       //define a new class to handle this
       //FineLineEventAcceptor flea = new FineLineEventAcceptor(this, string, flConfig);
       
       
    }
    
    private void popUpDeleteMenuActionPerformed(ActionEvent evt) 
    {
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             int tempX = fle.getX();
             if (tempX < 0)
                 continue;
             if (tempX < ribbonWidth)
             {
                 int tempW = fle.getWidth()/2;
                 int tempY = fle.getY();
                 int tempH = fle.getHeight()/2;
                 if ((mouseX > (tempX - tempW)) && (mouseX < (tempX + tempW)) && (mouseY > (tempY - tempH)) && (mouseY < (tempY + tempH)))
                 {
                     //TODO: popup an option dialog to request confirmation
                      System.out.println("Deleted event: " + fle.getSummary());
                      flEventList.remove(i);
                      repaint();
                      break;
                 }
             }
             else
             {
                 break;
             }
          }
                         
    }
    private void popUpCopyMenuActionPerformed(ActionEvent evt) 
    {
       System.out.println("Copy Menu Clicked.");      
       //TODO: copy the event fields to the system clipboard
       
    }
    private void popUpMarkMenuActionPerformed(ActionEvent evt) 
    {
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             int tempX = fle.getX();
             if (tempX < 0)
                 continue;
             if (tempX < ribbonWidth)
             {
                 int tempW = fle.getWidth()/2;
                 int tempY = fle.getY();
                 int tempH = fle.getHeight()/2;
                 if ((mouseX > (tempX - tempW)) && (mouseX < (tempX + tempW)) && (mouseY > (tempY - tempH)) && (mouseY < (tempY + tempH)))
                 {
                      fle.mark();
                      repaint();
                      break;
                 }
             }
             else
             {
                 break;
             }
          }           
    }
    
    private void popUpUnMarkMenuActionPerformed(ActionEvent evt) 
    {
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             int tempX = fle.getX();
             if (tempX < 0)
                 continue;
             if (tempX < ribbonWidth)
             {
                 int tempW = fle.getWidth()/2;
                 int tempY = fle.getY();
                 int tempH = fle.getHeight()/2;
                 if ((mouseX > (tempX - tempW)) && (mouseX < (tempX + tempW)) && (mouseY > (tempY - tempH)) && (mouseY < (tempY + tempH)))
                 {
                      fle.unmark();
                      repaint();
                      break;
                 }
             }
             else
             {
                 break;
             }
          }           
    }

    private void popUpUnMarkAllMenuActionPerformed(ActionEvent evt) 
    {
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             fle.unmark();
          }        
          repaint();
    }

    private void popUpShowAllMenuActionPerformed(ActionEvent evt) 
    {
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             fle.unhideEvent();
             if (!fle.getSpread())
                 fle.unhideText();
          }   
          repaint();
    }
    private void popUpRehideMenuActionPerformed()
    {
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             if (fle.getSpread())
                 fle.hideText();
          }   
          repaint();       
    }
    private void popUpHideEventMenuActionPerformed(ActionEvent evt) 
    {
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             int tempX = fle.getX();
             if (tempX < 0)
                 continue;
             if (tempX < ribbonWidth)
             {
                 int tempW = fle.getWidth()/2;
                 int tempY = fle.getY();
                 int tempH = fle.getHeight()/2;
                 if ((mouseX > (tempX - tempW)) && (mouseX < (tempX + tempW)) && (mouseY > (tempY - tempH)) && (mouseY < (tempY + tempH)))
                 {
                      fle.hideEvent();
                      repaint();
                      break;
                 }
             }
             else
             {
                 break;
             }
          }
    }       
    private void popUpHideEventTextMenuActionPerformed(ActionEvent evt) 
    {
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             int tempX = fle.getX();
             if (tempX < 0)
                 continue;
             if (tempX < ribbonWidth)
             {
                 int tempW = fle.getWidth()/2;
                 int tempY = fle.getY();
                 int tempH = fle.getHeight()/2;
                 if ((mouseX > (tempX - tempW)) && (mouseX < (tempX + tempW)) && (mouseY > (tempY - tempH)) && (mouseY < (tempY + tempH)))
                 {
                      fle.hideText();
                      repaint();
                      break;
                 }
             }
             else
             {
                 break;
             }
          }
    }
    
        private void pinEvent() 
    {
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             int tempX = fle.getX();
             if (tempX < 0)
                 continue;
             if (tempX < ribbonWidth)
             {
                 int tempW = fle.getWidth()/2;
                 int tempY = fle.getY();
                 int tempH = fle.getHeight()/2;
                 if ((mouseX > (tempX - tempW)) && (mouseX < (tempX + tempW)) && (mouseY > (tempY - tempH)) && (mouseY < (tempY + tempH)))
                 {
                      fle.pinEvent();
                      repaint();
                      break;
                 }
             }
             else
             {
                 break;
             }
          }
    }

    private void unpinEvent() 
    {
          for (int i = 0; i < flEventList.size(); i++)
          {
             FineLineEvent fle = (FineLineEvent)flEventList.get(i);
             int tempX = fle.getX();
             if (tempX < 0)
                 continue;
             if (tempX < ribbonWidth)
             {
                 int tempW = fle.getWidth()/2;
                 int tempY = fle.getY();
                 int tempH = fle.getHeight()/2;
                 if ((mouseX > (tempX - tempW)) && (mouseX < (tempX + tempW)) && (mouseY > (tempY - tempH)) && (mouseY < (tempY + tempH)))
                 {
                      fle.unPinEvent();
                      repaint();
                      break;
                 }
             }
             else
             {
                 break;
             }
          }
    }

    
    /* 
    Name   : initTimeTicks
    Purpose: initialises the time tick list and associated extents, 
             must be called after setTimeLineExtents() to ensure
             paneWidth != 0
    Caller: Constructor   
    */
    private void initTimeTicks() 
    {
       timeTickOffset = 0;
       timeTickCounter = 0;
       maxTimeTick = timeTickScaleFactor * totalDays * 24;
       int hourCount = 0;
      
       if (flTickList.size() > 0) //empty out the time tick list, a new timeline is being loaded.
       {
           flTickList.clear();
       }
       Calendar date = Calendar.getInstance();
       date.set(startYear, startMonth-1, startDay); //Calendar starts months at 0, so to roll correctly subtract 1 from the real month
       for (int i = 1; i < (totalDays+1); i++) 
       {
           for (int j = 0; j < 24; j++)
           {
               FineLineTimeTick flTick = new FineLineTimeTick(j, i, hourCount*timeTickScaleFactor, ribbonY);
               flTick.setDate(date.get(Calendar.DAY_OF_MONTH),date.get(Calendar.MONTH),date.get(Calendar.YEAR));
               flTickList.add(flTick);
               hourCount++;
           }
           date.roll(Calendar.DAY_OF_YEAR, true);
       }
    }

    /* 
    Name   : resetTimeTicks
    Purpose: reinitialises the time tick list and associated extents, 
             must be called after setTimeLineExtents() to ensure
             paneWidth != 0
    Caller: Constructor   
    */
    private void resetTimeTicks() //zoom
    {
       timeTickOffset = 0;
       maxTimeTick = timeTickScaleFactor * totalDays * 24;
       int xPos;
       
       for (int i = 0; i < flTickList.size(); i++) //to seven days
       {
          FineLineTimeTick flTick = flTickList.get(i);
          xPos = (i * timeTickScaleFactor); // - timeTickCounter; 
          
          flTick.setX(xPos);
          flTick.setY(ribbonY);
       }
    }

    private void initEventExtents() 
    {
        if (!flEventList.isEmpty())
        {
           //first calculate the event y position above the timeline ribbon then
           //calculate the event x position based on the scale factor produced by
           //dividing 24 by the panel width to get the hour scaling factor
           //then dividing by 60 to get the minute scale factor. This produces
           //the initial (x,y) coordinates for the event icon on the timeline ribbon.
           int initY = (ribbonY - (maxEventHeight/2));
           int initX;
           float minScaleFactor = (float)timeTickScaleFactor / (float)60;
           
           for (int i = 0; i < flEventList.size(); i++)
           {
              FineLineEvent fle = flEventList.get(i);
              initX = ((fle.getDaySequence() - 1) * ribbonWidth) + (timeTickScaleFactor * fle.getHour());
              initX = (int) ((float)initX + ((float)fle.getMinute() * minScaleFactor));
              initY = fle.getY();
              if ((initY > ribbonY) || (initY < maxEventHeight))
              {
                 initY = (ribbonY - (maxEventHeight/2));            
              }
              fle.setPos(initX, initY);
           }     
           stackMultiEvents(); // Now vertically stack any simultaneous events
        }
        else
        {
            System.out.println("FineLineGraphViewPanel <INFO> Event list is empty.");
        }
    }

    private void resetEventExtents() 
    {
        if (flEventList.isEmpty())
        {
            System.out.println("FineLineGraphViewPanel <INFO> Event list is empty.");
            return;
        }
        
        int initX;
        int initY;
        //int initY = (ribbonY - (maxEventHeight/2));
        float minScaleFactor = (float)timeTickScaleFactor / (float)60;
        
        for (int i = 0; i < flEventList.size(); i++)
        {
            FineLineEvent fle = flEventList.get(i);
            int hourSequence = (((fle.getDaySequence() - 1) * 24) + fle.getHour());
            int minSequence = hourSequence * 60;
            initX = (int) (((float)minSequence + (float)fle.getMinute()) * minScaleFactor);
            initY = fle.getY();
            if ((initY > ribbonY) || (initY < maxEventHeight))
            {
                 initY = (ribbonY - (maxEventHeight/2));            
            }
            fle.setPos(initX, initY);
        }     
        stackMultiEvents();
    }
    
    //DEPRECATED
    public synchronized void setEventList(List<FineLineEvent> events)
    {
        flEventList = events;
    }
        
    /* 
    Name   : addEvent
    Purpose: adds an event to the end of the event list during project loading.
    Caller : FineLineEventLogLoader
    */
    public synchronized void addEvent(FineLineEvent evt)
    {
        flEventList.add(evt);
        //System.out.println("adding event: " + evt.getEventID());
    }
    
    /* 
    Name   : finishedEventLoad
    Purpose: reinitialises the event records and time ticks after an event log
             or project has been loaded.
    Caller : FineLineEventLogLoader
    */
    public synchronized void finishedEventLoad(int days)
    {
        if (flEventList.size() > 0)
        {
            FineLineEvent fle = flEventList.get(0);
            totalDays = days;
            displayPeriods = days;   //this starts as the day count because we initially display 24 hour periods
            startDay = fle.getDay(); //set the timeline start date to the date of the first event record
            startMonth = fle.getMonth();
            startYear = fle.getYear();
            initEventExtents();
            initTimeTicks();
            repaint();
        }
    }
    
    /* 
    Name   : loadProject
    Purpose: loads a project or event file.
    Caller : FineLineMainFrame
    */
    public void loadProject(FineLineProject flp, File f)
    {
        if (!flEventList.isEmpty()) //if already have events then clear the list for a new event log
        {
            flEventList.clear();
        }
        flProject = flp;
        FineLineEventLogLoader fll = new FineLineEventLogLoader(mainFrame, this, f);
        Thread loaderThread = new Thread(fll);
        loaderThread.start();
        System.out.println("Finished loading project file.");
    }
    
    /* 
    Name   : calculateRibbonWidth
    Purpose: Calculates ribbon width to ensure it is an exact multiple of the hours displayed.
             This prevents rounding errors during calculation of event positions causing drifting
             away from the timeline ribbon time ticks with large datasets.
    Caller : initTimeLineExtents, resetTimeLineExtents
    */
    private void calculateRibbonWidth()
    {
        ribbonWidth = 0;
        //timeTickHoursDisplayed = 24; set this with the slider control default = 24
        
        while (ribbonWidth <= paneWidth)
        {
            ribbonWidth += timeTickHoursDisplayed;
        }
        ribbonWidth = ribbonWidth - timeTickHoursDisplayed;
        
        displayPeriods = (totalDays * 24) / timeTickHoursDisplayed;
    }

    @Override
    public void actionPerformed(ActionEvent e) 
    {
       scrollTimeLine();
    }
    
    public void setScrollType(int scrollType)
    {
        scrollDirection = scrollType;

        // 0  = stop scrolling
        // 1  = scroll forward
        // 2  = scroll back
    }

    public void scrollToEnd() 
    {
        //goto last day
        int offset = timeTickScaleFactor * 24 * (totalDays - 1);
        timeTickCounter = offset;
        for (int i = 0; i < flEventList.size(); i++)
        {
            FineLineEvent fle = (FineLineEvent)flEventList.get(i);
            fle.setX(fle.getX() - offset);
        }
        for (int i = 0; i < flTickList.size(); i++)
        {
            FineLineTimeTick fltt = (FineLineTimeTick) flTickList.get(i);
            fltt.setX(fltt.getX() - offset);
        }
        repaint();
    }

    public void scrollNextDay() 
    {
        //check scrolling boundaries to prevent scrolling off the end of the timeline,
        //then adjusts the X position offsets to display the next day/time period.
        if (timeTickCounter < maxTimeTick)
        {
            int offset = timeTickHoursDisplayed * timeTickScaleFactor;
            timeTickCounter = timeTickCounter + offset;
            for (int i = 0; i < flEventList.size(); i++)
            {
                FineLineEvent fle = (FineLineEvent)flEventList.get(i);
                fle.setX(fle.getX() - offset);
            }
            for (int i = 0; i < flTickList.size(); i++)
            {
                FineLineTimeTick fltt = (FineLineTimeTick) flTickList.get(i);
                fltt.setX(fltt.getX() - offset);
            }
            repaint();
        }
    }

    public void scrollToStart() 
    {
        resetTimeLineExtents();
        repaint();
    }

    public void scrollPrevDay() 
    {
        //check scrolling boundaries to prevent scrolling past the start of the timeline,
        //then calculate the offsets to display the previous day/time display period.

        if (timeTickCounter > 0)
        {
            int offset = timeTickHoursDisplayed * timeTickScaleFactor;
            timeTickCounter = timeTickCounter - offset;
            for (int i = 0; i < flEventList.size(); i++)
            {
                FineLineEvent fle = (FineLineEvent)flEventList.get(i);
                fle.setX(fle.getX() + offset);
            }
            for (int i = 0; i < flTickList.size(); i++)
            {
                FineLineTimeTick fltt = (FineLineTimeTick) flTickList.get(i);
                fltt.setX(fltt.getX() + offset);
            }
            repaint();
        }
    }
    
    /* 
    Name   : setZoomLevel
    Purpose: Changes the number of hours currently displayed on the timeline using
             zoomValue equal to the number of hours to display. This is adjusted
             using the slider widget on the main frame toolbar.
    Caller : FineLineMainFrame
    */
    public void setZoomLevel(int zoomValue) 
    {
        if (timeTickHoursDisplayed != zoomValue)
        {
           timeTickHoursDisplayed = zoomValue;
           System.out.println("zoomValue: " + timeTickHoursDisplayed);
           resetTimeLineExtents();
           repaint();
        }
    }
    
    /* 
    Name   : showEventListWindow
    Purpose: Displays a non-modal dialog with a list of events at a given point on the timeline.
    Caller : FineLineGraphViewPanel
    */
    private void showEventListWindow(int index) 
    {
       if (eventListPopUp == null)
       {
           eventListPopUp = new FineLineEventListPopUpWindow(mainFrame);
           eventListPopUp.showDialog("Event List:");
       }
       String eventList = "\n";
       FineLineEvent fle = flEventList.get(index);
       int tempX = fle.getX();
       for (int i = 0; i < flEventList.size(); i++)
       {
           fle = flEventList.get(i);
           int xpos = fle.getX();
           if (xpos < 0)
               continue;
           if (xpos > ribbonW)
               break;
           if (xpos == tempX)
           {
               eventList = eventList + fle.getTime() + " " + fle.getSummary() + "\n";
           }
       }
      
       eventListPopUp.addText(eventList);
    }
    
    /* 
    Name   : spreadEvents
    Purpose: stacks multiple simultaneous events in a vertical line above the timeline.
    Caller : FineLineGraphViewPanel
    */
    private void spreadEvents() 
    {
        //System.out.println("spreadEvents called. ");
      int shiftY = ribbonY - 15; //assuming icon height = 10, then stack them 10 apart with the bottom one 15 above ribbon
      for (int i = 0; i < flEventList.size(); i++)
      {
         FineLineEvent fle = (FineLineEvent)flEventList.get(i);
         int tempX = fle.getX();
         if (tempX < 0)
             continue;
         if (tempX < ribbonWidth)
         {
             int tempW = fle.getWidth()/2;
             int tempH = fle.getHeight()/2;
             int tempY = fle.getY();
             if ((mouseX > (tempX - tempW)) && (mouseX < (tempX + tempW)) && (mouseY > (tempY - tempH)) && (mouseY < (tempY + tempH)))
             {
                 fle.spread(shiftY);
                 shiftY = shiftY - 20;
             }
         }
         if (tempX > ribbonW)
         {
              break;
         }
      }
      repaint();
    }

    /* 
    Name   : clearList
    Purpose: empties the event list when a new project is loaded.
    Caller : FineLineMainFrame
    */
    void clearList() 
    {
        if (!flEventList.isEmpty()) //if already have events then clear the list for a new event log
        {
            //TODO: check for save current project/timeline
            flEventList.clear();
        }
        repaint();
    }
    
    /* 
    Name   : serializeEventList
    Purpose: stringifies the event list and writes to the file parameter.
    Caller : FineLineProject
    */
    public void serializeEventList(PrintWriter out)
    {
        for (int i = 0; i < flEventList.size(); i++)
        {
            FineLineEvent fle = flEventList.get(i);
            out.println(fle.toString());
        }
        System.out.println("FineLineGraphViewPanel <INFO> Finished event list save.");
    }

    //DEPRECATED
    public void setProject(FineLineProject prj)
    {
        flProject = prj;
    }
    
    /* 
    Name   : insertNewEvent
    Purpose: inserts a manually created event at the correct position in the timeline.
    Caller : FineLineEventDialog
    */
    public synchronized void insertNewEvent(FineLineEvent flEvent) 
    {
        //System.out.println("Inserting event: " + flEvent.getTime());
      int hour = flEvent.getHour();
      int minute = flEvent.getMinute();
      int month = flEvent.getMonth();
      int day = flEvent.getDay();
      for (int i = 0; i < flEventList.size(); i++)
      {
         FineLineEvent fle = (FineLineEvent)flEventList.get(i);
         int tempX = fle.getX();
         if (tempX < 0)
             continue;
         if (tempX < ribbonWidth)
         {
             if ((day == fle.getDay()) && (month == fle.getMonth()))
             {
                 //System.out.println("Inserting new event at position: " + Integer.toString(i));
                 int initY = (ribbonY - (maxEventHeight/2));
                 int initX = ((fle.getDaySequence() - 1) * ribbonWidth) + (timeTickScaleFactor * hour);
                 float minScaleFactor = (float)timeTickScaleFactor / (float)60;
                 initX = (int) ((float)initX + ((float)minute * minScaleFactor));
                 flEvent.setPos(initX, initY);
                 flEvent.setEventID(flEventList.size()+1);
                 flEvent.setDaySequence(fle.getDaySequence());
                 flEventList.add(i, flEvent);
                 break; //make sure to exit the loop or it will keep inserting events forever
             }
         }
         if (tempX > ribbonW)
         {
              break;
         }
       }       
      repaint();
    }
    
    /* 
    Name   : insertImportedEvent
    Purpose: inserts events created using the import function. This allows the imported
             events to be added to an existing timeline project in the correct time position.
    Caller : FineLineImporter
    */
    public synchronized void insertImportedEvent(FineLineEvent flEvent) 
    {
      if (flEventList.isEmpty())
      {
          flEventList.add(flEvent);
          return;
      }
      int hour = flEvent.getHour();
      int minute = flEvent.getMinute();
      int month = flEvent.getMonth();
      int day = flEvent.getDay();
      for (int i = 0; i < flEventList.size(); i++)
      {
         FineLineEvent fle = (FineLineEvent)flEventList.get(i);
         if ((day == fle.getDay()) && (month == fle.getMonth()))
         {
             //System.out.println("Inserting new event at position: " + Integer.toString(i));
             int initY = (ribbonY - (maxEventHeight/2));
             int initX = ((fle.getDaySequence() - 1) * ribbonWidth) + (timeTickScaleFactor * hour);
             float minScaleFactor = (float)timeTickScaleFactor / (float)60;
             initX = (int) ((float)initX + ((float)minute * minScaleFactor));
             flEvent.setPos(initX, initY);
             flEvent.setEventID(flEventList.size()+1);
             flEvent.setDaySequence(fle.getDaySequence());
             flEventList.add(i, flEvent);
             break; //make sure to exit the loop or it will keep inserting events forever
         }
       }       
      repaint();
    }

    /* 
    Name   : stackMultiEvents
    Purpose: stacks multiple simultaneous events in a vertical line above the timeline.
    Caller : FineLineGraphViewPanel
    */
    private void stackMultiEvents() 
    {
      FineLineEvent lowfle = (FineLineEvent)flEventList.get(0);
      int prevX = lowfle.getX();
      int shiftY = ribbonY - 15; //assuming icon height = 10, then stack them 10 apart with the bottom one 15 above 
      int stackY = shiftY - 20;
      for (int i = 1; i < flEventList.size(); i++)
      {
         FineLineEvent nextfle = flEventList.get(i);
         int tempX = nextfle.getX();
         if (tempX == prevX)
         {
            lowfle.spread(shiftY);
            nextfle.spread(stackY);
            stackY = stackY - 20;
         }
         else
         {
            lowfle = nextfle;
            stackY = shiftY - 20;
            prevX = tempX;
         }
      }
    }

    void setProjectModified() 
    {
        if (flProject != null)
           flProject.eventChange();
    }
    
    public List<FineLineEvent> getEventList()
    {
        return(flEventList);
    }

} // FineLineGraphViewPanel
