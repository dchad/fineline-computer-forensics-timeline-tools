
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
 * Class  : FineLineEventListPopUpWindow
 * 
 * Description: A Swing dialog to display an event list popup window on the timeline.
 *              
 * 
 * 
 */



package FineLineGUI;

import java.awt.Container;
import java.awt.Dimension;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

/**
 *
 * @author Derek
 */
public class FineLineEventListPopUpWindow extends JDialog
{
   private JTextArea eventList;
   private JPanel contentPanel;
   private JButton closeButton;
   private JButton saveButton;
   private Container cp;
   

   public FineLineEventListPopUpWindow(JFrame parent) 
   {
      super(parent, "FineLine PopUp", false);
      //setUndecorated(true);
      //setBackground(new Color(0,0,0,0));
      cp = getContentPane();
     
      setSize(250,600);
     
      contentPanel = new JPanel();
      contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
      contentPanel.setPreferredSize(new Dimension(250,600));
      
      JScrollPane scrollPane = new JScrollPane();
      
      eventList = new JTextArea();
      eventList.setCaretPosition(0);
      //eventList.setLineWrap(true);
      scrollPane.getViewport().add(eventList);
      
      Box buttonBox = Box.createHorizontalBox();
      buttonBox.add(Box.createHorizontalGlue());
      
      closeButton = new JButton("Close");
      closeButton.addActionListener(new java.awt.event.ActionListener() 
      {
         public void actionPerformed(java.awt.event.ActionEvent evt) 
         {
            hideDialog();
         }
      });
      buttonBox.add(closeButton);
      buttonBox.add(Box.createRigidArea(new Dimension(15,0)));
      
      contentPanel.add(scrollPane);
      contentPanel.add(Box.createRigidArea(new Dimension(0,5)));
      contentPanel.add(buttonBox);
      contentPanel.add(Box.createRigidArea(new Dimension(0,5)));
      
      cp.setLayout(new BoxLayout(cp, BoxLayout.Y_AXIS));
      cp.add(contentPanel);
      setModal(false);
      
   }

   public void setText(String newText)
   {
      eventList.setText(newText);
   }
   
   public void addText(String evt)
   {
       eventList.append(evt);
   }
   
   public void showDialog(String tagText)
   {
       eventList.setText(tagText);
       //eventList.setCaretPosition(0);
       setVisible(true);
   }
   
   public void hideDialog()
   {
      setVisible(false);
   }

}
