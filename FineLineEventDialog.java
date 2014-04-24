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
 * Class  : FineLineEventDialog
 * 
 * Description: A Swing dialog for creating and modifying events and evidence on the timeline.
 *              
 * 
 * 
 */


package FineLineGUI;

import java.awt.Container;
import java.awt.Dimension;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;

/**
 *
 * @author Derek
 */
public class FineLineEventDialog extends JDialog
{
   private JEditorPane summaryArea;
   private JPanel contentPanel;
   private JButton closeButton;
   private JButton saveButton;
   private Container cp;
   private String filePath;
   private JFileChooser fileChoose;
   private JTextField fileName;
   private JTextField eventType;
   //private JComboBox typeList;
   private JTextField summaryName;
   private JTextField investigatorName;
   private JTextField evidenceNumber;
   private JTextField projectName;
   private JTextField dateField;
   private JTextField timeField;
   private final JFrame parent;
   private FineLineEvent flEvent;
   private FineLineGraphViewPanel flGraph;
   private Boolean newEvent;
   

   public FineLineEventDialog(final JFrame jf, FineLineGraphViewPanel flg) 
   {
      super(jf, "FineLine Event Editor", false);
      parent = jf;
      flGraph = flg;
      newEvent = true;
      
      initDialog();
   }

   public FineLineEventDialog(final JFrame jf, FineLineGraphViewPanel flg, FineLineEvent evt) 
   {
      super(jf, "FineLine Event Editor", false);
      parent = jf;
      flGraph = flg;
      flEvent = evt;
      newEvent = false;
      
      initDialog();
      
      //now initialise all the fields
      
      summaryName.setText(evt.getSummary());
      dateField.setText(evt.getDate());
      timeField.setText(evt.getDisplayTime());
      evidenceNumber.setText(evt.getEvidenceNumber());
      summaryArea.setText(evt.getData());
      eventType.setText(evt.getEventType());
      //typeList.add(evt.g)
      
   }
      
   public void initDialog()
   {
      cp = getContentPane();
     
      setSize(800,600);
     
      contentPanel = new JPanel();
      contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
      contentPanel.setPreferredSize(new Dimension(800,600));
      contentPanel.setBorder(BorderFactory.createTitledBorder("FineLine Event Editor"));
      
      JScrollPane scrollPane = new JScrollPane();
      /*
      JLabel projectLabel = new JLabel("Project/Case:");
      projectName = new JTextField();
      projectName.setMinimumSize(new Dimension(400, 30));
      projectName.setMaximumSize(new Dimension(800, 30));
      
      Box projectBox = Box.createHorizontalBox();
      projectBox.add(projectLabel);
      projectBox.add(Box.createRigidArea(new Dimension(15,0)));
      projectBox.add(projectName);
      projectBox.setPreferredSize(new Dimension(800,30));
      */
      JLabel evidenceLabel = new JLabel("Evidence No:");
      evidenceNumber = new JTextField();
      evidenceNumber.setMinimumSize(new Dimension(400, 30));
      evidenceNumber.setMaximumSize(new Dimension(800, 30));
      
      Box evidenceBox = Box.createHorizontalBox();
      evidenceBox.add(evidenceLabel);
      evidenceBox.add(Box.createRigidArea(new Dimension(17,0)));
      evidenceBox.add(evidenceNumber);
      evidenceBox.setPreferredSize(new Dimension(800,30));
      /*
      JLabel investigatorLabel = new JLabel("Investigator:");
      investigatorName = new JTextField();
      investigatorName.setMinimumSize(new Dimension(400, 30));
      investigatorName.setMaximumSize(new Dimension(800, 30));
      
      Box investigatorBox = Box.createHorizontalBox();
      investigatorBox.add(investigatorLabel);
      investigatorBox.add(Box.createRigidArea(new Dimension(23,0)));
      investigatorBox.add(investigatorName);
      investigatorBox.setPreferredSize(new Dimension(800,30)); 
      */
      JLabel summaryLabel = new JLabel("Summary:");
      summaryName = new JTextField();
      summaryName.setMinimumSize(new Dimension(400, 30));
      summaryName.setMaximumSize(new Dimension(800, 30));
      
      Box summaryBox = Box.createHorizontalBox();
      summaryBox.add(summaryLabel);
      summaryBox.add(Box.createRigidArea(new Dimension(33,0)));
      summaryBox.add(summaryName);
      summaryBox.setPreferredSize(new Dimension(800,30)); 
      
      /*
      String[] evidenceType = {
         "Email",
         "Web Page",
         "Document",
         "Image",
         "Video",
         "Application",
         "System Event",
         "External Event",
         "Witness Statement",
         "Physical Evidence",
         "Information",
         "Warning",
         "Error",
         "Critical",
         "Malware",
         "Intusion",
         "Verbose",
         "Other Evidence"
        };
        
        JLabel typeLabel = new JLabel("Type:");
        typeList = new JComboBox(evidenceType);
        typeList.setEditable(true);
        typeList.setMinimumSize(new Dimension(400, 30));
        typeList.setMaximumSize(new Dimension(800, 30));
        typeList.addActionListener(new java.awt.event.ActionListener() 
        {
         public void actionPerformed(java.awt.event.ActionEvent evt) 
         {
            //get the text
         }
        });
      */
        
      JLabel typeLabel = new JLabel("Type:");
      eventType = new JTextField();
      eventType.setEditable(true);
      eventType.setMinimumSize(new Dimension(400, 30));
      eventType.setMaximumSize(new Dimension(800, 30));
      Box typeBox = Box.createHorizontalBox();
      typeBox.add(typeLabel);
      typeBox.add(Box.createRigidArea(new Dimension(60,0)));
      typeBox.add(eventType);
      typeBox.setPreferredSize(new Dimension(800,30)); 
      /*
      JLabel fileLabel = new JLabel("File:");
      fileName = new JTextField();
      fileName.setMinimumSize(new Dimension(400, 30));
      fileName.setMaximumSize(new Dimension(800, 30));
      
      JButton fileButton = new JButton();
      java.net.URL imageURL = FineLineAboutDialog.class.getResource("/FineLineGUI/images/folder_green.png");
      ImageIcon fileButtonIcon = new ImageIcon(imageURL);
      fileButton.setIcon(fileButtonIcon);
      fileButton.addActionListener(new java.awt.event.ActionListener() 
      {
         public void actionPerformed(java.awt.event.ActionEvent evt) 
         {
            
            fileChoose.showOpenDialog(parent); //TODO: what is the return value of this?????
            File f = fileChoose.getSelectedFile();
             try {
                 filePath = f.getCanonicalPath();
                 fileName.setText(filePath);
             } catch (IOException ex) {
                 System.out.println("FineLineEventDialog: failed to get canonical file path.");
             }
         }
      });
      
      Box fileBox = Box.createHorizontalBox();
      fileBox.add(fileLabel);
      fileBox.add(Box.createRigidArea(new Dimension(65,0)));
      fileBox.add(fileName);
      fileBox.add(fileButton);
      fileBox.setPreferredSize(new Dimension(800,30)); 
      */
      //DateFormat tf = DateFormat.getTimeInstance(DateFormat.SHORT);
      //DateFormat df = DateFormat.getDateInstance(DateFormat.SHORT, Locale.ENGLISH);
      JLabel dateLabel = new JLabel("Date:");
      dateField = new JTextField("DD/MM/YYYY");
      dateField.setMinimumSize(new Dimension(100, 30));
      dateField.setMaximumSize(new Dimension(400, 30));
      JLabel timeLabel = new JLabel("Time:");
      timeField = new JTextField("HH:MM");
      timeField.setMinimumSize(new Dimension(100, 30));
      timeField.setMaximumSize(new Dimension(400, 30));
      
      Box dateBox = Box.createHorizontalBox();
      dateBox.add(dateLabel);
      dateBox.add(Box.createRigidArea(new Dimension(60,0)));
      dateBox.add(dateField);
      dateBox.add(Box.createRigidArea(new Dimension(23,0)));
      dateBox.add(timeLabel);
      dateBox.add(Box.createRigidArea(new Dimension(23,0)));
      dateBox.add(timeField);
      //dateBox.add(Box.createRigidArea(new Dimension(200,0)));
      dateBox.setPreferredSize(new Dimension(800,30)); 
      
      
      /* ---------------------------------------------------*/
      
      JLabel descriptionLabel = new JLabel(" Description:");
      descriptionLabel.setMaximumSize(new Dimension(800, 30));
      Box descriptionBox = Box.createHorizontalBox();
      descriptionBox.add(descriptionLabel);
      descriptionBox.add(Box.createHorizontalGlue());
      descriptionBox.setPreferredSize(new Dimension(800,30));
      
      summaryArea = new JEditorPane();
      summaryArea.setContentType("text/plain");
      //summaryArea.setLineWrap(true);
      scrollPane.getViewport().add(summaryArea);
      
      Box buttonBox = Box.createHorizontalBox();
      buttonBox.add(Box.createHorizontalGlue());
      
      saveButton = new JButton("Save");
      saveButton.addActionListener(new java.awt.event.ActionListener() 
      {
         public void actionPerformed(java.awt.event.ActionEvent evt) 
         {
            saveEvent();
         }
      });
      buttonBox.add(saveButton);
      buttonBox.add(Box.createRigidArea(new Dimension(15,0)));

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
      
      //JSeparator descSeparator = new JSeparator(JSeparator.HORIZONTAL);
      //descSeparator.setMaximumSize(new Dimension(800, 5));
      
      //contentPanel.add(projectBox);
      contentPanel.add(evidenceBox);
      //contentPanel.add(investigatorBox);
      contentPanel.add(summaryBox);
      contentPanel.add(typeBox);
      //contentPanel.add(fileBox);
      contentPanel.add(dateBox);
      //contentPanel.add(descSeparator);
      contentPanel.add(descriptionBox);
      contentPanel.add(scrollPane);
      contentPanel.add(Box.createRigidArea(new Dimension(0,5)));
      contentPanel.add(buttonBox);
      contentPanel.add(Box.createRigidArea(new Dimension(0,5)));
      
      cp.setLayout(new BoxLayout(cp, BoxLayout.Y_AXIS));
      cp.add(contentPanel);
      
      fileChoose = new JFileChooser();
       
   }
   public void setText(String newText)
   {
      summaryArea.setText(newText);
   }
   
   public void showDialog(String tagText)
   {
       //summaryArea.setText(tagText);
       //summaryArea.setCaretPosition(0);
       setVisible(true);
   }
   
   public void hideDialog()
   {
      setVisible(false);
   }

   private void saveEvent()
   {
       
      //if a new event then create a new FineLineEvent object and insert it into the event list then repaint the graph view panel.
      
      if (newEvent)
      {
          flEvent = new FineLineEvent();
      }
      flEvent.setSummary(summaryName.getText());
      flEvent.setDate(dateField.getText());
      flEvent.setDisplayTime(timeField.getText());
      flEvent.setTime(dateField.getText() + " " + timeField.getText());
      flEvent.setEvidenceNumber(evidenceNumber.getText());
      flEvent.setEventType(eventType.getText());
      flEvent.setEventID(1000);
      flEvent.setY(100); //TODO: get the default height from the graph panel
      
      String sText = summaryArea.getText();
      String result =  sText.replaceAll("[\\n\\r]+","<nl>"); //Remove all the newlines
      flEvent.setData(result);
        
      if (newEvent)
      {
         flGraph.insertNewEvent(flEvent);
      }
      flGraph.setProjectModified();
      
      hideDialog();
   }

}
