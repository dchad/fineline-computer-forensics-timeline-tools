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
 * Class  : FineLineProjectDialog
 * 
 * Description: A Swing dialog for editing project/case/investigation information that will be saved as a header
 *              in a project/event file.
 * 
 * 
 */

package FineLineGUI;

import java.awt.Container;
import java.awt.Dimension;
import java.text.DateFormat;
import java.util.Locale;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JFormattedTextField;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;

/**
 *
 * @author Derek
 */
public class FineLineProjectDialog extends JDialog
{
   private JEditorPane summaryArea;
   private JPanel contentPanel;
   private JButton closeButton;
   private JButton saveButton;
   private Container cp;
   //private String filePath;
   //private String eventFilePath;
   //private JFileChooser fileChoose;
   //private JTextField fileName;
   //private JTextField eventFileName;
   private JTextField summaryName;
   private JTextField investigatorName;
   private JTextField projectName;
   private FineLineProject flProject;
   private JFormattedTextField startDateField;
   private JFormattedTextField endDateField;
   

   public FineLineProjectDialog(final JFrame parent) 
   {
      super(parent, "FineLine Project Editor");

      cp = getContentPane();
     
      setSize(800,600);
      setModal(true);
      
      contentPanel = new JPanel();
      contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
      contentPanel.setPreferredSize(new Dimension(800,600));
      contentPanel.setBorder(BorderFactory.createTitledBorder("FineLine Project/Case Editor"));
      
      JScrollPane scrollPane = new JScrollPane();
      
      JLabel projectLabel = new JLabel("Project/Case:");
      projectName = new JTextField();
      projectName.setMinimumSize(new Dimension(400, 30));
      projectName.setMaximumSize(new Dimension(800, 30));
      
      Box projectBox = Box.createHorizontalBox();
      projectBox.add(projectLabel);
      projectBox.add(Box.createRigidArea(new Dimension(15,0)));
      projectBox.add(projectName);
      projectBox.setPreferredSize(new Dimension(800,30));
      
      JLabel investigatorLabel = new JLabel("Investigator:");
      investigatorName = new JTextField();
      investigatorName.setMinimumSize(new Dimension(400, 30));
      investigatorName.setMaximumSize(new Dimension(800, 30));
      
      Box investigatorBox = Box.createHorizontalBox();
      investigatorBox.add(investigatorLabel);
      investigatorBox.add(Box.createRigidArea(new Dimension(23,0)));
      investigatorBox.add(investigatorName);
      investigatorBox.setPreferredSize(new Dimension(800,30)); 
      
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
      JLabel fileLabel = new JLabel("Project File:");
      fileName = new JTextField();
      fileName.setMinimumSize(new Dimension(400, 30));
      fileName.setMaximumSize(new Dimension(800, 30));
      
      JButton fileButton = new JButton();
      java.net.URL imageURL = FineLineAboutDialog.class.getResource("/FineLineGUI/images/folder_red.png");
      ImageIcon fileButtonIcon = new ImageIcon(imageURL);
      fileButton.setIcon(fileButtonIcon);
      fileButton.addActionListener(new java.awt.event.ActionListener() 
      {
         public void actionPerformed(java.awt.event.ActionEvent evt) 
         {
            
            fileChoose.showOpenDialog(parent); 
            File f = fileChoose.getSelectedFile();
            if (f.exists())
            {
             try {
                 filePath = f.getCanonicalPath();
                 fileName.setText(filePath);
             } catch (IOException ex) {
                 System.out.println("FineLineProjectDialog: failed to get canonical file path.");
             }
            }
            else
            {
                try {
                    f.createNewFile();
                } catch (IOException ex) {
                    System.out.println("FineLineProjectDialog: failed to create new file.");
                }
            }
         }
      });
      
      Box fileBox = Box.createHorizontalBox();
      fileBox.add(fileLabel);
      fileBox.add(Box.createRigidArea(new Dimension(25,0)));
      fileBox.add(fileName);
      fileBox.add(fileButton);
      fileBox.setPreferredSize(new Dimension(800,30)); 
   
      JLabel eventFileLabel = new JLabel("Event File:");
      eventFileName = new JTextField();
      eventFileName.setMinimumSize(new Dimension(400, 30));
      eventFileName.setMaximumSize(new Dimension(800, 30));
      
      JButton eventFileButton = new JButton();
      eventFileButton.setIcon(fileButtonIcon);
      eventFileButton.addActionListener(new java.awt.event.ActionListener() 
      {
         public void actionPerformed(java.awt.event.ActionEvent evt) 
         {
            
            fileChoose.showOpenDialog(parent); 
            File f = fileChoose.getSelectedFile();
            if (f.exists())
            {
               try {
                   eventFilePath = f.getCanonicalPath();
                   eventFileName.setText(eventFilePath);
               } catch (IOException ex) {
                 System.out.println("FineLineProjectDialog: failed to get canonical file path.");
               }
            }
            else
            {
                System.out.println("FineLineProjectDialog: event file does not exist.");
            }
         }
      });
      
      Box eventFileBox = Box.createHorizontalBox();
      eventFileBox.add(eventFileLabel);
      eventFileBox.add(Box.createRigidArea(new Dimension(33,0)));
      eventFileBox.add(eventFileName);
      eventFileBox.add(eventFileButton);
      eventFileBox.setPreferredSize(new Dimension(800,30)); 
      */
      DateFormat df = DateFormat.getDateInstance(DateFormat.SHORT, Locale.ENGLISH);
      JLabel startDateLabel = new JLabel("Start Date:");
      startDateField = new JFormattedTextField(df);
      startDateField.setMinimumSize(new Dimension(100, 30));
      startDateField.setMaximumSize(new Dimension(400, 30));
      JLabel endDateLabel = new JLabel("End Date:");
      endDateField = new JFormattedTextField(df);
      startDateField.setMinimumSize(new Dimension(100, 30));
      startDateField.setMaximumSize(new Dimension(400, 30));
      endDateField.setMinimumSize(new Dimension(100, 30));
      endDateField.setMaximumSize(new Dimension(400, 30));
      
      Box dateBox = Box.createHorizontalBox();
      dateBox.add(startDateLabel);
      dateBox.add(Box.createRigidArea(new Dimension(32,0)));
      dateBox.add(startDateField);
      dateBox.add(Box.createRigidArea(new Dimension(23,0)));
      dateBox.add(endDateLabel);
      dateBox.add(Box.createRigidArea(new Dimension(10,0)));
      dateBox.add(endDateField);
      //dateBox.add(Box.createRigidArea(new Dimension(10,0)));
      dateBox.setPreferredSize(new Dimension(800,30)); 
      
      
      /* ---------------------------------------------------*/
      
      JLabel descriptionLabel = new JLabel(" Project/Case Description:");
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
            saveProject();
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
      
      contentPanel.add(projectBox);
      contentPanel.add(investigatorBox);
      contentPanel.add(summaryBox);
      //contentPanel.add(fileBox);
      //contentPanel.add(eventFileBox);
      contentPanel.add(dateBox);
      contentPanel.add(descriptionBox);
      contentPanel.add(scrollPane);
      contentPanel.add(Box.createRigidArea(new Dimension(0,5)));
      contentPanel.add(buttonBox);
      contentPanel.add(Box.createRigidArea(new Dimension(0,5)));
      
      cp.setLayout(new BoxLayout(cp, BoxLayout.Y_AXIS));
      cp.add(contentPanel);
      
   }
   
   public void showDialog(String tagText, FineLineProject flp)
   {
       flProject = flp;
       fillDialogueFields();
       setVisible(true);
   }
   
   public void hideDialog()
   {
      setVisible(false);
   }

   private void saveProject() 
   {
      //set all the fields in the FineLineProject
      flProject.setProjectName(projectName.getText());
      flProject.setProjectInvestigator(investigatorName.getText());
      flProject.setProjectSummary(summaryName.getText());
      flProject.setProjectStartDate(startDateField.getText());
      flProject.setProjectEndDate(endDateField.getText());
      flProject.setProjectDescription(summaryArea.getText());
      hideDialog();
   }

    private void fillDialogueFields() 
    {
       projectName.setText(flProject.getProjectName());
       investigatorName.setText(flProject.getProjectInvestigator());
       summaryName.setText(flProject.getProjectSummary());
       startDateField.setText(flProject.getProjectStartDate());
       endDateField.setText(flProject.getProjectEndDate());
       summaryArea.setText(flProject.getProjectDescription());
    }
             
}
