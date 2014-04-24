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
 * Class  : FineLineFilterViewPanel
 * 
 * Description: A JPanel for displaying event filtering options and for running the 
 *              command line tools to analyse system event files.
 * 
 * 
 */


package FineLineGUI;

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;


/**
 *
 * @author Derek
 */
class FineLineFilterViewPanel extends JPanel
{
    private final JTabbedPane pane;
    
    //private final JCheckBox deleteEventsCheckBox;
    private final JRadioButton searchRadioButton;
    private final JRadioButton filterRadioButton;        
    private final ButtonGroup group;
    private final JFileChooser fileChoose;
    private final JTextField keywordFileTextField;
    private final JButton keywordFileButton;
    private final JScrollPane scrollPane;
    private final JTextArea keywordArea;
    private final JScrollPane outputScrollPane;
    private final JTextArea outputArea;
    private final FineLineMainFrame flParent;
    private final JButton filterStartButton;
    private final JButton commandStartButton;
    private final JTextField commandTextField;
    private final JButton commandFileButton;
    private final JTextField filterTextField;
    private final JTextField inputEventFileTextField;
    private final JTextField outputFileTextField;
    private final JTextField guiAddressTextField;
    private final JButton commandFilterFileButton;
    private final JButton outputFileButton;
    private final JButton inputEventFileButton;
    
    
    public FineLineFilterViewPanel(final JTabbedPane pane, FineLineMainFrame parent, FineLineConfig flc)
    {
       super(new FlowLayout(FlowLayout.CENTER, 0, 0));
       this.pane = pane;
       this.setOpaque(false);
       
       Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
       
       this.setPreferredSize(screen);
       
       flParent = parent;
       fileChoose = new JFileChooser();
       
       Box topLevelBox = Box.createHorizontalBox();
       Box leftBox = Box.createVerticalBox();  //this contains the filter and tools Jpanels vertically
       Box rightBox = Box.createVerticalBox(); //this contains the output text area for displaying the filter progress
       
       // Components for the searching and filtering panel
       Box filterPanelBox = Box.createVerticalBox();
       filterPanelBox.setPreferredSize(new Dimension(800,300));
       
       scrollPane = new JScrollPane();
       
       Box filterBox = Box.createVerticalBox();
       Box keywordsBox = Box.createHorizontalBox();
       
       JLabel keywordLabel = new JLabel("Keywords: ");
       keywordLabel.setMaximumSize(new Dimension(800, 30));
       keywordsBox.add(keywordLabel);
       keywordsBox.add(Box.createHorizontalStrut(25));
       keywordsBox.setPreferredSize(new Dimension(800, 250));
       keywordArea = new JTextArea();
       keywordArea.setPreferredSize(new Dimension(800, 250));
       scrollPane.getViewport().add(keywordArea);
       keywordsBox.add(scrollPane);
       
       filterBox.add(keywordsBox);
       
       Box keywordFileBox = Box.createHorizontalBox();
       
      JLabel keywordFileLabel = new JLabel("Keyword File: ");
      keywordFileTextField = new JTextField();
      keywordFileTextField.setMaximumSize(new Dimension(800, 30));
      keywordFileTextField.setMinimumSize(new Dimension(250, 30));
      keywordFileTextField.addActionListener(new java.awt.event.ActionListener() 
      {
           @Override
           public void actionPerformed(ActionEvent e) {
               //TODO: test which action types are performed and when
               openKeywordFile();
           }
      });
      keywordFileButton = new JButton();
      java.net.URL imageURL = FineLineAboutDialog.class.getResource("/FineLineGUI/images/folder_green.png");
      ImageIcon fileButtonIcon = new ImageIcon(imageURL);
      keywordFileButton.setIcon(fileButtonIcon);
      keywordFileButton.addActionListener(new java.awt.event.ActionListener() 
      {
           @Override
           public void actionPerformed(ActionEvent e) {
               fileActionPerformed(0);
           }
      });
       
      keywordFileBox.add(keywordFileLabel);
      keywordFileBox.add(Box.createHorizontalStrut(8));
      keywordFileBox.add(keywordFileTextField);
      keywordFileBox.add(keywordFileButton);
      
      filterPanelBox.add(keywordFileBox);
      
             
      Box buttonBox = Box.createHorizontalBox();
      Box innerButtonBox = Box.createVerticalBox();
      //deleteEventsCheckBox = new JCheckBox("Delete Matched Events");
      searchRadioButton = new JRadioButton("Search for Events");
      searchRadioButton.setSelected(true);
      filterRadioButton = new JRadioButton("Filter out Events");
      filterRadioButton.setSelected(false);
      filterStartButton = new JButton("Start");
      filterStartButton.addActionListener(new java.awt.event.ActionListener() 
      {
           @Override
           public void actionPerformed(ActionEvent e) {
               startFilter();
           }
      });
      group = new ButtonGroup();
      group.add(searchRadioButton);
      group.add(filterRadioButton);
      innerButtonBox.add(searchRadioButton);
      innerButtonBox.add(filterRadioButton);
      //innerButtonBox.add(deleteEventsCheckBox);
      buttonBox.add(innerButtonBox);
      buttonBox.add(Box.createHorizontalStrut(215));
      buttonBox.add(filterStartButton);
      
      filterBox.add(buttonBox);
      
      filterPanelBox.add(filterBox);
      filterPanelBox.setBorder(BorderFactory.createTitledBorder("Keyword Search/Filter"));
      leftBox.add(filterPanelBox);
      
       // Components for the command line tools panel
       
      Box toolsPanelBox = Box.createVerticalBox();
      toolsPanelBox.setPreferredSize(new Dimension(800,300));
      toolsPanelBox.setBorder(BorderFactory.createTitledBorder("Command Line Tools"));
      
      Box commandBox = Box.createHorizontalBox();

      JLabel commandLabel = new JLabel("Command: ");
      commandTextField = new JTextField();
      commandTextField.setMaximumSize(new Dimension(800, 30));
      commandTextField.setMinimumSize(new Dimension(250, 30));
      commandBox.add(commandLabel);
      commandBox.add(Box.createHorizontalStrut(11));
      commandBox.add(commandTextField);
      commandFileButton = new JButton();
      commandFileButton.setIcon(fileButtonIcon);
      commandFileButton.addActionListener(new java.awt.event.ActionListener() 
      {
           @Override
           public void actionPerformed(ActionEvent e) {
               fileActionPerformed(1);
           }
      });
      commandBox.add(commandFileButton);
      
      Box inputFileBox = Box.createHorizontalBox();

      JLabel inputFileLabel = new JLabel("Input File: ");
      inputEventFileTextField = new JTextField();
      inputEventFileTextField.setMaximumSize(new Dimension(800, 30));
      inputEventFileTextField.setMinimumSize(new Dimension(250, 30));
      inputFileBox.add(inputFileLabel);
      inputFileBox.add(Box.createHorizontalStrut(20));
      inputFileBox.add(inputEventFileTextField);
      inputEventFileButton = new JButton();
      inputEventFileButton.setIcon(fileButtonIcon);
      inputEventFileButton.addActionListener(new java.awt.event.ActionListener() 
      {
           @Override
           public void actionPerformed(ActionEvent e) {
               fileActionPerformed(2);
           }
      });
      inputFileBox.add(inputEventFileButton);
      
      Box filterFileBox = Box.createHorizontalBox();
      
      JLabel filterLabel = new JLabel("Filter File: ");
      filterTextField = new JTextField();
      filterTextField.setMaximumSize(new Dimension(800, 30));
      filterTextField.setMinimumSize(new Dimension(250, 30));
      filterFileBox.add(filterLabel);
      filterFileBox.add(Box.createHorizontalStrut(20));
      filterFileBox.add(filterTextField);
      commandFilterFileButton = new JButton();
      commandFilterFileButton.setIcon(fileButtonIcon);
      commandFilterFileButton.addActionListener(new java.awt.event.ActionListener() 
      {
           @Override
           public void actionPerformed(ActionEvent e) {
               fileActionPerformed(3);
           }
      });
      filterFileBox.add(commandFilterFileButton);
      
      Box outputFileBox = Box.createHorizontalBox();
      
      JLabel outputFileLabel = new JLabel("Output File: ");
      outputFileTextField = new JTextField();
      outputFileTextField.setMaximumSize(new Dimension(800, 30));
      outputFileTextField.setMinimumSize(new Dimension(250, 30));
      outputFileBox.add(outputFileLabel);
      outputFileBox.add(Box.createHorizontalStrut(11));
      outputFileBox.add(outputFileTextField);
      outputFileButton = new JButton();
      outputFileButton.setIcon(fileButtonIcon);
      outputFileButton.addActionListener(new java.awt.event.ActionListener() 
      {
           @Override
           public void actionPerformed(ActionEvent e) {
               fileActionPerformed(4);
           }
      });
      outputFileBox.add(outputFileButton);
      
      //Box commandButtonBox = Box.createHorizontalBox();
      Box guiAddressBox = Box.createHorizontalBox();
      //guiAddressBox.setAlignmentY(LEFT_ALIGNMENT);
      
      commandStartButton = new JButton("Start");
      commandStartButton.addActionListener(new java.awt.event.ActionListener() 
      {
           @Override
           public void actionPerformed(ActionEvent e) {
               startCommand();
           }
      });
           
      /*generateCheckBox = new JCheckBox("Generate Event File");
      generateCheckBox.setSelected(true);
      sendEventsCheckBox = new JCheckBox("Send Events to GUI");
      sendEventsCheckBox.setSelected(true);
      useFilterFileCheckBox = new JCheckBox("Use Filter File");
      useFilterFileCheckBox.setSelected(true);
      innerCommandButtonBox.add(generateCheckBox);
      innerCommandButtonBox.add(sendEventsCheckBox);
      innerCommandButtonBox.add(useFilterFileCheckBox);*/
      JLabel guiAddressLabel = new JLabel("GUI IP Address:");
      guiAddressTextField = new JTextField();
      guiAddressTextField.setMinimumSize(new Dimension(250, 30));
      guiAddressTextField.setMaximumSize(new Dimension(250, 30));
      //guiAddressBox.add();
      guiAddressBox.add(guiAddressLabel);
      guiAddressBox.add(guiAddressTextField);
      guiAddressBox.add(Box.createHorizontalStrut(50));
      guiAddressBox.add(commandStartButton);
      guiAddressBox.add(Box.createHorizontalStrut(50));
      //commandButtonBox.add(guiAddressBox);
      //commandButtonBox.add(commandStartButton);
      //commandButtonBox.add(Box.createHorizontalGlue());
      
      toolsPanelBox.add(commandBox);
      toolsPanelBox.add(inputFileBox);
      toolsPanelBox.add(filterFileBox);
      toolsPanelBox.add(outputFileBox);
      toolsPanelBox.add(guiAddressBox);
      
      leftBox.add(toolsPanelBox);
      
      outputScrollPane = new JScrollPane();
      outputArea = new JTextArea();
      outputArea.setPreferredSize(new Dimension(pane.getWidth()/2, screen.height-200));
      outputArea.setEditable(false);
      outputScrollPane.getViewport().add(outputArea);
      outputScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
      outputScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
      rightBox.add(outputScrollPane);
      rightBox.setBorder(BorderFactory.createTitledBorder("Output"));
      
      topLevelBox.add(leftBox);
      topLevelBox.add(rightBox);
      
      add(topLevelBox);

    }
    
    
     private void fileActionPerformed(int selectorField) 
     {

        fileChoose.showOpenDialog(flParent); //TODO: what is the return value of this?????
        File f = fileChoose.getSelectedFile();
         try {
             if (f != null)
             {
                String filePath = f.getCanonicalPath();
                switch(selectorField)
                {
                    case 0: keywordFileTextField.setText(filePath); openKeywordFile(); break;
                    case 1: commandTextField.setText(filePath); break;
                    case 2: inputEventFileTextField.setText(filePath); break;
                    case 3: filterTextField.setText(filePath); break;
                    case 4: outputFileTextField.setText(filePath); break;
                    default: break;
                }
             }
         } catch (IOException ex) {
             System.out.println("FineLineFilterViewPanel: failed to get canonical file path.");
             outputArea.append("ERROR: Failed to get file path.\n");
         }
 
     }
     
     private void startFilter()
     {
        Pattern p;
        Matcher m;
        List<FineLineEvent> flEventList; 
        FineLineGraphViewPanel flgvp;
        String regexstr;
        int matchCount = 0;
        
        regexstr = createRegex();
        
        if (regexstr == null)
        {
            outputArea.append("Invalid regular expression.\n");
            return;
        }
         
        outputArea.append("Regular expression = " + regexstr + "\n");
        if (regexstr.length() > 0)
        {
            p = Pattern.compile(regexstr, Pattern.DOTALL);
        
           // get the event list from the graph view panel and iterate over it
           flgvp = flParent.getGraphPanel();
           flEventList = flgvp.getEventList();
           if (flEventList.size() > 0)
           {
               for (int i = 0; i < flEventList.size(); i++)
               {
                   FineLineEvent fle = flEventList.get(i);
                   m = p.matcher(fle.toString());
                   if (m.find()) 
                   {
                      // this event matches on the keyword list
                      matchCount++;
                      outputArea.append("Matched Event: " + fle.getTime() + " " + fle.getSummary() + "\n");
                      if (filterRadioButton.isSelected())
                      {
                          fle.hideEvent();
                      }
                   }
                   else
                   {
                       // this event does not match on the keyword list
                       if (searchRadioButton.isSelected())
                       {
                           fle.hideEvent();
                       }
                   }
               }
               outputArea.append("Matched Events = " + matchCount + "\n");
               outputArea.setCaretPosition(outputArea.getText().length());
           }
           else
           {
               outputArea.append("No events in timeline.\n");
           }
         }
     }
     
     private void startCommand()
     {
         //Note: always start a thread with the start method, not the run method.
         FineLineCommandThread flct = new FineLineCommandThread(this);
         Thread t = new Thread(flct);
         t.start();
     }
     
     private void openKeywordFile()
     {
         //open the keyword file and add contents to the keyword text area
         String kwFile;
         File kf;
         BufferedReader in;
         
         if ((kwFile = keywordFileTextField.getText()) != null)
         {
             kf = new File(kwFile);
             if (kf.exists())
             {
                try {
                   in = new BufferedReader(new FileReader(kf));
                } catch (FileNotFoundException ex) {
                   System.out.println("FineLineFilterViewPanel <ERROR> Could not open keyword file.");
                   outputArea.append("ERROR: Could not open keyword file.\n");
                   return;
                }
             }
             else
             {
                System.out.println("FineLineFilterViewPanel <ERROR> Could not open keyword file.");
                outputArea.append("ERROR: Could not open keyword file.\n");
                return;
             }
         } 
         else
         {
             System.out.println("FineLineFilterViewPanel <ERROR> No keyword file specified.");
             outputArea.append("ERROR: No keyword file specified.\n");
             return;
         }
         String keywords;
         try {
            while ((keywords = in.readLine()) != null)
            {
                keywordArea.append(keywords);
            }
         } catch (IOException ex) {
             System.out.println("FineLineFilterViewPanel <ERROR> Could not read keyword file.");
             outputArea.append("ERROR: Could not read keyword file.\n");
        }
     }
     
     private String createRegex()
     {
        String keywords;
        String[] keylist;
        String regexstring = null;
        keywords = keywordArea.getText();
        
        //now tokenize it and build the regex
        keylist = keywords.split("\\s+");
        if (keylist.length == 0)
        {
            return(keywords);
        }
        regexstring = keylist[0];
        for (int i = 1; i < keylist.length; i++)
        {
            regexstring = regexstring + " | " + keylist[i];
        }
        
        return(regexstring);
        
     }
     
     public synchronized String getCommand()
     {
         return(commandTextField.getText());
     }
     public synchronized String getFilter()
     {
         return(filterTextField.getText());
     }
     public synchronized String getOutputFile()
     {
         return(outputFileTextField.getText());
     }
     
     /* DEPRECATED: unnecessary
     public synchronized Boolean getFileGeneration()
     {
         return(generateCheckBox.isSelected());
     }
     public synchronized Boolean getSendEvents()
     {
         return(sendEventsCheckBox.isSelected());
     }
     public synchronized Boolean getUseFilter()
     {
         return(useFilterFileCheckBox.isSelected());
     }
     */
    public synchronized void putMessage(String msg) 
    {
        outputArea.append(msg);
    }

    public String getGUIAddress() 
    {
        return(guiAddressTextField.getText());
    }
    
    public String getInputEventFile()
    {
        return(inputEventFileTextField.getText());
    }
     
}
