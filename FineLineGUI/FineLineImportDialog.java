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
 * Description: a dialog for selecting an event file to import (MACTIME/FLS, SYSLOG, FINELINE).
 *              .
 * 
 */
/*
   Modified code from the Zeitline class by Florian Buchholz, Courtney Falk.
*/


package FineLineGUI;

import java.awt.Container;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

/**
 *
 * @author Derek
 */
public class FineLineImportDialog extends JDialog implements ActionListener, ItemListener 
{
    
    public final int OK_OPTION = 0, CANCEL_OPTION = 1;
    private int return_value;
    private JFileChooser fc;  

    private JComboBox cbx_filter_types;
    private JTextField txt_file_name;

    private JButton btn_file_name, btn_ok, btn_cancel;
    private JPanel fieldPane;
    private GridBagConstraints c;
   
    
    /*
     * Set up and show the dialog.  The first Component argument
     * determines which frame the dialog depends on; it should be
     * a component in the dialog's controlling frame. The second
     * Component argument should be null if you want the dialog
     * to come up with its left corner in the center of the screen;
     * otherwise, it should be the component on top of which the
     * dialog should appear.
     */
    public int showDialog(JFrame frameComp) 
    {
        this.setVisible(true);
        
        return return_value;
    } // showDialog

    public FineLineImportDialog(JFrame frame) 
    {
        super(frame, "Import Data", true);
        
        this.setLocationRelativeTo(frame);
        
	fc = new JFileChooser(System.getProperty("user.dir"));
        // create and initialize the buttons.
        btn_cancel = new JButton("Cancel");
        btn_cancel.addActionListener(this);
        btn_ok = new JButton("Import");
        btn_ok.setActionCommand("Ok");
        btn_ok.addActionListener(this);
        getRootPane().setDefaultButton(btn_ok);

        // create a container so that we can add a title around
        // the scroll pane.  Can't add a title directly to the
        // scroll pane because its background would be white.
        // lay out the label and scroll pane from top to bottom.
        fieldPane = new JPanel();
        fieldPane.setLayout(new GridBagLayout());
//        GridBagConstraints c = new GridBagConstraints();
        c = new GridBagConstraints();

        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);

        String[] filterType = {
         "MACTIME/FLS",
         "SYSLOG",
         "FINELINE"       
        };
	cbx_filter_types = new JComboBox(filterType);
        cbx_filter_types.setEditable(false);
	cbx_filter_types.addItemListener(this);
	
        JLabel label = new JLabel("Filter type: ", JLabel.TRAILING);
        label.setLabelFor(cbx_filter_types);
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.PAGE_START;
        fieldPane.add(label, c);

        c.gridx = 1;
        c.gridy = 0;
        c.anchor = GridBagConstraints.CENTER;
        c.weightx = 1;
        fieldPane.add(cbx_filter_types, c);

        txt_file_name = new JTextField(20);
        btn_file_name = new JButton("...");
        btn_file_name.addActionListener(this);
        JPanel pnl_file_name = new JPanel();
        pnl_file_name.add(txt_file_name);
        pnl_file_name.add(btn_file_name);
		
        label = new JLabel("File name: ", JLabel.TRAILING);
        label.setLabelFor(pnl_file_name);
        c.gridx = 0;
        c.gridy = 1;
        c.anchor = GridBagConstraints.PAGE_START;
        c.weightx = 0;
        fieldPane.add(label, c);
		
        c.gridx = 1;
        c.gridy = 1;
        c.anchor = GridBagConstraints.CENTER;
        c.weightx = 1;
        fieldPane.add(pnl_file_name, c);

        // lay out the buttons from left to right.
        JPanel buttonPane = new JPanel();
        buttonPane.setLayout(new BoxLayout(buttonPane, BoxLayout.LINE_AXIS));
        buttonPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 10));
        buttonPane.add(Box.createHorizontalGlue());
        buttonPane.add(btn_ok);
        buttonPane.add(Box.createRigidArea(new Dimension(10, 0)));
        buttonPane.add(btn_cancel);
        buttonPane.add(Box.createHorizontalGlue());

        // put everything together, using the content pane's BorderLayout.
        Container contentPane = getContentPane();
	contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS));
        contentPane.add(fieldPane);
        contentPane.add(buttonPane);
        setResizable(false);
        pack();
    } 
   
    /*
     * Handles button clicks.  This is required for implementing
     * the ActionListener interface.
     *
     * @param e ActionEvent generated by a button click
     */
    public void actionPerformed(ActionEvent e) 
    {
        Object source = e.getSource();
        
        if(source == btn_ok) {
            // Ok button was clicked
            File temp_file = new File(txt_file_name.getText());
            if(!temp_file.exists()) 
            {
                JOptionPane.showMessageDialog(this, "File not found: \"" + temp_file.getAbsolutePath() + "\"", "File Not Found", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            return_value = OK_OPTION;
            setVisible(false);
        }
        else if(source == btn_file_name) 
        {
            // ... button to choose file was clicked

            int returnVal = fc.showOpenDialog(this);
            if(returnVal != JFileChooser.APPROVE_OPTION) return;
	    
            File temp_file = new File(fc.getSelectedFile().getAbsolutePath());
            if(!temp_file.exists()) 
            {
                JOptionPane.showMessageDialog(this, "Couldn't find the desired file \""  + temp_file.getAbsolutePath() + "\"", "File Not Found", JOptionPane.ERROR_MESSAGE);
                return;
            }
            txt_file_name.setText(temp_file.getAbsolutePath());
        }
        else if(source == btn_cancel) 
        {
            // Cancel button was clicked
            return_value = CANCEL_OPTION;
            setVisible(false);
        }
    } // actionPerformed

    public void itemStateChanged(ItemEvent e) 
    {
	if (e.getStateChange() == ItemEvent.SELECTED) 
        {
	}
    }
    
    
    public String getFileName() 
    {
        return txt_file_name.getText();
    } // getFileName
  
    public int getImportFilterType() 
    {
        //returns 0 for first item in list
        return cbx_filter_types.getSelectedIndex();
    }
} 

