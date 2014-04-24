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
 * Description: displays a progress dialog for event file imports.
 *              Modified from the Zeitline class by Florian Buchholz and Courtney Falk.
 * 
 */


package FineLineGUI;

import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;

public class FineLineProgressDialog extends JDialog implements ActionListener 
{

    private Thread thread;
    private JLabel status;
    private JProgressBar progress_bar;
    private JButton cancel_button;
    private FineLineImporter runner;

    public FineLineProgressDialog(Frame owner, String title, FineLineImporter run) 
    {
        super(owner, title, true);
                
	runner = run;
        
	JPanel pane = (JPanel) getContentPane();
        pane.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
	
        pane.setLayout(new GridLayout(3,1));
	
	status = new JLabel("Adding events to the timeline", JLabel.CENTER);
	pane.add(status);
	
        progress_bar = new JProgressBar();
        progress_bar.setStringPainted(true);
        pane.add(progress_bar);

        cancel_button = new JButton("Cancel");
        cancel_button.addActionListener(this);
        pane.add(cancel_button);
        
        setResizable(false);
        pack();
        setLocationRelativeTo(owner);
        this.setModal(false); //make sure the dialog does not block on display
    } 
    
    public void actionPerformed(ActionEvent e) 
    {
        Object source = e.getSource();
        
        if(source == cancel_button) 
        {
            runner.stop();
	    setVisible(false);
        }
    } // actionPerformed
    
    public JProgressBar getProgressBar() 
    {
        return progress_bar;
    } // getProgressBar
    
    public void setStatus(String newStatus) 
    {
	    status.setText(newStatus);
    }
    
    public void setVisible(boolean visible) 
    {
        if(visible) 
        {
            // setting visible to true causes control to be given to the dialog
            super.setVisible(true);
        }
        else 
        {
            super.setVisible(false);
        }
    } // setVisible
} // class ProgressDlg
