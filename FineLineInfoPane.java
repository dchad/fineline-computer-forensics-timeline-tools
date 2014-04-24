/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
DEPRECATED: DO NOT USE

*/

package FineLineGUI;

import java.awt.Container;
import java.awt.Dimension;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;

/**
 *
 * @author Derek
 */
public class FineLineInfoPane extends JDialog
{
    JLabel message;
    
    public FineLineInfoPane(JFrame parent)
    {
        super(parent);
        setModal(false);
        setUndecorated(true);
        
        Container cp = getContentPane();
        
        //TODO: add an info icon before the textfield and put both in a box
        message = new JLabel();
        message.setPreferredSize(new Dimension(250, 30));
        
        cp.add(message);
    }
    
    public void show(String mess)
    {
        message.setText(mess);
        setVisible(true);
    }
    
    @Override
    public void hide()
    {
        setVisible(false);
    }
}
