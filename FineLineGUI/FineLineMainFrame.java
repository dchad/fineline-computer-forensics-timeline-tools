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
 * Date   : 01/12/2013
 * Class  : FineLineMainFrame
 * 
 * Description: the main application frame, initialisation and start routine.
 * 
 * 
 */



package FineLineGUI;

import java.awt.Frame;
import java.awt.print.PrinterException;
import java.awt.print.PrinterJob;
import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSlider;
import javax.swing.Timer;

/**
 *
 * @author Derek
 */
public class FineLineMainFrame extends javax.swing.JFrame {

    /**
     * Creates new form FineLineMainFrame
     */
    public FineLineMainFrame() {
        initComponents();
        initMenuComponents();
        initTabComponents();
        initSocketServer();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        graphPopUp = new javax.swing.JPopupMenu();
        eventPopUp = new javax.swing.JPopupMenu();
        ribbonPopUp = new javax.swing.JPopupMenu();
        jToolBar1 = new javax.swing.JToolBar();
        beginButton = new javax.swing.JButton();
        prevPageScrollButton = new javax.swing.JButton();
        leftScrollButton = new javax.swing.JButton();
        pauseScrollButton = new javax.swing.JButton();
        rightScrollButton = new javax.swing.JButton();
        nextPageScrollButton = new javax.swing.JButton();
        endButton = new javax.swing.JButton();
        magnifierSlider = new javax.swing.JSlider();
        fineLineTabPane = new javax.swing.JTabbedPane();
        mainMenu = new javax.swing.JMenuBar();
        fileMenu = new javax.swing.JMenu();
        New = new javax.swing.JMenuItem();
        Open = new javax.swing.JMenuItem();
        Save = new javax.swing.JMenuItem();
        SaveAs = new javax.swing.JMenuItem();
        Import = new javax.swing.JMenuItem();
        Close = new javax.swing.JMenuItem();
        Print = new javax.swing.JMenuItem();
        jSeparator1 = new javax.swing.JPopupMenu.Separator();
        Exit = new javax.swing.JMenuItem();
        editMenu = new javax.swing.JMenu();
        Copy = new javax.swing.JMenuItem();
        Paste = new javax.swing.JMenuItem();
        Cut = new javax.swing.JMenuItem();
        jSeparator2 = new javax.swing.JPopupMenu.Separator();
        projectSettings = new javax.swing.JMenuItem();
        helpMenu = new javax.swing.JMenu();
        About = new javax.swing.JMenuItem();
        Help = new javax.swing.JMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setPreferredSize(new java.awt.Dimension(1000, 600));

        jToolBar1.setRollover(true);

        beginButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/FineLineGUI/images/simbegin.gif"))); // NOI18N
        beginButton.setToolTipText("");
        beginButton.setFocusable(false);
        beginButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        beginButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        beginButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                beginButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(beginButton);

        prevPageScrollButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/FineLineGUI/images/simfirs.gif"))); // NOI18N
        prevPageScrollButton.setToolTipText("Go to first event.");
        prevPageScrollButton.setFocusable(false);
        prevPageScrollButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        prevPageScrollButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        prevPageScrollButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                prevPageScrollButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(prevPageScrollButton);

        leftScrollButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/FineLineGUI/images/simprev.gif"))); // NOI18N
        leftScrollButton.setToolTipText("Scroll event backward.");
        leftScrollButton.setFocusable(false);
        leftScrollButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        leftScrollButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        leftScrollButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                leftScrollButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(leftScrollButton);

        pauseScrollButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/FineLineGUI/images/simpause.gif"))); // NOI18N
        pauseScrollButton.setToolTipText("");
        pauseScrollButton.setFocusable(false);
        pauseScrollButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        pauseScrollButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        pauseScrollButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pauseScrollButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(pauseScrollButton);

        rightScrollButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/FineLineGUI/images/simnext.gif"))); // NOI18N
        rightScrollButton.setToolTipText("Scroll events forward.");
        rightScrollButton.setFocusable(false);
        rightScrollButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        rightScrollButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        rightScrollButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rightScrollButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(rightScrollButton);

        nextPageScrollButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/FineLineGUI/images/simlast.gif"))); // NOI18N
        nextPageScrollButton.setToolTipText("Go to last event time.");
        nextPageScrollButton.setFocusable(false);
        nextPageScrollButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        nextPageScrollButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        nextPageScrollButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nextPageScrollButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(nextPageScrollButton);

        endButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/FineLineGUI/images/simend.gif"))); // NOI18N
        endButton.setToolTipText("");
        endButton.setFocusable(false);
        endButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        endButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        endButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                endButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(endButton);

        magnifierSlider.setMajorTickSpacing(1);
        magnifierSlider.setMaximum(48);
        magnifierSlider.setMinimum(1);
        magnifierSlider.setPaintTicks(true);
        magnifierSlider.setSnapToTicks(true);
        magnifierSlider.setToolTipText("Zoom");
        magnifierSlider.setValue(24);
        magnifierSlider.setBorder(javax.swing.BorderFactory.createEmptyBorder(1, 50, 1, 1));
        magnifierSlider.setMaximumSize(new java.awt.Dimension(1000, 31));
        magnifierSlider.setMinimumSize(new java.awt.Dimension(50, 31));
        magnifierSlider.setName("magnifierSlider"); // NOI18N
        magnifierSlider.setPreferredSize(new java.awt.Dimension(650, 33));
        magnifierSlider.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                magnifierSliderStateChanged(evt);
            }
        });
        magnifierSlider.addInputMethodListener(new java.awt.event.InputMethodListener() {
            public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
            }
            public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
                magnifierSliderCaretPositionChanged(evt);
            }
        });
        jToolBar1.add(magnifierSlider);

        fineLineTabPane.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        fineLineTabPane.setName(""); // NOI18N

        fileMenu.setText("File");
        fileMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                fileMenuActionPerformed(evt);
            }
        });

        New.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_N, java.awt.event.InputEvent.ALT_MASK));
        New.setText("New");
        New.setToolTipText("");
        New.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NewActionPerformed(evt);
            }
        });
        fileMenu.add(New);

        Open.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_O, java.awt.event.InputEvent.ALT_MASK));
        Open.setText("Open");
        Open.setToolTipText("");
        Open.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                OpenActionPerformed(evt);
            }
        });
        fileMenu.add(Open);

        Save.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_S, java.awt.event.InputEvent.ALT_MASK));
        Save.setText("Save");
        Save.setToolTipText("");
        Save.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SaveActionPerformed(evt);
            }
        });
        fileMenu.add(Save);

        SaveAs.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_A, java.awt.event.InputEvent.ALT_MASK));
        SaveAs.setText("Save As");
        SaveAs.setToolTipText("");
        SaveAs.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SaveAsActionPerformed(evt);
            }
        });
        fileMenu.add(SaveAs);

        Import.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_I, java.awt.event.InputEvent.ALT_MASK));
        Import.setText("Import");
        Import.setToolTipText("");
        Import.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ImportActionPerformed(evt);
            }
        });
        fileMenu.add(Import);

        Close.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_C, java.awt.event.InputEvent.ALT_MASK));
        Close.setText("Close");
        Close.setToolTipText("");
        Close.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CloseActionPerformed(evt);
            }
        });
        fileMenu.add(Close);

        Print.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_P, java.awt.event.InputEvent.ALT_MASK));
        Print.setText("Print");
        Print.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PrintActionPerformed(evt);
            }
        });
        fileMenu.add(Print);
        fileMenu.add(jSeparator1);

        Exit.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_X, java.awt.event.InputEvent.ALT_MASK));
        Exit.setText("Exit");
        Exit.setToolTipText("");
        Exit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ExitActionPerformed(evt);
            }
        });
        fileMenu.add(Exit);

        mainMenu.add(fileMenu);

        editMenu.setText("Edit");

        Copy.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_C, java.awt.event.InputEvent.CTRL_MASK));
        Copy.setText("Copy");
        Copy.setToolTipText("");
        Copy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CopyActionPerformed(evt);
            }
        });
        editMenu.add(Copy);

        Paste.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_V, java.awt.event.InputEvent.CTRL_MASK));
        Paste.setText("Paste");
        Paste.setToolTipText("");
        Paste.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PasteActionPerformed(evt);
            }
        });
        editMenu.add(Paste);

        Cut.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_X, java.awt.event.InputEvent.CTRL_MASK));
        Cut.setText("Cut");
        Cut.setToolTipText("Cut the event item.");
        Cut.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CutActionPerformed(evt);
            }
        });
        editMenu.add(Cut);
        editMenu.add(jSeparator2);

        projectSettings.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_S, java.awt.event.InputEvent.CTRL_MASK));
        projectSettings.setText("Project Settings");
        projectSettings.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                projectSettingsActionPerformed(evt);
            }
        });
        editMenu.add(projectSettings);

        mainMenu.add(editMenu);

        helpMenu.setText("Help");

        About.setText("About");
        About.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AboutActionPerformed(evt);
            }
        });
        helpMenu.add(About);

        Help.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_H, java.awt.event.InputEvent.ALT_MASK));
        Help.setText("Help");
        Help.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                HelpActionPerformed(evt);
            }
        });
        helpMenu.add(Help);

        mainMenu.add(helpMenu);

        setJMenuBar(mainMenu);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jToolBar1, javax.swing.GroupLayout.DEFAULT_SIZE, 744, Short.MAX_VALUE)
                .addGap(6, 6, 6))
            .addComponent(fineLineTabPane)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addComponent(fineLineTabPane, javax.swing.GroupLayout.DEFAULT_SIZE, 461, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jToolBar1, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void fileMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_fileMenuActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_fileMenuActionPerformed

    private void ExitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ExitActionPerformed
        if (flProject != null)
        {
            if (flProject.modified())
            {
                //popup a dialog to ask for a save
                System.out.println("Exiting with save...");
                int n = JOptionPane.showConfirmDialog(this, "Save current project?", " ", JOptionPane.YES_NO_OPTION);
                if (n == JOptionPane.YES_OPTION)
                {
                    flProject.save();
                }
            }
        }
        System.exit(0);
    }//GEN-LAST:event_ExitActionPerformed

    private void OpenActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_OpenActionPerformed

        //FineLine generated event files have a default project header at the start of the file
        //so there is no need to distinguish between project files and event files, the default
        //project header can then be edited to change the project name etc...
        int fc = flFileChoice.showOpenDialog(this);
        if (fc == JFileChooser.APPROVE_OPTION)
        {
            File selectedFile = flFileChoice.getSelectedFile();
            if (selectedFile != null)
            {
                flProject = new FineLineProject(graphViewPanel, selectedFile);
                flProject.open();
                //now show the project dialog???
                //flProjectDialog.showDialog("Open Project/Case Editor", flProject);
                this.setTitle(flProject.getProjectName());
            }
        }
    }//GEN-LAST:event_OpenActionPerformed

    private void SaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SaveActionPerformed

        this.setTitle("FineLineGUI - Saving Project...");
        if (flProject == null)
        {
            NewActionPerformed(evt);
        }
        else
        {
            flProject.save();
        }
        this.setTitle("FineLineGUI - Project Saved.");
        
    }//GEN-LAST:event_SaveActionPerformed

    private void SaveAsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SaveAsActionPerformed

        this.setTitle("FineLineGUI - Saving Project...");
        int c = flFileChoice.showSaveDialog(this);
        if (c == JFileChooser.APPROVE_OPTION)
        {
            File pf = flFileChoice.getSelectedFile();
            if (flProject != null)
            {
               flProject.saveAs(pf);
            }
        }
        this.setTitle("FineLineGUI - Project Saved.");
    }//GEN-LAST:event_SaveAsActionPerformed

    private void CloseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CloseActionPerformed
        flProject = null;
        graphViewPanel.clearList();
        this.setTitle("FineLineGUI - Project Closed.");
    }//GEN-LAST:event_CloseActionPerformed

    private void CopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CopyActionPerformed
        JOptionPane.showMessageDialog(this, "This function not implemented yet.", " ", JOptionPane.OK_OPTION);
    }//GEN-LAST:event_CopyActionPerformed

    private void PasteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PasteActionPerformed
        // TODO add your handling code here:
        JOptionPane.showMessageDialog(this, "This function not implemented yet.", " ", JOptionPane.OK_OPTION);
    }//GEN-LAST:event_PasteActionPerformed

    private void CutActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CutActionPerformed
        // TODO add your handling code here:
        JOptionPane.showMessageDialog(this, "This function not implemented yet.", " ", JOptionPane.OK_OPTION);
    }//GEN-LAST:event_CutActionPerformed

    private void AboutActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_AboutActionPerformed
        // TODO add your handling code here:
        FineLineAboutDialog fldial = new FineLineAboutDialog(this);
    }//GEN-LAST:event_AboutActionPerformed

    private void HelpActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_HelpActionPerformed
        // TODO add your handling code here:
        JOptionPane.showMessageDialog(this, "This function not implemented yet.", " ", JOptionPane.INFORMATION_MESSAGE);
    }//GEN-LAST:event_HelpActionPerformed

    private void NewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NewActionPerformed
        //open the project dialogue, keep the filename of the project file for saving and checking
        int c = flFileChoice.showSaveDialog(this);
 
        if (c == JFileChooser.APPROVE_OPTION)
        {
            File pf = flFileChoice.getSelectedFile();
            flProject = new FineLineProject(graphViewPanel, pf);
            flProjectDialog.showDialog("New Project/Case Editor", flProject);
            //TODO: check for cancel operation
            flProject.saveAs(pf);
        }
        this.setTitle("FineLineGUI - New Project.");
    }//GEN-LAST:event_NewActionPerformed

    private void rightScrollButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rightScrollButtonActionPerformed
        graphViewPanel.setScrollType(1);
        controlTimer.start();
    }//GEN-LAST:event_rightScrollButtonActionPerformed

    private void pauseScrollButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pauseScrollButtonActionPerformed
        graphViewPanel.setScrollType(0);
        controlTimer.stop();
    }//GEN-LAST:event_pauseScrollButtonActionPerformed

    private void leftScrollButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_leftScrollButtonActionPerformed
        graphViewPanel.setScrollType(2);
        controlTimer.start();
    }//GEN-LAST:event_leftScrollButtonActionPerformed

    private void prevPageScrollButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_prevPageScrollButtonActionPerformed
        graphViewPanel.scrollPrevDay();
    }//GEN-LAST:event_prevPageScrollButtonActionPerformed

    private void beginButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_beginButtonActionPerformed
        graphViewPanel.scrollToStart();
    }//GEN-LAST:event_beginButtonActionPerformed

    private void nextPageScrollButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nextPageScrollButtonActionPerformed
        graphViewPanel.scrollNextDay();
    }//GEN-LAST:event_nextPageScrollButtonActionPerformed

    private void endButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_endButtonActionPerformed
        graphViewPanel.scrollToEnd();
    }//GEN-LAST:event_endButtonActionPerformed

    private void magnifierSliderStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_magnifierSliderStateChanged
        JSlider sauce = (JSlider) evt.getSource();
        graphViewPanel.setZoomLevel(sauce.getValue());
    }//GEN-LAST:event_magnifierSliderStateChanged

    private void magnifierSliderCaretPositionChanged(java.awt.event.InputMethodEvent evt) {//GEN-FIRST:event_magnifierSliderCaretPositionChanged
        // TODO add your handling code here:
    }//GEN-LAST:event_magnifierSliderCaretPositionChanged

    private void ImportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ImportActionPerformed

        //graphViewPanel.clearList(); leave the existing events in place???
        Thread t = new Thread(flImporter);
        t.start();
    }//GEN-LAST:event_ImportActionPerformed

    private void projectSettingsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_projectSettingsActionPerformed
            if (flProject != null)
            {
                //now show the project dialog
                flProjectDialog.showDialog("Open Project/Case Editor", flProject);
            }
            else
            {
                JOptionPane.showMessageDialog(this, "No project file open.");
            }
    }//GEN-LAST:event_projectSettingsActionPerformed

    private void PrintActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PrintActionPerformed
        PrinterJob job = PrinterJob.getPrinterJob();
        job.setPrintable(new FineLinePrinter(this, graphViewPanel));
        boolean doPrint = job.printDialog();
        if (doPrint)
        {
           try {
              job.print();
           } catch (PrinterException e) {
              System.out.println("Could not print job.");
           }
        }
    }//GEN-LAST:event_PrintActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(FineLineMainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                new FineLineMainFrame().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenuItem About;
    private javax.swing.JMenuItem Close;
    private javax.swing.JMenuItem Copy;
    private javax.swing.JMenuItem Cut;
    private javax.swing.JMenuItem Exit;
    private javax.swing.JMenuItem Help;
    private javax.swing.JMenuItem Import;
    private javax.swing.JMenuItem New;
    private javax.swing.JMenuItem Open;
    private javax.swing.JMenuItem Paste;
    private javax.swing.JMenuItem Print;
    private javax.swing.JMenuItem Save;
    private javax.swing.JMenuItem SaveAs;
    private javax.swing.JButton beginButton;
    private javax.swing.JMenu editMenu;
    private javax.swing.JButton endButton;
    private javax.swing.JPopupMenu eventPopUp;
    private javax.swing.JMenu fileMenu;
    private javax.swing.JTabbedPane fineLineTabPane;
    private javax.swing.JPopupMenu graphPopUp;
    private javax.swing.JMenu helpMenu;
    private javax.swing.JPopupMenu.Separator jSeparator1;
    private javax.swing.JPopupMenu.Separator jSeparator2;
    private javax.swing.JToolBar jToolBar1;
    private javax.swing.JButton leftScrollButton;
    private javax.swing.JSlider magnifierSlider;
    private javax.swing.JMenuBar mainMenu;
    private javax.swing.JButton nextPageScrollButton;
    private javax.swing.JButton pauseScrollButton;
    private javax.swing.JButton prevPageScrollButton;
    private javax.swing.JMenuItem projectSettings;
    private javax.swing.JPopupMenu ribbonPopUp;
    private javax.swing.JButton rightScrollButton;
    // End of variables declaration//GEN-END:variables

    private FineLineGraphViewPanel graphViewPanel;
    private FineLineTextViewPanel textViewPanel;
    private FineLineFilterViewPanel filterViewPanel;
    private FineLineTabPanel graphViewTab;
    private FineLineTabPanel textViewTab;
    private FineLineTabPanel filterViewTab;
    private FineLineSocketServer sockServer;
    private Thread sockThread;
    private JFileChooser flFileChoice;
    //private FineLineGraphController graphController;
    //private Thread controllerThread;
    private Timer controlTimer;
    private FineLineImporter flImporter;
    private FineLineProject flProject;
    private FineLineProjectDialog flProjectDialog;
    public FineLineConfig flConfig;
    
private void initTabComponents()
{
   String title = "Graph View";
   flConfig = new FineLineConfig();
   fineLineTabPane.add(title, new JLabel(title));
   graphViewPanel = new FineLineGraphViewPanel(fineLineTabPane, this, flConfig);
   fineLineTabPane.setTabComponentAt(0, graphViewTab = new FineLineTabPanel(fineLineTabPane));
   fineLineTabPane.setComponentAt(0, graphViewPanel);
   title = "Text View";
   fineLineTabPane.add(title, new JLabel(title));
   textViewPanel = new FineLineTextViewPanel(fineLineTabPane, this, flConfig);
   fineLineTabPane.setTabComponentAt(1, textViewTab = new FineLineTabPanel(fineLineTabPane));
   fineLineTabPane.setComponentAt(1, textViewPanel);
   title = "Filters";
   fineLineTabPane.add(title, new JLabel(title));
   filterViewPanel = new FineLineFilterViewPanel(fineLineTabPane, this, flConfig);
   fineLineTabPane.setTabComponentAt(2, filterViewTab = new FineLineTabPanel(fineLineTabPane));
   fineLineTabPane.setComponentAt(2, filterViewPanel);
   controlTimer = new Timer(20, graphViewPanel);
   flImporter = new FineLineImporter(this, graphViewPanel, textViewPanel, flConfig);
   flFileChoice = new JFileChooser();
   flProjectDialog = new FineLineProjectDialog(this);
   this.setExtendedState(Frame.MAXIMIZED_BOTH);
   this.setTitle("FineLineGUI");
}

    private void initMenuComponents() 
    {
         //initialise the popup and main menu items
    }
    
    private void getFonts()
    {
        //GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
 
        //Font[] fonts = ge.getAllFonts();
        //for (int i = 0; i < fonts.length; i++) 
        //{
        //   System.out.print(fonts[i].getFontName() + " : ");
        //   System.out.println(fonts[i].getFamily());
        //}
    }

    private void initSocketServer() 
    {
        sockServer = new FineLineSocketServer(this, flConfig);
        sockThread = new Thread(sockServer);
        sockThread.start();
    }
    
    private void initGraphController()
    {
        //graphController = new FineLineGraphController(graphViewPanel);
        //controllerThread = new Thread(graphController);
        //controllerThread.start();
    }

    public FineLineFilterViewPanel getFilterPanel()
    {
        return(filterViewPanel);
    }
    
    public FineLineTextViewPanel getTextPanel() 
    {
        return(textViewPanel);
    }
    
    public FineLineGraphViewPanel getGraphPanel()
    {
        return(graphViewPanel);
    }
    
    public FineLineProject getProject()
    {
        return(flProject);
    }
    
    public FineLineImporter getImporter()
    {
        return(flImporter);
    }
}
