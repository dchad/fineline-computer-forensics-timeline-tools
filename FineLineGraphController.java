/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package FineLineGUI;

import static java.lang.Thread.sleep;
import javax.swing.SwingUtilities;

/**
 *
 * @author Derek
 */
public class FineLineGraphController extends Thread
{
   private int direction;
   private Boolean scrolling;
   private FineLineGraphViewPanel viewPanel;
   
   public FineLineGraphController(FineLineGraphViewPanel vPanel)
   {
       scrolling = false;
       viewPanel = vPanel;
       direction = -1;
   }
   
    @Override
    public void run() 
    {
       while (true)
       {
           if (scrolling)
           {
            Runnable scrollRunnable = new Runnable() {

            @Override
            public void run() {
                //viewPanel.scrollTimeLine(direction);
            }
            };
            invokeLater(scrollRunnable);
              
            //System.out.println("FineLineGraphController: button pressed.");
           }
            try {
            sleep(100);
            } catch (InterruptedException ex) {
            System.out.println("FineLineGraphController: interrupted exception.");
            }
       }
    }
    
    public void scrollGraph(final int direction)
    {
        scrolling = true;
        while (scrolling)
        {
        Runnable scrollRunnable = new Runnable() {

            @Override
            public void run() {
                //viewPanel.scrollTimeLine(direction);
            }
        };
        invokeLater(scrollRunnable);
              
            //System.out.println("FineLineGraphController: button pressed.");

            try {
            sleep(100);
            } catch (InterruptedException ex) {
            System.out.println("FineLineGraphController: interrupted exception.");
            }
                
        }
    }

    public synchronized void pauseScrolling()
    {
        scrolling = false;
    }
    
    public synchronized void startScrolling()
    {
        scrolling = true;
    }
    
    private static void invokeAndWait(Runnable run) {
        try {
            SwingUtilities.invokeAndWait(run);
        } catch (Exception e) {
            System.out.println("FineLineGraphController: invocation exception.");
        }
    }
    
        private static void invokeLater(Runnable run) {
        try {
            SwingUtilities.invokeLater(run);
        } catch (Exception e) {
            System.out.println("FineLineGraphController: invocation exception.");
        }
    }
}

/*
final Runnable doHelloWorld = new Runnable() {
     public void run() {
         System.out.println("Hello World on " + Thread.currentThread());
     }
 };

 Thread appThread = new Thread() {
     public void run() {
         try {
             SwingUtilities.invokeAndWait(doHelloWorld);
         }
         catch (Exception e) {
             e.printStackTrace();
         }
         System.out.println("Finished on " + Thread.currentThread());
     }
 };
 appThread.start();



//invokeLater

Runnable doHelloWorld = new Runnable() {
     public void run() {
         System.out.println("Hello World on " + Thread.currentThread());
     }
 };

 SwingUtilities.invokeLater(doHelloWorld);
 System.out.println("This might well be displayed before the other message.");
 
*/