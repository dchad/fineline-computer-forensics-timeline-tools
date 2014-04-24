/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package FineLineGUI;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;

/**
 *
 * @author Derek
 */
public class FineLineSocketServer implements Runnable
{
    FineLineMainFrame mainFrame;
    ServerSocket flServerSocket = null;
    FineLineConfig flConfig;
    FineLineGraphViewPanel flGraph;
    
    public FineLineSocketServer(FineLineMainFrame parent, FineLineConfig flc)
    {
        mainFrame = parent;
        flConfig = flc;
        flGraph = mainFrame.getGraphPanel();
        try {
            flServerSocket = new ServerSocket(flConfig.FL_PORT_NUMBER);
        } catch (IOException ex) {
            System.err.println("Could not listen on port: ." + flConfig.FL_PORT_NUMBER);
            //System.exit(1);
        }
    }

    @Override
    public void run() 
    {
        if (flServerSocket != null)
        {
            listen();
            try {
                flServerSocket.close();
            } catch (IOException ex) {
                System.err.println("FineLineSocketServer.listen() : server socket close error.");
            }
        }
    }

    private void listen() 
    {
        try {
            Socket clientSocket;
            
            clientSocket = flServerSocket.accept();
       
            BufferedReader in;
        
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
           
            String inputEvent;
            //TODO: send message to graph panel to clear panel of current project or create a new graph/project
            //TODO: should be able to receive multiple event streams for multiple remote computers
            while ((inputEvent = in.readLine()) != null)
            {
                System.out.println(inputEvent);
                flGraph.addEvent(new FineLineEvent(inputEvent));
                if (inputEvent.equals("END"))
                {
                    break;
                }
            }
            in.close();
            clientSocket.close();
            
        } catch (IOException ex) {
            System.err.println("FineLineSocketServer.listen() : IO error.");
        }
        flGraph.finishedEventLoad(1);
    }
}
