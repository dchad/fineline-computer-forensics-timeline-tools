/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package FineLineGUI;

/**
 *
 * @author Derek
 */
public class FineLineConfig implements FineLineConstants
{
    public int enableSocketServer;
    
    
    
    //Get/Set methods
    public int getOption(int option)
    {
        int optionVal = 0;
        switch(option)
        {
            case 0: break;
            case 1: break;
            default: System.out.println("FineLineConfig.getOption() <ERROR> Unknown option.");
        }
        return(optionVal);
    }
}
