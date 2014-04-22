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
 * Class  : FineLineConstants
 * 
 * Description: Global constant definitions.
 * 
 * 
 */


package FineLineGUI;

import java.awt.Color;

/**
 *
 * @author Derek
 */
public interface FineLineConstants 
{
    //General colors
    public final Color FL_DARK_BLUE = new Color(19, 36, 64);
    public final Color FL_MID_BLUE  = new Color(0, 64, 128);
    public final Color FL_LIGHT_BLUE = new Color(64, 128, 128);
    public final Color FL_DARK_BLUE2 = new Color(31, 45, 54);
    public final Color FL_BRICK_RED  = new Color(174, 17, 29);
    public final Color FL_DARK_RED = new Color(77, 2, 7);
    public final Color FL_MID_GREEN = new Color(44, 148, 51);
    public final Color FL_LIGHT_GREEN = new Color(82, 188, 128);
    public final Color FL_DARK_GOLD  = new Color(187, 151, 4);
    public final Color FL_YELLOW     = new Color(255, 255, 74);
    public final Color FL_PINK = new Color(248, 145, 133);
    public final Color FL_SKY_BLUE = new Color(172, 193, 208);
    public final Color FL_ROSE = new Color(255, 128, 128);
    
    //public final Color [] colourList = {};  //an array or hashmap may be more efficent than a switch statement
    
    //Event type colours
    //public final Color FL_SHUTDOWN_COLOR    = new Color(77, 88, 77);
    //public final Color FL_BOOT_COLOR        = new Color(44, 150, 55);
    //public final Color FL_USER_LOGIN_COLOR  = new Color(180,150,20);
    //public final Color FL_USER_LOGOUT_COLOR = new Color(180,150,20);
    
    //Network definitions
    public final int FL_PORT_NUMBER = 58989;
    
    public final int FL_WIN_VERBOSE              = 5;
    public final int FL_WIN_INFORMATION          = 4;
    public final int FL_WIN_WARNING              = 3;
    public final int FL_WIN_ERROR                = 2;
    public final int FL_WIN_CRITICAL             = 1;
    public final int FL_EVENT_FILE_CLEARED_EVENT = 6;
    public final int FL_BOOT_EVENT               = 7;
    public final int FL_SHUTDOWN_EVENT           = 8;
    public final int FL_USER_LOGIN_EVENT         = 9;
    public final int FL_USER_LOGOUT_EVENT        = 10;
    public final int FL_TIME_CHANGE_EVENT        = 11;
    public final int FL_TIMEZONE_CHANGE_EVENT    = 12;
    public final int FL_FILE_DELETED_EVENT       = 13;
    public final int FL_FILE_CREATED_EVENT       = 14;
    public final int FL_FILE_MODIFIED_EVENT      = 15;
    public final int FL_MANUAL_EVIDENCE_EVENT    = 16; //Inserted into timeline by the investigator, evidence subtypes below.
    public final int FL_MACTIME_FLS_EVENT        = 17; //Events imported from a Sleuthkit mactime/fls format event file
    public final int FL_SYSLOG_EVENT             = 18; //Events imported from a syslog format file
    public final int FL_UNKNOWN_EVENT            = 1024;
    
    //Evidence Type definitions for manually created evidence/events.
    public final int FL_LOG_EVID    = 1;
    public final int FL_EMAIL_EVID  = 2;
    public final int FL_CHAT_EVID   = 3;
    public final int FL_IMAGE_EVID  = 4;
    public final int FL_WEB_EVID    = 5;
    public final int FL_APP_EVID    = 6;
    public final int FL_DOC_EVID    = 8;
    public final int FL_FILE_EVID   = 9;
    public final int FL_VID_EVID    = 10;
    public final int FL_OTHER_EVID  = 1024;
    
    //Event import filter type definitions
    public final int FL_MACTIME_FLS_FILTER  = 0;
    public final int FL_SYSLOG_FILTER       = 1;
    public final int FL_FINELINE_FILTER     = 2;
    public final int FL_LOG2TIMELINE_FILTER = 3;
    
    public static final String DEFAULT_CHAR_ENCODING = "UTF-8";
    public static final String LINE_FEED = System.getProperty("line.separator");
}
