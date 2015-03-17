# fineline-computer-forensics-timeline-tools
Automatically exported from code.google.com/p/fineline-computer-forensics-timeline-tools

A collection of command line and GUI tools for analysing event logs on Linux and Microsoft Windows computers to generate graphical timelines of events during the investigation of computer security incidents or crimes involving computers.

# 1. Quick Start Guide

## 1.1 Download

User Guide, Windows Binaries, Java GUI Package and source code tarball can be downloaded from:

https://googledrive.com/host/0B6maxAp3j2akRnBvcGdSTThJbXM/

Unzip the binary package into any directory, no installation or system configuration is required.

The following applications are included in the Windows binary package:

- FineLineGUIJava.jar - FineLine? GUI. 

- fineline.exe - analyse Windows EVT/EVTX log files. 

- fineline-ie.exe - analyse Internet Explorer 10+ WebCacheV01?.dat cache files. 

- fineline-iepre10.exe - analyse Internet Explorer 1 - 9 index.dat cache files. 

- fineline-ws.exe - analyse Windows Search database files. 

- TODO fineline-wl.exe - analyse Windows Live database files. 

- TODO fineline-search.exe - GUI for searching forensic images and live filesystems. 

- TODO fineline-sensor.exe - monitor network connections on live systems or analyse pcap/unified2 log files. 

## 1.2 Generate Event Files

Copy the .evt/.evtx files you want to analyse to the FineLine? directory. The recommended process is to analyse Security.evtx to obtain a basic computer usage timeline and use this as the starting point for the project/investigation. Windows event files are usually located in: C:\Windows\System32\winevt\Logs

Basic Usage:

Use the command line tools or the Java GUI to analyse the .evt/.evtx files, for example:

C:\fineline\fineline.exe -w -i Security.evtx

This will parse the Security.evtx event records and generate an output file called fineline-events-YYYYMMDD-HHMMSS.fle

The .fle file extension is not mandatory, you can specify any file name for output using the "-o" option. For example:

C:\fineline\fineline.exe -w -i System.evtx -o my-system-events.txt

Using Filters:

An optional filter file can be used to remove extraneous events. The file "fl-filter-list.txt" is included in the download package or you can create your own custom filters using a text editor. For example:

C:\fineline\fineline.exe -w -i Security.evtx -f fl-filter-list.txt

Using a Network Connection:

Events can also be sent to the GUI via TCP/IP if the GUI is already running on the local machine or another host on the network. For example:

C:\fineline\fineline.exe -s -a 127.0.0.1 -i Security.evtx

Using the GUI:

To view a graphical timeline of events, start the Java GUI by double clicking on the jar file: FineLineGUIJava.jar

From the File menu select the Open menu item and use the file open dialogue to select the generated event file: fineline-events-YYYMMDD-HHMMSS.fle

When the event file has been imported you can add/delete or modify events on the timeline or manually add external events/evidence by right clicking on the timeline and selecting the appropriate command from the popup menu.

You can also import event files such as Syslog or MACTIME/FLS files using the Import menu item on the File menu.

The command line tools can also be run from the GUI in the filters tab.


## 1.3 Event File Analysis

From the forensics/security point of view most event records generated by an OS are irrelevant and attempting to analyse large volumes of these records is counter-productive. Therefore, the recommended method is to start the event analysis by focusing on a particular subset of security related events (Microsoft, 2014), (NSA/CSA, 2013).

For Microsoft Windows systems, these events include:

Account Activities 512, 513, 516, 517, 520, 521, 528, 529, 531, 540, 576, 624, 630, 642, 685, 4624, 4625, 4648, 4728, 4732, 4634, 4735, 4740, 4756

Application Crashes and Hangs 1000, 1002

Windows Error Reporting 1001

Blue Screen of Death (BSOD) 1001

Windows Defender Errors 1005, 1006, 1008, 1010, 2001, 2003, 2004, 3002, 5008

Windows Integrity Errors 3001, 3002, 3003, 3004, 3010 and 3023

Windows Firewall Logs 2004, 2005, 2006, 2009, 2033

MSI Packages Installed 1022 and 1033

Windows Update Installed 2 and 19

Windows Service Manager Errors 7022, 7023, 7024, 7026, 7031, 7032, 7034

Group Policy Errors 1125, 1127, 1129

AppLocker? and SRP Logs 865, 866, 867, 868, 882, 8003, 8004, 8006, 8007

Windows Update Errors 20, 24, 25, 31, 34, 35

Hotpatching Error 1009

Kernel Driver and Kernel Driver Signing Errors 5038, 6281, 219

Log Clearing 104, 1102

Kernel Filter Driver 6

Windows Service Installed 7045

Program Inventory 800, 903, 904, 905, 906, 907, 908

Wireless Activities 8000, 8001, 8002, 8003, 8011, 10000, 10001, 11000, 11001, 11002, 11004, 11005, 11006, 11010, 12011, 12012, 12013

USB Activities 43, 400, 410

Printing Activities 307

Filtering:

The initial analysis should use aggressive filtering to remove extraneous events, for example:

C:\fineline\fineline.exe -s -a 192.168.1.100 -i Security.evtx -f fl-filter-list.txt

The file "fl-filter-list.txt" is included in the FineLine? package and contains a list of 400 security related Windows event identifiers and filter flags, for example:

512 0 513 0 514 1 515 1 516 1 517 1 518 1 519 1 520 0 521 1 528 0 529 1 530 1 531 1 532 1 533 1 534 1 535 1 536 1 537 1 538 1 ...

A flag value of 0 means include this event type and a flag value of 1 means filter out this event type. In this example almost all event types are filtered out as they are not relevant to the current stage of the investigation.


## 1.4 Project/Case Management

TODO:

# 2. Installation From Source

## 2.1 Windows Build

Requirements:

    libevt/libevtx/libesedb/libmsiecf by Joachim Metz (http://code.google.com/p/libevtx/)
    Oracle Java Development Kit (JDK) 1.7 or later to build the GUI.
    Microsoft Visual C++ 2010 or Visual Studio 2012 to build the command line tools. 

Download the FineLine? source code package and unzip into any directory.


### 2.1.1 Java GUI

Building the FineLine? GUI requires version 1.7 of the Oracle Java Development Kit (JDK). The GUI can be built using an IDE such as Netbeans or from the command line using the Java compiler. In Netbeans, open the project and select "Clean and Build" from the run menu.

### 2.1.2 Command Line Tools

The FineLine? source package includes a Microsoft Visual Studio 2012 solution file. You will need to download and build the libevt/libevtx/libesedb/libmsiecf libraries before building FineLine?. The latest source code for libevt/libevtx can be obtained from: http://code.google.com/p/libevtx/

The easiest method of building libevt/libevtx on Windows is to use the Microsoft Visual C++ project file included with the libraries. Instructions are available on the libevtx Google Code page. After building libevt.dll and libevtx.dll you can install them using regsvr32.exe, if you get an error saying "Entry point not found" then just copy the DLL files to the FineLine? build directory.

To build the FineLine? tools open the MSVC project file, go to the project properties and change the include and linker search directories to the location of your libevt/libevtx build. For example:

Header Files - C:\libevtx20130101\include;C:\libevt20130101\include;

Libraries - C:\libevtx20130101\msvcpp\Release;C:\libevt20130101\msvcpp\Release;

Now select the "Build Project" item from the build menu. When the build is complete you should have the following files in the various build directories:

fineline.exe 

fineline-ie.exe 

fineline-iepre10.exe 

FineLineGUIJava.jar 

libevt.dll 

libevtx.dll 

fl-event-filter-list-example.txt 

fl-url-filter-list-example.txt 

fl-windows-security-event-list.txt 

Copy all these files to a single directory then copy the .evt/.evtx files you want to analyse to the same directory for analysis.

## 2.2 Linux Build And Install

Download, build and install the libevt/libevtx tools according to the instructions at http://code.google.com/p/libevtx/.

### 2.2.1 Command Line Tools

Unzip the FineLine? source code package into any directory, open the Makefile in a text editor and change the INCLUDE line to point to the required libevt/libevtx include directories. For example:

INCLUDES=-I/home/fred/libevtx-20131211/common/ -I/home/fred/libevtx-20131211/libfdatetime/ -I/home/fred/libevtx-20131211/libcerror/ -I/home/fred/libevtx-20131211/libcstring/

Aternatively you can just copy all the libevt/libevtx header files to /usr/local/include. Now build the tools with:

make

make strip

### 2.2.2 FineLine GUI

As per Windows build, open the project in Netbeans or similar Java IDE and run the build function. In Netbeans, open the project and select "Clean and Build" from the run menu.


# 3. Screenshots


Image7: Text view panel showing event listing for the current project.


# 4. References

Microsoft. (2014). Monitoring and Auditing for End systems. Online at: http://technet.microsoft.com/en-us/library/cc750908.aspx

National Security Agency/Central Security Agency. (2013). Spotting the Adversary with Windows Event Log Monitoring. Online at http://www.nsa.gov/ia/_files/app/Spotting_the_Adversary_with_Windows_Event_Log_Monitoring.pdf


# 5. Issues and Future Development

1. Printing functions not fully implemented and tested.

2. GUI improvements: graph view panel, filter panel and text view panel.

3. Implement log2timeline file import function.

4. Email and web analysis tools.

5. Scripting and automation functions.


# 6. Data Schema

FineLine? Project File: consists of a project header followed by 0 or more eventlists obtained from computers relevant to the investigation.

<finelineproject>

<projectname>

</projectname>

<investigator>

</investigator>

<summary>

</summary>

<filename>

</filename>

<startdate>

</startdate>

<enddate>

</enddate>

<description>

</description>

</finelineproject>

<eventlists>

<listcount>

</listcount>

<eventlist1>

<computername>

</computername>

<eventcount>

</eventcount>

<dateacquired>

</dateacquired>

<event1>

</event1>

<event2>

</event2>

. . .

</eventlist1>

<eventlist2>

</eventlist2>

. . .

</eventlists>
