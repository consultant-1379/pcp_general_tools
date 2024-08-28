# ----------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor:
#
# PURPOSE: Program to update a new Configuration File with information from either an ini or a current configuration XML file
#
#
# Usage: 
#
#       \usr\bin\python", update_config_probe_base , "<current config file>", "<new config file>"
#       
#       INputs: 
#             <current config file> can be .xml or .ini
#             <new config file> must be XML file
#                               MUST Have exactly 1 <process> block
#                                WITH:
#                                     1 x PcapDistributor "
#                                     1 x Caprool  "
#                                     1 x Staple "
#                                     1 x GTPC Merge per Config File only allowed & Must be in the First Process Block [logical Search from top of File]
#                                     
#                                     Note : resultant file with have only one GTPC Merge per Config File in the First Process Block [logical Search from top of File]"
#     
#
#       Required : classConfigParser.py
#                  readIniConfig.py
#
#       METHOD: updateConfigFile
#                1. takes the ini or XML file as input for the Old [or current]] config file
#                    uses readIniFile.py to process the ini file. This returns an array of the following format that is used to build the new config file
#                            #iniData[0]=host Data
#                            #Host master:
#                            #Host IP:
#                            #Number Processes
#                            #Total Number Services
#                          # Number Services By Process
#                          #          Process ID:
#                          #          Service ID:
#                          #          Name:"
#                          #          Class:"
#                          #          Init-Method:
#                          #          Proc-enabled:
#                          #          Args:
# 
#                2. Takes XML file as input for the new config file
#                   Uses methods in classConfigParser.py to open it, check it is "well -Formed" and  get the same information as got from the ini file above#
#
#                3. Use the information in "Total Number Services" to determine if the correct number of services are in the original files
#                    Total number of Service Blocks less 1 [for GtpC Merge] must be divisable By 3"
#                    Only Multiple sets of following Allowed:"
#                                          1 x PcapDistributor "
#                                          1 x Caprool  "
#                                          1 x Staple "
#                    Only 1 GTPC Merge per Config File only allowed & Must be in the First Process Block [logical Search from top of File]"
#                   
#                4. Open the new config.xml and use methods from classConfigParser.py & information got for the old ini or xml files to
#                        a. Set the Host master and IP information
#                        b. Duplicate the number of process blocks so that  it is the same as in the "old " config or ini file 
#                        b. Duplicate the number of service blocks so that  it is the same as in the "old " config or ini file 
#                        c.  Set the process ID's in correct order so as to match  the "old " config or ini file 
#                        d.  Set the service ID's in correct order so as to match  the "old " config or ini file 
#                        e. Update the name, class, init-methed, proc-enabled and args TAGS in each service block to match same info as for the same service ID as was in the "old " config or ini file 
#
# NOTE 1: - See the comments at the top of the source scripts for more information
# NOTE 2: - Also See the "Testing_procedure_config_file_merge.txt" for test completed and how to run.
# Note 3: - Only information in the <PROCESS> blocks is processed. all other blocks {i.e. the bits at the begining of the config file} remains unchanged
# Note 4: - This handles config-probe-base.xml only. Simon has created a bash script to handle "config-probe-extension.xml"
# Note 5: - Simon has created a bash script to ask the user for input and create the ".ini" config file
# ----------------------------------------------------------------------
# Copyright (c) 1999 - 2015 AB Ericsson Oy  All rights reserved.
# ---------------------------------------------------------------------
# Version 1.00
#       Initial Release
# Version 1.01
#       Update to sys.exit(EXIT_FAIL_ERROR) if there is a problem/error

import os
import sys, traceback
import datetime
from xml.dom.minidom import parse
import xml.dom.minidom
from classConfigParser import *
from readIniConfig import *

EXIT_FAIL_ERROR=2
EXIT_FAIL_NORMAL=1
EXIT_PASS=0

def updateConfigFile(oldConfig, newConfig):

  file_found=False
  FILENAME=oldConfig.upper()
  if(FILENAME.rfind(".INI",len(FILENAME)-4) != -1 ):
        iniData = readIniFile(oldConfig)
        file_found=True
        old_HostInfo = iniData[0]
        old_NumberProcesses = iniData[1]
        old_NumberServices = iniData[2]
        old_NumberServicesByProcess = iniData[3]
        old_processInfo = iniData[4]
        
        print "Host master:", old_HostInfo[0]
        print "Host IP:", old_HostInfo[1]
        print "Number of Process Blocks:", old_NumberProcesses
        print "Number of Service Blocks:", old_NumberServices
        print "Number of Service Blocks:", old_NumberServicesByProcess
        for i in range(0, len(old_processInfo[0])):
          print "Process ID:", old_processInfo[0][i]
          for j in range(0, len(old_processInfo[1][i])):
            print '{0:11} {1:3}'.format("Service ID:", old_processInfo[1][i][j])
            print '{0:12} {1:14} {2:72}'.format("", "Name:", old_processInfo[2][i][j])
            print '{0:12} {1:14} {2:72}'.format("", "Class:", old_processInfo[3][i][j])
            print '{0:12} {1:14} {2:72}'.format("", "Init-Method:", old_processInfo[4][i][j])
            print '{0:12} {1:14} {2:72}'.format("", "Proc-enabled:", old_processInfo[5][i][j])
            print '{0:12} {1:14} {2:72}'.format("", "Args:", old_processInfo[6][i][j].strip())
                  
          print
  if(FILENAME.rfind(".XML",len(FILENAME)-4) != -1 ): 
        file_found=True
        #print "Config File : ", oldConfig
        oldXML = configParser()
        myXML = oldXML.getXml(oldConfig)
        
        old_HostInfo = oldXML.getHostInfo(myXML)
        print "Host master:", old_HostInfo[0]
        print "Host IP:", old_HostInfo[1]
        
        old_NumberProcesses = oldXML.getNumberProcesses(myXML)
        print "Number of Process Blocks:", old_NumberProcesses
        
        old_NumberServices = oldXML.getNumberServices(myXML)
        print "Number of Service Blocks:", old_NumberServices
        
        old_NumberServicesByProcess = oldXML.getNumServicesByProcess(myXML)
        print "Number of Service Blocks:", old_NumberServicesByProcess

        old_processInfo = oldXML.getProcessID(myXML)
        for i in range(0, len(old_processInfo[0])):
          print "Process ID:", old_processInfo[0][i]
          for j in range(0, len(old_processInfo[1][i])):
            print '{0:11} {1:3}'.format("Service ID:", old_processInfo[1][i][j])
            print '{0:12} {1:14} {2:72}'.format("", "Name:", old_processInfo[2][i][j])
            print '{0:12} {1:14} {2:72}'.format("", "Class:", old_processInfo[3][i][j])
            print '{0:12} {1:14} {2:72}'.format("", "Init-Method:", old_processInfo[4][i][j])
            print '{0:12} {1:14} {2:72}'.format("", "Proc-enabled:", old_processInfo[5][i][j])
            print '{0:12} {1:14} {2:72}'.format("", "Args:", old_processInfo[6][i][j].strip())
                  
          print
        
        #Check that we have the correct number of Captool, Staple and PCap distributor in the original
        #old_NumberServices -1 as should only be 1 GPTC Merge service regardles of the number of process Blocks
        problem_process=-1
        if((old_NumberServices -1)%3 !=0):
             for i in range(len(old_NumberServicesByProcess)):
                if(i==0):
                  numServ=old_NumberServicesByProcess[i] -1
                else:
                  numServ=old_NumberServicesByProcess[i]
                if((numServ % 3) != 0):
                  problem_process = i;
                  break;
                  
             print "ERROR: Config File format not correct"
             print "<current config file> = ", oldConfig
             if(problem_process != -1):
                print "Problem with process ID ",old_processInfo[0][problem_process] ,"Too Many Service blocks: "
             else:
                print "Too Many Service blocks: "
                
             print "Total number of Service Blocks less 1 [for GtpC Merge] must be divisable By 3"
             print "Only Multiple sets of following Allowed:"
             print "                      1 x PcapDistributor "
             print "                      1 x Caprool  "
             print "                      1 x Staple "
             print
             print "1 GTPC Merge per Config File only allowed & Must be in the First Process Block [logical Search from top of File]"
             print 
             for i in range(0, len(old_processInfo[0])):
                print "Process ID:", old_processInfo[0][i]
                for j in range(0, len(old_processInfo[1][i])):
                  print '{0:11} {1:3} {2:72}'.format("Service ID:", old_processInfo[1][i][j] ,old_processInfo[2][i][j])
             
             sys.exit(EXIT_FAIL_ERROR)
        
  if(file_found==False):
        print "<current config file> need to be .INI or .XML"
        print "<current config file> = ", oldConfig
        sys.exit(EXIT_FAIL_ERROR)

  newXML = configParser()
  myNewXML = newXML.getXml(newConfig)
    
  newXML.sethost(myNewXML,old_HostInfo,newConfig)
          
  new_NumberServicesByProcess = newXML.getNumServicesByProcess(myNewXML)
  print "Number of Service Blocks:", new_NumberServicesByProcess
  
  newXML.moveComments(myNewXML,newConfig)
  newXML.createProcessBlock(myNewXML,old_NumberProcesses,newConfig)
  newXML.createServiceBlock(myNewXML,old_NumberServicesByProcess,new_NumberServicesByProcess, newConfig)
  
  newXML.setProcessID(myNewXML,old_processInfo[0],newConfig)
  newXML.setServiceID(myNewXML,old_processInfo[1],newConfig)
  
  #need to run this before updateServiceBlock so we can get the format of the new process locks
  new_processInfo = newXML.getProcessID(myNewXML)
  newXML.updateServiceBlock(myNewXML,old_processInfo,new_processInfo, newConfig)
  
  # Now run this to display for the user
  finalXML = configParser()
  myfinalXML = finalXML.getXml(newConfig)
  
  new_HostInfo = finalXML.getHostInfo(myfinalXML)
  print "Host master:", new_HostInfo[0]
  print "Host IP:", new_HostInfo[1]
  
  new_processInfo = finalXML.getProcessID(myfinalXML)
  for i in range(0, len(new_processInfo[0])):
    print "Process ID:", new_processInfo[0][i]
    for j in range(0, len(new_processInfo[1][i])):
      print '{0:11} {1:3}'.format("Service ID:", new_processInfo[1][i][j])
      print '{0:12} {1:14} {2:72}'.format("", "Name:", new_processInfo[2][i][j])
      print '{0:12} {1:14} {2:72}'.format("", "Class:", new_processInfo[3][i][j])
      print '{0:12} {1:14} {2:72}'.format("", "Init-Method:", new_processInfo[4][i][j])
      print '{0:12} {1:14} {2:72}'.format("", "Proc-enabled:", new_processInfo[5][i][j])
      print '{0:12} {1:14} {2:72}'.format("", "Args:", new_processInfo[6][i][j].strip())
            
    print
  
    






if __name__=="__main__":
  if len(sys.argv) < 2:
    print
    print "\n\nUsage:- python", sys.argv[0] , "<current config file>", "<new config file>"
    print "Example:- python update_config_probe_base  \"/var/opt/ericsson/probe-controller/probe-controller/etc/app-config/config-probe-base.xml\" \"/mypath/config-probe-base.xml\" "
    print "Example:- python update_config_probe_base  \"/mypath/config.ini\" \"/mypath/config-probe-base.xml\" "
    print
    sys.exit(EXIT_FAIL_ERROR)
    
    
  else:
    stop_mode = bool();
    oldConfig=sys.argv[1]
    newconfig=sys.argv[2]
 
    updateConfigFile(oldConfig, newconfig)
    sys.exit(EXIT_PASS)