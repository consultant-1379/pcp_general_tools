# ----------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor:
#
# PURPOSE: Configuration File Reader for .in files
#
# Usage: 
#
#       \usr\bin\python", readIninConfig , "<current config file.ini>
#       
#       INputs: 
#             <current config file> must be .ini
#
#       FILE FORMAT:
#                 Must be "TAG:Value" pair 
#                 where 
#                         "TAG" = the XML TAG name  or Atribute 
#                 and 
#                         "VAlue" is the value of that attribute
#
#
#                 Execption to this is for ARGS
#                 ARGS : Value1
#                        Value2
#                        Value3
#
#     
#       METHOD: readIniFile
#                1. takes the ini file as input, opens it and read all input into the "lines" array
#                2. Reads through the file to fins the HOST master and Host IP Settings
#                3. Reads through file to count the number of PROCESS ID and SERVICE ID tags
#                   and so determine the number of processes and services in the file. Save these to arrays for later
#                   Also Determines the process ID's and save these to arrays also
#                4. Read through the file to deterring the following information by process:
#                          #Number Services By Process
#                          #          Process ID:
#                          #          Service ID:
#                          #          Name:"
#                          #          Class:"
#                          #          Init-Method:
#                          #          Proc-enabled:
#                          #          Args:
#                   Use the following loops
#                          The i loop to read thought the file, line by line and find "PROCESS ID" tag
#                          The j loop to read through each process and find the "SERVICE ID" tag
#                          The k loop to read through each service and get the required information and put them into arrays
#                                    serviceID=[]
#                                    serviceName=[]
#                                    serviceClass=[]
#                                    serviceMethod=[]
#                                    serviceEnabled=[]
#                                    serviceArgs=[]
#                          The l Loop to process the "ARGS" tag.
#                 
#                    At the end of each PROCESS LOOP, Process the above arrays into these arrays
#                              procesLoop_serviceID.append(serviceID)
#                              procesLoop_serviceName.append(serviceName)
#                              procesLoop_serviceClass.append(serviceClass)
#                              procesLoop_serviceMethod.append(serviceMethod)
#                              procesLoop_serviceEnabled.append(serviceEnabled)
#                              procesLoop_serviceArgs.append(serviceArgs)
#                          
#                    At the end of the searching process all information into the thisIniData array and return it.
#          
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
EXIT_FAIL_ERROR=2
EXIT_FAIL_NORMAL=1
EXIT_PASS=0




def readIniFile(iniFile):
  print "ini File : ", iniFile
  f =  open(iniFile)
  lines = f.readlines()
  
  #array for all the data
  #iniData[0]=host Data
  #      print "Host master:" , old_HostInfo[0]
  #      print "Host IP:"     , old_HostInfo[1]
  #iniData[1]=old_NumberProcesses
  #iniData[2]=old_NumberServices
  #iniData[3]=old_NumberServicesByProcess
  #iniData[4]=old_processInfo
  #          Process ID:",    old_processInfo[0][i]
  #          Servcie ID:",    old_processInfo[1][i][j]
  #          Name:",          old_processInfo[2][i][j]
  #          Class:",         old_processInfo[3][i][j]
  #          Init-Method:",   old_processInfo[4][i][j]
  #          Proc-enabled:",  old_processInfo[5][i][j]
  #          Args:",          old_processInfo[6][i][j]
  
  thisIniData=[]
  
  #host data
  hostData=[]
  for i in range(len(lines)):
      if(lines[i].upper().find("HOST MASTER") != -1):
          data = extractData(lines[i])
          hostData.append(data)
      if(lines[i].upper().find("HOST IP") != -1):
          data = extractData(lines[i])
          hostData.append(data)
  #print "hostData = ", hostData
  #old_NumberProcesses
  #old_NumberServices
  numProcesses=[]
  numServices=[]
  process_id=[]
  countProcess=0
  countService=0
  
  for i in range(len(lines)):      
      if(lines[i].upper().find("PROCESS ID") != -1):
          data = extractData(lines[i])
          process_id.append(data)
          countProcess +=1
      if(lines[i].upper().find("SERVICE ID") != -1):
          countService +=1
          
  numProcesses.append(countProcess)
  numServices.append(countService)
  #print "numProcesses = ", numProcesses, "process_id = ", process_id
  #print "numServices = ", numServices
  
  #old_NumberServicesByProcess
  numServicesByProcess=[]
  serviceInfo=[]
  procesLoop_serviceID=[]
  procesLoop_serviceName=[]
  procesLoop_serviceClass=[]
  procesLoop_serviceMethod=[]
  procesLoop_serviceEnabled=[]
  procesLoop_serviceArgs=[]
  
  for i in range(len(lines)):     
      #print"FILE LOOP: i = ",i, "lines [i] = ", lines[i]

      if(lines[i].upper().find("PROCESS ID") != -1):
          END_OF_PROCESS=False
          j=i+1 # use j index for the service LOOP 
          countServiceByProcess=0
          
          serviceID=[]
          serviceName=[]
          serviceClass=[]
          serviceMethod=[]
          serviceEnabled=[]
          serviceArgs=[]
          
          while(END_OF_PROCESS == False):
              #print"PROCESS LOOP: j = ",j, "lines [j] = ", lines[j]
              if(lines[j].upper().find("SERVICE ID") != -1):
                  data = extractData(lines[j])
                  #print "SERVICE ID : LINE = ", lines[j]
                  #print "SERVICE ID : DATA = ", data
                  serviceID.append(data)
                  countServiceByProcess +=1
                  
                  #process data inside the Service Loop
                  END_OF_SERVICE=False
                  k=j+1 # use k index for the inner LOOP 
                  
                  while(END_OF_SERVICE == False):
                      #print"SERVICE LOOP: k = ",k, "lines [k] = ", lines[k]
                      if(lines[k].upper().find("NAME") != -1):
                          data = extractData(lines[k])
                          serviceName.append(data)
                      if(lines[k].upper().find("CLASS") != -1):
                          data = extractData(lines[k])
                          serviceClass.append(data)
                      if(lines[k].upper().find("INIT-METHOD") != -1):
                          data = extractData(lines[k])
                          serviceMethod.append(data)
                      if(lines[k].upper().find("PROC-ENABLED") != -1):
                          data = extractData(lines[k])
                          serviceEnabled.append(data)
                      if(lines[k].upper().find("ARGS") != -1):
                          data = extractData(lines[k])
                          l=k+1
                          END_OF_ARGS=False
                          while (END_OF_ARGS == False):
                              #print"ARGS LOOP: l = ",l, "lines [l] = ", lines[l]
                              if(lines[l].upper().find("=") != -1):
                                data2 =lines[l]
                                data = data + " \n\t\t\t    " + data2.strip()
                              if(lines[l].upper().find("SERVICE ID") != -1):
                                  END_OF_ARGS=True
                              if(lines[l].upper().find("PROCESS ID") != -1):
                                  END_OF_ARGS=True
                              l +=1
                              if (l>=len(lines)): #end of file , no  more SERVICE ID's, so break
                                  END_OF_ARGS=True
                                  break;
                          serviceArgs.append(data)
                          # k will move on one line below. So k loop can find "SERVICE ID" but not find ARGS                          
                      if(lines[k].upper().find("SERVICE ID") != -1):
                          END_OF_SERVICE=True
                      if(lines[k].upper().find("PROCESS ID") != -1):
                          END_OF_SERVICE=True
                      k += 1
                      if (k>=len(lines)): #end of file , no  more SERVICE ID's, so break
                          END_OF_SERVICE=True
                          break;
                  #end while
                  #print "END OF SERVICE"
                  #j will move on one line below & track back one line to pick up Next service ID loop
                      
              if(lines[j].upper().find("PROCESS ID") != -1):
                END_OF_PROCESS=True
              j += 1
              if (j>=len(lines)): #end of file , no  more PROCESS ID, so break
                  END_OF_PROCESS=True
                  break;
            
            
          #end While
          #print "END OF PROCESS"
          numServicesByProcess.append(countServiceByProcess)
          
          procesLoop_serviceID.append(serviceID)
          procesLoop_serviceName.append(serviceName)
          procesLoop_serviceClass.append(serviceClass)
          procesLoop_serviceMethod.append(serviceMethod)
          procesLoop_serviceEnabled.append(serviceEnabled)
          procesLoop_serviceArgs.append(serviceArgs)

          # For LOOP will confinue at nest line after last PROCESS ID. A bit of back tracking through the file.
  #end For Loop
  #print "numServicesByProcess = ", numServicesByProcess
 
  #build the process info array
  serviceInfo.append(process_id)
  serviceInfo.append(procesLoop_serviceID)
  serviceInfo.append(procesLoop_serviceName)
  serviceInfo.append(procesLoop_serviceClass)
  serviceInfo.append(procesLoop_serviceMethod)
  serviceInfo.append(procesLoop_serviceEnabled)
  serviceInfo.append(procesLoop_serviceArgs) 
  
  #prepare array for return data
  thisIniData.append(hostData)
  thisIniData.append(numProcesses[0])
  thisIniData.append(numServices[0])
  thisIniData.append(numServicesByProcess)
  thisIniData.append(serviceInfo)
  
  #print "Ini Data 0", thisIniData[0]
  #print "Ini Data 1", thisIniData[1]
  #print "Ini Data 2", thisIniData[2]
  #print "Ini Data 3", thisIniData[3]
  #print "Ini Data 4 0", thisIniData[4][0]
  #print "Ini Data 4 1", thisIniData[4][1]
  #print "Ini Data 4 2", thisIniData[4][2]
  #print "Ini Data 4 3", thisIniData[4][3]
  #print "Ini Data 4 4", thisIniData[4][4]
  #print "Ini Data 4 4", thisIniData[4][5]
  #print "Ini Data 4 4", thisIniData[4][6]
    
  return thisIniData
    
   
   
   
def extractData(dataLine):
  
  # dataline should be of the forn "identifer : data "
  # estract the bit after the : and return it as data
  if(dataLine.find(":") != -1):
      tmp=dataLine.split(":",1)
      if(len(tmp) == 2):
        return tmp[1].strip()
      else:
        print "ERROR in INI FILE FORMAT. UNABLE TO SPILT BASED ON \":\""
        print dataLine
        print 
        sys.exit(EXIT_FAIL_ERROR)
  else:
    print "ERROR in INI FILE FORMAT. MISSING \":\""
    print dataLine
    print 
    sys.exit(EXIT_FAIL_ERROR)




if __name__=="__main__":
  if len(sys.argv) < 1:
    print "\n\nUsage:- python", sys.argv[0] , "<current config file.ini>"
    print "Example:- python readIniConfig \"/var/opt/ericsson/probe-controller/probe-controller/etc/app-config/config-probe-base.ini\" "
    sys.exit(EXIT_FAIL_ERROR)
    
    
  else:
    iniConfig=sys.argv[1]

 
    
    iniData = readIniFile(iniConfig)
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
        print '{0:11} {1:3}'.format("Servcie ID:", old_processInfo[1][i][j])
        print '{0:12} {1:14} {2:72}'.format("", "Name:", old_processInfo[2][i][j])
        print '{0:12} {1:14} {2:72}'.format("", "Class:", old_processInfo[3][i][j])
        print '{0:12} {1:14} {2:72}'.format("", "Init-Method:", old_processInfo[4][i][j])
        print '{0:12} {1:14} {2:72}'.format("", "Proc-enabled:", old_processInfo[5][i][j])
        print '{0:12} {1:14} {2:72}'.format("", "Args:", old_processInfo[6][i][j].strip())
              
      print
    sys.exit(EXIT_PASS)    
    