# ----------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor:
#
# PURPOSE: class with methods  for reading and setting parameters in the <process> block of a configuration XML file
#
# Usage: To be included in python script
#
#       from classConfigParser import *
#
# INPUTS:
#       
#        <configFile> must be XML file
#
# USED BY:
#
#           update_config_probe_base.py
#
# METHODS:
#  
#                  __init__(self):  get a reference to the class. 
#                  getXml(self,filename ): Opens the XML, Checks that it is well formed  returns DOM to top/root node
#                  getNumberProcesses(self, xml): returns the number of <process> blocks
#                  getNumberServices(self, xml): returns the TOTAL number of <service> blocks, regardless of what <process> that are in
#                  getProcessID(self, xml): 0 Retrieves the "procid" argument from the <process> blocks; Returns array of process id's
#                                           1 Retrieves the "service-id" argument from the <service> blocks for each <process> block; Returns array of service id's per process [process id][service id]
#                                           2 Retrieves the value of the "names" tag from the <service> blocks for each <process> block; Returns array of service names per process [process id][service names]
#                                           3 Retrieves the value of the "class" tag from the <service> blocks for each <process> block; Returns array of service class per process [process id][service class]
#                                           4 Retrieves the value of the "init-method" tag from the <service> blocks for each <process> block; Returns array of service init-methods per process [process id][service init-methods]
#                                           5 Retrieves the value of the "proc-enabled" tag from the <service> blocks for each <process> block; Returns array of service proc-enabled per process [process id][service proc-enabled]
#                                           6 Retrieves the value of the "args" tag from the <service> blocks for each <process> block; Returns array of service args per process [process id][service args]
#                                      
#                    
#                                            RETURN:processIDs, self.serviceIDByProcess, self.serviceNames, self.serviceClass, self.serviceInitMethod, self.serviceProc_enabled, self.servicArgs
#              
#                  getServiceID(self, proc): Retrieves the "service-id" argument from the <service> blocks for each <process> block; Returns array of service id's per process [process id][service id]
#                  serviceByProcess(self,xml): gets #1 as determined by method getProcessID
#                  getNumServicesByProcess(self,xml): returns the number of <service> blocks per <process> block
#                  getServiceNames(self, proc): gets #2 as determined by method getProcessID
#                  getServiceElementInfo(self, proc, tagName): returns the value from ad given element tag <tagNAME>value</tagNAME>
#                  getHostInfo(self, xml): returns ip="123.123.123.123" master="false" from <host>
#                  saveXML_File(self,XMLfile): saves the XML files using codecs and writxml
#                  setProcessID(self, xml,procID,fileName): sets the "procid" argument from the <process> blocks; procID is array of process ID's to set
#                  setServiceID(self, xml,srvID,fileName): sets the "service-id" argument from the <service> blocks for each <process> block; srvID is an arrays of service id per process
#                  sethost(self, xml, newHostInfo,fileName): sets ip="123.123.123.123" master="false" in <host>; srvID is array with master value and IP value
#                  createProcessBlock(self, xml, NumProcessBlocks,fileName): Duplicates the <process> block in the file <filename> to match the number as indicated by NumProcessBlocks
#                  matchServiceName_childNodes(self, ServiceNameTag, RequiredName): Used for getting  the value of the <name> tag and determine if it matched RequiredName
#                  matchServiceName(self, ServiceNameTag, RequiredName): loop version of matchServiceName_childNodes; for a slightly different angle
#                  createServiceBlock(self, xml, required_NumServiceBlocks,current_NumServiceBlocks, fileName): Duplicates the <service> blocks in the file <filename> to match the number as indicated by required_NumServiceBlocks. 
#                                                                                                                required_NumServiceBlocks is a multi dimensional array indicating the number of services per <process> block
#                  updateServiceBlock(self, xml, oldProcInfo,newProcInfo, fileName): updates the service blocks on a per process levels with 
#                                                                                                                                        Name:"
#                                                                                                                                        Class:"
#                                                                                                                                        Init-Method:
#                                                                                                                                        Proc-enabled:
#                                                                                                                                        Args:
#                                                                                     Method does not use xml.minidom to set the values as there is no method in the minidom to set the value of and ELEMENT TAG [like <name>]
#                                                                                     So it opens the file, read it into "lines" array and loops thought the file to set the appropriate values.
#                  moveComments(self, xml, fileName): moves any comments in the <service> block to the <host> block
#              
#
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
from xml.dom.minidom import parse
import xml.dom.minidom
import codecs

DEBUG=False
TESTING=True
EXIT_FAIL_ERROR=2
EXIT_FAIL_NORMAL=1
EXIT_PASS=0

class configParser:

  configFile=""
  try:
      def __init__(self):
        print ""
        #xml = self.getXml(configFile) 

      def getXml(self,filename ):
        
        
        self.serviceIDByProcess=[]
        self.serviceNames=[]
        self.serviceClass=[]
        self.serviceInitMethod=[]
        self.serviceProc_enabled=[]
        self.servicArgs=[]
        self.NumServiceByProcess=[]
        
        print "Config File : ", filename
        f = codecs.open (filename, "r", "utf-8") 
        self.doc = xml.dom.minidom.parseString (codecs.encode (f.read(), "utf-8"))
        #self.doc = xml.dom.minidom.parse(f)
        node = self.doc.documentElement        
        if node.nodeType == xml.dom.Node.ELEMENT_NODE:
            print 'Element name: %s' % node.nodeName
            for (name, value) in node.attributes.items():
                print '    Attr -- Name: %s  Value: %s' % (name, value)                  
        return node
        
      def getNumberProcesses(self, xml):
           processe = None
           processes = xml.getElementsByTagName("process")   
           return processes.length
      
      def getNumberServices(self, xml):
           services = xml.getElementsByTagName("service")   
           return services.length
                
      def getProcessID(self, xml):
           processIDs=[]
           servID=[]
           servNames=[]
           servClass=[]
           servInitMethod=[]
           servProc_enabled=[]
           servArgs=[]
        
           self.serviceIDByProcess=[]
           self.serviceNames=[]
           self.serviceClass=[]
           self.serviceInitMethod=[]
           self.serviceProc_enabled=[]
           self.servicArgs=[]
           self.NumServiceByProcess=[]
        
           processes = xml.getElementsByTagName("process")  
           for process in  processes: 
             for (name,  value) in process.attributes.items():
                #print '    Attr -- Name: %s  Value: %s' % (name, value)
                processIDs.append(value)
                servID = self.getServiceID(process)
                self.serviceIDByProcess.append(servID)
                #print "servID = ", servID
                self.NumServiceByProcess.append(len(servID))
                
                servNames = self.getServiceElementInfo(process,"name")
                self.serviceNames.append(servNames)
                
                servClass = self.getServiceElementInfo(process,"class")
                self.serviceClass.append(servClass)
                
                servInitMethod = self.getServiceElementInfo(process,"init-method")
                self.serviceInitMethod.append(servInitMethod)
                
                servProc_enabled = self.getServiceElementInfo(process,"proc-enabled")
                self.serviceProc_enabled.append(servProc_enabled)
                
                servicArgs = self.getServiceElementInfo(process,"args")
                self.servicArgs.append(servicArgs)
                
           return processIDs, self.serviceIDByProcess, self.serviceNames, self.serviceClass, self.serviceInitMethod, self.serviceProc_enabled, self.servicArgs
      
      def getServiceID(self, proc):
           serviceIDS=[]
           services = proc.getElementsByTagName("service")  
           for service in  services: 
             for (name,  value) in service.attributes.items():
                #print '    Attr -- Name: %s  Value: %s' % (name, value)
                serviceIDS.append(value)
           return serviceIDS  
      
      def serviceByProcess(self,xml):
           self.getProcessID(xml)
           return self.serviceIDByProcess
           
      def getNumServicesByProcess(self,xml):
           self.getProcessID(xml)
           return self.NumServiceByProcess
      
      def getServiceNames(self, proc):
           servNames=[]
           services = proc.getElementsByTagName("service")  
           for service in  services:
            srvObj = service.getElementsByTagName("name")[0]
            servNames.append(srvObj)

           for servName in servNames:
            nodes = servName.childNodes
            for node in nodes:
              if node.nodeType == node.TEXT_NODE:
                print node.data
                
           
      def getServiceElementInfo(self, proc, tagName):
           serviceInfo=[]
           servInfos=[]
           services = proc.getElementsByTagName("service")  
           for service in  services:
            srvObj = service.getElementsByTagName(tagName)[0]
            servInfos.append(srvObj)

           for servinfo in servInfos:
            nodes = servinfo.childNodes
            for node in nodes:
              if node.nodeType == node.TEXT_NODE:
                #print node.data
                serviceInfo.append(node.data)
           return serviceInfo
           
      def getHostInfo(self, xml):
          hostMaster=""
          hostIP=""
          hosts = xml.getElementsByTagName("host") 
          for host in  hosts: 
           for (name,  value) in host.attributes.items():
              #print '    Attr -- Name: %s  Value: %s' % (name, value)
              if (name.find("master") != -1):
                hostMaster=value
              if (name.find("ip") != -1):
                hostIP=value
          return hostMaster, hostIP 
      
      def saveXML_File(self,XMLfile):
        #print "Saving XML"
        f1=codecs.open( XMLfile, "wb", "utf-8" )
        self.doc.writexml( f1, '', '','', "utf-8")
        f1.close()
      
      def setProcessID(self, xml,procID,fileName):
         processes = xml.getElementsByTagName("process")  
         #print procID
         procCtr=0
         for process in  processes: 
           index=0
           for index in range (len(processes.item(0).attributes.items())):
              #print '    Attr -- Name: %s  Value: %s' % (process.attributes.item(index).name, process.attributes.item(index).value)
              oldValue=process.attributes.item(index).value
              if (process.attributes.item(index).name.find("procid") != -1):
                process.attributes.item(index).value=procID[procCtr]
              #print 'Attr -- Name: %s  Old Value: %s New Value: %s' % (process.attributes.item(index).name, oldValue, process.attributes.item(index).value)
           procCtr +=1   

         self.saveXML_File(fileName)

      def setServiceID(self, xml,srvID,fileName):
         processes = xml.getElementsByTagName("process") 
         #print srvID
         procCtr=0
         proc_id=self.getProcessID(xml)
         
         for process in  processes: 
           services = process.getElementsByTagName("service")             
           srvCtr=0
           #print "Process ID: ",proc_id[0][procCtr]
           for service in services:
             index=0
             for index in range (len(service.attributes.items())):
                #print "index = ",index, "len(service.attributes.items()) = ",len(service.attributes.items())
                #print '    Attr -- Name: %s  Value: %s' % (service.attributes.item(index).name, service.attributes.item(index).value)
                oldValue=service.attributes.item(index).value
                if (service.attributes.item(index).name.find("service-id") != -1):
                  service.attributes.item(index).value=srvID[procCtr][srvCtr]
                #print 'Attr -- Name: %s  Old Value: %s New Value: %s' % (service.attributes.item(index).name, oldValue, service.attributes.item(index).value)
             srvCtr +=1
           procCtr +=1   

         self.saveXML_File(fileName)
      def sethost(self, xml, newHostInfo,fileName):
          hosts = xml.getElementsByTagName("host") 
          for host in  hosts: 
            index=0
            for index in range (len(host.attributes.items())):
              #print '    Attr -- Name: %s  Value: %s' % (host.attributes.item(index).name, host.attributes.item(index).value)
              if (host.attributes.item(index).name.find("master") != -1):
                host.attributes.item(index).value=newHostInfo[0]
              if (host.attributes.item(index).name.find("ip") != -1):
                host.attributes.item(index).value=newHostInfo[1]
                
          self.saveXML_File(fileName)        

      def createProcessBlock(self, xml, NumProcessBlocks,fileName):
          #Check how many process blocks are currently
          current_NumProcessBlocks = self.getNumberProcesses(xml)
          print "Current Number of process blocks = ", current_NumProcessBlocks
          print "Required Number of process blocks = ", NumProcessBlocks
          
          
          if (current_NumProcessBlocks <= NumProcessBlocks):
            #1 to NumProcessBlocks as we will already have one process block in the new file.
            for i in range(1, NumProcessBlocks):
              hosts = xml.getElementsByTagName("host")
              processesElements = hosts.item(0).childNodes
              #Always clone th first process element
              #Find the first Process element
              for z in range(processesElements.length):
                  if(processesElements.item(z).nodeType == processesElements.item(z).ELEMENT_NODE):
                      #If this is a process node, clone it & exit loop
                      if(processesElements.item(z).tagName =="process"):
                          #processesElements.item(0) is a text node.. use it to add a CR after appending the element
                          cloned_textNode = processesElements.item(0).cloneNode(True)              
                          cloned_process_element = processesElements.item(z).cloneNode(True)
                          hosts.item(0).appendChild(cloned_process_element)
                          hosts.item(0).appendChild(cloned_textNode)
                          self.saveXML_File(fileName)
              
                          print "Checking for GTPC Merge in process # ", i
                          if(i !=0): # we don't neeed gtpc Merge services in the other process blocks. Ony block 0
                              myprocesses = xml.getElementsByTagName("process")
                              myServiceElements = myprocesses.item(i).childNodes
                              index=self.matchServiceName(myServiceElements,"GTPCMergerService")
                              if(index != -1):
                                  print "Removing GTP Merge"
                                  gtpMerge_element=myServiceElements.item(index)
                                  myprocesses.item(i).removeChild(gtpMerge_element)
                                  txt_element=myServiceElements.item(index)
                                  myprocesses.item(i).removeChild(txt_element)
                                  self.saveXML_File(fileName) 
                          break;
          else:
            #Too many process blocks.. not handled at the moment.
            print "Too many process blocks.. not handled at the moment"
            print "Current Number of process blocks = ", current_NumProcessBlocks
            print "Required Number of process blocks = ", NumProcessBlocks
            print "EDIT ", fileName ," to have just one process block and try again"
            sys.exit(EXIT_FAIL_ERROR)  
      
      def matchServiceName_childNodes(self, ServiceNameTag, RequiredName):
            #pass in serviceElements.item(i) as ServiceNameTag
            # flatted the tag to astring
            #u'<name>PcapDistributorService</name>'
            #returns the index of the first match of the required name
            
            if(ServiceNameTag.childNodes.item(1).nodeType != ServiceNameTag.childNodes.item(1).TEXT_NODE):
                strTagName=ServiceNameTag.childNodes.item(1).toxml()            
                #print strTagName
                if( strTagName.find(RequiredName) != -1):
                    return 0
                else:
                  return -1    
 
            
      def matchServiceName(self, ServiceNameTag, RequiredName):
            #pass in serviceElements as ServiceNameTag
            # flatted the tag to astring
            #u'<name>PcapDistributorService</name>'
            #returns the index of the first match of the required name
            for i in range(len(ServiceNameTag)):
                #print i
                if(ServiceNameTag.item(i).nodeType != ServiceNameTag.item(i).TEXT_NODE):
                    strTagName=ServiceNameTag.item(i).childNodes.item(1).toxml()            
                    #print strTagName
                    if( strTagName.find(RequiredName) != -1):
                        return i
            return -1    
                  
            
      def createServiceBlock(self, xml, required_NumServiceBlocks,current_NumServiceBlocks, fileName):
          #Check how many service blocks are currently
          # current_NumServiceBlocks = self.getNumServicesByProcess(xml)
          current_NumServiceBlocks = current_NumServiceBlocks
          
          #print "Current Number of Service blocks = ", current_NumServiceBlocks[0]
          print "Current Number of Service blocks = ", current_NumServiceBlocks
          print "Required Number of Service blocks = ", required_NumServiceBlocks
          
          current_NumProcessBlocks = self.getNumberProcesses(xml)
          print "Current Number of Process blocks [including the RECENTLY ADDED BLOCKS] = ", current_NumProcessBlocks
          
          for i in range(int(current_NumProcessBlocks)):
            #print "i, current_NumProcessBlocks",i, current_NumProcessBlocks
            if(i== 0):
              max=4
            else:
              max=3  # no GTPCmerge in porces block != 0
              
            if (int(current_NumServiceBlocks[i]) == max ):

                 
              while(int(current_NumServiceBlocks[i]) < required_NumServiceBlocks[i] ):
                  processes = xml.getElementsByTagName("process")
                  serviceElements = processes.item(i).childNodes
                  
                  index=self.matchServiceName(serviceElements,"PcapDistributorService")
                  if(index != -1):
                      print "Add pcap distributor"
                      # add pcap distributor
                      cloned_textNode = serviceElements.item(0).cloneNode(True)
                      cloned_service_element = serviceElements.item(index).cloneNode(True)
                      referenceElement=serviceElements.item(index+1)
                      processes.item(i).insertBefore(cloned_service_element,referenceElement)
                      #reference element will move
                      referenceElement=serviceElements.item(index+1)
                      processes.item(i).insertBefore(cloned_textNode,referenceElement)

                  index=self.matchServiceName(serviceElements,"StapleService")
                  if(index != -1):
                      print "Add StapleService"
                      # add pcap distributor
                      cloned_textNode = serviceElements.item(0).cloneNode(True)
                      cloned_service_element = serviceElements.item(index).cloneNode(True)
                      referenceElement=serviceElements.item(index+1)
                      processes.item(i).insertBefore(cloned_service_element,referenceElement)
                      #reference element will move
                      referenceElement=serviceElements.item(index+1)
                      processes.item(i).insertBefore(cloned_textNode,referenceElement)

                  index=self.matchServiceName(serviceElements,"CaptoolService")
                  if(index != -1):
                      print "Add CaptoolService"
                      # add pcap distributor
                      cloned_textNode = serviceElements.item(0).cloneNode(True)
                      cloned_service_element = serviceElements.item(index).cloneNode(True)
                      referenceElement=serviceElements.item(index+1)
                      processes.item(i).insertBefore(cloned_service_element,referenceElement)
                      #reference element will move
                      referenceElement=serviceElements.item(index+1)
                      processes.item(i).insertBefore(cloned_textNode,referenceElement)
              
                  self.saveXML_File(fileName) 
                  current_NumServiceBlocks = self.getNumServicesByProcess(xml)   
                 
            else:
              #Too many Service blocks.. not handled at the moment.
              print "Too many service blocks in the process block.. not handled at the moment"
              print "Current Number of Service blocks = ", current_NumServiceBlocks[0]
              print "Required Number of Service blocks = 4"
              print "EDIT ", fileName ," to have just one process block and the following Service Blocks  and try again"
              print "1 Service Block for PcapDistributorService as first element"
              print "1 Service Block for StapleService as second element"
              print "1 Service Block for CaptoolService as third element"
              print "1 Service Block for GTPCMergerService as fourth element"   
              sys.exit(EXIT_FAIL_ERROR)  
                    
          print "Current Number of Service blocks [After Update] = ", current_NumServiceBlocks
          print "Required Number of Service blocks = ", required_NumServiceBlocks
          return    


      def updateServiceBlock(self, xml, oldProcInfo,newProcInfo, fileName):
          # Method does not use xml.minidom to set the values as there is no method in the minidom to set the value of and ELEMENT TAG [like <name>]
          # So it opens the file, read it into "lines" array and loops throught the file to set the appropriate values.
          # Use the following loops
          #                The k loop to read thought the file, line by line and find "PROCESS ID" tag
          #                The i loop to read through each process and find the "SERVICE ID" tag
          #                The j loop to read through each service and get the required information and put them into arrays

          
          #"Servcie ID  : newProcInfo[1][process block][service block]
          #"Name        : newProcInfo[2]
          #"Class       : newProcInfo[3]
          #"Init-Method : newProcInfo[4]
          #"Proc-enabled: newProcInfo[5]
          #"Args        : newProcInfo[6]
          
          #Check how many service blocks are currently
          current_NumServiceBlocks = self.getNumServicesByProcess(xml)          
          print "Current Number of Service blocks = ", current_NumServiceBlocks
          
          current_NumProcessBlocks = self.getNumberProcesses(xml)
          print "Current Number of Process blocks [including the RECENTLY ADDED BLOCKS] = ", current_NumProcessBlocks
          
          f1=open(fileName,"r+")
          lines=f1.readlines()
          f1.close()
          for k in range(len(lines)):
          
            for i in range(int(current_NumProcessBlocks)):
                if(lines[k].find("<process") != -1):  #FIND THE PROCESS BLOCK
                  if(lines[k].find(newProcInfo[0][i]) != -1): #if  it has the correct id
                      
                      process_start=k
                      while(lines[k].find("</process>") == -1):  #following only applies in this Process block, find start and end lines for this process block
                          process_end=k
                          k +=1 # move on a line
                              
                      j=0
                      #print "PROCESS: Start = ", process_start, " : END =" ,process_end
                      # now search for services between process_start and process_end
                      for line_no in range(process_start,process_end):
                          #print "PROCESS: Line NO = ", line_no, " : " ,lines[line_no]
                          if(lines[line_no].find("<service") != -1):  #FIND THE next Service Block
                            if(lines[line_no].find(newProcInfo[1][i][j]) != -1): #if  it has the correct id
                                srv_start=line_no
                                while(lines[line_no].find("</service>") == -1):  #following only applies in this service block
                                    #print "SERVICE: Line NO = ", line_no, " : " ,lines[line_no]
                                    srv_end=line_no
                                    line_no += 1
                                    
                                #loop through service block   
                                #print "SERVICE: Start = ", srv_start, " : END =" ,srv_end 
                                for line_no2 in range(srv_start,srv_end):
                                  if(lines[line_no2].find("<name>") != -1):
                                          #search from end of the TAGNAME so than the replace will replace only 1 occurance of "init" in <init-method>line
                                          idx= lines[line_no2].find("<name>")
                                          idx = idx + len("<name>")
                                          a =lines[line_no2][idx:].replace(newProcInfo[2][i][j].strip(),oldProcInfo[2][i][j].strip(),1);
                                          lines[line_no2] = lines[line_no2][:idx] + a
                                          #print "line : ",line_no2, " : ",lines[line_no2]

                                  if(lines[line_no2].find("<class>") != -1):
                                          idx= lines[line_no2].find("<class>")
                                          idx = idx + len("<class>") -2
                                          a =lines[line_no2][idx:].replace(newProcInfo[3][i][j].strip(),oldProcInfo[3][i][j].strip(),1);
                                          lines[line_no2] = lines[line_no2][:idx] + a
                                          #print "line : ",line_no2, " : ",lines[line_no2]


                                  if(lines[line_no2].find("<init-method>") != -1):
                                          idx= lines[line_no2].find("<init-method>")
                                          idx = idx + len("<init-method>")
                                          a =lines[line_no2][idx:].replace(newProcInfo[4][i][j].strip(),oldProcInfo[4][i][j].strip(),1);
                                          lines[line_no2] = lines[line_no2][:idx] + a
                                          #print "line : ",line_no2, " : ",lines[line_no2]


                                  if(lines[line_no2].find("<proc-enabled>") != -1):
                                          idx= lines[line_no2].find("<proc-enabled>")
                                          idx = idx + len("<proc-enabled>")
                                          a =lines[line_no2][idx:].replace(newProcInfo[5][i][j].strip(),oldProcInfo[5][i][j].strip(),1);
                                          lines[line_no2] = lines[line_no2][:idx] + a
                                          #print "line : ",line_no2, " : ",lines[line_no2]


                                  if(lines[line_no2].find("<args>") != -1):
                                          args_start=line_no2
                                          while(lines[line_no2].find("</args>") == -1):  #following only applies in this args block, its multi line
                                              #print "ARGS: Line NO = ", line_no2, " : " ,lines[line_no2]
                                              args_end=line_no2
                                              line_no2 += 1
                                          newArgs = newProcInfo[6][i][j].split()
                                          oldArgs = oldProcInfo[6][i][j].split()

                                          #print "newArgs ", newArgs
                                          #print "oldArgs ", oldArgs
                                          #print newArgs[0]
                                          
                                          el_num=0
                                          for line_no3 in range(args_start+1, args_end+1):     
                                              #print newArgs[el_num]                                         
                                              lines[line_no3] =lines[line_no3].replace(newArgs[el_num].strip(),oldArgs[el_num],1);
                                              if(lines[line_no3].find(oldArgs[el_num].strip())):
                                                  el_num += 1
                                              #print "line : ",line_no3, " : ",lines[line_no3]
                                          
                                          line_no2=args_end
                                          #lines[line_no2]=lines[line_no2].replace(newProcInfo[6][i][j],oldProcInfo[6][i][j]);
                                
                                #end for loop
                                j=j+1 #move to next service
                                line_no=srv_end  # set line number to end of last service 
                                 

                          f1=open(fileName,"wb")
                          f1.writelines(lines)
                          f1.close()
                      #end process for loop
                      k=process_end #set line number to end of last process 
          return        
      def moveComments(self, xml, fileName):
          #Check how many process blocks are currently
          current_NumProcessBlocks = self.getNumberProcesses(xml)
          print "Current Number of process blocks = ", current_NumProcessBlocks
          
          print "Checking for Comments in the Service Elements and  moving them "
          if (int(current_NumProcessBlocks) == 1): # Should only be one process block in  then new config 
              processes2 = xml.getElementsByTagName("process")
              serviceElements2 = processes2.item(0).childNodes
              hosts = xml.getElementsByTagName("host")
              hostElements=hosts.item(0).childNodes
                  
              #LOOP through all the service Elemets
              for z in range(serviceElements2.length): 
                #loop through all the child elements in each service Element
                #print "SERVICE BLOCK: z = ",z, " Numer Service Elements = ", serviceElements2.length
                y=0
                MaxServiceNodes = len(serviceElements2.item(z).childNodes)
                while(y<MaxServiceNodes):
                #for y in range(len(serviceElements2.item(z).childNodes)): 
                  #print "INSIDE SERVICE BLOCK: z = ",z, "y = ",y," Number of SUB Elements = ", MaxServiceNodes
                
                  if(serviceElements2.item(z).childNodes.item(y).nodeType == serviceElements2.item(z).childNodes.item(y).COMMENT_NODE):
                    index=self.matchServiceName_childNodes(serviceElements2.item(z),"PcapDistributorService")
                    if(index != -1):
                        print "Moving PcapDistributorService comments"
                        msg = "PcapDistributorService Comment:"
                    index=self.matchServiceName_childNodes(serviceElements2.item(z),"StapleService")
                    if(index != -1):
                        print "Moving StapleService comments"
                        msg = "StapleService Comment:"
                    
                    index=self.matchServiceName_childNodes(serviceElements2.item(z),"CaptoolService")
                    if(index != -1):
                        print "Moving CaptoolService comments"
                        msg = "CaptoolService Comment:"
                    
                    index=self.matchServiceName_childNodes(serviceElements2.item(z),"GTPCMergerService")
                    if(index != -1):
                        print "Moving GTPCMergerService comments"
                        msg = "GTPCMergerService Comment:"


                    cloned_comment=serviceElements2.item(z).childNodes.item(y)
                    cloned_textNode = hostElements.item(0).cloneNode(True)
                    referenceElement=hostElements.item(0)
                    hosts.item(0).insertBefore(cloned_comment,referenceElement)
                    referenceElement=hostElements.item(0)
                    hosts.item(0).insertBefore(cloned_textNode,referenceElement)
                    comment=hostElements.item(1) # new comment is now item 1
                    comment.data = msg + comment.data 

                    
                    #remove the extra left over txt node
                    #As we have moved the comment. The txt node is now in the lcoation [y] that the comment was in
                    txt_to_remove=serviceElements2.item(z).childNodes.item(y)
                    serviceElements2.item(z).removeChild(txt_to_remove)                        
                    self.saveXML_File(fileName) 
                    #just removed a comment and  atext node. reduce MaxServiceNodes
                    MaxServiceNodes=MaxServiceNodes-2
                  
                  #end while
                  y +=1
 
          else:
              #Too many process blocks.. not handled at the moment.
              print "Too many process blocks.. There should only be one Process BLOCK in the config file: ", fileName
              print "EDIT ", fileName ," to have just one process block and try again"
              sys.exit(EXIT_FAIL_ERROR)  
          
  except SystemExit:
      print sys.argv[0], "exiting\n"

  except:
      exc_type, exc_value, exc_traceback = sys.exc_info()
      
      print "\n\n\n\n\n\n\n"
      print "*** print_traceback [LIMIT = 10 Lines]:"
      traceback.print_tb(exc_traceback, limit=10, file=sys.stdout)
      
      print "\n\n"
      print "*** print_exception[LIMIT = 2 exceptions]:"
      traceback.print_exception(exc_type, exc_value, exc_traceback, limit=2, file=sys.stdout)
      
      print "\n\n"
      print "*** print_exc:"
      traceback.print_exc()
      
      print "\n\n"
      print "*** format_exc, first and last line:"
      formatted_lines = traceback.format_exc().splitlines()
      print formatted_lines[0]
      print formatted_lines[-1]
      print "*** format_exception:"
      print repr(traceback.format_exception(exc_type, exc_value, exc_traceback))
      print "\n\n"
      print "*** extract_tb:"
      print repr(traceback.extract_tb(exc_traceback))
      
      print "\n\n"
      print "*** format_tb:"
      print repr(traceback.format_tb(exc_traceback))
      
      print "\n\n"
      print "*** tb_lineno:", exc_traceback.tb_lineno


  
 