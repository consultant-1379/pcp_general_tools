# ----------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor  Napatech hashing algorithm Verification Tool [one of a number of tools]
#
# Usage:
#
#       /usr/bin/python ipSearch_removeDuplicates4.py <file with list of IP's> 
#
#
# SUMMARY      
#
#  Removes Duplicate occurance of IP ina given file
#
# Process:
# 1. Reads all the IP's in <file with list of IP's>  into an array
# 2. Loops through the array and creates a hash map, using the IP as botht he KEY and value for the key:value pair of the has map
#    Since a hash map can not have duplicate keys, then duplicate IP are removed.
# 3. While looping, partial IP's  and IP not of the form xxx.xxx.xxx.xxx [xxx :: 0 -> 255] are removed.
#
# ----------------------------------------------------------------------
# Copyright (c) 1999 - 2012 AB Ericsson Oy  All rights reserved.
# ---------------------------------------------------------------------
# Version 1.00
#
#   Release.   




import sys, traceback
import string
import os

FILENAME=""
DEBUG=False
TESTING=False
EXIT_FAIL_ERROR=2
EXIT_FAIL_NORMAL=1
EXIT_PASS=0

def main_ip_Search():
  f = open(FILENAME)
  lines = f.readlines()
  f.close()
  
  print "Searching ", FILENAME, " :Please Wait"
  
  ipt = {}

  for i in range(0,len(lines)):
          if(lines[i].strip().find(".") != -1):
            l=lines[i].strip().split(".");
            if (len(l) == 4):
              if((len(l[0]) >0) and (len(l[0]) <=3)):
                if((len(l[1]) >0) and (len(l[0]) <=3)) :
                  if((len(l[2]) >0) and (len(l[0]) <=3)):
                    if((len(l[3]) >0) and (len(l[0]) <=3)):
                      ipt[lines[i].strip()] = lines[i].strip();

  linesOut = []
  for k in ipt.keys():
          if (ipt.get(k) != None):
                  #print ipt[k]
                  linesOut.append(ipt.get(k)+"\n")

  #FILENAME2=FILENAME+"-2"
  f = open(FILENAME,'w')
  f.writelines(linesOut)
  f.close()



  
  
  





if __name__=="__main__":
  if len(sys.argv) < 2:
    print "\n\nUsage:- python", sys.argv[0] , "<filename>"
    print "Example:- python ipSearch_removeDuplicates.py ips.txt "
    sys.exit(EXIT_FAIL_NORMAL)
    
    
  else:
    
    FILENAME=sys.argv[1]
    #print "Filename is ", FILENAME
    
    main_ip_Search()