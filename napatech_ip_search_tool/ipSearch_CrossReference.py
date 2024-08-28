# ----------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor  Napatech hashing algorithm Verification Tool [one of a number of tools]
#
# Usage:
#
#       /usr/bin/python ipSearch_CrossReference.py <reference file with IP> <file with IP's to search through> 
#
# SUMMARY      
#
#  Cross referencing for duplicate IP.
#  Searches <file with IP's to search through>  for each IP in <reference file with IP> and outputs to log file if matching IP's found
#
# Process:
# 1. Reads all the IP in <reference file with IP>  into an array
# 2. Reads all the IP in <file with IP's to search through>  into an array
# 3  Searches for each IP in the <reference file with IP> in <file with IP's to search through>
# 4. If maching IP found, output info to a log file "ue_ip_search_duplicates.txt"
#
# ----------------------------------------------------------------------
# Copyright (c) 1999 - 2012 AB Ericsson Oy  All rights reserved.
# ---------------------------------------------------------------------
# Version 1.00
#
#   Release.   
# Version 1.01
#
#   updated to check len of ref and search IP are same so that 1.2.3.400 != 1.2.3.40 

import sys, traceback
import string
import os



FILENAME=""
DEBUG=False
TESTING=False
EXIT_FAIL_ERROR=2
EXIT_FAIL_NORMAL=1
EXIT_PASS=0

def main_ip_duplicates(ref_file, search_file):
  f = open(ref_file)
  ref_lines = f.readlines()
  f.close()
  
  f = open(search_file)
  search_lines= f.readlines()
  f.close()
  
  print "Check for Duplicates: ", ref_file, search_file
  
  duplicates=[]
  for x in range(0,len(ref_lines)):
    for y in range(0,len(search_lines)):
      ref_ip=ref_lines[x].strip()
      search_ip=search_lines[y].strip()
      #msg = "Ref IP = "+ ref_ip + " search_ip = " + search_ip
      #print msg
      if(len(ref_ip) == len(search_ip)):
        #print "len ref ip = " + str(len(ref_ip)) + "len search_ip = "+ str(len(search_ip))
        if(ref_ip.find(search_ip) != -1): #found
            msg = "Duplicate IP: "+ ref_ip + "," + ref_file + "," + search_file
            print msg
            duplicates.append(msg + "\n")
   
  f = open("ue_ip_search_duplicates.txt",'a')
  f.writelines(duplicates)
  f.close()
  





if __name__=="__main__":
  if len(sys.argv) < 3:
    print "\n\nUsage:- python", sys.argv[0] , "<filename>"
    print "Example:- python ipSearch_CrossReference.py ips1.txt ips2.txt"
    sys.exit(EXIT_FAIL_NORMAL)
    
    
  else:
    
    REF_FILENAME=sys.argv[1]
    SEARCH_FILENAME=sys.argv[2]
    
    #print "Filename is ", FILENAME
    
    main_ip_duplicates(REF_FILENAME, SEARCH_FILENAME) 