#!/bin/bash
# ----------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor Napatech hashing algorithm Verification Tool [one of a number of tools]
#
# Usage:
#
#       ./test_for_duplicates.sh <reference file with IP> <file with IP's to search through> 
#
# SUMMARY      
#
# Same as ue-ip-search5.sh except with out the Tshark bit to produce the IP's and the "ipSearch_removeDuplicates4.py" to remove duplicate IP's
# Hence two files need to exist, each containing IP's  which need to be cross references for duplicates.   
# Needs pcap files produced by the napaptech to be in the same directory, Also python scripts need to be in the same directory 
# PRESUMES FILES ARE CALLED "pcapX.pcap" [x = 0 ->31]
#
# Process:
# 1. Creates a new log file "ue_ip_search_duplicates.txt" and add the date.
# 2. Searches through all pcap files from 2 to 31 produced by the napatech. {0 = traffic we want to discard, 1, Gtpc data => don't search these}
# 3. Checks if the file to search through is the same as the reference file. If so it does not need to search through it.
# 4. Searches for each IP in the reference file in the file to be searched through.
# 5. If a match is found then print info to the log file.
# 6. Uses ipSearch_CrossReference.py to do the searching. This python script uses the SAME Log file. So Don't change the name of it.
#
# ----------------------------------------------------------------------
# Copyright (c) 1999 - 2012 AB Ericsson Oy  All rights reserved.
# ---------------------------------------------------------------------
# Version 1.00
#
#   Release.   
 
if test $# -lt 1 
then
  echo .
  echo "./test_for_duplicates.sh <reference file with IP> <file with IP's to search through> "
  echo .
  echo .
  exit 0 
fi  
FILENAME=$1
MINLEN=1
MAX_FILES=31

#1.  get list of  IP's  in all the files
#for idx in $(seq 0 $MAX_FILES)
#do
#  echo "Processing $FILENAME$idx.pcap"
#  echo "">ips-pcap-$FILENAME$idx.txt
#  /usr/sbin/tshark -r "$FILENAME$idx.pcap" -R "ip.src_host == 220.206.147.171" -T "fields" -e "ip.dst" -E "separator=/t">>ips-pcap-$FILENAME$idx.txt
#  /usr/sbin/tshark -r "$FILENAME$idx.pcap" -R "ip.dst_host == 220.206.147.171" -T "fields" -e "ip.src" -E "separator=/t">>ips-pcap-$FILENAME$idx.txt
#
#
#  #2. Get list of unique IP's
#  /usr/bin/python ipSearch_removeDuplicates4.py ips-pcap-$FILENAME$idx.txt
#done

#3. Search for Duplciates
date>ue_ip_search_duplicates.txt
echo "">>ue_ip_search_duplicates.txt
echo "">>ue_ip_search_duplicates.txt

for idx1 in $(seq 2 $MAX_FILES)
do
  echo "Searching for duplicate IP from $FILENAME$idx1.pcap"
  for idx2 in $(seq 2 $MAX_FILES)
  do
    if [ $idx1 -ne $idx2 ]
    then
      if [ -f ips-pcap-$FILENAME$idx1.txt ];
      then
         if [ -f ips-pcap-$FILENAME$idx2.txt ];
         then
             /usr/bin/python ipSearch_CrossReference.py ips-pcap-$FILENAME$idx1.txt ips-pcap-$FILENAME$idx2.txt
         else
            echo "File  ips-pcap-$FILENAME$idx2.txt does not exist">>ue_ip_search_duplicates.txt
         fi
      else
          echo "File  ips-pcap-$FILENAME$idx1.txt does not exist">>ue_ip_search_duplicates.txt
      fi
    fi     
  done
done

echo "...........done"
