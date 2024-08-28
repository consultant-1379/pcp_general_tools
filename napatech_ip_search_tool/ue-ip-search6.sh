#!/bin/bash
# ----------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor Napatech hashing algorithm Verification Tool [one of a number of tools]
#
# Usage:
#
#      ./ue-ip-search5_stream28.sh <pcap|nt3g> <MAX Interface count> ggsn1_ip ggsn2_ip ggsn3_ip ggsn4_ip ggsn5_ip ggsn6_ip 
#      
#      ./ue-ip-search5_stream28.sh <filename> 32 203.78.47.209 203.78.47.210 203.78.47.211 203.78.47.212 203.78.47.213"
#
#      filename could be nt3gXX.pcap or pcapXX.pcap or myFileNAmeXX.pcap where xx ==0 to <number of napatech streams>
#      no need to enter the XX.pcap ..F that is assumed 
#
# SUMMARY      
#
# Uses Tshark to produce a list of IP's and uses the "ipSearch_removeDuplicates4.py" to remove duplicate IP's
# Uses ipSearch_CrossReference.py to do the cross referencing for duplicates.  
# Needs pcap files produced by the napaptech to be in the same directory, Also python scripts need to be in the same directory 
# PRESUMES FILES ARE CALLED "pcapX.pcap" [x = 0 ->31]
# TSHARK need to be in "/usr/sbin/"
#
# Process:
# 1. Searches through all pcap files from 2 to 31 produced by the napatech. 
# 2. Uses Tshark to produce a list of destination  UE-IP's where the source host {GGSN} IP 220.206.147.17. Output directed to text file
# 3. Uses Tshark to produce a list of host UE-IP's where the destination host {GGSN} IP 220.206.147.17. Output directed to text file
# 4. uses ipSearch_removeDuplicates4.py to remove duplicate IP from each file produced by Tshark
# 5. Creates a new log file "ue_ip_search_duplicates.txt" and add the date.
# 6. Searches through all pcap files from 2 to 31 produced by the napatech. {0 = traffic we want to discard, 1, Gtpc data => don't search these}
# 7. Checks if the file to search through is the same as the reference file. If so it does not need to search through it.
# 8. Searches for each IP in the reference file in the file to be searched through.
# 9. If a match is found then print info to the log file.
# 10. Uses ipSearch_CrossReference.py to do the searching. This python script uses the SAME Log file. So Don't change the name of it.
#
# ----------------------------------------------------------------------
# Copyright (c) 1999 - 2012 AB Ericsson Oy  All rights reserved.
# ---------------------------------------------------------------------
# Version 1.00
#
#   Release.  
# Version 1.01
# Updated to remove records with Internet Control Mesage Protocol & Packet Caple Lawful Intercept from the tshark results as these were throwing up false duplicates



FILENAME=$1
MINLEN=1
MAX_FILES=31

if test $# -lt 1 
then
  echo .
  echo "USAGE:- ./ue-ip-search5_stream28.sh <pcap|nt3g> <MAX Interface count> ggsn1_ip ggsn2_ip ggsn3_ip ggsn4_ip ggsn5_ip ggsn6_ip"
  echo .
  echo "USAGE:- ./ue-ip-search5_stream28.sh <filename> 32 203.78.47.209 203.78.47.210 203.78.47.211 203.78.47.212 203.78.47.213"
  echo .
  echo "filename could be nt3gXX.pcap or pcapXX.pcap or myFileNAmeXX.pcap where xx ==0 to <number of napatech streams>"
  echo "no need to enter the 'XX.pcap'. It is assumed"
  echo .
  echo "EXAMPLE:- ./ue-ip-search5_stream28.sh nt3g"
  echo .
  exit 0 
fi
MAX_FILES=$2
MAX_FILES=$((MAX_FILES-1))
echo $0 $1 $2 $3 $4 $5 $6 $7




#1.  get list of  IP's  in all the files
for idx in $(seq 0 $MAX_FILES)
do
  echo "Processing $FILENAME$idx.pcap"
  echo "">ips-pcap-$FILENAME$idx.txt
#  /usr/sbin/tshark -r "$FILENAME$idx.pcap" -R "(ip.dst_host == 203.78.47.209 || ip.dst_host == 203.78.47.210 || ip.dst_host == 203.78.47.211 || ip.dst_host == 203.78.47.212 || ip.dst_host == 203.78.47.213) && gtp && !(icmp) && !(pcli)" -T "fields" -e "ip.src" -E "separator=/t">>ips-pcap-$FILENAME$idx.txt
#  /usr/sbin/tshark -r "$FILENAME$idx.pcap" -R "(ip.src_host == 203.78.47.209 || ip.src_host == 203.78.47.210 || ip.src_host == 203.78.47.211 || ip.src_host == 203.78.47.212 || ip.src_host == 203.78.47.213) && gtp && !(icmp) && !(pcli)" -T "fields" -e "ip.dst" -E "separator=/t">>ips-pcap-$FILENAME$idx.txt

  /usr/sbin/tshark -r "$FILENAME$idx.pcap" -R "(ip.dst_host == $7 || ip.dst_host == $3 || ip.dst_host == $4 || ip.dst_host == $5 || ip.dst_host == $6) && gtp && !(icmp) && !(pcli)" -T "fields" -e "ip.src" -E "separator=/t">>ips-pcap-$FILENAME$idx.txt
  /usr/sbin/tshark -r "$FILENAME$idx.pcap" -R "(ip.src_host == $7 || ip.src_host == $3 || ip.src_host == $4 || ip.src_host == $5 || ip.src_host == $6) && gtp && !(icmp) && !(pcli)" -T "fields" -e "ip.dst" -E "separator=/t">>ips-pcap-$FILENAME$idx.txt

  #2. Get list of unique IP's
  /usr/bin/python ipSearch_removeDuplicates4.py ips-pcap-$FILENAME$idx.txt
done

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
