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
# USE QUICK START SCRIPTS FOR KNOWN PCAPS
# 
# USAGE: ./ue-ip-search6_stream28.sh  <max interface no>"
#
# RECALL: nt3g0 - nt3g9 is 10 interfaces"
#
#
# SUMMARY      
#
# Uses Tshark to produce a list of IP's 
# Uses the "ipSearch_removeDuplicates4.py" to remove duplicate IP's
# Uses ipSearch_CrossReference.py to do the cross referencing for duplicates.  
# Needs pcap files produced by the napaptech to be in the same directory, Also python scripts need to be in the same directory 
# PRESUMES FILES ARE CALLED "pcapX.pcap" [x = 0 ->31]
# TSHARK need to be in "/usr/sbin/"
#
#FILES IN HASH ALGORITHM VERIFICATION TOOL SET
#
# ue-ip-search6.sh
# test_for_duplicates.sh
# ipSearch_removeDuplicates4.py
# ipSearch_CrossReference.py

# Version 1.01
# Updated to remove records with Internet Control Mesage Protocol & Packet Caple Lawful Intercept from the tshark results as these were throwing up false duplicates

