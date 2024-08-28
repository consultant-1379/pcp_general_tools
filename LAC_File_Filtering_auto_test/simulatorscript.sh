#!/bin/bash
#---------------------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor LAC Filtering Test
#
# Usage:
#
#       ./simulatorscript.sh
#       exit 0 for success
#
#
#               Author:         Luke Potter             elukpot
#               Date:           21/01/2013
#
# ----------------------------------------------------------------------
# Copyright (c) 1999 - 2012 AB Ericsson Oy  All rights reserved.
# ----------------------------------------------------------------------
# Version 1.0
# 
# This script is designed to exist on the PCP server, it is called by
# the gn_simulator_auto_LAC_filtering_test.sh to execute commands
# on the simulator machine.
#
#---------------------------------------------------------------------------------

# Constants for the replaying of PCAP file.
GN_SIM_DIR="/root/gn-sim"
PCAP_FILE_DIR="pcapsGolden"

CREATE_PCAP="Create_GTPC_UE_IP_4.pcap"
UPDATE_PCAP="Update_GTPC_UE_IP_4_MCC_321_MNC_123_LAC_6001.pcap"
CONTINUE_SESSION="Single_UE_IP_4_3615_packets.pcap"

ieth='eth6'
ueth='eth5'
cieth='eth1'

# Make sure this script is being executed from the /root/gn-sim directory
#echo $(pwd)
if [ "$(pwd)" != "$GN_SIM_DIR" ]
then
	cd $GN_SIM_DIR
fi

# Replay the Golden PCAP file for creating the session
echo "    [INFO]    Replaying a Golden PCAP to create the session: $CREATE_PCAP"
./simulator -r "$PCAP_FILE_DIR/$CREATE_PCAP" -g "203.78.47.193"  -i $cieth -t 1
sleep 10 # Sleep for 10 seconds to allow the file to be replayed.

# Replay the Golden PCAP file for continue the session
echo "    [INFO]    Replaying a Golden PCAP to continue the session: $CONTINUE_SESSION"
./simulator -r "$PCAP_FILE_DIR/$CONTINUE_SESSION" -g "203.78.47.209","203.78.47.210","203.78.47.10","203.78.47.211","203.78.47.212","203.78.47.213"  -i $ieth -u $ueth -t 1
sleep 10 # Sleep for 10 seconds to allow the file to be replayed.

# Replay the Golden PCAP file for update the session
echo "    [INFO]    Replaying a Golden PCAP to update the session: $UPDATE_PCAP"
./simulator -r "$PCAP_FILE_DIR/$UPDATE_PCAP" -g "203.78.47.194"  -i $cieth -t 1
sleep 10 # Sleep for 10 seconds to allow the file to be replayed.

# Replay the Golden PCAP file for continue the session
echo "    [INFO]    Replaying a Golden PCAP to continue the session: $CONTINUE_SESSION"
./simulator -r "$PCAP_FILE_DIR/$CONTINUE_SESSION" -g "203.78.47.209","203.78.47.210","203.78.47.10","203.78.47.211","203.78.47.212","203.78.47.213"  -i $ieth -u $ueth -t 1
sleep 10 # Sleep for 10 seconds to allow the file to be replayed.

exit 0 # Success
