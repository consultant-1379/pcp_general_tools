#!/bin/bash
#---------------------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor LAC Filtering Test
#
# Usage:
#
#       ./gn_simulator_auto_LAC_filtering_test.sh
#       exit 0 for success
#       exit 1 for no Directory
#       exit 2 for no File or Link
#       exit 3 for incorrect args
#
# read file expected_files.txt for for all files that should exist
# read file expected_directories.txt for for all directories that should exist
#
#               Author:         Luke Potter             elukpot
#               Date:           22/01/2013
#
# ----------------------------------------------------------------------
# Copyright (c) 1999 - 2012 AB Ericsson Oy  All rights reserved.
# ----------------------------------------------------------------------
# Version 1.2
#
#---------------------------------------------------------------------------------

# Exit constants used in the script.
EXIT_SUCCESS=0
EXIT_NO_DIR=1
EXIT_NO_FILE=2
EXIT_BAD_ARGS=3

#---------------------------------------------------------------------------------
# Functions used in the Script.

# Function to replay the golden pcap file in the Gn Simulator
function REPLAY_PCAP_FILE_WITH_GN_SIMULATOR {
	
	echo "    [INFO]    Starting to Replay a Golden PCAP through the Gn Simulator."
	
	# Open SSH connection to GN Simulator Server and run the simulator script
	ssh root@atsfsx160 'bash -s' < simulatorscript.sh
	
	# Roll over GTP-C log
    rename .log.latest .log /var/opt/ericsson/probe-controller/probe/gtpc/*.log.latest

	#Finish function
	echo "    [DONE]    Finished Replaying Golden PCAPs through the Capture card."
}

# Function to check the directory names
function CHECK_DIRECTORY_NAMES {
	
	echo "    [INFO]    Checking the output directories."
	while read line
	do
		#echo $line
		DIR_SECTION=$( echo `expr index "$line" '#'` )
		#echo $DIR_SECTION
		if [ $DIR_SECTION == 0 ]
		then
			CHECK_DIR_EXISTS $line
		fi
	done < expected_directories.txt
	echo "    [PASS]    Expected output directories are present."
}

# Function to check the file names
function CHECK_FILE_NAMES {
	
	echo "    [INFO]    Checking the output files."
	while read line
	do
		#echo $line
		DIR_SECTION=$( echo `expr index "$line" '#'` )
		#echo $DIR_SECTION
		if [ $DIR_SECTION == 0 ]
		then
			CHECK_FILE_EXISTS $line
		fi
	done < expected_files.txt
	echo "    [PASS]    Expected output files exist."
}

# Function to check that the given directory exists
function CHECK_DIR_EXISTS {
	if [ -d "$1" ]
	then
		echo "    [INFO]    Directory:  " $1 " exists"
	else
		echo .
		echo "    [FAIL]    Directory: " $1 " does not exist!"
		STOP_PCP_SERVER
		exit $EXIT_NO_DIR
	fi
}

# Function to check that the given file exists.
function CHECK_FILE_EXISTS {
	if [ -f "$1" ]
	then
		echo "    [INFO]    File: " $1 " exists"
	else
		if [ -L "$1" ]
		then
			echo "    [INFO]    Link: " $1 " exists"
		else
			echo .
			echo "    [FAIL]    File or Link: " $1 " does not exist"
			STOP_PCP_SERVER
			exit $EXIT_NO_FILE
		fi
	fi
}

# A function that wait until the end of the ROP to proceed
function WAIT_UNTIL_END_OF_ROP {
	
	echo "    [INFO]    Waiting for the end of the current ROP."
	
	# The `date +%M` extracts the minute value from the date.
	# Determine if the five modulo minute is 0
	while [ $((`date +%M`%5)) -ne 0 ]
	do
		sleep 30s
		
		minsgone=$((`date +%M`%5))
		minsremaining=`echo 5 - $minsgone | bc`
		if [ "$minsremaining" == "5" ]
		then
			minsremaining = "0"
		fi
		
		echo "          Minutes remaining in ROP: $minsremaining"
	done

	# Sleep for another 32 seconds to make sure the files are published
	sleep 32s
	
	echo "    [DONE]    ROP over, continuing."
}

# Function to delete the contents of the intermediate directories
function WIPE_TEMP_DIRS {
	
	# Staple Directories
	echo "    [INFO]    Cleaning the intermediate Staple files."
	rm -Rf /var/opt/ericsson/probe-controller/probe/staple/*
	
	echo "    [INFO]    Cleaning the enriched Staple files."
	rm -Rf /var/opt/ericsson/probe-controller/output/staple/3g/*
	
	echo "    [DONE]    Staple output directories cleaned."
	
	# Captool Directories
	echo "    [INFO]    Cleaning the intermediate Captool files."
	rm -Rf /var/opt/ericsson/probe-controller/probe/captool/*
	
	echo "    [INFO]    Cleaning the enriched Captool files."
	rm -Rf /var/opt/ericsson/probe-controller/output/captool/3g/*
	
	echo "    [DONE]    Captool output directories cleaned."
}

# A Function to call the script that creates expected_files.txt and expected_directories.txt
function GENERATE_ACCEPTANCE_CRITERIA {
	
	echo "    [INFO]    Creating the acceptance criteria."
	./createExpectedDirectoriesAndExpectedFilesFiles.sh -o 321 123 6001
	echo "    [DONE]    Acceptance Criteria created."
}

# Function to start the PCP Server
function START_PCP_SERVER {
	
	echo "    [INFO]    Starting the PCP server."
	/etc/init.d/probe-controller start
	echo "    [DONE]    PCP server started."
}

# Function to stop the PCP Server
function STOP_PCP_SERVER {
	
	echo "    [INFO]    Stopping the PCP server."
	/etc/init.d/probe-controller stop
	echo "    [DONE]    PCP server stopped."
}



#---------------------------------------------------------------------------------
# Start the script here.

# Print out the starting message.
echo "    [START]   Starting the Automatic Test of LAC filtering of the Staple output files."

# Stagelist, comment to skip a stage.

# Stop the Packet Capture Pre-processor server.
STOP_PCP_SERVER

# Call the function to generate the appeptance criteria.
GENERATE_ACCEPTANCE_CRITERIA

# Delete the contents of the output dirs.
WIPE_TEMP_DIRS

# Start the PCP server.
START_PCP_SERVER

# Replay Golden PCAP file.
REPLAY_PCAP_FILE_WITH_GN_SIMULATOR

# Wait until the end of the current ROP, to have the files generated
WAIT_UNTIL_END_OF_ROP

# Check that the directories contain the MCC_MNC_LAC info that are expected in the Golden PCAP.
CHECK_DIRECTORY_NAMES

# Check the output files names.
CHECK_FILE_NAMES

# Stop the Packet Capture Pre-processor server.
STOP_PCP_SERVER


# Output message saying that it works.
echo "    [DONE]    The test was successful, all passing!"
exit 0 # Success
# End of Script.
