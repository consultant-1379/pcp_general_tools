#!/bin/bash
#---------------------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor LAC Filtering Test
#
# Usage:
#
#       ./auto_createExpectedDirectoriesAndExpectedFilesFiles.sh
#       exit 0 for success
#       exit 1 for incorrect args
#
# write to file expected_directories.txt with the values that should exist
# write to file expected_files.txt with the values that should exist
#
#               Author:         Luke Potter             elukpot
#               Date:           22/01/2013
#
#---------------------------------------------------------------------------------
# Copyright (c) 1999 - 2012 AB Ericsson Oy  All rights reserved.
#---------------------------------------------------------------------------------
# Version 2.4
#
#---------------------------------------------------------------------------------

#---------------------------------------------------------------------------------
# Functions

# A function to calculate the start time of the ROP
function calcStarttime {

        hour="`date +%H`"
        min="`date +%M`"

        nmin="${min:1}"

        if [ "$nmin" == "1" ]
        then
                min="${min:0:1}0"

        elif [[ "$nmin" == "2" || "$nmin" == "3" || "$nmin" == "4" || "$nmin" == "6" ]]
        then
                min="${min:0:1}5"

        elif [[ "$nmin" == "7" || "$nmin" == "8" || "$nmin" == "9"  ]]
        then
                zero="0"
                smin=`echo ${min:0:1} + 1 | bc`
                min=$smin$zero
        fi

		# Check if the hour need to be ticked over
        if [ $min -ge 60  ]
        then
                hour=`echo $hour + 1 | bc`
                min="00"
        fi

        echo "$hour$min"
}

# A function to calculate the end time of the ROP
# ARGS are the output from calcStarttime function or in the form of 1200, for noon
function calcEndtime {

        time=`echo $1 + 5 | bc`

        hour="${time:0:2}"
        min="${time:2:2}"

		# Check if the hour need to be ticked over
        if [ $min -ge 60  ]
        then
                hour=`echo $hour + 1 | bc`
                min="00"
        fi

        echo "$hour$min"
}

# A function to calculate the EPOCH time
# ARGS are the date (20130122) and the output from the calcEndtime function (1200)
function calcEndtimeEPOCH {

        epoch=$(date -d "$1 $2" +%s)

        echo $epoch
}

# This function evalueates the option args for append or overwriting the expected files of directories files
function appendOverwriteError {
	# Create the expected_files.txt file - The first ">" is to overwrite the current file
	# The $1 used here is local to the function, expected to be a file name.
	case "$Option" in
		-a)
			echo '# Appending to file' >> $1
			;;
		-o)
			echo '# Wipe file contents' > $1
			;;
		*)
			echo "    [ERROR]   Use -a to append to the expected file. Use -o to overwrite the expected files."
			exit $BAD_ARGS
	esac
}

# A function to generate the Staple directories for the acceptance criteria
function genStapleDirs {
	#echo $STAPLE_BASE_DIR/tcpta/$MCC_MNC_LAC >> $DIR_OUT
	echo $STAPLE_BASE_DIR/tcpta-partial/$MCC_MNC_LAC >> $DIR_OUT
	#echo $STAPLE_BASE_DIR/flv/$MCC_MNC_LAC >> $DIR_OUT
	#echo $STAPLE_BASE_DIR/flv-partial/$MCC_MNC_LAC >> $DIR_OUT
	#echo $STAPLE_BASE_DIR/webreq/$MCC_MNC_LAC >> $DIR_OUT
	#echo $STAPLE_BASE_DIR/webpage/$MCC_MNC_LAC >> $DIR_OUT
}

# A function to generate the Captool directories for the acceptance criteria
function genCaptoolDirs {
	echo $CAPTOOL_BASE_DIR/$MCC_MNC_LAC >> $DIR_OUT
}

# A function to generate the Staple files for the acceptance criteria
function genStapleFiles {
	# Create Staple files
	#echo $STAPLE_BASE_DIR/tcpta/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_staple_tcpta_"$ROP_END_EPOCH"_000.log-"$SW_VERSION.gz                >> $FILE_OUT
	echo $STAPLE_BASE_DIR/tcpta-partial/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_staple_tcpta-partial_"$ROP_END_EPOCH"_000.log-"$SW_VERSION.gz >> $FILE_OUT
	#echo $STAPLE_BASE_DIR/flv/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_staple_flv_"$ROP_END_EPOCH"_000.log-"$SW_VERSION.gz                    >> $FILE_OUT
	#echo $STAPLE_BASE_DIR/flv-partial/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_staple_flv-partial_"$ROP_END_EPOCH"_000.log-"$SW_VERSION.gz    >> $FILE_OUT
	#echo $STAPLE_BASE_DIR/webpage/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_staple_webpage_"$ROP_END_EPOCH"_000.log-"$SW_VERSION.gz            >> $FILE_OUT
	#echo $STAPLE_BASE_DIR/webreq/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_staple_webreq_"$ROP_END_EPOCH"_000.log-"$SW_VERSION.gz              >> $FILE_OUT
}

# A function to generate the Captool files for the acceptance criteria
function genCaptoolFiles {
	# Create Captool Files
	ROP_END=`echo $ROP_END - 4 | bc` # Reduce ROP_END by four minutes
	ROP_END_EPOCH=`echo $ROP_END_EPOCH - 240 | bc` # Reduce END_ROP_EPOC by 240 scronds(4 minutes)

	# Create Captool files for each minute of the ROP
	echo $CAPTOOL_BASE_DIR/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_summary_"$ROP_END_EPOCH"_000.log"-$SW_VERSION.gz >> $FILE_OUT
	updateValues
	echo $CAPTOOL_BASE_DIR/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_summary_"$ROP_END_EPOCH"_000.log"-$SW_VERSION.gz >> $FILE_OUT
	updateValues
	echo $CAPTOOL_BASE_DIR/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_summary_"$ROP_END_EPOCH"_000.log"-$SW_VERSION.gz >> $FILE_OUT
	updateValues
	echo $CAPTOOL_BASE_DIR/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_summary_"$ROP_END_EPOCH"_000.log"-$SW_VERSION.gz >> $FILE_OUT
	updateValues
	echo $CAPTOOL_BASE_DIR/$MCC_MNC_LAC/$MCC_MNC_LAC"-A"$DATE.$ROP_START-$ROP_END"_summary_"$ROP_END_EPOCH"_000.log"-$SW_VERSION.gz >> $FILE_OUT
}

# A function used during the generation of the Captool files
function updateValues {
	# This function updates the values of the ROP_START, ROP_END and ROP_END_EPOCH variables by one minute
	ROP_START=`echo $ROP_START + 1 | bc`
	ROP_END=`echo $ROP_END + 1 | bc`
	ROP_END_EPOCH=`echo $ROP_END_EPOCH + 60 | bc` # Increase by 60 seconds(1 minute)
}


#---------------------------------------------------------------------------------
# Main part of the sctipt
#---------------------------------------------------------------------------------
# Sanitise Inputs
if [ $# -ne 4 ]
then
	echo "                 ----- [  ERROR  ] ------"
	echo "Call script as follows;                                          MCC MNC LAC "
	echo "    ./createExpectedDirectoriesAndExpectedFilesFiles.sh [-a|-o]  321 123 6001"
	echo "                       Append or Overwrite expected files^                   "
	exit $BAD_ARGS
fi
#---------------------------------------------------------------------------------
# User Inputted values
Option=$1
MCC=$2
MNC=$3
LAC=$4
DATE="`date +%Y``date +%m``date +%d`"
ROP_START=$(calcStarttime)
ROP_END=$(calcEndtime $ROP_START)
ROP_END_EPOCH=$(calcEndtimeEPOCH $DATE $ROP_END)
SW_VERSION="2.2.6"

# Constants
MCC_MNC_LAC=$MCC"_"$MNC"_"$LAC
BASE_DIR="/var/opt/ericsson/probe-controller/output"
STAPLE_BASE_DIR=$BASE_DIR/staple/3g
CAPTOOL_BASE_DIR=$BASE_DIR/captool/3g
DIR_OUT=expected_directories.txt
FILE_OUT=expected_files.txt
SUCCESS=0
BAD_ARGS=1

# Call to function to append or overwrite expected output files
appendOverwriteError $DIR_OUT
appendOverwriteError $FILE_OUT

echo "    [START]   Starting creation of expected files."

# Generate the Expected Directories
echo "    [INFO]    Creating expected_directories.txt file."
genStapleDirs
genCaptoolDirs
chmod 777 $DIR_OUT
echo "    [DONE]    Finished creating expected_directories.txt file."

# Generate the Expected Files
echo "    [INFO]    Creating expected_files.txt file."
genStapleFiles
genCaptoolFiles
chmod 777 $FILE_OUT
echo "    [DONE]    Finished creating expected_files.txt file."

# Exiting messages
echo "    [FINISH]  Finished creation of expected files."
# Exit success
exit $SUCCESS
