#---------------------------------------------------------------------------------
# Ericsson Network IQ Packet Capture Pre Processor LAC Filtering Test
#
#
#        This is the ReadMe file for the LAC Filtering test.
#
#               Author:         Luke Potter             elukpot
#               Date:           01/02/2013
#
#---------------------------------------------------------------------------------
# Copyright (c) 1999 - 2012 AB Ericsson Oy  All rights reserved.
#---------------------------------------------------------------------------------
# 
# Version 1.4
#

1. Switch to root user.

2. Decide when you're going to run the "gn_simulator_auto_LAC_filtering_test.sh"
   script.
   Choose to run it as close to the start of a ROP as possible, e.g. 12:41:01.
   Basically a minute and a few seconds after every 5 minute block.

3. Run the "gn_simulator_auto_LAC_filtering_test.sh" script.
   This script will run through a number of stages.

   It will call the "createExpectedDirectoriesAndExpectedFilesFiles.sh" to
   create the acceptance criteria for the test. You can change the MNC, MCC and
   LAC that get used in the accpetance criteria from the
   "GENERATE_ACCEPTANCE_CRITERA" function in the
   "gn_simulator_auto_LAC_filtering_test.sh" script.

   It will also call the "simulatorscript.sh" script, change the PCAP files
   here to get different results.

   The stage list is as follows:
        * Stopping the PCP Server,
        * Creating the acceptance criteria
        * Wiping the Captool and Staple intermediate and output directories,
        * Starting the PCP Server,
        * SSHes to the Simulator server to replay pcaps, you must enter the
		  machine's password here,
        * Waits until the end of the current ROP,
        * Then it enters it's evalueation phase,
          and checks the output directories against the contents of
          "expected_directories.txt",
        * It checks output files against the contents of "expected_files.txt",
        * Finally, it Stops the PCP Server.

4. If there's any problems finding the "expected_directories" and
   "expected_files" text files, make sure you've ran the
   "gn_simulator_auto_LAC_filtering_test.sh" script whilst you are
   in the same directory as it, i.e. via ./gn_simulator_auto_LAC_filtering_test.sh
