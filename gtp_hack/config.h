/************************************************************************
* COPYRIGHT (C) Ericsson 2012                                           *
* The copyright to the computer program(s) herein is the property       *
* of Telefonaktiebolaget LM Ericsson.                                   *
* The program(s) may be used and/or copied only with the written        *
* permission from Telefonaktiebolaget LM Ericsson or in accordance with *
* the terms and conditions stipulated in the agreement/contract         *
* under which the program(s) have been supplied.                        *
*************************************************************************
*************************************************************************
* File: config.h
* Date: Oct 8, 2012
* Author: LMI/LXR/PE Simon Richardson
************************************************************************/


/**********************************************************************
 * Read in the configuration files for the Gn Simulator and put the
 * configuration information in global memory
 */

#ifndef CONFIG_H
# define CONFIG_H
#include <time.h>


struct traffic_file_struct {
	char *filename;
	char local_ip[4];
};

struct UE_struct {
	char *imsi;
	char ip[4];
	char *access_point_name;
	char *msisdn;
	char *imei;	
    unsigned int seqNum;

/* these should start as zero */
	int rai;	
// esirich: move the state machine's states to an enum in config.h
	enum ue_state_enum {
		UE_STATE_IDLE = 0,
		UE_STATE_CONNECTING,
		UE_STATE_CONNECTED,
		UE_STATE_UPDATING,
		UE_STATE_DISCONNECTING
	} UE_state;
	unsigned long long next_packet_milliseconds; // esirich: time outgoing packets
	int trafficFlow, trafficFlowPacket;
    unsigned long long timeLastUsed;
    int firstTimeUsed;
    time_t touch;
};

# ifndef CONFIG_C
#  include <pcap.h>

extern char config_SGSN_mac[6];
extern int config_SGSNc_port;
extern int config_SGSNu_port;
extern char config_SGSN_ip[4];

extern char config_GGSN_mac[6];
extern int config_GGSNc_port;
extern int config_GGSNu_port;
extern char config_GGSN_ip[4];

extern struct traffic_file_struct *config_traffic_files;
extern int config_traffic_file_count;
extern char **config_RAI_list;
extern int config_RAI_list_count;

extern struct UE_struct *config_UE_buffer;
extern int config_UE_buffer_count;

// esirich: add separate control output		
extern char *config_write_filename_control;
extern char *config_write_interface_control;
extern char *config_write_filename;
extern char *config_write_interface;
extern char *config_write_upstream;

extern int config_lifetime;

/* efitleo */
extern char *config_replay_pcap;
extern char *config_replay_ggsn_addr;
extern u_char **config_pcap_ggsns;
extern int max_num_ggsn;

// Add event output stream
extern char *config_event_output;

// esirich: add throttle value
extern long int config_max_rate;

//efitleo
extern int config_imsi_count_interval;
extern int config_replay_count_ueip;
extern int config_replay_mac_addr;
extern int config_use_wait_signal;
extern int config_interPacket_delay_mS;
extern int config_create_GTPC_sequence;

# endif

int config_read(int argc, char *args[]);

#endif
