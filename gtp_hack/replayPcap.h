/***********************************************************************
 * Reads a pcap file from the command line, determines up or downstream 
 * by referenceing a user supplied GGSN address and plays it out through 
 * the upstream and down stream interfaces
************************************************************************/
#ifndef REPLAYPCAP_H
#define REPLAYPCAP_H
/**********************************************************************
 * Fetch the packet & determines upstrem and downstrem by comparing src
 * and destination IP to lsit of GGSN in config_pcap_ggsns.
 * Return the length
 */
size_t replay_get_packet(int stream, int packet, char ggsn[],
			char *buf, int *downstream);

/**********************************************************************
 * Return the number of streams that are available in the traffic buffer
 */
size_t replay_get_stream_count(void);

#endif
