/***************************************************************
 * Create a collection of buffered IP packets for each pcap file,
 * allowing these to be accessed easily.
 */


#ifndef TRAFFIC_H
#define TRAFFIC_H

struct gtp_v1_hdr {
    u_int8_t flags;
    u_int8_t msgtype;
    u_int16_t length;
    u_int32_t teid;
};

/**********************************************************************
 * Fetch the packet performing the appropriate IP substitution to
 * make the local IP as the ip string, and return the length
 */
// esirich: msec_delay added to give real-time replay
size_t traffic_get_packet(int stream, int packet, char ip[],
			char *buf, int *downstream, int *msec_delay);

/**********************************************************************
 * Return the number of streams that are available in the traffic buffer
 */
size_t traffic_get_stream_count(void);

#endif
