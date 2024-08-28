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
* File: traffic.c
* Date: Oct 8, 2012
* Author: LMI/LXR/PE Simon Richardson
************************************************************************/

//#define DEBUG

/**********************************************************************
 * Create a collection of buffered IP packets for each pcap file in
 * memory, allowing these to be accessed quickly.
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "traffic.h"

#include "config.h"

#include "gtp_hack.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

/*
 * traffic points to arrays of character strings, each one containing
 * a packet.  There is an array of packets for every pcap file read.
 * 
 * The number of files read is stored in traffic_file_count
 */
static char ***traffic;
static int traffic_file_count;

static char errbuf[PCAP_ERRBUF_SIZE];

/*
 * This is called by the pcap_loop function with each packet found
 * in the pcap file.  It saves each packet in memory ready to be read
 * by the simulator.
 * 
 * Parameters:-
 *   - user: not used
 *   - h: packet header information
 *   - bytes: packet payload
 * 
 * Local variables:-
 *   - traffic_this_file: index to the file in the traffic buffer
 *   - traffic_this_packet: index to the packet in the traffic buffer  
 */

#define SIZE_ETHERNET 	(14)
#define IP_SRC_OFFSET   (12)
#define IP_DEST_OFFSET  (16)
#define VLAN_OFFSET     (12)
#define SIZE_VLAN        (4)
#define SIZE_UDP         (8)


static int traffic_this_file;
static int traffic_this_packet;
// esirich: add delay parameter to packet store
static struct timeval traffic_last_timestamp;

static void traffic_save_buffer(u_char *user, 
				const struct pcap_pkthdr *h, const u_char *bytes)
{
	int packet_size, IP_offset = 0;
	char *local_src;
	int milliseconds;

// IP packet size is packet length minus the Ethernet frame	
	packet_size = h->caplen - 14;

	if(packet_size > GTP_MAX_SAFE_PAYLOAD_LEN) {
		packet_size = GTP_MAX_SAFE_PAYLOAD_LEN;
	}

	//TODO: Check the packet size and set appropriate size based on max length

// TODO: add code to check Ethernet frame type and go into the VLAN frame if present


// discover the direction by looking for the local IP address

	if(!memcmp(bytes + 14 + 12, config_traffic_files[traffic_this_file].local_ip, 4))
	{
		IP_offset = 12;
	}
	
	if(!memcmp(bytes + 14 + 16, config_traffic_files[traffic_this_file].local_ip, 4))
	{
		IP_offset = 16;
	}

#ifdef DEBUG
		printf("File %d packet %d read %d bytes ... ", traffic_this_file, traffic_this_packet, packet_size);
#endif

// if the packet is not to or from the local address, don't buffer it
	if(!IP_offset)
	{
#ifdef DEBUG
		printf("unmatched\n", traffic_this_packet, packet_size);
#endif
		return;
	}

// allocate buffer storage
	if(!traffic_this_packet)
	{
		traffic[traffic_this_file] = (char **) malloc(sizeof(char *)*2);
	}
	else
	{
		traffic[traffic_this_file] = (char **) realloc(
				traffic[traffic_this_file],
				(traffic_this_packet + 2) * sizeof(char *));
	}

// allocate the packet length plus three bytes
	traffic[traffic_this_file][traffic_this_packet] 
			= (char *) malloc(packet_size + 5);
	
// encode packet length in first two bytes
		
	traffic[traffic_this_file][traffic_this_packet][0] = packet_size >> 8;
	traffic[traffic_this_file][traffic_this_packet][1] = packet_size & 0xFF;

// encode IP offset in the next byte

	traffic[traffic_this_file][traffic_this_packet][2] = IP_offset;

// calculate millsecond offset since last packet and encode in last two byte
	if(!traffic_this_packet)
	{
		milliseconds = 0;
	}
	else
	{
		milliseconds = (h->ts.tv_sec - traffic_last_timestamp.tv_sec) * 1000
					 + (h->ts.tv_usec - traffic_last_timestamp.tv_usec) / 1000;
					 
		if(milliseconds > 65535) milliseconds = 65535;

// we've measured time before the packet, so write delay into previous packet
		traffic[traffic_this_file][traffic_this_packet - 1][3] = milliseconds >> 8;
		traffic[traffic_this_file][traffic_this_packet - 1][4] = milliseconds & 0xFF;

		traffic[traffic_this_file][traffic_this_packet][3] = 0;
		traffic[traffic_this_file][traffic_this_packet][4] = 0;
	}
	memcpy(&(traffic_last_timestamp), &(h->ts), sizeof(struct timeval));
	

// copy IP frame out of Ethernet frame
	memcpy(traffic[traffic_this_file][traffic_this_packet] + 5,
			bytes + 14, packet_size);

	// rewrite the IP length
	traffic[traffic_this_file][traffic_this_packet][2+5]=packet_size >> 8;
	traffic[traffic_this_file][traffic_this_packet][3+5]=packet_size & 0x00FF;

// NULL-terminate the list	
	traffic[traffic_this_file][++traffic_this_packet] = NULL;

#ifdef DEBUG
		printf("buffered!\n", traffic_this_packet, packet_size);
#endif
}


static void traffic_save_buffer2(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	int packet_size, IP_offset = 0;
	char *local_src;
	int milliseconds;
    const struct iphdr *ip1;
    const struct ethhdr *ethernet;
    int version, type;
    const struct udphdr *udp;
    const struct tcphdr *tcp;
    const struct gtp_v1_hdr *gtp;
    int size_ip;
    int size_tcp;
    int len = 0;
    int isGtpuSeqPresent = 0;
    uint16_t src_port1, dst_port1;
    int ip_src_addr_location_offset, ip_dest_addr_location_offset, ip_location_offset;

    // GTP is carried in UDP packets. NO UDP  then No GTP  => process as normal
    ethernet = (struct ethhdr *)(bytes);
    type = ethernet->h_proto;
    int size_vlan_if_present;
        
    if(type == htons(ETH_P_8021Q)) {
        ip1 = (struct iphdr *)(bytes + SIZE_ETHERNET + SIZE_VLAN);
        size_vlan_if_present=SIZE_VLAN;
    } else if (type == htons(ETH_P_IP)){
        ip1 = (struct iphdr *)(bytes + SIZE_ETHERNET);
        size_vlan_if_present=0;
    } else {
        // Could be any of those defined in if_ether.h (Like ARP)
        return;
    }

    version = ip1->version;

    if(version == 6) {
        return;
    }
    size_ip = ip1->ihl * 4;

    if(size_ip < 20) {
        fprintf(stderr, "Processing Traffic : Invalid IP header length (Ethernet):File = %d, Packet Number = %d, Num bytes = %d , full packet size = %d \n",traffic_this_file, traffic_this_packet, size_ip, h->caplen );
        return;
    }

    // default locations if GTP not present
    ip_location_offset = SIZE_ETHERNET;
    ip_src_addr_location_offset = SIZE_ETHERNET + IP_SRC_OFFSET;
    ip_dest_addr_location_offset = SIZE_ETHERNET + IP_DEST_OFFSET;

    // Default IP packet size is packet length minus the Ethernet frame	
    // May be reset if GTP Present
	packet_size = h->caplen - ip_location_offset;
	//Check the packet size and set appropriate size based on max length
	if(packet_size > GTP_MAX_SAFE_PAYLOAD_LEN) {
		packet_size = GTP_MAX_SAFE_PAYLOAD_LEN;
	}
    
    if(ip1->protocol == IPPROTO_UDP) {

        #ifdef DEBUG
            fprintf(stderr, "Processing Traffic : PROCESSING UDP PACKET\n");
        #endif
        udp = (struct udphdr *)(bytes + SIZE_ETHERNET + size_vlan_if_present + size_ip);
        src_port1 = ntohs(udp->source);
        dst_port1 = ntohs(udp->dest);

        if(src_port1 == 2152 || dst_port1 == 2152) {
            gtp = (struct gtp_v1_hdr *)(bytes + SIZE_ETHERNET + size_vlan_if_present + size_ip + SIZE_UDP);
            len = ntohs(gtp->length);
            isGtpuSeqPresent = (gtp->flags >> 1) & 1;

            if(isGtpuSeqPresent) {
                ip_location_offset = SIZE_ETHERNET + size_vlan_if_present + size_ip + SIZE_UDP + 12;
                ip_src_addr_location_offset = ip_location_offset + IP_SRC_OFFSET;
                ip_dest_addr_location_offset = ip_location_offset + IP_DEST_OFFSET;
            } else {
                ip_location_offset = SIZE_ETHERNET + size_vlan_if_present + size_ip + SIZE_UDP + 8;
                ip_src_addr_location_offset = ip_location_offset + IP_SRC_OFFSET;
                ip_dest_addr_location_offset = ip_location_offset + IP_DEST_OFFSET;
            }
            // IP packet size.
            packet_size = h->caplen - ip_location_offset;

        }

    }


// discover the direction by looking for the local IP address

	if(!memcmp(bytes + ip_src_addr_location_offset, config_traffic_files[traffic_this_file].local_ip, 4))
	{
		IP_offset = 12;
	}
	
	if(!memcmp(bytes + ip_dest_addr_location_offset, config_traffic_files[traffic_this_file].local_ip, 4))
	{
		IP_offset = 16;
	}

#ifdef DEBUG
		printf("File %d packet %d read %d bytes ... ", traffic_this_file, traffic_this_packet, packet_size);
#endif

// if the packet is not to or from the local address, don't buffer it
	if(!IP_offset)
	{
#ifdef DEBUG
		printf("unmatched\n", traffic_this_packet, packet_size);
#endif
		return;
	}

// allocate buffer storage
	if(!traffic_this_packet)
	{
		traffic[traffic_this_file] = (char **) malloc(sizeof(char *)*2);
	}
	else
	{
		traffic[traffic_this_file] = (char **) realloc(
				traffic[traffic_this_file],
				(traffic_this_packet + 2) * sizeof(char *));
	}

// allocate the packet length plus five bytes
	traffic[traffic_this_file][traffic_this_packet] 
			= (char *) malloc(packet_size + 5);
	
// encode packet length in first two bytes
		
	traffic[traffic_this_file][traffic_this_packet][0] = packet_size >> 8;
	traffic[traffic_this_file][traffic_this_packet][1] = packet_size & 0xFF;

// encode IP offset in the next byte

	traffic[traffic_this_file][traffic_this_packet][2] = IP_offset;

// calculate millsecond offset since last packet and encode in last two byte
	if(!traffic_this_packet)
	{
		milliseconds = 0;
	}
	else
	{
        if(config_interPacket_delay_mS) {
            milliseconds=config_interPacket_delay_mS;
        } 
        else {
            milliseconds = (h->ts.tv_sec - traffic_last_timestamp.tv_sec) * 1000
                         + (h->ts.tv_usec - traffic_last_timestamp.tv_usec) / 1000;
                         
        }
		if(milliseconds > 65535) milliseconds = 65535;

// we've measured time before the packet, so write delay into previous packet
        traffic[traffic_this_file][traffic_this_packet - 1][3] = milliseconds >> 8;
		traffic[traffic_this_file][traffic_this_packet - 1][4] = milliseconds & 0xFF;

		traffic[traffic_this_file][traffic_this_packet][3] = 0;
		traffic[traffic_this_file][traffic_this_packet][4] = 0;
	}
	memcpy(&(traffic_last_timestamp), &(h->ts), sizeof(struct timeval));
	

// copy IP frame out of Ethernet frame
	memcpy(traffic[traffic_this_file][traffic_this_packet] + 5,
			bytes + ip_location_offset, packet_size);

	// rewrite the IP length
	traffic[traffic_this_file][traffic_this_packet][2+5]=packet_size >> 8;
	traffic[traffic_this_file][traffic_this_packet][3+5]=packet_size & 0x00FF;

// NULL-terminate the list	
	traffic[traffic_this_file][++traffic_this_packet] = NULL;

#ifdef DEBUG
		printf("buffered!\n", traffic_this_packet, packet_size);
#endif
}



/*
 * this reads the packets in the files into the traffic buffer
 * 
 * Parameters:-
 *    (none)
 */
static void traffic_buffer_packets(void)
{
	int i, count = 0;

	if(traffic_file_count && traffic) return;
	
	
	traffic = (char ***) calloc(config_traffic_file_count+1, sizeof(char **));
	
	
	for(i = 0; i < config_traffic_file_count; i++)
	{
		pcap_t *pd;
		
#ifdef DEBUG
		printf("Opening %s for packet capture\n", config_traffic_files[i].filename);
#endif
		pd = pcap_open_offline(config_traffic_files[i].filename, errbuf);
		
		if(!pd)
		{
			fprintf(stderr, "%s failed to buffer: %s\n", 
					config_traffic_files[i].filename,
					errbuf);

			continue;
		}
		
		traffic_this_file = count;
		traffic_this_packet = 0;
		
		switch(pcap_loop(pd, -1, traffic_save_buffer2, NULL))
		{
		default:
			fprintf(stderr, "problem buffering %s: %s\n",
					config_traffic_files[i].filename,
					pcap_geterr(pd)
					);
		case 0: break;
		}
		
		if(traffic_this_packet)
		{
			count++;
		}
		else
		{
			fprintf(stderr, "no packets read from %s:"
					" is the source IP address correct?\n",
					config_traffic_files[i].filename);
		}
		
		pcap_close(pd);

#ifdef DEBUG
		printf("Completed %s packet capture\n", config_traffic_files[i].filename);
#endif
	}
	
	traffic_file_count = count;
}

/*
 * Fetch the packet performing the appropriate IP substitution to
 * make the local IP as the ip string, and return the length
 * 
 * Parameters:-
 *    - stream: the index of streams read from the files
 *    - packet: the index of packets within each stream
 *    - ip: 4 bytes giving the IPv4 address of desired source of the flow
 *    - buf: a place to put the packet, ideally bigger than GTP_FRAME_LEN
 *    - downstream: a pointer to an integer which will be nonzero if 
 *      this is a downstream packet
 */
// esirich: delay added to give real-time replay
size_t traffic_get_packet(int stream, int packet, char ip[], char *buf, int *downstream, int *delay)
{
	int length, IP_offset, length_offset;

	if(!traffic_file_count || !traffic)
	{
		traffic_buffer_packets();
	}

	if(traffic_file_count <= stream) return(0);
	
	if(!traffic[stream][packet]) return(0);
	
	if(downstream)
	{
		*downstream = 0;
		
		if(traffic[stream][packet][2] == 16)
		{
			*downstream = 1;
		}
	}
	
	length = (traffic[stream][packet][0] << 8) | ((traffic[stream][packet][1]) & 0x00FF);

	IP_offset = traffic[stream][packet][2];
	
	length_offset = traffic[stream][packet][1];

	if(delay)
	{
		*delay = (traffic[stream][packet][3] << 8) 
			  | ((traffic[stream][packet][4]) & 0x00FF);
	}

	memcpy(buf, traffic[stream][packet]+5, length);
// TODO if ip is NULL, don't substitute
	memcpy(buf + IP_offset, ip, 4);

	return(length);
}

/*
 * Return the number of streams that are available in the traffic buffer
 *
 * Parameters:-
 *    (none)
 */
size_t traffic_get_stream_count(void)
{
	if(!traffic_file_count || !traffic)
	{
		traffic_buffer_packets();
	}

	return(traffic_file_count);
}


/**********************************************************************
 * This test harness reads a set of packets out of a file
 * and prints them out as hex.  It demonstrates (we hope) that the
 * substitution works
 */
#if defined(TEST)

int main(void)
{
	int stream = 0, packet, size;
	char buffer[2000]; // big enough for Ethernet packets
	char ip[4]={1,2,3,4};

	for(stream = 0; stream < traffic_get_stream_count(); stream++)
	{
		packet = 0;

		do
		{
			int i, ds;
		
			size = traffic_get_packet(stream, packet, ip, buffer, &ds);
		
			printf("[%d][%d]%c:", stream, packet, '>' - ds * 2);
		
			for(i=0; i<size; i++)
			{
				printf(" %02X", 0x00FF & buffer[i]);
			}
		
			printf("\n");
			
			if(size) packet++;
		}
		while(size);
	}
	
	return(0);
}
#endif
