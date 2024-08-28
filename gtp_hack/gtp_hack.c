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
* File: gtp_hack.c
* Date: Oct 8, 2012
* Author: LMI/LXR/PE Simon Richardson
************************************************************************/


#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#define GTP_HACK_C
#include "gtp_hack.h"

#include "config.h"

/**********************************************************************
 * This code is not beautiful.  But it is fast.
 **********************************************************************/

// Optimise uses one buffer, not several, to assemble the 
// UDP/IP and Ethernet layers.  It also reduces the amount of
// testing and copying, and disables Ethernet checksums.

#define OPTIMISE

// total number of bytes/packets sent
unsigned long long gtp_write_packets, gtp_write_bytes, gtp_write_misses;

static char static_gtp_SGSN_mac[6] = {0x00, 0x30, 0x75, 0xC8, 0x28, 0xE5};
static char static_gtp_SGSN_ip[4]={127, 0, 0, 1};
static char static_gtp_GGSN_mac[6] = {0x00, 0x21, 0x02, 0xFA, 0x70, 0xAA};
static char static_gtp_GGSN_ip[4]={127, 0, 0, 2};

// These values may be altered externally, but they have defaults,
// so the gtp_hack library may be called without worrying about them

char *gtp_SGSN_mac = static_gtp_SGSN_mac;
int gtpc_SGSN_port = 54321;
int gtpu_SGSN_port = 54312;
char *gtp_SGSN_ip= static_gtp_SGSN_ip;
char gtp_new_SGSN_ip[4];
char new_teid_c[4] ={0, 0, 0, 0}; //default
char new_teid_d_sgsn[4] ={0, 0, 0, 0}; //default

char *gtp_GGSN_mac = static_gtp_GGSN_mac;
int gtpc_GGSN_port = 2123; // see 3GPP TS 29.060 10.1.1.1
int gtpu_GGSN_port = 2152; // see 3GPP TS 29.060 10.1.1.1
char *gtp_GGSN_ip= static_gtp_GGSN_ip;
char gtp_new_GGSN_ip[4];

/*
 * set up the output file that will receive the simulated traffic
 * 
 * Parameters:- 
 *   - filename: the pcap file to dump the output data
 */

// esirich: add separate control output		 
static pcap_dumper_t *pdumper, *pdumper_up, *pdumper_control;
static pcap_t *pd, *pd_up, *pd_control;
static char errbuf[PCAP_ERRBUF_SIZE];
// esirich: add separate control output		
static int gtp_control_packet;

void write_pcap_start(char *filename)
{
	if(!pdumper)
	{

		pd = pcap_open_dead(DLT_EN10MB, 65535 /* snaplen */);

    /* Create the output file. */
		pdumper = pcap_dump_open(pd, filename);
	}
}

void write_pcap_start_upstream(char *filename)
{
	if(!pdumper_up)
	{

		pd_up = pcap_open_dead(DLT_EN10MB, 65535 /* snaplen */);

    /* Create the output file. */
		pdumper_up = pcap_dump_open(pd_up, filename);
	}
}

void write_pcap_start_control(char *filename)
{
	if(!pdumper_control)
	{

		pd_control = pcap_open_dead(DLT_EN10MB, 65535 /* snaplen */);

    /* Create the output file. */
		pdumper_control = pcap_dump_open(pd_control, filename);
	}
}

/*
 * set up the output interface that will receive the simulated traffic
 * 
 * Parameters:- 
 *   - interface: the network interface to dump the output data
 */

void write_pcap_start_interface(char *interface)
{
	if(!pd)
	{
		pd = pcap_open_live(interface, 65535, 0, 1, errbuf);
		
		if(!pd)
		{
			perror(errbuf);
			exit(255);
		}
	}
}


/*
 * set up the output interface that will receive the upstream simulated 
 * traffic (if required)
 * 
 * Parameters:- 
 *   - interface: the network interface to dump the output data
 */

void write_pcap_start_interface_upstream(char *interface)
{
	if(!pd_up)
	{
		pd_up = pcap_open_live(interface, 65535, 0, 1, errbuf);
		
		if(!pd_up)
		{
			perror(errbuf);
			exit(255);
		}
	}
}

// esirich: add separate control output		
void write_pcap_start_interface_control(char *interface)
{
	if(!pd_control)
	{
		pd_control = pcap_open_live(interface, 65535, 0, 1, errbuf);
		
		if(!pd_control)
		{
			perror(errbuf);
			exit(255);
		}
	}
}


/*
 * close the output
 * 
 * Parameters:- 
 *   (none)
 */
void write_pcap_end(void)
{
	if(pdumper)
	{
		pcap_dump_close(pdumper);
		pdumper = 0;
	}
	
	if(pdumper_up)
	{
		pcap_dump_close(pdumper_up);
		pdumper_up = 0;
	}

// esirich: add separate control output		
	if(pdumper_control)
	{
		pcap_dump_close(pdumper_control);
		pdumper_control = 0;
	}
	
	if(pd)
	{
		pd = 0;
	}
}

static void write_pcap_live(pcap_t *p, char *packet, int length)
{
	int i;
	
	for(i = 1000000; pcap_sendpacket(p, packet, length) 
			&& i ; i--)
		gtp_write_misses++;
	
	if(!i)
	{
		perror("write_pcap_live: cannot send packet");
		exit(23);
	}
}

/*
 * write a packet using the pcap library
 * 
 * Parameters:- 
 *   - payload: the buffer containing the packet
 *   - length: how many bytes are in the packet
 */
static void write_pcap(char *payload, int length, int upstream, int control)
{
	static struct pcap_pkthdr header;

    gtp_write_packets++;
    gtp_write_bytes += length;

        /* write packet to savefile */
// esirich: add separate control output		
	if((control && pdumper_control) || pdumper)
	{
#ifndef OPTIMISE
		gettimeofday(&header.ts, 0);
#else
		if((header.ts.tv_usec++ & 0x00004FFF) == 0)
		{
			time_t now;
			
			time(&now);

/* memcmp is quicker than difftime and more portable than '=' */			
			if(!header.ts.tv_sec || memcmp(&(header.ts.tv_sec), &now, sizeof(time_t)))
			{
				memcpy(&(header.ts.tv_sec), &now, sizeof(time_t)); 
				header.ts.tv_usec = 0;
			}
		}
#endif
		header.caplen = length;
		header.len = length;

// esirich: fix separate control output		
		if(control && pdumper_control)
		{
			pcap_dump((u_char *) pdumper_control, &header, payload);
		}
		else if(upstream && pdumper_up)
		{
			pcap_dump((u_char *) pdumper_up, &header, payload);
		}
		else
		{
			pcap_dump((u_char *) pdumper, &header, payload);
		}

#ifndef OPTIMISE
		pcap_dump_flush(pdumper);
#endif
	}
// esirich: fix separate control output		
	else if((control && pd_control) || pd)
	{
// esirich: add separate control output		
		if(control && pd_control)
		{
			write_pcap_live(pd_control, payload, length);
		}
		else if(upstream && pd_up)
		{
			write_pcap_live(pd_up, payload, length);
		}
		else
		{
			write_pcap_live(pd, payload, length);
		}
	}
}

/*
 * Write the payload as an Ethernet IP frame & stick it in the pcap file
 * 
 * Parameters:- 
 *   - payload: the buffer containing the packet
 *   - length: how many bytes are in the packet
 *   - src_mac: the address the packet is supposed to originate from
 *   - dest_mac: the address the packet is supposed to be delivered to
 */
#ifdef OPTIMISE
static char stack_buffer[ETH_FRAME_LEN];
#endif
static void write_ethernet(char *payload, int length,
							char *src_mac, char *dest_mac, int upstream)
{
//#define ETH_FRAME_LEN 1518
#ifdef OPTIMISE
	char *buffer = stack_buffer;
#else
	char buffer[ETH_FRAME_LEN];
#endif
	int i;
	unsigned char* etherhead = buffer;
	unsigned char* data = buffer + 14;
	struct ethhdr *eh = (struct ethhdr *)etherhead;
	unsigned int crc_table[] =
	{
		0x4DBDF21C, 0x500AE278, 0x76D3D2D4, 0x6B64C2B0,
		0x3B61B38C, 0x26D6A3E8, 0x000F9344, 0x1DB88320,
		0xA005713C, 0xBDB26158, 0x9B6B51F4, 0x86DC4190,
		0xD6D930AC, 0xCB6E20C8, 0xEDB71064, 0xF0000000,
	};
  unsigned int n, crc=0;

/*set the frame header*/
	memcpy((void*)buffer, (const void*) dest_mac, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN), (const void*) src_mac, ETH_ALEN);
	eh->h_proto = 0x0008;

/*fill the frame with some data*/
#ifndef OPTIMISE
	if(length > ETH_FRAME_LEN - 18) length = ETH_FRAME_LEN - 18;
		memcpy(buffer + 14, payload, length);

	for (i=0; i<length + 14; i++)
	{
		crc = (crc >> 4) ^ crc_table[(crc ^ (buffer[i] >> 0)) & 0x0F];  /* lower nibble */
		crc = (crc >> 4) ^ crc_table[(crc ^ (buffer[i] >> 4)) & 0x0F];  /* upper nibble */
	}

	for (i=0; i<4; i++)  /* display the CRC, lower byte first */
	{
		buffer[length + 14 + i] = (crc & 0xFF);
		crc >>= 8;
	}
#endif
	
	write_pcap(buffer, 14 + length + 4, upstream, gtp_control_packet);
}

/* Defines to read and write from buffers */
#define READ_16(p)		((((unsigned char *)p)[0]<<8) \
						| (((unsigned char *)p)[1]))
#define WRITE_16(p, x)	{((char *)p)[0]=(((x)>>8)& 0x0FF);\
						((char *)p)[1]=((x)&0x0FF);}
#define WRITE_32(p, x)	{((char *)p)[0]=(((x)>>24)& 0x0FF);\
						((char *)p)[1]=(((x)>>16)& 0x0FF);\
						((char *)p)[2]=(((x)>>8)& 0x0FF);\
						((char *)p)[3]=((x)&0x0FF);}

/*
 * calculate and write in the checksum for an IP packet header
 * 
 * Parameters:-
 *   - IP_buffer: the buffer containing the packet
 */

void make_IP_checksum(char *IP_buffer)
{
	int i;
	unsigned int checksum = 0;
	
	for(i = 0; i < 20; i += 2)
	{
		if(i != 10)
		{
			checksum += READ_16(IP_buffer + i);
			while(checksum > 0x0000FFFF)
			{
				checksum = (checksum & 0x0000FFFF)
						+ (checksum >> 16);
			}
		}
	}
	
	
	WRITE_16(IP_buffer + 10, (~checksum));	
}

/*
 * Write the payload as a UDP packet and pass it to the Ethernet frame
 * 
 * Parameters:-
 *   - src_ip: the source IPv4 address as four bytes
 *   - src_port: the source port
 *   - dst_ip: the destination IPv4 address as four bytes
 *   - dst_port: the destination port
 *   - src_mac: the source ethernet address
 *   - dst_mac: the destination ethernet address
 *   - payload: the buffer containing the packet to go in UDP
 *   - length: how many bytes are in the packet to go in UDP
 */
static void write_udp(unsigned char *src_ip, int src_port, 
					unsigned char *dst_ip, int dst_port,
					char *src_mac, char *dst_mac,
					char *payload, int length, int upstream)
{
#ifdef OPTIMISE
	char *buffer = stack_buffer + 14;
#else
	char buffer[ETH_FRAME_LEN];
#endif
	int i;
	
#ifdef OPTIMISE
	bzero(buffer, 28*sizeof(char));
#else
	bzero(buffer, sizeof(buffer));
#endif
	
	buffer[0]=0x45;
	buffer[1]=0;
	WRITE_16(buffer + 2, length + 28);
	
	buffer[8]=100;
	buffer[9]=0x11;
	
	memcpy(buffer + 12, src_ip, 4);
	memcpy(buffer + 16, dst_ip, 4);
	
	WRITE_16(buffer + 20, src_port);
	WRITE_16(buffer + 22, dst_port);
	WRITE_16(buffer + 24, length + 8);

#ifndef OPTIMISE
	for(i = 0; i < ETH_FRAME_LEN - 28 && i < length; i++)
	{
		buffer[i + 28] = payload[i];
	}
#endif
	
	make_IP_checksum(buffer);
	
	write_ethernet(buffer, length + 28, src_mac, dst_mac, upstream);
}


/*******************************************************************
 * From here on we're in GTP land.
 * These functions start a GTP message, write Information Elements
 * into it, and then send it to UDP.
 */
static unsigned char gtp_message_firstbyte;
static int gtp_message_type;
int gtp_length;
#ifdef OPTIMISE
static char *gtp_buffer = stack_buffer + 14 + 28;
#else
static char gtp_buffer[GTP_FRAME_LEN];
#endif

/*
 * begin assembling a GTP packet
 * 
 * Parameters:-
 *   - version: the GTP protocol version (see 3GPP TS 29.060 section 6)
 *   - message_type: the GTP message type (see 3GPP TS 29.060 section 7.1)
 *   - teid: the TEID of the header (see 3GPP TS 29.060 section 6)
 *   - flags: PT/E/S/PN flags for the first byte (see 3GPP TS 29.060 section 6)
 *   - ext: the bytes making up the 'extension' header; 2 bytes sequence number, 1 byte N-PDU, 1 byte next extension header
 */
static int gtp_GGSN_port, gtp_SGSN_port;
void write_gtp_start(int version, int message_type, unsigned int teid, int flags, int ext)
{
	gtp_GGSN_port = gtpc_GGSN_port;
	gtp_SGSN_port = teid;

	gtp_message_type = message_type;
	gtp_length = GTP_MIN_HDR_LEN;
#ifdef OPTIMISE
	bzero(gtp_buffer, GTP_FRAME_LEN);
#else
	bzero(gtp_buffer, 8*sizeof(char));
#endif
	
	if(flags & 0x07)
	{
		gtp_length = GTP_MAX_HDR_LEN;
    WRITE_32(gtp_buffer+8, ext);
	}
	
	gtp_buffer[0]=(version << 5) | flags;
	WRITE_32(gtp_buffer + 4,  message_type == 16 ? 0 :teid);
}

/*
 * complete and send a GTP packet
 * 
 * Parameters:-
 *   - send_up: if this is non-zero, send the packet to GGSN
 *              otherwise send from GGSN
 */
void write_gtp_end(int send_up)
{
	gtp_buffer[1] = gtp_message_type;
	WRITE_16(gtp_buffer + 2, gtp_length - 8);
	
	if(send_up)
	{
		write_udp(gtp_SGSN_ip, gtp_SGSN_port,
				gtp_GGSN_ip, gtp_GGSN_port,
				gtp_SGSN_mac, gtp_GGSN_mac, 
				gtp_buffer, gtp_length, 1);
	}
	else
	{
		write_udp(gtp_GGSN_ip, gtp_GGSN_port,
				gtp_SGSN_ip, gtp_SGSN_port,
				gtp_GGSN_mac, gtp_SGSN_mac, 
				gtp_buffer, gtp_length, 0);
	}
}

/*
 * Add an information element to a previously-opened GTP-C packet
 * 
 * Parameters:-
 *   - type: as defined in 3GPP TS 29.060 section 7.7
 *   - length: of information element data: encoded in TLV case
 *   - payload: bytes to be written to information element 
 */
void write_gtp_IE(int type, int length, char *payload)
{
	int i;

	gtp_control_packet = 1;
	gtp_buffer[gtp_length++] = type;
	
	if(type > 127)
	{
		WRITE_16(gtp_buffer + gtp_length, length);
		gtp_length += 2;
	}
	
	if(length > GTP_FRAME_LEN - gtp_length)
	{
		length = GTP_FRAME_LEN - gtp_length;
	}
	
	memcpy(gtp_buffer + gtp_length, payload, length);
	gtp_length += length;
}

/*
 * encode a user-plane IP packet in the previously-opened GTP packet, 
 * ready to send with write_gtp_end()
 * 
 * Parameters:-
 *   - length: of the IP packet to encode
 *   - payload: pointer to the IP packet to encode
 */

void write_gtp_PDU(int length, char *payload)
{
	gtp_GGSN_port = gtpu_GGSN_port;
	gtp_SGSN_port = gtpu_SGSN_port;
	gtp_control_packet = 0;

	if(length > GTP_FRAME_LEN - gtp_length)
	{
		length = GTP_FRAME_LEN - gtp_length;
	}
	
	memcpy(gtp_buffer + gtp_length, payload, length);
	gtp_length += length;
}
