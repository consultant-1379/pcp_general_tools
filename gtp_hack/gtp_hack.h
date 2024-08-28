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
* File: gtp_hack.h
* Date: Oct 8, 2012
* Author: LMI/LXR/PE Simon Richardson
************************************************************************/

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define GTP_FRAME_LEN (ETH_FRAME_LEN - 28 - 14)
#define GTP_MAX_HDR_LEN 12
#define GTP_MIN_HDR_LEN 8
#define GTP_MAX_SAFE_PAYLOAD_LEN (GTP_FRAME_LEN - GTP_MAX_HDR_LEN)
#define GTP_UP 1
#define GTP_DOWN 0

#if !defined(GTP_HACK_C)
extern int gtp_length;
extern unsigned long long gtp_write_packets, gtp_write_bytes, gtp_write_misses;

extern char *gtp_SGSN_mac;;
extern int gtpc_SGSN_port;
extern int gtpu_SGSN_port;
extern char *gtp_SGSN_ip;
extern char gtp_new_SGSN_ip[4];
extern char new_teid_c[4];
extern char new_teid_d_sgsn[4];
extern char gtp_new_GGSN_ip[4];


extern char *gtp_GGSN_mac;
extern int gtpc_GGSN_port;
extern int gtpu_GGSN_port;
extern char *gtp_GGSN_ip;
#endif

void write_pcap_start(char *filename);
void write_pcap_start_upstream(char *filename);
void write_pcap_start_interface_upstream(char *interface);
void write_pcap_start_interface(char *interface);
void write_pcap_end(void);

void make_IP_checksum(char *IP_buffer);

void write_gtp_start(int version, int message_type, unsigned int teid, int flags, int ext);
void write_gtp_end(int send_up);
void write_gtp_IE(int type, int length, char *payload);
void write_gtp_PDU(int length, char *payload);

