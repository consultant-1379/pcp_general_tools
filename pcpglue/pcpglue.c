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
 * File: pcpglue.c
 * Date: December 7, 2012
 * Author: LMI/LXR/PE Simon Richardson
 ************************************************************************/

/**********************************************************************
 * This code reads a packet from either a file or a live interface,
 * then writes that packet to a list of output files.  The output
 * files need only exist in the filesystem: they could be files, 
 * devices or pipes.
 * 
 * An option exists to un-tunnel the packets by removing the GTP
 * header from the packet.
 **********************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include "pcpglue.hpp"
#include "classify.h"
#include "packetbuffer.h"

// ip stuff for the gtpv1 header find function
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "include/gtp_ie_gtpv2.h"

// TODO: a logger!
#define log_message		printf

typedef struct packet_source_struct *packet_source;
typedef struct packet_sink_struct *packet_sink;

static packetbuffer packet_pool;


enum capture_from{
	CAPTURE_FILE,
	CAPTURE_LIVE
};

struct packet_source_struct {
	pthread_mutex_t mutex;
	pthread_t thread;
	enum capture_from capture_type;
	const char *source_name;
	pcap_t *input;
	int queue; // queue for output: 0 = hash on UE-IP
	unsigned long bytes, packets, truncated;
};

struct packet_sink_struct {
	pthread_mutex_t mutex;
	pthread_t thread;
	int queue; // queue for input
	classify_data cd;
	unsigned long bytes, packets, truncated;
};

static packet_source config_source_array;
static int config_source_count;
static packet_sink config_sink_array;
static int config_sink_count;

struct ipv4{
	unsigned int sourceAddress:32;
	unsigned int destinationAddress:32;
};

ipv4 * get_ip_header(const struct pcap_pkthdr *header, const unsigned char *packet) {
	const struct ether *ethernet = (struct ether *) packet;
	unsigned char * data = (unsigned char *) ethernet;

	//get the GTP header this allows us to ignore VLANs
	struct gtpv1hdr* gtpv1hdr = gtpv1_get_header(header->caplen, (const unsigned char *) packet);
	int GTPFlags = gtpv1hdr->flag_options;
	int IPLocation = 0;
	//account for the two sizes of GTP header
	if (GTPFlags > 0) {
		IPLocation = 0x0c;
	} else {
		IPLocation = 0x08;
	}
	int theLengthOfTheGTPHeader = readByteArray(
			(unsigned char*) &(gtpv1hdr->length), 2, 0);
	unsigned char* theGTPHeaderIndex = (unsigned char *) gtpv1hdr;

	unsigned char* thePacket = &theGTPHeaderIndex[IPLocation];

	return (ipv4 *) &thePacket[0xc];
}

//this has been put in place for initial testing
//TODO Link the configuration to the macOfKnowElement and make it a list (array) of macs.
unsigned long macOfKnownElement = 0x002102FA70AA;
unsigned int theIPForHashSearch = 0;

void source_next_packet(u_char *config_source_ptr, const struct pcap_pkthdr *h, const u_char *bytes)
{
	packet_source input = (packet_source) config_source_ptr;
	int pool_packet, queue;
	struct pcap_pkthdr *ut_h;
	static char *packet;

	long theSourceMacAddress = readByteArray((unsigned char*)bytes, 6, 0);
	long theDestinationMacAddress = readByteArray((unsigned char*)bytes, 6, 6);

	pool_packet = packetbuffer_grab_free(packet_pool);
	ut_h = packetbuffer_header(packet_pool, pool_packet);
	packet = (char *) packetbuffer_data(packet_pool, pool_packet);

	memcpy(ut_h, h, sizeof(struct pcap_pkthdr));
	if(ut_h->caplen > PACKET_MAX_BYTES)
	{
		ut_h->caplen = PACKET_MAX_BYTES;
		input->truncated++;
	}

	memcpy(packet, bytes, ut_h->caplen);

	pthread_mutex_lock(&(input->mutex));
	input->bytes += h->caplen;
	input->packets++;
	pthread_mutex_unlock(&(input->mutex));

	char ip;
	if(!input->queue)
	{
		ipv4 * ip = get_ip_header(h,bytes);

		if(macOfKnownElement == theSourceMacAddress ) {
			//packetDirection = HEADING_TO_USER_EQUIPMENT;
			theIPForHashSearch = ip->sourceAddress;
			//packetsDown++;
		} else {
			//packetDirection = HEADING_TO_INTERNET;
			theIPForHashSearch = ip->destinationAddress;
			//packetsUp++;
		}
		queue = ntohl(theIPForHashSearch) & 3; // The number specified here should be (config_sink_count - 1), but it's hard coded to reduce the clock cycles requires.

		//printf("  IF: The IP is %x  %x", ntohl(0x03000000), theIPForHashSearch);
		queue++;
		//printf("  IF: The queue is: %i \n", queue);
	}
	else
	{
		queue = input->queue;
	}

	packetbuffer_queue(packet_pool, queue, pool_packet);

	packetbuffer_release(packet_pool, pool_packet);
}

void *source_main(void *init) {
	packet_source source;

	source = (packet_source) init;

	switch(pcap_loop(source->input, -1, &source_next_packet, (u_char *) source)) {
	default:
		log_message("problem buffering %s: %s\n",
				source->source_name,
				pcap_geterr(source->input)
		);
	case 0: break;
	}

	return(0);
}

void *sink_main(void *init) {
	packet_sink sink;
	int pool_packet;
	struct pcap_pkthdr *ut_h;
	static char *packet;

	sink = (packet_sink) init;

	sink->cd = classify_start();

	if(!sink->cd)
	{
		perror("Cannot start classifier\n");
		exit(255);
	}

	while(1) // never return
	{
		pool_packet = packetbuffer_grab_next(packet_pool, sink->queue, 1);

		ut_h = packetbuffer_header(packet_pool, pool_packet);
		packet = (char *) packetbuffer_data(packet_pool, pool_packet);

		classify(sink->cd, ut_h, packet);

		pthread_mutex_lock(&sink->mutex);
		sink->packets++;
		sink->bytes += ut_h->len;
		pthread_mutex_unlock(&sink->mutex);

		packetbuffer_release(packet_pool, pool_packet);
	}	

	classify_end(sink->cd);
}

static char errbuf[PCAP_ERRBUF_SIZE];
#define SNAPLEN	65536

int sink_start(void) {
	pthread_attr_t attr;
	int i;

	pthread_attr_init(&attr);

	// open the sink output threads

	for(i = 0; i < config_sink_count; i++)
	{
		pthread_mutex_init(&(config_sink_array[i].mutex), 0);
		pthread_create(&(config_sink_array[i].thread), &attr, sink_main, 
				&(config_sink_array[i]));
	}

	pthread_attr_destroy(&attr);

	// TODO: something about waiting for these threads to finish?

	return(0);
}

int source_start(void) {
	pthread_attr_t attr;
	int i;

	pthread_attr_init(&attr);

	for(i = 0; i < config_source_count; i++)
	{
		if(config_source_array[i].capture_type == CAPTURE_LIVE) {
			config_source_array[i].input = pcap_open_live(
					config_source_array[i].source_name, 
					SNAPLEN, 0, 0, errbuf);


			if(!config_source_array[i].input) {
				log_message("Cannot open interface \"%s\" for input: %s",
						config_source_array[i].source_name,
						errbuf);

				return(1);
			}
		} else {
			config_source_array[i].input = pcap_open_offline(
					config_source_array[i].source_name, errbuf);


			if(!config_source_array[i].input) {
				log_message("Cannot open file \"%s\" for input: %s",
						config_source_array[i].source_name,
						errbuf);

				return(1);
			} 
		}

		pthread_mutex_init(&(config_source_array[i].mutex), 0);
		// open the source input for capture

		pthread_create(&(config_source_array[i].thread), &attr, 
				source_main, &(config_source_array[i]));
	}

	pthread_attr_destroy(&attr);

	// TODO: something about waiting for this thread to finish?

	return(0);
}

int config_read(int argument_count, char *args[])
{

	// TODO: some kind of reading in of parameters
	config_source_count = 1;
	config_source_array = (packet_source_struct *) calloc(config_source_count, sizeof(struct packet_source_struct));
	config_source_array[0].capture_type = CAPTURE_LIVE;
	config_source_array[0].source_name = "nt3g2";
	config_source_array[0].queue = 0;

	config_sink_count = 4; // When updating the number of sinks, make sure to update the number at the end of the queue variable in source_next_packet function.
	config_sink_array = (packet_sink_struct *) calloc(config_sink_count, sizeof(struct packet_sink_struct));
	config_sink_array[0].queue = 1;
	config_sink_array[1].queue = 2;
	config_sink_array[2].queue = 3;
	config_sink_array[3].queue = 4;

	return(0);
}

extern int freePacketCount;

void source_monitor(int seconds)
{
	int i;


	for(i = 0; i < config_source_count; i++)
	{
		unsigned long packets, bytes;

		pthread_mutex_lock(&(config_source_array[i].mutex));
		packets = config_source_array[i].packets;
		bytes = config_source_array[i].bytes;
		config_source_array[i].packets = 0;
		config_source_array[i].bytes = 0;
		pthread_mutex_unlock(&(config_source_array[i].mutex));

		printf("PCPglue input from %s: %ld packets, %ld bytes, %ld bits/sec\n",
				config_source_array[i].source_name,
				packets,
				bytes,
				(bytes * 8)/ seconds);
	}

	for(i = 0; i < config_sink_count; i++)
	{
		unsigned long packets, bytes;

		pthread_mutex_lock(&(config_sink_array[i].mutex));
		packets = config_sink_array[i].packets;
		bytes = config_sink_array[i].bytes;
		config_sink_array[i].packets = 0;
		config_sink_array[i].bytes = 0;
		pthread_mutex_unlock(&(config_sink_array[i].mutex));

		printf("PCPglue output to queue %d: %ld packets, %ld bytes, %ld bits/sec\n",
				i + 1,
				packets,
				bytes,
				(bytes * 8)/ seconds);
	}

	classify_print_log(stdout);
}

void * startTheSinkSourceAndMonitorOfPCPGlue(void *init){

	if(config_read(1, 0)) {
		perror("Cannot set up config");
		exit(255);
	}

	packet_pool = packetbuffer_start(config_sink_count + 1, 1000000);

	sink_start();
	source_start();

	int time=5;
	while(1) {
		source_monitor(time);
		sleep(time);
	}

	// TODO: something about logging, returning, and intercepting signals
	return(0); // for now, will never happen
}
