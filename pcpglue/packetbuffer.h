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
* File: packetbuffer.h
* Date: Oct 8, 2012
* Author: LMI/LXR/PE Simon Richardson
************************************************************************/

/**********************************************************************
 * This is headers for a packet buffer pool.  It creates the pool, 
 * assigns the buffers to one of a number of output queues, and the
 * frees them in turn.
 * It is controlled by mutexes to make it thread-safe.
 **********************************************************************/

/* enough for an Ethernet frame and a bit more */
#define PACKET_MAX_BYTES	1600

typedef struct packetbuffer_struct *packetbuffer;

/*
 * Initializes a packet buffer with the supplied number of queues and packets
 * 
 */
packetbuffer packetbuffer_start(int queues, int packets);

/*
 * Deletes a pre-existing packetbuffer and frees all the associated storage
 */
void packetbuffer_end(packetbuffer pb);

/*
 * Grabs the index of the next free packet
 * 
 * @param pb The packetbuffer to get a free packet from
 * 
 * @return The index of the next free packet
 */
int packetbuffer_grab_free(packetbuffer pb);

/*
 * Adds the given packet to an output queue
 * 
 * @param pb The packetbuffer to use
 * @param queue The index of the queue to add the packet to
 * @param packet The index of the packet to add
 */
void packetbuffer_queue(packetbuffer pb, int queue, int packet); 

/*
 * Gets the index of the next packet in the given queue
 * 
 * @param pb The packetbuffer to use
 * @param queue The index of the queue to access
 * @param wait Non-zero indicates that the method should wait for a free packet if there is none
 * 
 * @return The index of the next packet.  A value of 0 indicates that no packet could be obtained
 */
int packetbuffer_grab_next(packetbuffer pb, int queue, int wait);

/*
 * Releases the given packet, once the packet has been released from all queues
 * the packet is reinserted into the free queue for reuse
 * 
 * @param pb The packet buffer in which the packet belongs
 * @param packet The index of the packet in question
 */
void packetbuffer_release(packetbuffer pb, int packet);

/*
 * Returns a pointer to the header information for the packet at the given index
 * 
 * @param pb The packet buffer which contains the desired packet
 * @param packet The index of the packet to get the header information
 * 
 * @return The pcap packet header structure of the given packet
 */
struct pcap_pkthdr *packetbuffer_header(packetbuffer pb, int packet);

/*
 * Returns a pointer to the data for the packet at the given index
 * 
 * @param pb The packet buffer which contains the desired packet
 * @param packet The index of the packet to get the data from
 * 
 * @return A char array containing the packet's data
 */
unsigned char *packetbuffer_data(packetbuffer pb, int packet);
