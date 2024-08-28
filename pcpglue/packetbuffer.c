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

#include <pcap.h>

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include "packetbuffer.h"

// Hacking in the ip stuff
#include <net/ethernet.h>
#include "classify.h"
// End of hack

#ifndef TEST
# define OPTIMISE
#endif

#ifndef OPTIMISE
#define ASSERT(x)														\
{ 																		\
	if(!(x)) { 															\
		fprintf(stderr, "%s:%d ASSERT failed :-(\n", 					\
						__FILE__, __LINE__); 							\
		exit(255); 														\
	}																	\
}																		\

#else
#define ASSERT(x)	/* do nothing */
#endif

struct packetqueue_struct {
	int first, last;
	pthread_cond_t queue_semaphore;
};

struct packetpool_struct {
	unsigned char data[PACKET_MAX_BYTES];
	struct pcap_pkthdr header;
	int number_of_queues;
	int *next;
};

struct packetbuffer_struct {
	int queue_count;
	int packet_count;
	struct packetqueue_struct *packetqueues;
	struct packetpool_struct *packetpool;
	int free;
	pthread_cond_t free_semaphore;
	pthread_mutex_t packet_mutex;
};

int freePacketCount = 0;



/*
 * This creates a packetbuffer which supports a fixed number
 * of queues and packets
 */

packetbuffer packetbuffer_start(int queues, int packets) {
	freePacketCount = packets;
	packetbuffer ret;
	int i;

	ASSERT(queues > 0 && packets > 0);

	ret = (packetbuffer) calloc(1, sizeof(struct packetbuffer_struct));

	if (ret) {
		ret->queue_count = queues;
		ret->packet_count = packets;
		ret->packetqueues = (packetqueue_struct*) calloc(ret->queue_count,
				sizeof(struct packetqueue_struct));

		if (!ret->packetqueues) {
			free(ret);
			return (0);
		}

		ret->packetpool = (packetpool_struct*) calloc(ret->packet_count,
				sizeof(struct packetpool_struct));

		if (!ret->packetpool) {
			free(ret->packetqueues);
			free(ret);
			return (0);
		}

		/* add all the new packets to the free packet queue */
		ret->free = 1;
		for (i = 0; i < ret->packet_count; i++) {
			ret->packetpool[i].next = (int *) calloc(ret->queue_count + 1,
					sizeof(int));

			if (!ret->packetpool[i].next) {
				while (i > 0) {
					free(ret->packetpool[--i].next);
				}

				free(ret->packetpool);
				free(ret->packetqueues);
				free(ret);
				return (0);
			}

			if (i < ret->packet_count - 1) {
				ret->packetpool[i].next[0] = i + 2;
			}
		}

		for (i = 0; i < ret->queue_count; i++) {
			pthread_cond_init(&(ret->packetqueues[i].queue_semaphore), 0);
		}

	}

	pthread_cond_init(&(ret->free_semaphore), 0);
	pthread_cond_signal(&(ret->free_semaphore)); // free packets available
	pthread_mutex_init(&(ret->packet_mutex), 0);

	return (ret);
}

/*
 * This deletes a pre-existing packetbuffer and frees
 * all the associated storage
 */
void packetbuffer_end(packetbuffer pb) {
	int i;

	ASSERT(pb);

	pthread_mutex_lock(&(pb->packet_mutex));

	free(pb->packetqueues);

	for (i = 0; i < pb->packet_count - 1; i++) {
		free(pb->packetpool[i].next);
		pb->packetpool[i].next = 0;
	}

	for (i = 0; i < pb->queue_count; i++) {
		pthread_cond_destroy(&(pb->packetqueues[i].queue_semaphore));
	}

	pthread_cond_destroy(&(pb->free_semaphore));
	pthread_mutex_destroy(&(pb->packet_mutex));

	free(pb->packetpool);
	free(pb);
}

/*
 * This grabs a free packetbuffer
 */
int packetbuffer_grab_free(packetbuffer pb) {
	int ret;
	struct packetpool_struct *pkt;

	ASSERT(pb);

	pthread_mutex_lock(&(pb->packet_mutex));
	while (!pb->free) {
		pthread_cond_wait(&(pb->free_semaphore), &(pb->packet_mutex));
	}

	ret = pb->free;
	pkt = &(pb->packetpool[ret - 1]);

	pb->free = pkt->next[0];
	pkt->next[0] = 0;
	pkt->number_of_queues = 1;
	freePacketCount--;
	pthread_mutex_unlock(&(pb->packet_mutex));

	return (ret);
}

/*
 * This releases the interest in a packet.  If the packet is queued
 * on other queues it stays on the queues, if not it returns to the
 * free pool.
 */

void packetbuffer_release(packetbuffer pb, int packet) {
	ASSERT(pb && packet > 0 && packet <= pb->packet_count);

	pthread_mutex_lock(&(pb->packet_mutex));

	if (--(pb->packetpool[packet - 1].number_of_queues) == 0) {
		if (!pb->free) {
			pthread_cond_signal(&(pb->free_semaphore));
		}

		pb->packetpool[packet - 1].next[0] = pb->free;
		pb->free = packet;
		freePacketCount++;
	}

	pthread_mutex_unlock(&(pb->packet_mutex));
}



void packetbuffer_queue(packetbuffer pb, int queue, int packet) {
	struct packetqueue_struct *q;
	struct packetpool_struct *pkt;
	int last;

	ASSERT(pb); ASSERT(queue > 0 && queue <= pb->queue_count); ASSERT(packet > 0 && packet <= pb->packet_count);

	pthread_mutex_lock(&(pb->packet_mutex));

	pkt = &(pb->packetpool[packet - 1]);
	q = &(pb->packetqueues[queue - 1]);

	last = q->last;

	if (!last) {
		q->first = packet;
		pthread_cond_signal(&(q->queue_semaphore));
	} else {
		pb->packetpool[last - 1].next[queue] = packet;
	}

	q->last = packet;
	pkt->number_of_queues++;
	pkt->next[queue] = 0;

	pthread_mutex_unlock(&(pb->packet_mutex));
}

/*
 * Get the next packet off the queue.
 * If wait is zero and there are no packets on the queue it returns
 * zero.  If the wait is nonzero then it waits until a packet is 
 * available on the queue, and returns that.
 */
int packetbuffer_grab_next(packetbuffer pb, int queue, int wait) {
	struct packetqueue_struct *q;
	struct packetpool_struct *pkt;
	int ret;

	ASSERT(pb); ASSERT(queue > 0 && queue <= pb->queue_count);

	pthread_mutex_lock(&(pb->packet_mutex));

	q = &(pb->packetqueues[queue - 1]);

	while (!q->first) {
		if (!wait)
			return (0);

		pthread_cond_wait(&(q->queue_semaphore), &(pb->packet_mutex));
	}

	ret = q->first;

	pkt = &(pb->packetpool[ret - 1]);

	q->first = pkt->next[queue];

	if (!q->first) {
		q->last = 0;
	}

	pthread_mutex_unlock(&(pb->packet_mutex));

	return (ret);
}

/*
 * Returns a pointer to the header information for the packet
 */
struct pcap_pkthdr *packetbuffer_header(packetbuffer pb, int packet) {
	ASSERT(pb); ASSERT(packet > 0 && packet <= pb->packet_count);
	return (&pb->packetpool[packet - 1].header);
}

/*
 * Returns a pointer to the data buffer for the packet
 */
unsigned char *packetbuffer_data(packetbuffer pb, int packet) {
	ASSERT(pb); ASSERT(packet > 0 && packet <= pb->packet_count);
	return (pb->packetpool[packet - 1].data);
}

#if defined(TEST)
#include <string.h>

/* Although this function will work outside the test environment,
 * don't call it, because it will take a long time.  
 * You don't need to know the sizes of the queues or the free
 * packets in the pool, except for testing.
 * 
 * And there is no mutex.  So ... just don't do it.
 */
static int packet_queue_count(packetbuffer pb, int queue)
{
	ASSERT(pb);
	ASSERT(queue >= 0 && queue <= pb->queue_count);
	int ret = 0, packet;

	if(queue == 0)
	{ /* count free packets */
		for(packet = pb->free;
				packet;
				packet = pb->packetpool[packet - 1].next[queue])
		{
			ret++;
		}
	}
	else
	{ /* count packets in queue */
		for(packet = pb->packetqueues[queue - 1].first;
				packet;
				packet = pb->packetpool[packet - 1].next[queue])
		{
			ret++;
		}
	}

	return(ret);
}

int main(void)
{
	/*
	 * Random bit of Victorian poetry serves as our "packets".
	 * James Kenneth Stephen was an Eton scholar and athlete, tutor to
	 * the grandson of Queen Victoria and, according to some conspiracy
	 * theories, a Jack the Ripper suspect.
	 *
	 * Rudyard Kipling wrote "The Jungle Book", and Henry Rider
	 * Haggard's character, Allan Quatermain, has recently returned
	 * to fame as one of the characters in Alan Moore's "League of
	 * Extraordinary Gentlemen", and, according to Spielberg, served
	 * as a prototype for Indiana Jones.
	 */
	char *packets[]= {
		"WILL there never come a season",
		"Which shall rid us from the curse",
		"Of a prose which knows no reason",
		"And an unmelodious verse:",
		"When the world shall cease to wonder",
		"At the genius of an ass,",
		"And a boy's eccentric blunder",
		"Shall not bring success to pass:",
		" ",
		"When mankind shall be delivered",
		"From the clash of magazines,",
		"And the inkstand shall be shivered",
		"Into countless smithereens:",
		"When there stands a muzzled stripling,",
		"Mute, beside a muzzled bore:",
		"When the Rudyards cease from kipling",
		"And the Haggards ride no more.	",
		"		\"To R.K\", James Kenneth Stephen"
	};
	packetbuffer pb;
	int i;

	pb = packetbuffer_start(3, 1000000);

	if(!pb)
	{
		fprintf(stderr, "Cannot allocate packet buffer\n");
		return(1);
	}

	printf("%d:%d:%d:%d\n",
			packet_queue_count(pb, 1),
			packet_queue_count(pb, 2),
			packet_queue_count(pb, 3),
			packet_queue_count(pb, 0));

	for(i = 0; i < sizeof(packets)/sizeof(char *); i++)
	{
		int pool_packet, len;
		struct pcap_pkthdr *header;
		char *data;

		pool_packet = packetbuffer_grab_free(pb);

		if(pool_packet)
		{
			len = strlen(packets[i]);

			header = packetbuffer_header(pb, pool_packet);
			data = (char *) packetbuffer_data(pb, pool_packet);

			memcpy(data, packets[i], strlen(packets[i]));
			header->caplen = len;
			header->len = len;
			gettimeofday(&(header->ts), 0);

			packetbuffer_queue(pb, 1, pool_packet);

			if(i < sizeof(packets)/(2*sizeof(char *)))
			{
				packetbuffer_queue(pb, 2, pool_packet);
			}
			else
			{
				packetbuffer_queue(pb, 3, pool_packet);
			}

			packetbuffer_release(pb, pool_packet);
			printf("%d:%d:%d:%d\n",
					packet_queue_count(pb, 1),
					packet_queue_count(pb, 2),
					packet_queue_count(pb, 3),
					packet_queue_count(pb, 0));
		}
	}

	printf("%d:%d:%d:%d\n",
			packet_queue_count(pb, 1),
			packet_queue_count(pb, 2),
			packet_queue_count(pb, 3),
			packet_queue_count(pb, 0));

	for(i = 1; i <= 3; i++)
	{
		int pool_packet;

		do
		{
			pool_packet = packetbuffer_grab_next(pb, i, 0);

			if(pool_packet)
			{
				struct pcap_pkthdr *header;
				char *data;

				header = packetbuffer_header(pb, pool_packet);
				data = (char *) packetbuffer_data(pb, pool_packet);

				printf("Queue %d: %d:%06d \t\"%s\" (length %d of %d)\n",
						i,
						header->ts.tv_sec, header->ts.tv_usec,
						data,
						header->caplen,
						header->len);

				packetbuffer_release(pb, pool_packet);

				printf("%d:%d:%d:%d\n",
						packet_queue_count(pb, 1),
						packet_queue_count(pb, 2),
						packet_queue_count(pb, 3),
						packet_queue_count(pb, 0));
			}
		}
		while(pool_packet);
	}

	printf("%d:%d:%d:%d\n",
			packet_queue_count(pb, 1),
			packet_queue_count(pb, 2),
			packet_queue_count(pb, 3),
			packet_queue_count(pb, 0));

	packetbuffer_end(pb);
	return(0);
}
#endif
