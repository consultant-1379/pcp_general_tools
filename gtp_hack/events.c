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
* File: events.c
* Date: December 13, 2012
* Author: LMI/LXR/PE Simon Richardson
************************************************************************/

/*
 * Provide a separate interface to an events thread which calls external
 * code when the simulator undergoes state transitions.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
 
#include "events.h"

#define EVENTS_QUEUE_COUNT 		(1 << (EVENTS_QUEUE_COUNT_BITS))
#define EVENTS_QUEUE_COUNT_MASK	((1 << (EVENTS_QUEUE_COUNT_BITS)) - 1)
#define EVENTS_QUEUE_NEXT(q)	(((q)+1) & EVENTS_QUEUE_COUNT_MASK)

static FILE *out;

static int events_call(int ue, enum ue_state_enum newstate, int RAI, time_t timestamp)
{
	int i, lac;
	struct tm utc;
	
	switch(newstate)
	{
	default: return;

	case UE_STATE_CONNECTING:
		fputs("SETUP,", out);
		break;

	case UE_STATE_UPDATING:
		fputs("CELLCHANGE,", out);
		break;

	case UE_STATE_DISCONNECTING:
		fputs("RELEASE,", out);
		break;
	}

	for(i = 0; i < 20 && i < config_UE_buffer[ue].imei[0] << 1; i++)
	{
		if(i & 1)
		{
			fputc(((config_UE_buffer[ue].imei[1 + (i >> 1)] >> 4) & 0x0F) + '0', out);
		}
		else
		{
			fputc((config_UE_buffer[ue].imei[1 + (i >> 1)] & 0x0F) + '0', out);
		}
	}

	gmtime_r(&timestamp, &utc);

	fprintf(out, ",%04d%02d%02d%02d%02d%02d,%d\n",
			utc.tm_year + 1900,
			utc.tm_mon + 1,
			utc.tm_mday,
			utc.tm_hour,
			utc.tm_min,
			utc.tm_sec,
			0x00FFFF & ((config_RAI_list[RAI][3] << 8) + config_RAI_list[RAI][4]));
}



static struct {
	enum ue_state_enum newstate;
	int ue, RAI;
	time_t timestamp;
} events_queue[EVENTS_QUEUE_COUNT];

static int events_queue_head, events_queue_tail;
static pthread_cond_t events_queue_semaphore;
static pthread_mutex_t events_queue_mutex;
static pthread_t events_queue_thread;
static char events_runstop;

void *events_thread_main(void *init)
{
	int runstop, ue, RAI;
	enum ue_state_enum newstate;
	time_t timestamp;


	do
	{
		int event  = 0;

		pthread_mutex_lock(&events_queue_mutex);
		if(events_queue_head == events_queue_tail)
		{
			pthread_cond_wait(&events_queue_semaphore, &events_queue_mutex);
		}

		if(events_queue_head != events_queue_tail)
		{
			event = 1;
			ue = events_queue[events_queue_tail].ue;
			newstate = events_queue[events_queue_tail].newstate;
			RAI = events_queue[events_queue_tail].RAI;
			memmove(&timestamp, &(events_queue[events_queue_tail].timestamp), sizeof(time_t));

			events_queue_tail = EVENTS_QUEUE_NEXT(events_queue_tail);
		}
		runstop = events_runstop;
		pthread_mutex_unlock(&events_queue_mutex);			
		
		if(event)
		{
			events_call(ue, newstate, RAI, timestamp);
		}		
	}
	while(runstop);	
}

void events_queue_start_thread(void)
{
	pthread_attr_t attr;
	
	if(!config_event_output) return;
	
	if(!strcmp(config_event_output, "-"))
	{
		out = stdout;
	}
	else
	{
		out = fopen(config_event_output, "a+");
	}

	if(!out)
	{
		fprintf(stderr, "Cannot open \"%s\" for writing\n", config_event_output);
		perror("events_queue_start_thread:");
		exit(13);
	}
	
	events_runstop = 1; // allow the thread to continue when it starts
	
	pthread_mutex_init(&events_queue_mutex, 0);
	pthread_cond_init(&events_queue_semaphore, 0);
	pthread_attr_init(&attr);
	pthread_create(&events_queue_thread, &attr, events_thread_main, 0);
	
	pthread_attr_destroy(&attr);
}

void events_queue_stop_thread(void)
{
	if(!out) return;

	pthread_mutex_lock(&events_queue_mutex);
	events_runstop = 0; // the thread should notice and shut down
	pthread_cond_signal(&events_queue_semaphore);
	pthread_mutex_unlock(&events_queue_mutex);
	// this makes sure the thread starts moving again so it can exit
	
	pthread_join(events_queue_thread, 0);
	pthread_cond_destroy(&events_queue_semaphore);
	pthread_mutex_destroy(&events_queue_mutex);
	
	fclose(out);
}

void events_queue_add(int ue, enum ue_state_enum newstate, int RAI, time_t timestamp)
{
	if(!out) return;

	pthread_mutex_lock(&events_queue_mutex);
	if(EVENTS_QUEUE_NEXT(events_queue_head) != events_queue_tail)
	{
		events_queue[events_queue_head].ue = ue;
		events_queue[events_queue_head].newstate  = newstate;
		events_queue[events_queue_head].RAI = RAI;
		memmove(&(events_queue[events_queue_head].timestamp), &timestamp, sizeof(time_t));
		
		events_queue_head = EVENTS_QUEUE_NEXT(events_queue_head);
	}
	pthread_cond_signal(&events_queue_semaphore);
	pthread_mutex_unlock(&events_queue_mutex);
}
