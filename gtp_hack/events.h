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
* File: events.h
* Date: December 13, 2012
* Author: LMI/LXR/PE Simon Richardson
************************************************************************/

/*
 * Provide a separate interface to an events thread which calls external
 * code when the simulator undergoes state transitions.
 */

#ifndef EVENTS_H
# define EVENTS_H

# include "config.h"

/* use this macro so we can speed up by directly manipulating the queue */ 
#define EVENTS_QUEUE_ADD(ue, newstate, rai, time)	\
					(events_queue_add(ue, newstate, rai, time))

/* defines how many bits are used to index the queue: so 20->1048576 */
#define EVENTS_QUEUE_COUNT_BITS		(20)


void events_queue_add(int ue, enum ue_state_enum newstate, int RAI, time_t timestamp);

void events_queue_start_thread(void);
void events_queue_stop_thread(void);
#endif
