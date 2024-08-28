/*
 * mutex.cc
 *
 *  Created on: 21 Jan 2013
 *      Author: ericker
 */

#include "mutex.hpp"
#include <pthread.h>

pthread_mutex_t map_mutex;

void MapMutex::lockMapMutex() {
	pthread_mutex_lock(&map_mutex);
}

void MapMutex::unlockMapMutex() {
	pthread_mutex_unlock(&map_mutex);
}

MapMutex::MapMutex() {
	pthread_mutex_init(&map_mutex, 0);
}

static MapMutex* instance;
static bool instanceFlag;

MapMutex* MapMutex::getInstance() {
	if (instanceFlag == false) {
		instanceFlag = true;
		instance = new MapMutex();

	}

	return instance;
}

