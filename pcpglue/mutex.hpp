/*
 * mutex.h
 *
 *  Created on: 21 Jan 2013
 *      Author: ericker
 */

#ifndef MUTEX_H_
#define MUTEX_H_
#include <pthread.h>

class MapMutex
{
private:
	MapMutex();

public:
	void lockMapMutex();
	void unlockMapMutex();
	static MapMutex* getInstance();
};


#endif /* MUTEX_H_ */
