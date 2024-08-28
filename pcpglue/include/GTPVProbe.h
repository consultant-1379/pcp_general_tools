/*
 * GTPVProbe.h
 *
 *  Created on: 11 Jul 2012
 *      Author: eroryma
 */

#ifndef GTPVPROBE_H_
#define GTPVPROBE_H_

class GTPFlags {
public:
	enum Protocol {
		UDP = 0x11, other = 99
	};
	enum PCAPReadStatus {
		OK = 1, TIMEOUT = 0, EndOfFile = -2, ERROR = -1
	};
};

#endif /* GTPVPROBE_H_ */
