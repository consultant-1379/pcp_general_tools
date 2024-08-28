/*
 * gtpv1_utils.h
 *
 *  Created on: 12 Jul 2012
 *      Author: emilawl
 */
#ifndef GTPV1_UTILS_H_
#define GTPV1_UTILS_H_

#define LENGTHOF(a) (sizeof(a)/sizeof(a[0]))

//#pragma pack(1) //vital to get bit fields to line up correctly
typedef unsigned char UCHAR;

#include <iostream>
#include <string>
#include <netinet/in.h>
#include "GTPv1_packetFields.h"
#include <netinet/if_ether.h>
#include <unordered_map>

//using __gnu_cxx::iterator;

using std::ofstream;
using std::cerr;
using std::endl;
using std::string;
using std::ostream;

struct EArgs{
	string GTPCVersion;
	string GTPCOutput1, GTPCOutput2;
	string GTPCInput;
	int GTP_file_interval;
	string GTPCInstance_tag;
	string GTPCLogOutput;
	bool GTPCVerbose;
	string type;
	int GTPC_HASHMAP_MAX_SIZE;
	string propertyFileName;
	bool usePropertyFile;
} ;

// Utility functions
bool is_dir(const char *path);
int parseArgs(int argc, char ** argv, pcap_t** descr);
bool checkDataMatches(const string& description, long long expectedValue, long long obtainedValue);
bool checkDataGE(const string& description, long long expectedValue, long long obtainedValue);
bool GetPacketPointerAndLength(const u_char * packet, bool cooked,const struct my_ip** ipP, int *lengthP, struct pcap_pkthdr* pkthdr);


using std::endl;
using std::ostream;


class PacketCounter{
private:
	PacketCounter(const PacketCounter& pc) {
		totalUnexpectedPackets = pc.totalUnexpectedPackets;
		totalErrorPackets = pc.totalErrorPackets;
		totalPackets = pc.totalPackets;
		totalNonEthernetPackets = pc.totalNonEthernetPackets;
		totalNumberOfVersionOnePackets = pc.totalNumberOfVersionOnePackets;
		totalNumberOfVersionTwoPackets = pc.totalNumberOfVersionTwoPackets;
	}

	PacketCounter():
		totalUnexpectedPackets(0),
		totalErrorPackets(0),
		totalPackets(0),
		totalNonEthernetPackets(0),
		totalNumberOfVersionOnePackets(0),
		totalNumberOfVersionTwoPackets(0)
		{}
public:
	string getDetails() const;
	~PacketCounter(){
		if (theInstance){
			theInstance = 0;
		}

	}
public:
	static PacketCounter* getInstance(){
		if(!theInstance){
			theInstance = new PacketCounter();
		}
		return theInstance;

	}
	void incrementTotalNumberOfVersion(int theVersion){
		switch(theVersion){
		case 1: totalNumberOfVersionOnePackets++ ; break;
		case 2: totalNumberOfVersionTwoPackets++ ; break;

		}

	}
	void incrementTotalPackets(){totalPackets++;}

	void incrementTotalErrorPackets(){totalErrorPackets++;}

	void incrementTotalUnexpectedPackets(){	totalUnexpectedPackets++;}

	void incrementNonEthernetPackets(){	totalNonEthernetPackets++;}

	long getTotalOKPackets() const {return totalPackets - totalUnexpectedPackets - totalErrorPackets;}

	long getTotalErrorPackets() const {	return totalErrorPackets;}

	void setTotalErrorPackets(long totalErrorPackets) {this->totalErrorPackets = totalErrorPackets;}

	long getTotalPackets() const {return totalPackets;}

	void setTotalPackets(long totalPackets) {this->totalPackets = totalPackets;}

	long getTotalUnexpectedPackets() const {return totalUnexpectedPackets;}

	void setTotalUnexpectedPackets(long totalUnexpectedPackets) {this->totalUnexpectedPackets = totalUnexpectedPackets;}

	long getTotalNonEthernetPackets() const {return totalNonEthernetPackets;}

	void setTotalNonEthernetPackets(long totalNonEthernetPackets) {this->totalNonEthernetPackets = totalNonEthernetPackets;}

	void clearCounters(){
		this->setTotalErrorPackets(0);
		this->setTotalPackets(0);
		this->setTotalUnexpectedPackets(0);
		this->setTotalNonEthernetPackets(0);
	}

	long getTotalNumberOfVersionOnePackets() const {
		return totalNumberOfVersionOnePackets;
	}

	long getTotalNumberOfVersionTwoPackets() const {
		return totalNumberOfVersionTwoPackets;
	}

private:
	long totalUnexpectedPackets;
	long totalErrorPackets;
	long totalPackets;
	long totalNonEthernetPackets;
	long totalNumberOfVersionOnePackets;
	long totalNumberOfVersionTwoPackets;
	static PacketCounter * theInstance;
};

ostream& operator<<(ostream& os, const PacketCounter *pc);

class printIFGT0{
public:
	printIFGT0(long long theValue, const string& theSeparator = ","):value(theValue), separator(theSeparator){}

	long long getValue() const {
		return value;
	}

	const string& getSeparator() const {
		return separator;
	}

private:
	long long value;
	string separator;
};
ostream& operator<<(ostream& os, const printIFGT0& value);

class printIFGE0{
public:
	printIFGE0(long long theValue, const string& theSeparator = ","):value(theValue), separator(theSeparator){}

	long long getValue() const {
		return value;
	}

	const string& getSeparator() const {
		return separator;
	}

private:
	long long value;
	string separator;
};
ostream& operator<<(ostream& os, const printIFGE0& value);

struct IPAddress{
	union {
		unsigned int address;
		unsigned char bytes[4];
	} data;
	IPAddress(unsigned int theAddress){
		this->data.address = theAddress;
	}
};
ostream& operator<< (ostream& os, const IPAddress& ipAddress);

class PDN_CAUSE{
public:
	enum VALUE{
	 NON_EXISTENT 								= 192,
	 INVALID_MESSAGE_FORMAT 					= 193,
	 IMSI_NOT_KNOWN								= 194,
	 MS_IS_GPRS_DETACHED						= 195,
	 MS_IS_NOT_GPRS_RESPONDING					= 196,
	 MS_REFUSES									= 197,
	 VERSION_NOT_SUPPORTED						= 198,
	 NO_RESOURCES_AVAILABLE	 					= 199,
	 SERVICE_NOT_SUPPORTED						= 200,
	 MANDATORY_IE_INCORRECT	 					= 201,
	 MANDATORY_IE_MISSING						= 202,
	 OPTIONAL_IE_INCORRECT 						= 203,
	 SYSTEM_FAILURE								= 204,
	 ROAMING_RESTRICTION						= 205,
	 P_TMSI_SIGNATURE_MISMATCH					= 206,
	 GPRS_CONNECTION_SUSPENDED					= 207,
	 AUTHENTICATION_FAILURE						= 208,
	 USER_AUTHENTICATION_FAILED					= 209,
	 CONTEXT_NOT_FOUND							= 210,
	 ALL_DYNAMIC_PDP_ADDRESSES_ARE_OCCUPIED		= 211,
	 NO_MEMORY_IS_AVAILABLE						= 212,
	 RELOCATION_FAILURE	 						= 213,
	 UNKNOWN_MANDATORY_EXTENSION_HEADER	 		= 214,
	 SEMANTIC_ERROR_IN_THE_TFT_OPERATION		= 215,
	 SYNTACTIC_ERROR_IN_THE_TFT_OPERATION		= 216,
	 SEMANTIC_ERRORS_IN_PACKET_FILTERS			= 217,
	 SYNTACTIC_ERRORS_IN_PACKET_FILTERS			= 218,
	 MISSING_OR_UNKNOWN_APN						= 219,
	 UNKNOWN_PDP_ADDRESS_OR_PDP_TYPE			= 220,
	 PDP_CONTEXT_WITHOUT_TFT_ALREADY_ACTIVATED	= 221,
	 APN_ACCESS_DENIED_NO_SUBSCRIPTION			= 222,
	 APN_RESTRICTION_TYPE_INCOMPATIBILITY_WITH_CURRENTLY_ACTIVE_PDP_CONTEXTS	= 223,
	 MS_MBMS_CAPABILITIES_NSUFFICIENT			= 224,
	 INVALID_CORRELATION_ID	 					= 225,
	 MBMS_BEARER_CONTEXT_SUPERSEDED	 			= 226,
	 BEARER_CONTROL_MODE_VIOLATION				= 227,
	 COLLISION_WITH_NETWORK_INITIATED_REQUEST	= 228,
	 APN_CONGESTION								= 229,
	 BEARER_HANDLING_NOT_SUPPORTED				= 230,
	};



};

inline unsigned short NetworkShortAt(unsigned char *p){
	return ntohs( * (unsigned short*) p);
}
inline unsigned int NetworkIntAt(unsigned char *p){
	return ntohl( * (unsigned int*) p);
}



#endif /* GTPV1_UTILS_H_ */
