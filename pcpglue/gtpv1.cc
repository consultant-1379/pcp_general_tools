//#include "stdio.h"
#include <assert.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <string.h>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <list>
#include "pcpglue.hpp"
#include <memory>
#include "include/gtp_ie_gtpv2.h"
#include "include/gtpv2_main.h"
#include "include/gtpv1_utils.h"
#include "include/GTPv1_packetFields.h"
#include <pthread.h>

//#include "libpq-fe.h"

#include "include/gtp_ie.h"
#include "include/GTPVProbe.h"
#include "include/MagicStringTester.h"

#include "mutex.hpp"
#include "UE_map.hpp"

using namespace std;

int gtp_records_written = 0;

extern bool verbose;
//PGconn *conn;

char output_file_name[FILENAME_MAX];
const char* instance_tag = NULL;
const char* base_dir = NULL;
ofstream f_out;

ostream* v1_out = &f_out;
ostream* v2_out = &f_out;

time_t file_time = 0;
time_t last_maint = 0;
int interval = 0;

extern EArgs evaluatedArguments;
extern UE_maptype ueMap;
extern IMSI_maptype imsiMap;

int n_pdp_req = 0;
int n_pdp_resp = 0;
int n_update_req = 0;
int n_update_resp = 0;
int n_delete_req = 0;
int n_delete_resp = 0;
int pdp_resp_teid_not_found = 0;
int pdp_resp_imsi_not_found = 0;
int purgedPDPSessionCount = 0;

// Declaration of imsimap (imsi to session) and
// teidmap (teid to imsi)
struct dataeq {
	size_t operator()(const FTEID& x) const {
		return std::hash<u_int32_t>()((u_int32_t) x.addr ^ (u_int32_t) x.teid);
	}
	;

	bool operator()(const FTEID f1, const FTEID f2) const {
		return (f1.addr == f2.addr) && (f1.teid == f2.teid);
	}
	;
};

//typedef unordered_map<unsigned long long, struct PDPSession*, hash_long_long> imsimaptype;
typedef unordered_map<struct FTEID, unsigned long long, dataeq, dataeq> teidmaptype;

//imsimaptype imsimap;
teidmaptype teidmap;

static void FillLoc(PDPSession *s, DecodedMsg *pmsg) {
	memcpy(s->mcc, pmsg->mcc, MCC_MAX_CHARS);
	memcpy(s->mnc, pmsg->mnc, MNC_MAX_CHARS);
	s->lac = pmsg->lac;
	s->rac = pmsg->rac;
	s->cid = pmsg->cid;
	s->sac = pmsg->sac;
}

static void FillQoS(PDPSession *s, DecodedMsg *pmsg) {
	s->arp = pmsg->arp;
	s->delay_class = pmsg->delay_class;
	s->reliability_class = pmsg->reliability_class;
	s->precedence = pmsg->precedence;
	s->thp = pmsg->thp;
	s->max_ul = pmsg->max_ul;
	s->max_dl = pmsg->max_dl;
	s->gbr_ul = pmsg->gbr_ul;
	s->gbr_dl = pmsg->gbr_dl;
	s->sdu = pmsg->sdu;

	s->traffic_class = pmsg->traffic_class;
}

int open_output_file(time_t timestamp);
void close_output_file();
void logStats(time_t last_stat, ofstream * stat_out);
int removeAllPDPSessionsInMemory();

void InsertIMSIIntoHash(IMSI_maptype& imsimap, unsigned long long imsi,
		PDPSession* s, unsigned int max = 200000);
//void insertUEIntoHash(UE_maptype& UE_map, unsigned long long UE, PDPSession* s, unsigned int max = 200000);

// list<FTEID> tropen; // list of transactions open

void printaddr(int a) {
	unsigned char* i = (unsigned char*) &(a);
	printf("%i.%i.%i.%i", i[3], i[2], i[1], i[0]);
}

void RemoveTEID(FTEID te) {
	teidmaptype::iterator it = teidmap.find((FTEID) te);
	teidmap.find(te);
	if (it != teidmap.end())
		teidmap.erase(it);
}

//void EraseSession(PDPSession *s) {
//
//	imsimaptype::iterator it = imsimap.find(strtoull(s->imsi, 0, IMSI_MAX_CHARS));
//	if(it != imsimap.end()) imsimap.erase(it);
//
//	RemoveTEID(s->sgsn);
//	RemoveTEID(s->ggsn_c);
//
//	delete(s);
//
//}

void EraseSession(PDPSession *s) {

	MapMutex::getInstance()->lockMapMutex();

	UE_maptype::iterator it = ueMap.find(s->ue_addr);
	if (it != ueMap.end())
		ueMap.erase(it);

	RemoveTEID(s->sgsn);
	RemoveTEID(s->ggsn_c);

	delete (s);

	MapMutex::getInstance()->unlockMapMutex();
}

void CreatePDPContextRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	n_pdp_req++;

	int pos = 0;
	while (pos < datalen)
		pos = DecodeIE(p, pos, datalen, pmsg);

	// GTPv1: SGSN --> GGSN
	// teid is not set
	// teid_i = TEID for data
	// teid_c = TEID for control plane
	// addr1 = SGSN address for signaling
	// addr2 = SGSN address for user traffic

	FTEID sgsn;
	sgsn.addr = pmsg->addr1;
	sgsn.teid = pmsg->teid_c;

	unsigned int UE_IP = pmsg->ue_addr;
	unsigned long long imsi_number = strtoull(pmsg->imsi, 0, IMSI_MAX_CHARS);

	PDPSession *s = NULL;

	MapMutex::getInstance()->lockMapMutex();

	//Serch for UE IP in the ue map, if found, remove previous teidmap entries, and create new pdpsession
//	UE_maptype::iterator ue_it = ueMap.find(UE_IP);
	IMSI_maptype::iterator imsi_it = imsiMap.find(imsi_number);
	//if(ue_it != ueMap.end()) {
	//s = ue_it->second;
	if (imsi_it != imsiMap.end()) {
		s = imsi_it->second;

		RemoveTEID(s->sgsn);
		RemoveTEID(s->ggsn_c);
		s->init();
	} else {
		s = new PDPSession(pmsg->imsi);

		InsertIMSIIntoHash(imsiMap, imsi_number, s,
				evaluatedArguments.GTPC_HASHMAP_MAX_SIZE); // hash is size limited, stalest session will be removed to make space if required.
		//insertUEIntoHash(ueMap, UE_IP, s,evaluatedArguments.GTPC_HASHMAP_MAX_SIZE);
	}

	// insert teid into map
	teidmap[sgsn] = imsi_number;

	if (pmsg->teid == 0) {
		s->pdp_type = "GPRS_PRIMARY";
	} else {
		s->pdp_type = "GPRS_SECONDARY";
	}

	s->startTime = pmsg->timestamp;
	s->sgsn = sgsn;

	// Fill relevant records
	if (pmsg->imei[0] != 0)
		memcpy(s->imei, pmsg->imei, IMEI_MAX_CHARS);
	if (pmsg->rat_present)
		s->rat = pmsg->rat;
	FillLoc(s, pmsg);
	s->nsapi = pmsg->nsapi;
	//strcpy(s->apn, pmsg->apn);
	s->apn = strdup(pmsg->apn);
	memcpy(s->msisdn, pmsg->msisdn, MSISDN_MAX_CHARS);

	s->touch = pmsg->timestamp;

	MapMutex::getInstance()->unlockMapMutex();
}

void CreatePDPContextResponse(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	n_pdp_resp++;

	int pos = 0;
	while (pos < datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	// GTPv1: GGSN-->SGSN
	// teid = SGSN control teid
	// teid_i = GGSN uplink data teid
	// teid_c = GGSN uplink control teid
	// addr1 = GGSN control addr
	// addr2 = GGSN data addr

	FTEID sgsn;
	sgsn.addr = pmsg->dst_addr;
	sgsn.teid = pmsg->teid;

	MapMutex::getInstance()->lockMapMutex();

	// Look into the TEID map to find the IMSI for this TEID
	teidmaptype::iterator it = teidmap.find(sgsn);
	if (it == teidmap.end()) {
		// If we can't find the TEID, we haven't received an appropriate REQUEST, so log this event and move on
		pdp_resp_teid_not_found++;
		MapMutex::getInstance()->unlockMapMutex();
		return;
	}

	// Get the IMSI from the TEID map entry
	unsigned long long imsi_number = it->second;

	// Find the session using the IMSI
	IMSI_maptype::iterator imsi_it = imsiMap.find(imsi_number);
	if (imsi_it == imsiMap.end()) {
		// If we can't find the IMSI, something has gone wrong! Log the event and clean up the TEID map and move on
		pdp_resp_imsi_not_found++;
		teidmap.erase(it);
		MapMutex::getInstance()->unlockMapMutex();
		return;
	}

	// Get the PDP session from the IMSI map
	PDPSession* s = imsi_it->second;

	// Time to update the ueMap
	// See if we can find the UEIP in the map already
	unsigned int UE_IP = pmsg->ue_addr;
	UE_maptype::iterator iit = ueMap.find(UE_IP);
	if (iit != ueMap.end()) {
		// If so, remove it as we have a new mapping to assign!
		ueMap.erase(iit);
		// TODO: Potential memory leak
	}

	// Add the new UEIP to the ueMap, pointing at the appropriate session
	//printf("UE_addr: %x \n", UE_IP);
	Insert_UE_IP_IntoHash(ueMap, UE_IP, s);

	// create ggsn based map
	FTEID ggsn;
	ggsn.addr = pmsg->addr1;
	ggsn.teid = pmsg->teid_c;
	teidmap[ggsn] = imsi_number;

	// Fill in relevant values
	s->ggsn_c = ggsn;
	s->ggsn_d.addr = pmsg->addr2;
	s->ggsn_d.teid = pmsg->teid_d;
	s->ue_addr = pmsg->ue_addr;
	s->time_pdn_response = pmsg->timestamp;
	s->pdn_cause = pmsg->cause;
	s->touch = pmsg->timestamp;
	if (pmsg->imei[0] > 0)
		memcpy(s->imei, pmsg->imei, IMEI_MAX_CHARS);
	FillQoS(s, pmsg);

	//s->printPDPSession();

	MapMutex::getInstance()->unlockMapMutex();
}
// end of CreatePDPContextResponse
void UpdatePDPContextRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	n_update_req++;

	int pos = 0;
	while (pos < datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	if (pmsg->teid_d_present) {

		// GTPv1: SGSN->GGSN
		// teid = ggsn control teid
		// teid_c = as below but for control
		// teid_d = GGSN downlink teid for data for the PDP context chosen by SGSN
		// addr1 = sgsn addr for control plane
		// addr2 = sgsn addr for data plane

		FTEID sgsn;
		sgsn.addr = pmsg->src_addr;
		sgsn.teid = pmsg->teid;

		MapMutex::getInstance()->lockMapMutex();
		teidmaptype::iterator tit = teidmap.find(sgsn);
		if (tit == teidmap.end()) {
			MapMutex::getInstance()->unlockMapMutex();
			return;
		}

		unsigned long long imsi = tit->second;
		// now search for session
		IMSI_maptype::iterator iit = imsiMap.find(imsi);
		if (iit == imsiMap.end()) {
			// remove obsolete teid from map
			teidmap.erase(tit);
			MapMutex::getInstance()->unlockMapMutex();
			return;
		}

		PDPSession *s = iit->second;

		// fill in relevant data
		s->dle.addr = pmsg->addr2;
		s->dle.teid = pmsg->teid_d;
		s->time_update_request = pmsg->timestamp;
		s->active_update_start = pmsg->timestamp;
		FillQoS(s, pmsg);
		s->dtflag = pmsg->dtflag;
		s->touch = pmsg->timestamp;
		if (pmsg->rat_present)
			s->rat = pmsg->rat;
		FillLoc(s, pmsg);
		MapMutex::getInstance()->unlockMapMutex();
	}

}

void UpdatePDPContextResponse(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	n_update_resp++;

	int pos = 0;
	while (pos < datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	// GTPv1:
	// teid = sgsn teid

	FTEID sgsn;
	sgsn.addr = pmsg->dst_addr;
	sgsn.teid = pmsg->teid;

	MapMutex::getInstance()->lockMapMutex();
	teidmaptype::iterator tit = teidmap.find(sgsn);
	if (tit == teidmap.end()) {
		MapMutex::getInstance()->unlockMapMutex();
		return;
	}

	unsigned long long imsi = tit->second;

	// now search for session
	IMSI_maptype::iterator iit = imsiMap.find(imsi);
	if (iit == imsiMap.end()) {
		printf("SESSION NOT FOUND+++++++++++++++++++++++++++++++++++\n");

		// remove obsolete teid from map
		teidmap.erase(tit);
		MapMutex::getInstance()->unlockMapMutex();
		return;
	}

	PDPSession *s = iit->second;

	s->time_update_response = pmsg->timestamp;
	s->update_cause = pmsg->cause;
	s->touch = pmsg->timestamp;
	FillQoS(s, pmsg);

	//s->printUpdate();
	cout.precision(3);
	MapMutex::getInstance()->unlockMapMutex();
	// pdpSession->printPDPSession();
} // end of UpdatePDPContextResponse

void DeletePDPContextRequest(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	n_delete_req++;

	int pos = 0;
	while (pos < datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	FTEID ggsn;
	ggsn.addr = pmsg->dst_addr;
	ggsn.teid = pmsg->teid;

	MapMutex::getInstance()->lockMapMutex();
	teidmaptype::iterator tit = teidmap.find(ggsn);
	if (tit == teidmap.end()) {
		MapMutex::getInstance()->unlockMapMutex();
		return;
	}

	unsigned long long imsi = tit->second;

	// Find the session in the imsi map
	IMSI_maptype::iterator imsiit = imsiMap.find(imsi);
	if (imsiit == imsiMap.end()) {
		// remove the redundant teid entry
		teidmap.erase(tit);
		MapMutex::getInstance()->unlockMapMutex();
		return;
	}

	// now search for session
	//UE_maptype::iterator iit = ueMap.find(UE_IP);
	//if(iit == ueMap.end()) {
	// remove obsolete teid from map
	//	teidmap.erase(tit);
//		return;
	//}

	PDPSession *s = imsiit->second;
	s->touch = pmsg->timestamp;
	RemoveTEID(s->sgsn);
	RemoveTEID(s->ggsn_c);

	// now search for UE IP
	UE_maptype::iterator iit = ueMap.find(s->ue_addr);
	if (iit != ueMap.end()) { // If we found it
		// Remove it from the map
		ueMap.erase(iit);
	}

	imsiMap.erase(imsiit);
	delete s;
	MapMutex::getInstance()->unlockMapMutex();

}

void DeletePDPContextResponse(unsigned char *p, int datalen, DecodedMsg *pmsg) {

	n_delete_resp++;

	return; // WE DO NOT NEED IT

	int pos = 0;
	while (pos < datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

	printaddr(pmsg->src_addr);
	printaddr(pmsg->dst_addr);

}

void processMessage(unsigned char gtpMessageType, unsigned char* data,
		int dataLength, DecodedMsg *message);

double diffclock(clock_t clock1, clock_t clock2) {
	double diffticks = clock1 - clock2;
	double diffms = (diffticks * 10) / CLOCKS_PER_SEC;
	return diffms;
}

int main(int argc, char **argv) {
	clock_t begin = clock();
	time_t last_stat = 0;
	bool cooked = false;
// PROCESS ARGUMENTS _______________________________________
	pcap_t* descr = NULL;
	MagicStringTester licenceTester;

	if (argc < 2 || licenceTester.testString(argv[1])) {
		cerr << "Licence check failed" << endl;
		return (254);
	}

	if (parseArgs(argc - 1, argv + 1, &descr) != 0) {
		cerr << "Argument errors, exiting" << endl;
		return 1;
	}

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_t threadPCPGlue;
	pthread_create(&(threadPCPGlue), &attr,
			startTheSinkSourceAndMonitorOfPCPGlue, NULL);

	char stat_file_name[FILENAME_MAX];
	sprintf(stat_file_name, "%s/gtpc_collection_%s.log",
			(char *) evaluatedArguments.GTPCLogOutput.c_str(), instance_tag);
	//FILE *stat_file = fopen(stat_file_name, "w");
	/*
	 if (!stat_file)
	 */
	ofstream stat_out(stat_file_name);
	if (!stat_out) {
		string statFileErrorString = "could not create statistics file ";
		statFileErrorString += stat_file_name;
		perror(statFileErrorString.c_str());
		return 1;
	}
	// END PROCESS ARGUMENTS _______________________________________

	//HANDLE PACKET COLLECTION AND TYPE________________________________________________________
	unique_ptr<PacketCounter> packetCounterPtr(PacketCounter::getInstance());
	int dlink = pcap_datalink(descr);
	if (dlink == 113)
		cooked = true;
	// Start  of main file read loop
	int totalPacketsProcessedDuringRun = 0;
	int totalV2Packets = 0;
	int totalV1Packets = 0;
	do {
		const u_char *packet;
		struct pcap_pkthdr* pkthdr; /* pcap.h */

		//Get next packet if no more packets end program
		enum GTPFlags::PCAPReadStatus retval =
				(GTPFlags::PCAPReadStatus) pcap_next_ex(descr, &pkthdr,
						&packet);
		if (retval == GTPFlags::EndOfFile) {
			sleep(5);
			continue;
		}
		if (retval == GTPFlags::TIMEOUT)
			continue;

		PacketCounter::getInstance()->incrementTotalPackets();
		totalPacketsProcessedDuringRun++;
		if (retval == GTPFlags::ERROR) {
			pcap_perror(descr, argv[3]);
			PacketCounter::getInstance()->incrementTotalErrorPackets();
			continue;
		} else if (retval != GTPFlags::OK) {
			PacketCounter::getInstance()->incrementTotalUnexpectedPackets();
			continue;
		}

		// Check if we need to open the output file, there is a new file for every 5 minutes (300 seconds) of output
		if ((pkthdr->ts.tv_sec - file_time > interval)
				&& strcmp(base_dir, "-")) {
			if (!open_output_file(pkthdr->ts.tv_sec)) {
				pcap_close(descr);
				cerr << "Unable to open output file." << endl;
				return 1;
			}
		}

		const struct my_ip* ip;
		int length;

		if (!GetPacketPointerAndLength(packet, cooked, &ip, &length, pkthdr))
			continue;

		int len = ntohs(ip->ip_len);
		int hlen = IP_HL(ip); /* header length */
		int version = IP_V(ip);/* ip version */

		if (!checkDataMatches("Version: ", IPVersion::IPV4, version))
			continue;
		if (!checkDataGE("Header length", 5, hlen))
			continue;
		if (!checkDataGE("Truncated IP", len, length))
			continue;

		//Start of IP packet processing after initial packet checks

		if (ip->ip_p != GTPFlags::UDP)
			continue;

		//TODO check sizeof
		unsigned char* udp = (unsigned char*) ip + hlen * sizeof(int);

		unsigned short sport = extractPortFromPacket(&udp[0]);
		unsigned short dport = extractPortFromPacket(&udp[2]);

		if (sport != GTPPorts::GTP_CONTROL_PORT
				&& dport != GTPPorts::GTP_CONTROL_PORT)
			continue;

		unsigned char* gtp = udp + sizeof(GTP_Control_Basic_Header);

		GTP_Control_Basic_Header gtpHeader = *(GTP_Control_Basic_Header *) gtp;

		unsigned long s = extractIpAddress((unsigned char*) &ip->ip_src);
		unsigned long d = extractIpAddress((unsigned char*) &ip->ip_dst);
		if (!(gtpHeader.Version == 1
				&& (evaluatedArguments.GTPCVersion == "v1"
						|| evaluatedArguments.GTPCVersion == "both"))) {
			if (gtpHeader.Version == 2
					&& (evaluatedArguments.GTPCVersion == "v2"
							|| evaluatedArguments.GTPCVersion == "both")) {
				PacketCounter::getInstance()->incrementTotalNumberOfVersion(2);
				if (++totalV2Packets % 50000 == 0 && verbose)
					cerr << "Total V2 packets: " << totalV2Packets << endl;
				processV2Packet(packet, pkthdr, dlink);

			}
			logV2Stats(last_stat, &stat_out);
			continue;
		} else {

			PacketCounter::getInstance()->incrementTotalNumberOfVersion(1);
			if (++totalV1Packets % 50000 == 0 && verbose)
				cerr << "Total V1 packets: " << totalV1Packets << endl;
		}
		unsigned char gtpMessageType = gtpHeader.MessageType;
		struct DecodedMsg msg;
		msg.timestamp = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1e6;
		msg.src_addr = extractIpAddress((unsigned char*) &ip->ip_src);
		msg.dst_addr = extractIpAddress((unsigned char*) &ip->ip_dst);
		msg.teid = ntohl(gtpHeader.TunnelEndpointIdentifier);

		unsigned char *data;
		GTP_Control_Header theHeader;
		if (gtpHeader.N_PDUNumberFlag || gtpHeader.SequenceNumberFlag
				|| gtpHeader.ExtensionHeaderFlag) {
			theHeader.fullHeader = *(GTP_Control_Full_Header*) &gtpHeader;
			data = gtp + sizeof(GTP_Control_Full_Header);
		} else {
			theHeader.basicHeader = *(GTP_Control_Basic_Header*) &gtpHeader;
			data = gtp + sizeof(GTP_Control_Basic_Header);
		}
		if (gtpHeader.ExtensionHeaderFlag) { // extension header
			if (verbose)
				cerr << "Extension header" << endl;
			while (data[-1] > 0) {
				if (data[0] <= 0) {
					if (verbose)
						cerr << "WRONG EXTENSION header" << endl;
					break;
				}
				data += (data[0]) * 4; // TODO - factor out 4
			}
		}

		unsigned short int gtplength = ntohs(gtpHeader.TotalLength);
		int datalen = gtplength
				- (data - gtp - sizeof(GTP_Control_Basic_Header)); //changed from 8 to sizeof Michael 16_07_12
		processMessage(gtpMessageType, data, datalen, &msg);
		logStats(last_stat, &stat_out);

	} while (1);
	close_output_file();
	clock_t end = clock();
	if (verbose)
		cout << "Time elapsed: " << double(diffclock(end, begin)) << " ms, "
				<< "Processed a total of " << totalPacketsProcessedDuringRun
				<< endl;
	//delete PacketCounter::getInstance();
	if (verbose)
		cout << "Removing remaining PDP Sessions, please wait....." << endl;
	if (verbose)
		cout << "The Total number of PDP sessions removed from memory was: "
				<< removeAllPDPSessionsInMemory() << endl;
	if (verbose)
		cout << "The number of PDP Sessions remaining in memory: "
				<< PDPSession::getInstanceCounter() << endl;
	if (verbose)
		cout << "The number of PDP sessions deleted during the run was: "
				<< PDPSession::getDeleteCounter() << endl;
	if (verbose)
		cout << "Removing remaining PDN Sessions, please wait....." << endl;
	if (verbose)
		cout << "The Total number of PDN sessions removed from memory was: "
				<< removeAllPDNSessionsInMemory() << endl;
	if (verbose)
		cout << "The number of PDN Sessions remaining in memory: "
				<< PDNSession_V2::getInstanceCounter() << endl;
	if (verbose)
		cout << "The number of PDN Sessions deleted during the run was: "
				<< PDNSession_V2::getDeleteCounter() << endl;
	if (verbose)
		cout << "The program has ended its run." << endl;
}

// esirich added a timestamp to the log output: see DEFTFTS-1677
void logStats(time_t last_stat, ofstream * stat_out) {
	// statistic reporting for 1 min of run time
	if (difftime(file_time, last_maint) > 60.0) {
		char timebuffer[30]; // 30 bytes is more than enough

		last_maint = file_time;
		*stat_out << ctime_r(&file_time, timebuffer);

		*stat_out << " Hashes: teid " << teidmap.size() << " IMSI " << imsiMap.size() << " UE_IP "
				<< ueMap.size() << " , Number of purged PDPsessions "
				<< purgedPDPSessionCount << endl;
		*stat_out << " PDP req " << n_pdp_req << " resp " << n_pdp_resp
				<< " UPDATE req " << n_update_req << " resp " << n_update_resp
				<< " DEL req " << n_delete_req << " resp " << n_delete_resp
				<< endl;
		*stat_out << " pdp_resp_teid_not_found " << pdp_resp_teid_not_found
				<< " pdp_resp_imsi_not_found " << pdp_resp_imsi_not_found
				<< endl;
		*stat_out << PacketCounter::getInstance();

		PacketCounter::getInstance()->clearCounters();

		n_pdp_req = 0;
		n_pdp_resp = 0;
		n_update_req = 0;
		n_update_resp = 0;
		n_delete_req = 0;
		n_delete_resp = 0;
		pdp_resp_teid_not_found = 0;
		pdp_resp_imsi_not_found = 0;
		purgedPDPSessionCount = 0;

	}
}

int open_output_file(long timestamp) {
	//modded to take care of compiler error
	if (f_out) {
		close_output_file();
	}
	long timestamp_temp = timestamp;
	// Work out the start of this five minute interval, round down to the start of the last five minute interval
	file_time = timestamp_temp / interval * interval;

	struct tm* time_tm;
	time_tm = gmtime(&file_time);

	sprintf(output_file_name, "%s/A%04d%02d%02d.%02d%02d_gtpc_%s.log", base_dir,
			time_tm->tm_year + 1900, time_tm->tm_mon + 1, time_tm->tm_mday,
			time_tm->tm_hour, time_tm->tm_min, instance_tag);

	char file_name[FILENAME_MAX];
	sprintf(file_name, "%s.latest", output_file_name);
	f_out.open(file_name);
	if (!f_out.is_open()) {
		//fprintf(stderr, "output to file %s failed, ", file_name);
		cerr << "Failed to open output file " << file_name << endl;
		perror("error opening file:");
		return 0;
	} else {
		return 1;
	}
}

void close_output_file() {
	f_out.flush();
	f_out.close();
	char file_name[FILENAME_MAX];
	sprintf(file_name, "%s.latest", output_file_name);

	rename(file_name, output_file_name);
}

void processMessage(unsigned char gtpMessageType, unsigned char* data,
		int dataLength, DecodedMsg *message) {

	switch (gtpMessageType) {

	case GTPMessageTypes::ECHO_REQUEST:
	case GTPMessageTypes::ECHO_RESPONSE:
	case GTPMessageTypes::VERSION_NOT_SUPPORTED:
	case GTPMessageTypes::SEND_ROUTING_FOR_QPRS_REQUEST:
	case GTPMessageTypes::SEND_ROUTING_FOR_QPRS_RESPONSE:

		break;

	case GTPMessageTypes::CREATE_PDP_CONTEXT_REQUEST:
		CreatePDPContextRequest(data, dataLength, message);
		break;

	case GTPMessageTypes::CREATE_PDP_CONTEXT_RESPONSE:
		CreatePDPContextResponse(data, dataLength, message);
		break;

	case GTPMessageTypes::UPDATE_PDP_CONTEXT_REQUEST:
		UpdatePDPContextRequest(data, dataLength, message);
		break;

	case GTPMessageTypes::UPDATE_PDP_CONTEXT_RESPONSE:
		UpdatePDPContextResponse(data, dataLength, message);
		break;

	case GTPMessageTypes::DELETE_PDP_CONTEXT_REQUEST:
		DeletePDPContextRequest(data, dataLength, message);
		break;

	case GTPMessageTypes::DELETE_PDP_CONTEXT_RESPONSE:
		DeletePDPContextResponse(data, dataLength, message);
		break;

	default:
		if (verbose)
			cout << "Undecoded message type " << (unsigned int) gtpMessageType
					<< endl; //Michael 16_07_12
		break;
	}

}

//void removeSession(imsimaptype::iterator imsiit){
//	if(imsiit != imsimap.end()) {
//		RemoveTEID(imsiit->second->sgsn);
//		RemoveTEID(imsiit->second->ggsn_c);
//		delete imsiit->second;
//		imsimap.erase(imsiit);
//	}
//}

void removeSession(IMSI_maptype::iterator imsiit) {
	if (imsiit != imsiMap.end()) {
		RemoveTEID(imsiit->second->sgsn);
		RemoveTEID(imsiit->second->ggsn_c);
		delete imsiit->second;
		imsiMap.erase(imsiit);
	}
}

//int removeAllPDPSessionsInMemory(){
//	int numberOfElementsAndSessionsRemoved=0;
//	int length = imsimap.size();
//	PDPSession* s;
//
//	for( int i = 0;i < length ; ++i){
//		imsimaptype::iterator imsiit = imsimap.begin();
//		removeSession(imsiit);
//		numberOfElementsAndSessionsRemoved++;
//	}
//
//	return numberOfElementsAndSessionsRemoved;
//}

int removeAllPDPSessionsInMemory() {
	int numberOfElementsAndSessionsRemoved = 0;
	int length = ueMap.size();
	PDPSession* s;

	for (int i = 0; i < length; ++i) {
		UE_maptype::iterator ueiit = ueMap.begin();
		removeSession(ueiit);
		numberOfElementsAndSessionsRemoved++;
	}

	return numberOfElementsAndSessionsRemoved;
}

void InsertIMSIIntoHash(IMSI_maptype& imap, unsigned long long imsi,
		PDPSession* s, unsigned int max) {
	if (imap.size() > max) {
		//Remove one element
		IMSI_maptype::iterator it, lowest;

		for (it = lowest = imap.begin(); it != imap.end(); ++it) {
			PDPSession *p = it->second;
			PDPSession *p1 = lowest->second;
			if (p->touch < p1->touch) {
				lowest = it;
			}
		}
		removeSession(lowest);
		purgedPDPSessionCount++;
	}

	imap[imsi] = s;
}

/*
 void insertUEIntoHash(UE_maptype& UE_map, unsigned long long UE_IP, PDPSession* s, unsigned int max){
 if (UE_map.size() > max){
 //Remove one element
 UE_maptype::iterator it, lowest;

 for (it = lowest = UE_map.begin(); it != UE_map.end(); ++it){
 PDPSession *p = it->second;
 PDPSession *p1 = lowest ->second;
 if (p->touch < p1->touch){
 lowest = it;
 }
 }
 removeSession(lowest);
 purgedPDPSessionCount++;
 }

 UE_map[UE_IP] = s;
 }
 */

