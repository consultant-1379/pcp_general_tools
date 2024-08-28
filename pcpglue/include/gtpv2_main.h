/*
 * gtpv2_main.h
 *
 *  Created on: 24 Jul 2012
 *      Author: emilawl
 */

#ifndef GTPV2_MAIN_H_
#define GTPV2_MAIN_H_

#include <time.h>

// esirich: DEFTFTS-1825 include lengths of fields that become strings
#include "gtp_ie.h"

extern int session_id_c;
extern int records_written;
extern ostream* v2_out;

int processV2Packet(const unsigned char *packet,const pcap_pkthdr *pkthdrPTR, int linktype);
void logV2Stats(time_t last_stat, ofstream * stat_out);
int removeAllPDNSessionsInMemory();

struct PDNSession_V2 {
	double start;

	double touch;  // last activity on this session of any kind

	int session_id;

	double time_pdn_response;
	double time_update_request;
	double time_update_response;

	double paging_start;

	double active_update_start;

	char imsi[IMSI_MAX_CHARS];

	struct FTEID mme;
	struct FTEID sgw_c, sgw_d;
	struct FTEID enb;

	char apn[APN_MAX_CHARS];
	char msisdn[MSISDN_MAX_CHARS];
	unsigned int ue_addr;
	int default_bearer_id;

	unsigned char pdn_cause;
	unsigned char update_cause;

	int default_bearer_established;

	int sreq_flag;
	int paging_flag;

	string RATType;
	char mcc[MCC_MAX_CHARS];
	char mnc[MNC_MAX_CHARS];
	int rai,sai,cgi,lac,tai,ecgi;
	int nsapi;
	int dtFlag;
	long max_ul;
	long max_dl;
	long gbr_ul;
	long gbr_dl;
	int arp;
	char mei[IMEI_MAX_CHARS];
	int S1U_TEID;

	static int instanceCounter;
	static int deleteCounter;

	bool operator<(const PDNSession_V2& rhs) { return this->touch < rhs.touch;}

	PDNSession_V2(){

		session_id = session_id_c;
		session_id_c ++;

		paging_start=0;
		touch=0;

		time_pdn_response=0;
		time_update_request=0;
		time_update_response=0;
		active_update_start=0;
		bzero(imsi, IMSI_MAX_CHARS);
		strcpy(imsi, IMSI_INIT_STRING);
		pdn_cause=-1;
		update_cause=0;
		bzero(msisdn, MSISDN_MAX_CHARS);
		strcpy(msisdn, MSISDN_INIT_STRING);
		ue_addr=0;
		default_bearer_id=255;

		default_bearer_established=0;

		sreq_flag = paging_flag = 0;
		bzero(mei, IMEI_MAX_CHARS);
		strcpy(mei, IMEI_INIT_STRING);
		bzero(mcc, MCC_MAX_CHARS);
		strcpy(mcc, MCC_INIT_STRING);
		bzero(mnc, MNC_MAX_CHARS);
		strcpy(mnc, MNC_INIT_STRING);
		rai = sai = cgi = lac = tai = ecgi = -1;
		nsapi=-1;
		dtFlag=-1;
		max_ul=max_dl=gbr_ul=gbr_dl=-1;
		arp=-1;
		S1U_TEID=-1;
		start = 0.0;
		
		bzero(apn, APN_MAX_CHARS);
		strcpy(apn, APN_INIT_STRING);

		instanceCounter++;
	}

	static int getInstanceCounter(){
		return instanceCounter;
	}
	static int getDeleteCounter(){
		return deleteCounter;
	}

	~PDNSession_V2(){
		instanceCounter--;
		deleteCounter++;
	}

	void print() {

		unsigned char* pmmeaddr=(unsigned char*)&(mme.addr);
		unsigned char* psgwcaddr=(unsigned char*)&(sgw_c.addr);
		unsigned char* psgwdaddr=(unsigned char*)&(sgw_d.addr);
		unsigned char* penbaddr=(unsigned char*)&(enb.addr);
		unsigned char* pueaddr=(unsigned char*)&(ue_addr);

		printf("\nPDNSESSSION (ID=%i) ********************************************************\n", session_id);
		printf("XXX start %f imsi %llu msisdn %llu mme %i.%i.%i.%i %0x sgw_c %i.%i.%i.%i %0x sgw_d %i.%i.%i.%i %0x enb %i.%i.%i.%i %0x apn %s ue_addr %i.%i.%i.%i default_bearer_id %i\n",
				start, imsi, msisdn,
				pmmeaddr[3], pmmeaddr[2], pmmeaddr[1], pmmeaddr[0], mme.teid,
				psgwcaddr[3], psgwcaddr[2], psgwcaddr[1], psgwcaddr[0], sgw_c.teid,
				psgwdaddr[3], psgwdaddr[2], psgwdaddr[1], psgwdaddr[0], sgw_d.teid,
				penbaddr[3], penbaddr[2], penbaddr[1], penbaddr[0], enb.teid,
				apn,
				pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0],
				default_bearer_id);
		printf("\n*************************************************************************\n");

	};

	void printPDNSession_V2() {

		records_written++;

		char delimiter =  ',';

		v2_out->precision(3);
		v2_out->setf(std::ios::fixed);

		*v2_out 	<< "UPDATE"			<< delimiter
				<< active_update_start	<< delimiter
				<< start				<< delimiter
				<< imsi 				<< delimiter
				<< RATType				<< delimiter
				<< printIFGE0(nsapi)
				<< printIFGE0(dtFlag)
				<< mcc << ','
				<< mnc << ','
				<< printIFGE0(lac)
				<< printIFGE0(rai)
				<< printIFGE0(cgi)
				<< printIFGE0(sai)
				<< printIFGE0(arp)
// esirich: DEFTFTS-1879 add empty strings
				<< EMPTY_INT_STRING    << delimiter	//delay_class
				<< EMPTY_INT_STRING    << delimiter //reliability_class
				<< EMPTY_INT_STRING    << delimiter	//precedence
				<< EMPTY_INT_STRING    << delimiter	//traffic_class
				<< EMPTY_INT_STRING    << delimiter	//thp
				<< printIFGE0(max_ul)
				<< printIFGE0(max_dl)
				<< printIFGE0(gbr_ul)
				<< printIFGE0(gbr_dl)
				<< printIFGE0(ecgi)
				<< time_update_request 	<< delimiter
				<< time_update_response << delimiter
				<< (int)update_cause 	<< delimiter
				<< apn 					<< delimiter
				<< default_bearer_id 	<< delimiter
				<< IPAddress(ue_addr)
				<< endl;
	}

	void printTunnelSession() {

		records_written++;
		char delimiter =  ',';

		v2_out->precision(3);
		v2_out->setf(std::ios::fixed);

		*v2_out 	<< "ACTIVATE" 		<< delimiter
				<< start 				<< delimiter
				<< time_pdn_response - start 	<< delimiter
				<< printIFGE0((int)pdn_cause)
// esirich: DEFTFTS-1879 add empty strings
				<< EMPTY_INT_STRING     << delimiter
				<< RATType				     << delimiter
				<< printIFGE0((int)pdn_cause) /*!=128*/

				<< mcc << ','
				<< mnc << ','
				<< printIFGE0(lac)
				<< printIFGE0(rai)
				<< printIFGE0(cgi)
				<< printIFGE0(sai)

				<< imsi 				<< delimiter
				<< mei					<< delimiter
				<< IPAddress(sgw_d.addr)<< delimiter
				<< apn					<< delimiter
				<< msisdn << ','
				<< printIFGE0(nsapi)
				<< IPAddress(ue_addr)	<< delimiter
				<< printIFGE0(arp)
				<< EMPTY_INT_STRING    << delimiter     //delay_class
				<< EMPTY_INT_STRING     << delimiter	//reliability_class
				<< EMPTY_INT_STRING     << delimiter	//precedence
				<< EMPTY_INT_STRING     << delimiter	//traffic_class
				<< EMPTY_INT_STRING     << delimiter	//thp
				<< printIFGE0(max_ul)
				<< printIFGE0(max_dl)
				<< printIFGE0(gbr_ul)
				<< printIFGE0(gbr_dl)
				<< EMPTY_INT_STRING     << delimiter	//sdu
				<< printIFGE0(ecgi)
				<< default_bearer_id 	<< delimiter
				<< IPAddress(mme.addr) 	<< delimiter
				<< mme.teid				<< delimiter
				<< IPAddress(sgw_c.addr)<< delimiter
				<< sgw_c.teid			<< delimiter
				<< sgw_d.teid			<< delimiter
				<< IPAddress(enb.addr) 	<< delimiter
				<< enb.teid				<< delimiter
				<< sreq_flag			<< delimiter
				<< paging_flag
				<< endl;

		//		unsigned char* pmmeaddr=(unsigned char*)&(mme.addr);
		//		unsigned char* psgwcaddr=(unsigned char*)&(sgw_c.addr);
		//		unsigned char* psgwdaddr=(unsigned char*)&(sgw_d.addr);
		//		unsigned char* penbaddr=(unsigned char*)&(enb.addr);
		//		unsigned char* pueaddr=(unsigned char*)&(ue_addr);
		//      sprintf(buff, "insert into tunnel_session.current values ( \
		//               %f, null, %llu, %i, '%s', \
		//	       '%i.%i.%i.%i'::inet,     \
		//	       '%i.%i.%i.%i'::inet, %u, \
		//	       '%i.%i.%i.%i'::inet, %u, \
		//	       '%i.%i.%i.%i'::inet, %u, \
		//	       '%i.%i.%i.%i'::inet, %u,  \
		//	       %i, %i \
		//      	             		    )",
		//      	       active_update_start, imsi, default_bearer_id, apn,
		//  	       pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0],
		//	       pmmeaddr[3], pmmeaddr[2], pmmeaddr[1], pmmeaddr[0], mme.teid,
		//	       psgwcaddr[3], psgwcaddr[2], psgwcaddr[1], psgwcaddr[0], sgw_c.teid,
		//	       psgwdaddr[3], psgwdaddr[2], psgwdaddr[1], psgwdaddr[0], sgw_d.teid,
		//	       penbaddr[3], penbaddr[2], penbaddr[1], penbaddr[0], enb.teid,
		//	       sreq_flag, paging_flag
		//	       );

		// printf("\n*************************************************************************\n");
		// printf(buff);
	}

	void CloseTunnelSession(DecodedMsg_V2 *pmsg) {

		//
		//      sprintf(buff,"update tunnel_session.all set duration = %f where imsi = %llu and start = %f",
		//      	             pmsg->timestamp - active_update_start,
		//		     imsi,
		//		     active_update_start);

		// printf("\n*************************************************************************\n");
		// printf(buff);


	}

	void printEPSBearerSession() {
		// printf("EPSBearerSession start %f end - imsi %llu linked_bearer_id %i qos -\n", start, imsi, nsapi);

		records_written++;

		/*
	fprintf(file_eps, "%f\t\\N\t%llu\t%i\t\\N\n",
		    start,
	imsi,
	nsapi); // qos is the last null
		 */

		//      PGresult *res;
		//      char buff[1000];
		//      sprintf(buff, "insert into epsbearer_session.current values (%f, NULL, %llu, %i)", start, imsi, default_bearer_id);
		//
		//      // printf("\n*************************************************************************\n");
		//      // printf(buff);
		//      res = InsertSQL(conn, buff, "epsbearer_session", start);

	}

};

#endif /* GTPV2_MAIN_H_ */
