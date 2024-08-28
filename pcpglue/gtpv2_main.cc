//#include "stdio.h"

#include <string.h>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <string>
#include <unordered_map>
#include <time.h>
#include <vector>

#include "include/gtpv1_utils.h"
#include "include/gtp_ie_gtpv2.h"
#include "include/GTPv1_packetFields.h"
#include "include/gtpv2_main.h"

using namespace std;
using namespace __gnu_cxx;

FILE *file_pdn=NULL;
FILE *file_eps=NULL;
FILE *file_tun=NULL;
int records_written=0;

int session_id_c = 0;

int num_create_session_response_notfound=0;
int num_modify_request_notfound=0;
int num_modify_response_notfound=0;
int num_notification_notfound=0;
int num_notification_ack_notfound=0;

int num_create_session_response=0;
int num_modify_request=0;
int num_modify_response=0;
int num_notification=0;
int num_notification_ack=0;
int purgedPDNSessionCount=0;

extern EArgs evaluatedArguments;
extern bool verbose;

struct dataeq {
	size_t operator()(const FTEID& x) const
	{
		return std::hash< u_int32_t >()((u_int32_t)x.addr ^ (u_int32_t)x.teid);
	};

	bool operator() (const FTEID f1, const FTEID f2) const {
		return (f1.addr==f2.addr)&&(f1.teid==f2.teid);
	};
};


int PDNSession_V2::instanceCounter = 0 ;
int PDNSession_V2::deleteCounter = 0;

typedef unordered_map<struct FTEID, struct PDNSession_V2*, dataeq, dataeq> PDNSessionMap;

PDNSessionMap::iterator it;
PDNSessionMap hmap_mme, hmap_sgw;

void
insertSessionIntoMMEMap(PDNSessionMap &theSessionMap, PDNSession_V2* s, FTEID mme, unsigned int max = 200000);

void
insertSessionIntoSGWMap(PDNSessionMap &theSessionMap, PDNSession_V2* s, FTEID sgw, unsigned int max = 200000);

void EraseSession(PDNSession_V2 *s) {

	it = hmap_mme.find(s->mme);
	if(it != hmap_mme.end()) hmap_mme.erase(it);

	it = hmap_sgw.find(s->sgw_c);
	if(it != hmap_sgw.end()) hmap_sgw.erase(it);

	delete(s);

}

void CreateSessionRequest(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {

	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	FTEID mme;
	mme = pmsg->fteid[0];

	// GTPv2
	// teid is not set
	// IMSI, MSISDN
	// fteid[1] = MME GTP-C
	// fteid[2] = PGW?
	// ue_addr = PDN address (may be empty!)
	// apn
	// default EPS bearer QoS (not decoded)
	// ambr (not decoded)

	// create new hash entry

	it = hmap_mme.find(mme);
	if(it != hmap_mme.end()) {

		PDNSession_V2 *pdnSession = it->second;

		if(pmsg->timestamp - pdnSession->start < 10) {
			pdnSession->touch = pmsg->timestamp;
			return;
		}
		EraseSession(it->second);
	}

	PDNSession_V2 *pdnSession = new PDNSession_V2();

	//hmap_mme[mme] = pdnSession;
	insertSessionIntoMMEMap(hmap_mme, pdnSession, mme, evaluatedArguments.GTPC_HASHMAP_MAX_SIZE);

	pdnSession->start = pmsg->timestamp;

	pdnSession->touch = pmsg->timestamp;


	memcpy(pdnSession->imsi, pmsg->imsi, IMSI_MAX_CHARS);
	memcpy(pdnSession->msisdn, pmsg->msisdn, MSISDN_MAX_CHARS);

	memcpy(pdnSession->apn, pmsg->apn, APN_MAX_CHARS);

	memcpy(pdnSession->mnc, pmsg->mnc, MNC_MAX_CHARS);
	memcpy(pdnSession->mcc, pmsg->mcc, MCC_MAX_CHARS);
	pdnSession->cgi = pmsg->cgi;
	pdnSession->rai	= pmsg->rai;
	pdnSession->tai = pmsg->tai;
	pdnSession->lac = pmsg->lac;
	pdnSession->sai = pmsg->sai;
	pdnSession->ecgi = pmsg->ecgi;
	pdnSession->nsapi = pmsg->nsapi;
	pdnSession->dtFlag = pmsg->dtFlag;

	pdnSession->max_ul = pmsg->max_ul;
	pdnSession->max_dl = pmsg->max_dl;
	pdnSession->gbr_ul = pmsg->gbr_ul;
	pdnSession->gbr_dl = pmsg->gbr_dl;
	pdnSession->RATType= pmsg->RATType;
	pdnSession->arp = pmsg->arp;
	pdnSession->S1U_TEID = pmsg->S1U_TEID;

	memcpy(pdnSession->mei, pmsg->mei, IMEI_MAX_CHARS);

	pdnSession->mme = mme;

	pdnSession->default_bearer_id = pmsg->eps_bearer_id;

	// pdnSession->print();
	// printf("*****************************************************\n");


}

void CreateSessionResponse(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {

	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	// GTPv2:
	// teid = MME control teid

	FTEID mme;
	mme.addr = pmsg->dst_addr;
	mme.teid = pmsg->teid;

	num_create_session_response++;

	it = hmap_mme.find(mme);
	if(it == hmap_mme.end()) {
		num_create_session_response_notfound++;
		return;
	}

	PDNSession_V2 *pdnSession = it->second;
	pdnSession->pdn_cause = pmsg->cause;
	pdnSession->touch = pmsg->timestamp;

	if(pmsg->cause != 16) {
		EraseSession(pdnSession);
		return;
	}
	pdnSession->sgw_c = pmsg->fteid[0];

	// store in second hash map the same pointer
	//hmap_sgw[pdnSession->sgw_c] = pdnSession;
	insertSessionIntoSGWMap(hmap_sgw, pdnSession, pdnSession->sgw_c, evaluatedArguments.GTPC_HASHMAP_MAX_SIZE);

	int id = pdnSession->default_bearer_id;

	if(pmsg->bearer[0][id].present==1) {
		pdnSession->sgw_d = pmsg->bearer[0][id].fteid[0];

		// printf("sgw_d fteid: ");
		// pdnSession->sgw_d.print();
	}


	pdnSession->ue_addr = pmsg->ue_addr;

	pdnSession->time_pdn_response = pmsg->timestamp;
	if(pmsg->cause_present) pdnSession->pdn_cause = pmsg->cause;

	// pdnSession->print();
	pdnSession->printTunnelSession();
}

void ModifyBearerRequest(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {
	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	// FTEID mme = pmsg->fteid[0]; THIS PROBABLY DOES NOT EXIST IN ALL CASES

	FTEID sgw;
	sgw.addr = pmsg->dst_addr;
	sgw.teid = pmsg->teid;

	num_modify_request++;

	it = hmap_sgw.find(sgw);
	if(it == hmap_sgw.end()) {
		num_modify_request_notfound++;
		return;
	}

	PDNSession_V2 *pdnSession = it->second;
	pdnSession->touch = pmsg->timestamp;
	double delay = pmsg->timestamp - pdnSession->paging_start;

	// check if this is in response to dl  notification and dl_not_ack?
	if(pdnSession->paging_flag == 1 && delay < 300) {
		pdnSession->paging_flag=1; // user to indicate that tunnel is due to pagign

		unsigned char* addr=(unsigned char*)&(pdnSession->mme.addr);

		// Successful paging goes into the paging table with cause code = 16 (success)
		//      sprintf(buff, "insert into paging.current values ( \
		//                     %f, %f, 16, \
		//		     %llu, \
		//		     '%i.%i.%i.%i'::inet,\
		//		     %u \
		//	     )",
		//      	             pdnSession->paging_start,
		//		     delay,
		//		     pdnSession->imsi,
		//		     addr[3], addr[2], addr[1], addr[0],
		//		     sgw.teid);

		// printf(buff);


		// pdnSession->paging_flag=0;

	}
	pdnSession->paging_start=0;


	if(pmsg->delay_value_present) {
		pdnSession -> sreq_flag = 1;
		// printf("This tunnel is a result of SREQ\n");
	} else pdnSession -> sreq_flag = 0;

	if(pdnSession->active_update_start>0) {
		if (pmsg->cgi!= -1){
			pdnSession->cgi = pmsg->cgi;
		}
		if(pmsg->rai!= -1){
			pdnSession->rai	= pmsg->rai;
		}
		if(pmsg->tai!=-1){
			pdnSession->tai = pmsg->tai;
		}
		if(pmsg->lac!=-1){
			pdnSession->lac = pmsg->lac;
		}
		if(pmsg->sai!=-1){
			pdnSession->sai = pmsg->sai;
		}
		if(pmsg->ecgi !=-1){
			pdnSession->ecgi = pmsg->ecgi;
		}
		if(pmsg->nsapi != -1){
			pdnSession->nsapi = pmsg->nsapi;
		}
		if(pmsg->dtFlag!=-1){
			pdnSession->dtFlag = pmsg->dtFlag;
		}
		if(pmsg->max_ul!=-1){
			pdnSession->max_ul = pmsg->max_ul;
		}
		if(pmsg->max_dl!=-1){
			pdnSession->max_dl = pmsg->max_dl;
		}
		if(pmsg->gbr_ul!=-1){
			pdnSession->gbr_ul = pmsg->gbr_ul;
		}
		if(pmsg->gbr_dl!=-1){
			pdnSession->gbr_dl = pmsg->gbr_dl;
		}
		if(pmsg->RATType != ""){
			pdnSession->RATType= pmsg->RATType;
		}
		if(pmsg->arp!=-1){
			pdnSession->arp = pmsg->arp;
		}
		if(pmsg->mei_present){
			memcpy(pdnSession->mei, pmsg->mei, IMEI_MAX_CHARS);
		}

		pdnSession->CloseTunnelSession(pmsg);

	}


	int id = pdnSession->default_bearer_id;

	// printf("\nModifyBearer default_bearer=%i\n", id);
	if(id==-1) {
		printf("Bearer id should be set! SessionID=%i\n", pdnSession->session_id);
		exit(0);
	}

	if(pmsg->bearer[0][id].present==1) {
		pdnSession->enb = pmsg->bearer[0][id].fteid[0];

		// printf("enb fteid: ");
		// pdnSession->enb.print();
	}

	if(pdnSession->time_update_request==0) pdnSession->time_update_request = pmsg->timestamp;

	pdnSession->active_update_start = pmsg->timestamp;

}

void ModifyBearerResponse(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {
	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}
	num_modify_response++;
	FTEID mme;
	mme.addr = pmsg->dst_addr;
	mme.teid = pmsg->teid;

	it = hmap_mme.find(mme);
	if(it == hmap_mme.end()) {
		num_modify_response_notfound++;
		return;
	}

	PDNSession_V2 *pdnSession = it->second;
	pdnSession->touch = pmsg->timestamp;
	pdnSession->time_update_response = pmsg->timestamp;
	if(pmsg->cause_present) pdnSession->update_cause = pmsg->cause;

	if(pdnSession->default_bearer_established==0) {

		pdnSession->printPDNSession_V2();
		pdnSession->printEPSBearerSession();
	}
	pdnSession->default_bearer_established=1;
	pdnSession->paging_flag=0;
}

void DeleteSessionRequest(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {
	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	FTEID sgw;
	sgw.addr = pmsg->dst_addr;
	sgw.teid = pmsg->teid;

	it = hmap_sgw.find(sgw);

	if(it == hmap_sgw.end()) {
		return;
	}

	PDNSession_V2 *s = (*it).second;
	s->dtFlag = pmsg->dtFlag;
	s->touch = pmsg->timestamp;

	if(s->active_update_start>0) {
		s->CloseTunnelSession(pmsg);
	}
	EraseSession(s);
}

void DownlinkDataNotification(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {

	// printf("*****************************************************\n");
	// printf("OOO DownlinkDataNotification\n");
	// printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

	// printf("src: ");
	// printaddr(pmsg->src_addr);
	// printf(" dst: ");
	// printaddr(pmsg->dst_addr);
	// printf(" teid: %0x\n", pmsg->teid);

	FTEID mme;
	mme.addr = pmsg->dst_addr;
	mme.teid = pmsg->teid;

	num_notification++;


	it = hmap_mme.find(mme);
	if(it == hmap_mme.end()) {
		num_notification_notfound++;
		return;
	}

	PDNSession_V2 *pdnSession = it->second;

	pdnSession->touch = pmsg->timestamp;

	if(pdnSession->paging_start==0 || pmsg->timestamp - pdnSession->paging_start> 300)
		pdnSession->paging_start = pmsg->timestamp;
}   

void DownlinkDataNotificationAck(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {
	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	FTEID sgw;
	sgw.addr = pmsg->dst_addr;
	sgw.teid = pmsg->teid;

	num_notification_ack++;

	it = hmap_sgw.find(sgw);
	if(it == hmap_sgw.end()) {
		num_notification_ack_notfound++;
		return;
	}

	PDNSession_V2 *pdnSession = it->second;
	pdnSession->touch = pmsg->timestamp;
	unsigned char* addr=(unsigned char*)&(sgw.addr);
	double delay = pmsg->timestamp - pdnSession->paging_start;
	char sdelay[100];
	if(delay>300) {
		sprintf(sdelay,"null");
		pdnSession->paging_start=0; // RESET PAGIONG START, WE DO NOT BELIEVE IT IS THE SAME PROC
		pdnSession->paging_flag = 0;
	} else {
		pdnSession->paging_flag = 1;
		sprintf(sdelay,"%f", delay);
	}
	//
	//   sprintf(buff, "insert into downlink_data_notification.current values ( \
	//                     %f, %s, %i, \
	//		     %llu, \
	//		     '%i.%i.%i.%i'::inet,\
	//		     %u \
	//	     )",
	//      	             pdnSession->paging_start,
	//		     sdelay, pmsg->cause,
	//		     pdnSession->imsi,
	//		     addr[3], addr[2], addr[1], addr[0],
	//		     sgw.teid);

	// printf(buff);


	// printf("*****************************************************\n");

}      

void DownlinkDataNotificationFailure(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {
	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

	FTEID sgw;
	sgw.addr = pmsg->dst_addr;
	sgw.teid = pmsg->teid;

	it = hmap_sgw.find(sgw);
	if(it == hmap_sgw.end()) {
		return;
	}

	PDNSession_V2 *pdnSession = it->second;
	pdnSession->touch = pmsg->timestamp;
	double delay = pmsg->timestamp - pdnSession->paging_start;
	unsigned char* addr=(unsigned char*)&(pdnSession->mme.addr);

	pdnSession->paging_start=0;
}      

void ContextRequest(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {

	printf("*****************************************************\n");
	printf("OOO ContextRequest\n");
	printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}

}      

void ContextResponse(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {
	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);

	}

} 

void ContextAck(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {
	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

} 

void ReleaseAccessBearersRequest(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {

	// printf("*****************************************************\n");
	// printf("OOO ReleaseAccessBearersRequest\n");
	// printf("teid 0x%x\n", pmsg->teid);

	int pos=0;
	while(pos<datalen) {

		pos = DecodeIE(p, pos, datalen, pmsg);
		// printf("pos %i datalen %i\n");

	}

	//printf("src: ");
	//printaddr(pmsg->src_addr);
	//printf(" dst: ");
	//printaddr(pmsg->dst_addr);
	//printf(" teid: %0x\n", pmsg->teid);

	FTEID sgw;
	sgw.addr = pmsg->dst_addr;
	sgw.teid = pmsg->teid;

	num_notification_ack++;

	it = hmap_sgw.find(sgw);
	if(it == hmap_sgw.end()) {
		num_notification_ack_notfound++;
		return;
	}

	PDNSession_V2 *pdnSession = it->second;
	pdnSession->touch = pmsg->timestamp;

	pdnSession->paging_start=0;

	if(pdnSession->active_update_start>0) {
		pdnSession->CloseTunnelSession(pmsg);
		pdnSession->active_update_start=0;

	}

}      

void ReleaseAccessBearersResponse(unsigned char *p, int datalen, DecodedMsg_V2 *pmsg) {
	int pos=0;
	while(pos<datalen) {
		pos = DecodeIE(p, pos, datalen, pmsg);
	}
}      

bool PDNSortFunc(const PDNSession_V2* d1, const PDNSession_V2* d2)
{
	return d1->touch < d2->touch;
}

void purgeOldSessions(double last_time) {
	int i=0;
	vector<PDNSession_V2 *> staleSessionList ;

	it = hmap_mme.begin();
	while(it != hmap_mme.end()) {
		PDNSession_V2 *pdnSession = it->second;
		if(last_time - pdnSession->touch > 3600*24) {
			staleSessionList.push_back(pdnSession);
		}
		it++;
		i++;
	}
	std::sort(staleSessionList.begin(), staleSessionList.end(), PDNSortFunc);
	int staleSessions = staleSessionList.size();
	if(staleSessions>1000) {
		for (int index=0; index<staleSessions-1000; ++index) {
			EraseSession(staleSessionList[index]);
		}
	}
}

int last_ipid=0;
int last_teid=0;
int last_src=0;
int last_dst=0;

extern time_t file_time;
extern time_t last_maint;

// esirich added a timestamp and indendation to fix DEFTFTS-1677
void logV2Stats(time_t last_stat, ofstream * stat_out){
	if (file_time-last_maint > 60) {
		char timebuffer[30]; // 30 bytes is more than enough
		
		last_maint = file_time;
		*stat_out << ctime_r(&file_time, timebuffer);

		*stat_out << " mme map size: " << hmap_mme.size()
					<< ", sgw map size: " << hmap_sgw.size()
					<<" , number of purged PDN Sessions: " << purgedPDNSessionCount
					<< ", num_create_session_response: " << num_create_session_response
					<< ", num_create_session_response_notfound: " << num_create_session_response_notfound << endl
					<< " num_modify_request: " << num_modify_request
					<< ", num_modify_request_notfound: " << num_modify_request_notfound << endl
					<< " num_modify_response: " << num_modify_response
					<< ", num_modify_response_notfound: " << num_modify_response_notfound << endl
					<< " num_notification: " << num_notification
					<< ", num_notification_notfound: " << num_notification_notfound << endl
					<< " num_notification_ack: " << num_notification_ack
					<< ", num_notification_ack_notfound: " << num_notification_ack_notfound <<endl
					<< PacketCounter::getInstance();

		PacketCounter::getInstance()->clearCounters();

		num_create_session_response_notfound=0;
		num_modify_request_notfound=0;
		num_modify_response_notfound=0;
		num_notification_notfound=0;
		num_notification_ack_notfound=0;

		num_create_session_response=0;
		num_modify_request=0;
		num_modify_response=0;
		num_notification=0;
		num_notification_ack=0;

		purgedPDNSessionCount=0;
	}
}

int processV2Packet(const unsigned char *packet,const pcap_pkthdr *pkthdrPTR, int linktype)
{
	int i;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct pcap_pkthdr pkthdr = *pkthdrPTR;     /* pcap.h */
	struct ether_header *eptr;  /* net/ethernet.h */
	double lastPurgeTime = -1;

	bool live = false;

	u_char *ptr; /* printing out hardware header info */

	double timeBetweenPurges=60;
	double lastpacket=0;
	double 	packetTime = pkthdr.ts.tv_sec + pkthdr.ts.tv_usec/1e6;
	//TODO IP checks need conditional exit continue statements
	const struct my_ip* ip;
	int length = pkthdr.len;

	if(linktype == 1) {
		/* lets start with the ether header... */
		eptr = (struct ether_header *) packet;

		/* Do a couple of checks to see what packet type we have..*/

		int ethertype = ntohs (eptr->ether_type);
		if (ethertype == ETHERTYPE_IP) {
			ip = (struct my_ip*)(packet + sizeof(struct ether_header));
			length -= sizeof(struct ether_header);
		} else if(ethertype == ETHERTYPE_VLAN) {
			ip = (struct my_ip*)(packet + sizeof(struct ether_header) + 4);
			length -= sizeof(struct ether_header)+4;
		} else return -1;
	} else if(linktype==113) {
		if(packet[14]!=0x08 || packet[15]!=0x00) return -1;
		ip = (struct my_ip*)(packet + 16);
		length -= 16;
	}

	/* check to see we have a packet of valid length */
	if (length < sizeof(struct my_ip))
	{
		printf("truncated ip %d",length);
		return -1;
	}

	int len     = ntohs(ip->ip_len);
	int hlen    = IP_HL(ip); /* header length */
	int IPversion = IP_V(ip);

	/* check version */
	if(IPversion != 4)
	{
		fprintf(stdout,"%f Unknown version %d\n",packetTime, IPversion);
		return -1;
		// return 0;
	}

	/* check header length */
	if(hlen < 5 )
	{
		fprintf(stdout,"bad-hlen %d \n",hlen);
	}

	/* see if we have as much packet as we should */
	if(length < len)
		printf("\ntruncated IP - %d %d\n",len, length);

	/* Check to see if we have the first fragment */
	int off = ntohs(ip->ip_off);

	int ipid = ip->ip_id;

	int ttl = ip->ip_ttl;
	//printf("ttl %i\n", ttl);

	int proto = ip->ip_p;
	//printf("proto 0x%x\n", proto);

	unsigned int src_addr=0;
	unsigned int dst_addr=0;
	for(int i=0; i<4; i++) {
		src_addr = src_addr*256 +((unsigned char*)&ip->ip_src)[i];
		dst_addr = dst_addr*256 +((unsigned char*)&ip->ip_dst)[i];
	}

	if(proto!=0x11) return -1; // if not UDP
	unsigned char* udp = (unsigned char*)ip+hlen*4;
	unsigned short sport = NetworkShortAt(udp); // udp[0]*256 + udp[1];//this check is done ------------------------------------------
	unsigned short dport = NetworkShortAt(udp+2); //udp[2]*256 + udp[3];//this check is done ------------------------------------------
	if(sport != 2123 && dport != 2123) return -1; //this check is done ------------------------------------------
	unsigned char* gtp = udp+8;
	unsigned char flags = gtp[0];
	if((flags & 0xe0) != 0x40) {
		return -1;
	}

	struct DecodedMsg_V2 msg;

	int k,n,m;
	if(flags & 8) {
		k = 1;
		m = 5;
		n = 9;
		msg.teid = ntohl(*(unsigned int *)(gtp+4));
	} else {
		msg.teid = -1;
		n = 5;
	}
	int gtp_hlen = n+3;
	if((flags & 16) && verbose) cout << "Piggybacking" <<endl;
	unsigned char msgtype = gtp[1];
	unsigned short int gtplen = NetworkShortAt(gtp+2);//gtp[2]*256+gtp[3];
	msg.timestamp = pkthdr.ts.tv_sec + pkthdr.ts.tv_usec/1e6;
	msg.src_addr = src_addr;
	msg.dst_addr = dst_addr;
	if(msg.teid == last_teid && last_src == src_addr && last_dst == dst_addr && msg.timestamp-lastpacket<1e-5) {
		printf("Duplicate?\n");
		return -1;
	}
	lastpacket=msg.timestamp;

	last_teid = msg.teid;
	last_src = src_addr;
	last_dst = dst_addr;
	unsigned char *data=gtp+gtp_hlen;

	int datalen = gtplen - 8  ; // EZ BIZTOS ROSSZ!
	switch (msgtype) {

	case 1:
		// printf("Echo Request\n");
		break;
	case 2:
		// printf("Echo Response\n");
		break;
	case 3:
		printf("Version not supported\n");
		break;
	case 32:
		CreateSessionRequest(data, datalen, &msg);
		break;
	case 33:
		CreateSessionResponse(data, datalen, &msg);
		break;
	case 34:
		ModifyBearerRequest(data, datalen, &msg);
		break;
	case 35:
		ModifyBearerResponse(data, datalen, &msg);
		break;
	case 36:
		DeleteSessionRequest(data, datalen, &msg);
		break;
	case 37:
		// printf("Delete Session response\n");
		//DeleteSessionResponse(data, datalen, &msg);
		break;
	case 70:
		DownlinkDataNotificationFailure(data, datalen, &msg);
		break;
	case 130:
		//ContextRequest(data, datalen, &msg); Michael checking run time overhead;
		break;
	case 131:
		//ContextResponse(data, datalen, &msg); // function does nothing
		break;
	case 132:
		//ContextAck(data, datalen, &msg);
		break;
	case 170:
		ReleaseAccessBearersRequest(data, datalen, &msg);
		break;
	case 171:
		//ReleaseAccessBearersResponse(data, datalen, &msg);
		break;
	case 176:
		DownlinkDataNotification(data, datalen, &msg);
		break;
	case 177:
		DownlinkDataNotificationAck(data, datalen, &msg);
		break;
	default:
		if (verbose) cout << "******************* undecoded message type " << (unsigned int) msgtype << endl;
		break;
	}
	return 0;
}

int removeAllPDNSessionsInMemory(){
	int numberOfElementsAndSessionsRemoved=0;
	int length = hmap_mme.size();

	for( int i = 0;i < length ; ++i){
		it = hmap_mme.begin();
		hmap_sgw.erase(hmap_sgw.find(it->second->sgw_c));
		delete it->second;
		hmap_mme.erase(it);
		numberOfElementsAndSessionsRemoved++;
	}
	length = hmap_sgw.size();
	for(int i=0; i<length; ++i){
		it = hmap_sgw.begin();
		delete it->second;
		hmap_sgw.erase(it);
		numberOfElementsAndSessionsRemoved++;
	}

	return numberOfElementsAndSessionsRemoved;
}

void
insertSessionIntoMMEMap(PDNSessionMap &theSessionMap, PDNSession_V2* s, FTEID mme, unsigned int max){
	if(hmap_mme.size() > max ){
		//Remove one element

		PDNSessionMap::iterator itt, lowest;
		for (itt = lowest = hmap_mme.begin(); itt != hmap_mme.end(); ++itt){
			PDNSession_V2 *p = itt->second;
			PDNSession_V2 *p1 = lowest->second;
			if (p->touch < p1->touch){
				lowest = itt;
			}
		}
		if(lowest != hmap_mme.end()) {
			hmap_sgw.erase(hmap_sgw.find(lowest->second->sgw_c));
			delete (lowest->second);
			hmap_mme.erase(lowest);
		}
	}

	hmap_mme[mme] = s;
}


void
insertSessionIntoSGWMap(PDNSessionMap &theSessionMap, PDNSession_V2* s, FTEID sgw, unsigned int max){

	if(hmap_sgw.size() > max ){
		//Remove one element

		PDNSessionMap::iterator itt, lowest;
		for (itt = lowest = hmap_sgw.begin(); itt != hmap_sgw.end(); ++itt){
			PDNSession_V2 *p = itt->second;
			PDNSession_V2 *p1 = lowest->second;
			if (p->touch < p1->touch){
				lowest = itt;
			}
		}
		if(lowest != hmap_sgw.end()) {
			hmap_mme.erase(hmap_mme.find(lowest->second->mme));
			delete (lowest->second);
			hmap_sgw.erase(lowest);
		}
		purgedPDNSessionCount++;
	}

	hmap_sgw[sgw] = s;

}
