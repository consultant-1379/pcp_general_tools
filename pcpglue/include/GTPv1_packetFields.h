
//the bitfield for the MNC as per GTPv1
#ifndef GTPv1_packetFields
#define GTPv1_packetFields


//#pragma pack(1) //vital to get bit fields to line up correctly
#include <pcap.h>
#include "gtpv1_utils.h"
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <unordered_map>
using std::string;
using std::cout;
using std::ostream;
using std::endl;
using std::hash;

//using std::precision;

// esirich: DEFTFTS-1825
// include the lengths of the character buffers
#include "gtp_ie.h"


extern std::ofstream f_out;

class GTPPorts{
public:
enum PortNumbers{GTP_CONTROL_PORT = 2123};
};

class IPVersion{
public:
	enum{IPV4 =  4};
};

class GTPMessageTypes{
public:
	enum {ECHO_REQUEST= 1,
		ECHO_RESPONSE = 2,
		VERSION_NOT_SUPPORTED = 3,
		SEND_ROUTING_FOR_QPRS_REQUEST =32,
		SEND_ROUTING_FOR_QPRS_RESPONSE = 33,
		CREATE_PDP_CONTEXT_REQUEST=0X10,
		CREATE_PDP_CONTEXT_RESPONSE =0X11,
		UPDATE_PDP_CONTEXT_REQUEST = 0X12,
		UPDATE_PDP_CONTEXT_RESPONSE= 0x13,
		DELETE_PDP_CONTEXT_REQUEST = 0x14,
		DELETE_PDP_CONTEXT_RESPONSE= 0x15
	};
};

struct FTEID {

	unsigned int addr;
	unsigned int teid;
	double time; // creation time

	FTEID() {
		addr = 0;
		teid = 0;
		time = -1;
	}

};


struct PDPSession {
	
	pthread_mutex_t PDP_session_mutex;
	
	double startTime;

	double touch;  // last activity on this session of any kind

	double time_pdn_response;
	double time_update_request;
	double time_update_response;

	double active_update_start;

   char imsi[IMSI_MAX_CHARS];
   char imei[IMEI_MAX_CHARS];   

	struct FTEID sgsn;
	struct FTEID ggsn_c, ggsn_d;
	struct FTEID dle; // downlink endpoint (rnc or sgsn)

	string apn;
    char msisdn[MSISDN_MAX_CHARS];
	unsigned int ue_addr;
	int nsapi;

	string pdp_type; //primary or secondary
	string rat; //GSM, ...

	int dtflag;

    char mnc[MNC_MAX_CHARS];
    char mcc[MCC_MAX_CHARS];
    int lac, rac;
    int cid, sac;

	int pdn_cause;
	unsigned char update_cause;

	int arp, delay_class, reliability_class, precedence;
	string traffic_class;
	int thp;

	int max_ul, max_dl;
	int gbr_ul, gbr_dl;

	int sdu;
	static int instanceCounter;
	static int deleteCounter;

	unsigned long unknownPackets;
	unsigned long unknownBytes;
	unsigned long httpPackets;
	unsigned long httpBytes;
	unsigned long googlePackets;
	unsigned long googleBytes;
	unsigned long steamPackets;
	unsigned long steamBytes;
	unsigned long dnsPackets;
	unsigned long dnsBytes;
	unsigned long igmpBytes;
	unsigned long igmpPackets;
	unsigned long mdnsBytes;
	unsigned long mdnsPackets;
	unsigned long sslBytes;
	unsigned long sslPackets;
	unsigned long adobeConnectBytes;
	unsigned long adobeConnectPackets;
	unsigned long afpBytes;
	unsigned long afpPackets;
	unsigned long aiminiBytes;
	unsigned long aiminiPackets;
	unsigned long antsp2pBytes;
	unsigned long antsp2pPackets;
	unsigned long aviBytes;
	unsigned long aviPackets;
	unsigned long blackBerryBytes;
	unsigned long blackBerryPackets;
	unsigned long dhcpBytes;
	unsigned long dhcpPackets;
	unsigned long fiestaBytes;
	unsigned long fiestaPackets;
	unsigned long flashBytes;
	unsigned long flashPackets;
	unsigned long ftpBytes;
	unsigned long ftpPackets;
	unsigned long gameKitBytes;
	unsigned long gameKitPackets;
	unsigned long gooberBytes;
	unsigned long gooberPackets;
	unsigned long greBytes;
	unsigned long grePackets;
	unsigned long gtpBytes;
	unsigned long gtpPackets;
	unsigned long guildWarsBytes;
	unsigned long guildWarsPackets;
	unsigned long H323Bytes;
	unsigned long H323Packets;
	unsigned long hamachiVPNBytes;
	unsigned long hamachiVPNPackets;
	unsigned long HTTPBytes;
	unsigned long HTTPPackets;
	unsigned long gTalkBytes;
	unsigned long gTalkPackets;
	unsigned long veohTVBytes;
	unsigned long veohTVPackets;
	unsigned long icmpBytes;
	unsigned long icmpPackets;
	unsigned long imoBytes;
	unsigned long imoPackets;
	unsigned long iptvBytes;
	unsigned long iptvPackets;
	unsigned long japBytes;
	unsigned long japPackets;
	unsigned long kerberosBytes;
	unsigned long kerberosPackets;
	unsigned long ldapBytes;
	unsigned long ldapPackets;
	unsigned long mailIMAPBytes;
	unsigned long mailIMAPPackets;
	unsigned long mailPOPBytes;
	unsigned long mailPOPPackets;
	unsigned long mailSMTPBytes;
	unsigned long mailSMTPPackets;
	unsigned long meeboBytes;
	unsigned long meeboPackets;
	unsigned long mpegBytes;
	unsigned long mpegPackets;
	unsigned long msnBytes;
	unsigned long msnPackets;
	unsigned long msSQLBytes;
	unsigned long msSQLPackets;
	unsigned long mySQLBytes;
	unsigned long mySQLPackets;
	unsigned long netbiosBytes;
	unsigned long netbiosPackets;
	unsigned long netflixBytes;
	unsigned long netflixPackets;
	unsigned long nfsBytes;
	unsigned long nfsPackets;
	unsigned long oovooBytes;
	unsigned long oovooPackets;
	unsigned long orbBytes;
	unsigned long orbPackets;
	unsigned long ospfBytes;
	unsigned long ospfPackets;
	unsigned long pandoraBytes;
	unsigned long pandoraPackets;
	unsigned long pppBytes;
	unsigned long pppPackets;
	unsigned long ps3Bytes;
	unsigned long ps3Packets;
	unsigned long quakeBytes;
	unsigned long quakePackets;
	unsigned long skypeBytes;
	unsigned long skypePackets;
	unsigned long telnetBytes;
	unsigned long telnetPackets;
	unsigned long teamspeakBytes;
	unsigned long teamspeakPackets;
	unsigned long viberBytes;
	unsigned long viberPackets;
	unsigned long WOWBytes;
	unsigned long WOWPackets;
	unsigned long wiiBytes;
	unsigned long wiiPackets;
	unsigned long xboxBytes;
	unsigned long xboxPackets;
	unsigned long yahooBytes;
	unsigned long yahooPackets;
	unsigned long zattoBytes;
	unsigned long zattoPackets;

	void init() {

		pthread_mutex_init(&(PDP_session_mutex), 0);
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
		pdp_type = "unknown";
		rat = "";
		traffic_class = "";
		nsapi = -1;
		bzero(imei, IMEI_MAX_CHARS);
		strcpy(imei, IMEI_INIT_STRING);
		ue_addr = 0;
		sdu=-1;
		max_ul = max_dl = gbr_ul = gbr_dl = -1;
		thp = arp = delay_class = reliability_class = precedence = -1;
		bzero(mcc, MCC_MAX_CHARS);
		strcpy(mcc, MCC_INIT_STRING);
		bzero(mnc, MNC_MAX_CHARS);
		strcpy(mnc, MNC_INIT_STRING);
		lac=rac=cid=sac=-1;
		dtflag=0;
		unknownPackets=0;
		unknownBytes=0;
		httpPackets=0;
		httpBytes=0;
		googlePackets=0;
		googleBytes=0;
		steamPackets=0;
		steamBytes=0;
		dnsPackets=0;
		dnsBytes=0;
		igmpBytes=0;
		igmpPackets=0;
		mdnsBytes=0;
		mdnsPackets=0;
		sslBytes=0;
		sslPackets=0;
		afpBytes=0;
		afpPackets=0;
		aiminiBytes=0;
		aiminiPackets=0;
		antsp2pBytes=0;
		antsp2pPackets=0;
		aviBytes=0;
		aviPackets=0;
		blackBerryBytes=0;
		blackBerryPackets=0;
		dhcpBytes=0;
		dhcpPackets=0;
		fiestaBytes=0;
		fiestaPackets=0;
		flashBytes=0;
		flashPackets=0;
		ftpBytes=0;
		ftpPackets=0;
		gameKitBytes=0;
		gameKitPackets=0;
		gooberBytes=0;
		gooberPackets=0;
		greBytes=0;
		grePackets=0;
		gtpBytes=0;
		gtpPackets=0;
		guildWarsBytes=0;
		guildWarsPackets=0;
		H323Bytes=0;
		H323Packets=0;
		hamachiVPNBytes=0;
		hamachiVPNPackets=0;
		HTTPBytes=0;
		HTTPPackets=0;
		gTalkBytes=0;
		gTalkPackets=0;
		veohTVBytes=0;
		veohTVPackets=0;
		icmpBytes=0;
		icmpPackets=0;
		imoBytes=0;
		imoPackets=0;
		iptvBytes=0;
		iptvPackets=0;
		japBytes=0;
		japPackets=0;
		kerberosBytes=0;
		kerberosPackets=0;
		ldapBytes=0;
		ldapPackets=0;
		mailIMAPBytes=0;
		mailIMAPPackets=0;
		mailPOPBytes=0;
		mailPOPPackets=0;
		mailSMTPBytes=0;
		mailSMTPPackets=0;
		meeboBytes=0;
		meeboPackets=0;
		mpegBytes=0;
		mpegPackets=0;
		msnBytes=0;
		msnPackets=0;
		msSQLBytes=0;
		msSQLPackets=0;
		mySQLBytes=0;
		mySQLPackets=0;
		netbiosBytes=0;
		netbiosPackets=0;
		netflixBytes=0;
		netflixPackets=0;
		nfsBytes=0;
		nfsPackets=0;
		oovooBytes=0;
		oovooPackets=0;
		orbBytes=0;
		orbPackets=0;
		ospfBytes=0;
		ospfPackets=0;
		pandoraBytes=0;
		pandoraPackets=0;
		pppBytes=0;
		pppPackets=0;
		ps3Bytes=0;
		ps3Packets=0;
		quakeBytes=0;
		quakePackets=0;
		skypeBytes=0;
		skypePackets=0;
		telnetBytes=0;
		telnetPackets=0;
		teamspeakBytes=0;
		teamspeakPackets=0;
		viberBytes=0;
		viberPackets=0;
		WOWBytes=0;
		WOWPackets=0;
		wiiBytes=0;
		wiiPackets=0;
		xboxBytes=0;
		xboxPackets=0;
		yahooBytes=0;
		yahooPackets=0;
		zattoBytes=0;
		zattoPackets=0;


	}

	PDPSession(char *imsi_init) {
		init();
		strncpy(imsi, imsi_init, IMSI_MAX_CHARS);
		instanceCounter++;
	}

	~PDPSession(){
		pthread_mutex_destroy(&(PDP_session_mutex));
		instanceCounter--;
		deleteCounter++;
	}

	static int getInstanceCounter(){
		return instanceCounter;
	}
	static int getDeleteCounter(){
		return deleteCounter;
	}
	
	void print() {

		unsigned char* psgsnaddr=(unsigned char*)&(sgsn.addr);
		unsigned char* pggsncaddr=(unsigned char*)&(ggsn_c.addr);
		unsigned char* pggsndaddr=(unsigned char*)&(ggsn_d.addr);
		unsigned char* pdleaddr=(unsigned char*)&(dle.addr);
		unsigned char* pueaddr=(unsigned char*)&(ue_addr);

		printf("\nPDPSESSSION_PRINT********************************************************\n");
		printf("XXX start %f imsi %llu msisdn %llu sgsn %i.%i.%i.%i %0x ggsn_c %i.%i.%i.%i %0x ggsn_d %i.%i.%i.%i %0x dle %i.%i.%i.%i %0x apn %s ue_addr %i.%i.%i.%i nsapi %i\n",
				startTime, imsi, msisdn,
				psgsnaddr[3], psgsnaddr[2], psgsnaddr[1], psgsnaddr[0], sgsn.teid,
				pggsncaddr[3], pggsncaddr[2], pggsncaddr[1], pggsncaddr[0], ggsn_c.teid,
				pggsndaddr[3], pggsndaddr[2], pggsndaddr[1], pggsndaddr[0], ggsn_d.teid,
				pdleaddr[3], pdleaddr[2], pdleaddr[1], pdleaddr[0], dle.teid,
				apn.c_str(),
				pueaddr[3], pueaddr[2], pueaddr[1], pueaddr[0],
				nsapi);
		printf("\n*************************************************************************\n");

	}
	void printUpdate();
	void printPDPSession();

};

struct MNCBCDDigits{
	unsigned char:4;
	unsigned char Hundreds:4;
	unsigned char Tens:4;
	unsigned char Units:4;
};


//the bitfield for the MCC as per GTPv1
struct MCCBCDDigits{
	unsigned char Hundreds:4;
	unsigned char Tens:4;
	unsigned char Units:4;
};

struct GTP_Control_Full_Header{
	unsigned char N_PDUNumberFlag:1;
	unsigned char SequenceNumberFlag:1;
	unsigned char ExtensionHeaderFlag:1;
	unsigned char Reserved:1;
	unsigned char ProtocolType:1;
	unsigned char Version:3;

	unsigned char MessageType:8;

	unsigned short TotalLength:16;

	unsigned int TunnelEndpointIdentifier :32;

	unsigned short SequenceNumber:16;
	unsigned char N_PDUNumber:8;
	unsigned char NextExtensionHeaderType:8;

};

struct GTP_Control_Basic_Header{
	unsigned char N_PDUNumberFlag:1;
	unsigned char SequenceNumberFlag:1;
	unsigned char ExtensionHeaderFlag:1;
	unsigned char Reserved:1;
	unsigned char ProtocolType:1;
	unsigned char Version:3;

	unsigned char MessageType:8;

	unsigned short TotalLength:16;

	unsigned int TunnelEndpointIdentifier :32;

};


union GTP_Control_Header{
	GTP_Control_Basic_Header basicHeader;
	GTP_Control_Full_Header fullHeader;
};

struct LinuxCookedHeader{
	u_short incoming:16;
	u_short ARPHPD_:16;
	u_short loopback:16;
	u_short llaAddressType:16;
	u_short llaAddress[4];

};

struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};


void decodeMNC(unsigned char *p, char *mnc);
void decodeMCC(unsigned char *p, char *mcc);
unsigned long long parseIMSI_IMEI_Field(unsigned char *p, int pos);
unsigned int extractIpAddress(unsigned char* p);
unsigned short extractPortFromPacket(unsigned char* p);


#endif

