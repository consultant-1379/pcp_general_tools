
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <pcap.h>

#include "include/ipq_api.h"

#include <linux/if_ether.h>
#include "classify.h"
#include "UE_map.hpp"
#include <stdint.h> 
#include <netinet/in.h>
#include "include/GTPv1_packetFields.h"
#include "include/gtp_ie_gtpv2.h"
#include "mutex.hpp"
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


//#
#define IPQ_TICK_RESOLUTION			(1000)
#define PACE_CONNECTION_HASH_SIZE	(10*1024*1024)
#define PACE_CONNECTION_TIMEOUT		(60*1000000/IPQ_TICK_RESOLUTION)
#define CAAP_MAX_PROTOCOLS (IPOQUE_MAX_SUPPORTED_PROTOCOLS + 32)
IPOQUE_PROTOCOL_BITMASK iptables_bm;

#define DEBUG   // TODO -- comment this out

#ifdef DEBUG
#define STRING(X)	#X
#define ASSERT(x) {if(!(x)) {fprintf(stderr, "Assert failed at %s:%d\n", __FILE__, __LINE__); exit(255);}}
#else
#define ASSERT(x)	
#endif
#define rdtscl(low) __asm__ __volatile__("rdtsc" : "=a" (low) : : "edx")

enum direction{NOT_YET_DEFINED = -1, HEADING_TO_INTERNET = 1, HEADING_TO_USER_EQUIPMENT = 2};

static u32 _size_flow_struct = 0;
static u32 _real_size_flow_struct = 0;
static u32 _flow_data_offset = 0;

static u64 ipq_hash_size = 10 * 1024 * 1024;
static u32 ipq_frag_hash_size = 1 * 1024 * 1024;
static u32 ipq_tick_resolution = 1000;
static u32 ipq_connection_timeout = 600;
static u32 _size_id_struct = 0;

static u64 protocol_counters[CAAP_MAX_PROTOCOLS + 1];
unsigned long long unalocatedPackets = 0;
unsigned long long alocatedPackets = 0;

extern UE_maptype ueMap;

struct classify_data_struct
{
	struct ipoque_detection_module_struct *ipq;
	struct timeorderedhash *connection_toh;	// Flow hash table
	struct timeorderedhash *subscriber_toh;	 //Subscriber [data] hash table
};

void helper_print_packet_details(const struct iphdr *iph, const struct pcap_pkthdr *header, const char *packet, int print_packet);


static void *ipq_get_id(u8 * ip, u8 is_ip_v6, classify_data cd)
{
	void *r;
	u8 new_entry = 0;

	if (cd->subscriber_toh == NULL) {
		printf("the hash table was not set for ipq_get_id");
		return NULL;
	}

	if (is_ip_v6 != 0) {

		return NULL;

	} else {
		r = ipoque_to_hash_insert(cd->subscriber_toh, ip, &new_entry);
	}
	if (new_entry != 0) {
		bzero(r, _size_id_struct);
	}
	return r;
}

static void *classify_malloc(unsigned long size)
{
	void *ret;

	ASSERT(size);

	ret = malloc((size_t) size);

	ASSERT(ret);
}

static void classify_free(void *ptr)
{
	ASSERT(ptr);

	free(ptr);
}

static void *classify_toh_malloc(unsigned long size, void *uheap)
{
	void *ret;

	ASSERT(size);

	ret = malloc((size_t) size);

	ASSERT(ret);
}

static void classify_toh_free(void *ptr, void *uheap)
{
	ASSERT(ptr);

	free(ptr);
}

int toh_timeout_callback(){
	//never gets to this one
	printf("we have timed out");
};
static void *malloc_32bit_safe_ext(unsigned long size, void *userptr)
{
	printf("the memory grab was %ul\n", size);
	return malloc(size);
}
static void free_32bit_safe(void *ptr, void *userptr)
{
	free(ptr);
}


struct flow_data {
	u64 packets;
	u64 bytes;
	u32 protocol;
};

static void init_flow_hash_table(classify_data cd)
{
	_real_size_flow_struct = ipoque_pace_get_sizeof_flow_data(cd->ipq);
	_size_flow_struct = _real_size_flow_struct + sizeof(struct flow_data);
	_flow_data_offset = _real_size_flow_struct;

	cd->connection_toh= ipoque_to_hash_create2(ipq_hash_size, _size_flow_struct,
			sizeof(struct ipoque_unique_flow_struct)
			, ipq_connection_timeout * ipq_tick_resolution,
			NULL, NULL, classify_toh_malloc, free_32bit_safe, NULL);

	if (cd->connection_toh == NULL) {
		fprintf(stderr, "ipoque_init_detection_module connection_toh [Flow]  malloc failed\n");
		exit(1);
	}

}

static void init_subscriber_hash_table(classify_data cd)
{
	_size_id_struct = ipoque_pace_get_sizeof_id_data(cd->ipq);

	cd->subscriber_toh= ipoque_to_hash_create2(ipq_hash_size, _size_id_struct,
			sizeof(u32)
			, ipq_connection_timeout * ipq_tick_resolution,
			NULL, NULL, classify_toh_malloc, free_32bit_safe, NULL);

	if (cd->subscriber_toh == NULL) {
		fprintf(stderr, "ipoque_init_detection_module subscriber_toh  malloc failed\n");
		exit(1);
	}
}

/**
 * starts the classify thread and creates and configures the IPOQUE module.
 *
 */
classify_data classify_start(void)
{

	classify_data cd;
	IPOQUE_PROTOCOL_BITMASK protocols;

	cd = (struct classify_data_struct *) calloc(1, sizeof(struct classify_data_struct));


	_size_id_struct = ipoque_pace_get_sizeof_id_data(cd->ipq);
	ASSERT(cd);

	cd->ipq = ipoque_init_detection_module(
			IPQ_TICK_RESOLUTION,
			classify_malloc,
			0);

	ipoque_set_rdt_correlation(cd->ipq,1);
	IPOQUE_BITMASK_SET_ALL(protocols); // TODO: be a bit more choosy about these!
	ipoque_set_protocol_detection_bitmask2(cd->ipq, &protocols);
	fprintf(stderr, "returned Bitmask is: " IPOQUE_BITMASK_DEBUG_OUTPUT_BITMASK_STRING " \n",
			IPOQUE_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(protocols));

	ipoque_set_plain_tunnel_decapsulation_level(cd->ipq, 50);



	init_flow_hash_table(cd);
	init_subscriber_hash_table(cd);

	bzero(protocol_counters, (CAAP_MAX_PROTOCOLS + 1) * sizeof(u64));

	return(cd);
}

void classify_end(classify_data cd)
{
	// TODO: dispose of the various ipoque data structures
	free(cd);
}

void incrementTheUsersSummaryCounters(unsigned int protocol, u32 theIPForHashSearch, long bytes){

	//TODO replace this with an array indexed by protocol the upkeep on this will be costly and will limit our ability to update IPOQUE on the fly
	//Simon said that this was quick though.....

	MapMutex::getInstance()->lockMapMutex();
	PDPSession* s = NULL;
	s = checkIfUEIsAlreadyPresentInHashMap(ntohl(theIPForHashSearch));
	if (s != NULL){

		switch(protocol)
		{
		case IPOQUE_PROTOCOL_UNKNOWN:
			s->unknownBytes += bytes;
			s->unknownPackets++;
			break;
		case IPOQUE_PROTOCOL_GOOGLE:
			s->googleBytes += bytes;
			s->googlePackets++;
			break;
		case IPOQUE_PROTOCOL_STEAM:
			s->steamBytes += bytes;
			s->steamPackets++;
			break;
		case IPOQUE_PROTOCOL_SSL:
			s->sslBytes += bytes;
			s->sslPackets++;
			break;
		case IPOQUE_PROTOCOL_DNS:
			s->dnsBytes += bytes;
			s->dnsPackets++;
			break;
		case IPOQUE_PROTOCOL_IGMP:
			s->igmpBytes += bytes;
			s->igmpPackets++;
			break;
		case IPOQUE_PROTOCOL_MDNS:
			s->mdnsBytes += bytes;
			s->mdnsPackets++;
			break;
		case IPOQUE_PROTOCOL_ADOBE_CONNECT:
			s->adobeConnectBytes += bytes;
			s->adobeConnectPackets++;
			break;
		case IPOQUE_PROTOCOL_AFP:
			s->afpBytes += bytes;
			s->afpPackets++;
			break;
		case IPOQUE_PROTOCOL_AIMINI:
			s->aiminiBytes += bytes;
			s->aiminiPackets++;
			break;
		case IPOQUE_PROTOCOL_ANTSP2P:
			s->antsp2pBytes += bytes;
			s->antsp2pPackets++;
			break;
		case IPOQUE_PROTOCOL_APPLEJUICE:
			break;
		case IPOQUE_PROTOCOL_ARES:
			break;
		case IPOQUE_PROTOCOL_ARMAGETRON:
			break;
		case IPOQUE_PROTOCOL_AUDIOGALAXY:
			break;
		case IPOQUE_PROTOCOL_AVI:
			s->aviBytes += bytes;
			s->aviPackets++;
			break;
		case IPOQUE_PROTOCOL_BATTLEFIELD:
			break;
		case IPOQUE_PROTOCOL_BGP:
			break;
		case IPOQUE_PROTOCOL_BLACKBERRY:
			s->blackBerryBytes += bytes;
			s->blackBerryPackets++;
			break;
		case IPOQUE_PROTOCOL_BOLT:
			break;
		case IPOQUE_PROTOCOL_CITRIX:
			s->afpBytes += bytes;
			s->afpPackets++;
			break;
		case IPOQUE_PROTOCOL_CITRIX_GOTO:
			break;
		case IPOQUE_PROTOCOL_CLUBPENGUIN:
			break;
		case IPOQUE_PROTOCOL_COMODOUNITE:
			break;
		case IPOQUE_PROTOCOL_CROSSFIRE:
			break;
		case IPOQUE_PROTOCOL_CYBERGHOST:
			break;
		case IPOQUE_PROTOCOL_DHCP:
			s->dhcpBytes += bytes;
			s->dhcpPackets++;
			break;
		case IPOQUE_PROTOCOL_DHCPV6:
			break;
		case IPOQUE_PROTOCOL_DOFUS:
			break;
		case IPOQUE_PROTOCOL_EBUDDY:
			break;
		case IPOQUE_PROTOCOL_EDONKEY:
			break;
		case IPOQUE_PROTOCOL_EGP:
			break;
		case IPOQUE_PROTOCOL_FASTTRACK:
			break;
		case IPOQUE_PROTOCOL_FEIDIAN:
			break;
		case IPOQUE_PROTOCOL_FICALL:
			break;
		case IPOQUE_PROTOCOL_FIESTA:
			s->fiestaBytes += bytes;
			s->fiestaPackets++;
			break;
		case IPOQUE_PROTOCOL_FILETOPIA:
			break;
		case IPOQUE_PROTOCOL_FLASH:
			s->flashBytes += bytes;
			s->flashPackets++;
			break;
		case IPOQUE_PROTOCOL_FLORENSIA:
			break;
		case IPOQUE_PROTOCOL_FREENET:
			break;
		case IPOQUE_PROTOCOL_FRING:
			break;
		case IPOQUE_PROTOCOL_FTP:
			s->ftpBytes += bytes;
			s->ftpPackets++;
			break;
		case IPOQUE_PROTOCOL_FUNSHION:
			break;
		case IPOQUE_PROTOCOL_GADUGADU:
			break;
		case IPOQUE_PROTOCOL_GAMEKIT:
			s->gameKitBytes += bytes;
			s->gameKitPackets++;
			break;
		case IPOQUE_PROTOCOL_GENVOICE:
			break;
		case IPOQUE_PROTOCOL_GNUTELLA:
			break;
		case IPOQUE_PROTOCOL_GOOBER:
			s->gooberBytes += bytes;
			s->gooberPackets++;
			break;
		case IPOQUE_PROTOCOL_GRE:
			s->greBytes += bytes;
			s->grePackets++;
			break;
		case IPOQUE_PROTOCOL_GTP:
			s->gtpBytes += bytes;
			s->gtpPackets++;
			break;
		case IPOQUE_PROTOCOL_GUILDWARS:
			s->guildWarsBytes += bytes;
			s->guildWarsPackets++;
			break;
		case IPOQUE_PROTOCOL_H323:
			s->H323Bytes += bytes;
			s->H323Packets++;
			break;
		case IPOQUE_PROTOCOL_HALFLIFE2:
			break;
		case IPOQUE_PROTOCOL_HAMACHI_VPN:
			s->hamachiVPNBytes += bytes;
			s->hamachiVPNPackets++;
			break;
		case IPOQUE_PROTOCOL_HTTP:
			s->HTTPBytes += bytes;
			s->HTTPPackets++;
			break;
		case IPOQUE_PROTOCOL_HTTP_APPLICATION_ACTIVESYNC:
			break;
		case IPOQUE_PROTOCOL_HTTP_APPLICATION_GOOGLE_TALK:
			s->gTalkBytes += bytes;
			s->gTalkPackets++;
			break;
		case IPOQUE_PROTOCOL_HTTP_APPLICATION_QQGAME:
			break;
		case IPOQUE_PROTOCOL_HTTP_APPLICATION_VEOHTV:
			s->veohTVBytes += bytes;
			s->veohTVPackets++;
			break;
		case IPOQUE_PROTOCOL_HTTP_TUNNEL:
			break;
		case IPOQUE_PROTOCOL_IAX:
			break;
		case IPOQUE_PROTOCOL_ICECAST:
			break;
		case IPOQUE_PROTOCOL_ICMP:
			s->icmpBytes += bytes;
			s->icmpPackets++;
			break;
		case IPOQUE_PROTOCOL_ICMPV6:
			break;
		case IPOQUE_PROTOCOL_IMESH:
			break;
		case IPOQUE_PROTOCOL_IMO:
			s->imoBytes += bytes;
			s->imoPackets++;
			break;
		case IPOQUE_PROTOCOL_IMPLUS:
			break;
		case IPOQUE_PROTOCOL_IPLAYER:
			break;
		case IPOQUE_PROTOCOL_IPP:
			break;
		case IPOQUE_PROTOCOL_IPSEC:
			break;
		case IPOQUE_PROTOCOL_IPSEC_UDP:
			break;
		case IPOQUE_PROTOCOL_IPTV:
			s->iptvBytes += bytes;
			s->iptvPackets++;
			break;
		case IPOQUE_PROTOCOL_IP_IN_IP:
			break;
		case IPOQUE_PROTOCOL_IRC:
			break;
		case IPOQUE_PROTOCOL_ISAKMP:
			break;
		case IPOQUE_PROTOCOL_ISKOOT:
			break;
		case IPOQUE_PROTOCOL_JABBER_APPLICATION_NIMBUZZ:
			break;
		case IPOQUE_PROTOCOL_JAP:
			s->japBytes += bytes;
			s->japPackets++;
			break;
		case IPOQUE_PROTOCOL_JBK3K:
			break;
		case IPOQUE_PROTOCOL_KERBEROS:
			s->kerberosBytes += bytes;
			s->kerberosPackets++;
			break;
		case IPOQUE_PROTOCOL_KONTIKI:
			break;
		case IPOQUE_PROTOCOL_L2TP:
			break;
		case IPOQUE_PROTOCOL_LDAP:
			s->ldapBytes += bytes;
			s->ldapPackets++;
			break;
		case IPOQUE_PROTOCOL_LDP:
			break;
		case IPOQUE_PROTOCOL_LYNC:
			break;
		case IPOQUE_PROTOCOL_MAIL_IMAP:
			s->mailIMAPBytes += bytes;
			s->mailIMAPPackets++;
			break;
		case IPOQUE_PROTOCOL_MAIL_POP:
			s->mailPOPBytes += bytes;
			s->mailPOPPackets++;
			break;
		case IPOQUE_PROTOCOL_MAIL_SMTP:
			s->mailSMTPBytes += bytes;
			s->mailSMTPPackets++;
			break;
		case IPOQUE_PROTOCOL_MANOLITO:
			break;
		case IPOQUE_PROTOCOL_MAPI:
			break;
		case IPOQUE_PROTOCOL_MAPLESTORY:
			break;
		case IPOQUE_PROTOCOL_MEEBO:
			s->meeboBytes += bytes;
			s->meeboPackets++;
			break;
		case IPOQUE_PROTOCOL_MGCP:
			break;
		case IPOQUE_PROTOCOL_MIG33:
			break;
		case IPOQUE_PROTOCOL_MMS:
			break;
		case IPOQUE_PROTOCOL_MOJO:
			break;
		case IPOQUE_PROTOCOL_MOVE:
			break;
		case IPOQUE_PROTOCOL_MPEG:
			s->mpegBytes += bytes;
			s->mpegPackets++;
			break;
		case IPOQUE_PROTOCOL_MSN:
			s->msnBytes += bytes;
			s->msnPackets++;
			break;
		case IPOQUE_PROTOCOL_MSRP:
			break;
		case IPOQUE_PROTOCOL_MSSQL:
			s->msSQLBytes += bytes;
			s->msSQLPackets++;
			break;
		case IPOQUE_PROTOCOL_MULTIMEDIA_MESSAGING:
			break;
		case IPOQUE_PROTOCOL_MUTE:
			break;
		case IPOQUE_PROTOCOL_MYPEOPLE:
			break;
		case IPOQUE_PROTOCOL_MYSQL:
			s->mySQLBytes += bytes;
			s->mySQLPackets++;
			break;
		case IPOQUE_PROTOCOL_NETBIOS:
			s->netbiosBytes += bytes;
			s->netbiosPackets++;
			break;
		case IPOQUE_PROTOCOL_NETFLIX:
			s->netflixBytes += bytes;
			s->netflixPackets++;
			break;
		case IPOQUE_PROTOCOL_NETMOTION:
			break;
		case IPOQUE_PROTOCOL_NFS:
			s->nfsBytes += bytes;
			s->nfsPackets++;
			break;
		case IPOQUE_PROTOCOL_NTP:
			break;
		case IPOQUE_PROTOCOL_OGG:
			break;
		case IPOQUE_PROTOCOL_OOVOO:
			s->oovooBytes += bytes;
			s->oovooPackets++;
			break;
		case IPOQUE_PROTOCOL_OPENFT:
			break;
		case IPOQUE_PROTOCOL_OPENVPN:
			break;
		case IPOQUE_PROTOCOL_OPERAMINI:
			break;
		case IPOQUE_PROTOCOL_ORB:
			s->orbBytes += bytes;
			s->orbPackets++;
			break;
		case IPOQUE_PROTOCOL_OSCAR:
			break;
		case IPOQUE_PROTOCOL_OSH:
			break;
		case IPOQUE_PROTOCOL_OSPF:
			s->ospfBytes += bytes;
			s->ospfPackets++;
			break;
		case IPOQUE_PROTOCOL_PALTALK:
			break;
		case IPOQUE_PROTOCOL_PANDO:
			break;
		case IPOQUE_PROTOCOL_PANDORA:
			s->pandoraBytes += bytes;
			s->pandoraPackets++;
			break;
		case IPOQUE_PROTOCOL_PCANYWHERE:
			break;
		case IPOQUE_PROTOCOL_PDPROXY:
			break;
		case IPOQUE_PROTOCOL_POPO:
			break;
		case IPOQUE_PROTOCOL_POSTGRES:
			break;
		case IPOQUE_PROTOCOL_PPLIVE:
			break;
		case IPOQUE_PROTOCOL_PPP:
			s->pppBytes += bytes;
			s->pppPackets++;
			break;
		case IPOQUE_PROTOCOL_PPSTREAM:
			break;
		case IPOQUE_PROTOCOL_PPTP:
			break;
		case IPOQUE_PROTOCOL_PS3:
			s->ps3Bytes += bytes;
			s->ps3Packets++;
			break;
		case IPOQUE_PROTOCOL_QQ:
			break;
		case IPOQUE_PROTOCOL_QQLIVE:
			break;
		case IPOQUE_PROTOCOL_QUAKE:
			s->quakeBytes += bytes;
			s->quakePackets++;
			break;
		case IPOQUE_PROTOCOL_QUICKTIME:
			break;
		case IPOQUE_PROTOCOL_RADIUS:
			break;
		case IPOQUE_PROTOCOL_RDP:
			break;
		case IPOQUE_PROTOCOL_RDT:
			break;
		case IPOQUE_PROTOCOL_REALMEDIA:
			break;
		case IPOQUE_PROTOCOL_RFACTOR:
			break;
		case IPOQUE_PROTOCOL_RHAPSODY:
			break;
		case IPOQUE_PROTOCOL_RTCP:
			break;
		case IPOQUE_PROTOCOL_RTP:
			break;
		case IPOQUE_PROTOCOL_RTSP:
			break;
		case IPOQUE_PROTOCOL_SAP:
			break;
		case IPOQUE_PROTOCOL_SCTP:
			break;
		case IPOQUE_PROTOCOL_SCYDO:
			break;
			//in alphabetical up to here
		case IPOQUE_PROTOCOL_SKYPE:
			s->skypeBytes += bytes;
			s->skypePackets++;
			break;
		case IPOQUE_PROTOCOL_TELNET:
			s->telnetBytes += bytes;
			s->telnetPackets++;
			break;
		case IPOQUE_PROTOCOL_TEAMSPEAK:
			s->teamspeakBytes += bytes;
			s->teamspeakPackets++;
			break;
		case IPOQUE_PROTOCOL_VIBER:
			s->viberBytes += bytes;
			s->viberPackets++;
			break;
		case IPOQUE_PROTOCOL_VNC:
			break;
		case IPOQUE_PROTOCOL_WHATSAPP:
			break;
		case IPOQUE_PROTOCOL_WORLDOFWARCRAFT:
			s->WOWBytes += bytes;
			s->WOWPackets++;
			break;
		case IPOQUE_PROTOCOL_WII:
			s->wiiBytes += bytes;
			s->wiiPackets++;
			break;
		case IPOQUE_PROTOCOL_XBOX:
			s->xboxBytes += bytes;
			s->xboxPackets++;
			break;
		case IPOQUE_PROTOCOL_YAHOO:
			s->yahooBytes += bytes;
			s->yahooPackets++;
			break;
		case IPOQUE_PROTOCOL_ZATTOO:
			s->zattoBytes += bytes;
			s->zattoPackets++;
			break;
		}

		alocatedPackets++;
	}else{
		unalocatedPackets++;
	}
	MapMutex::getInstance()->unlockMapMutex();

}

//this has been put in place for initial testing
//TODO Link the configuration to the macOfKnowElement and make it a list (array) of macs.
unsigned long macOfKnowElement = 0x002102FA70AA;
unsigned long packetsUp = 0;
unsigned long packetsDown = 0;
int numFlows=0;
unsigned long total=0;

struct ipv4{
	unsigned int sourceAddress:32;
	unsigned int destinationAddress:32;
};


//
// This function returns a pointer to a GTPv1 header in a packet in a data buffer
//
// Parameters:
//  const unsigned int length: The amount of data present in the data buffer
//  const unsigned char* data: A pointer to the packet data
//
// Return:
//  gtpv1hdr*: A pointer to a GTP V1 header if a GTP V1 packet is present, NULL otherwise
//
struct gtpv1hdr* gtpv1_get_header(const unsigned int length, const unsigned char* data)
{
	// Keep track of the current position to avoid complex casts
	unsigned int offset = 0;

	// Check if there is enough data for the Ethernet header
	if (length - offset < sizeof(struct ether_header)) {
		return NULL;
	}

	// Set the Ethernet header pointer
	struct ether_header* ether_header = (struct ether_header*)(data + offset);

	// Check if there is a VLAN specified in the Ethernet header
	int ether_type = ntohs(ether_header->ether_type);
	if (ether_type == ETHERTYPE_VLAN) {
		// In this case, we must skip past the 802.1Q tag and find the Ethernet type in the next 2 octets
		u_short* ether_typep = (u_short*)(((char*)&ether_header->ether_type) + TAG_ETHER_802_1_Q_LENGTH);
		ether_type = ntohs(*ether_typep);

		// Set the IP header pointer to the end of the Ethernet header, this is the outer IP header
		offset +=  sizeof(struct ether_header) + TAG_ETHER_802_1_Q_LENGTH;
	}
	else {
		// Set the IP header pointer to the end of the Ethernet header, this is the outer IP header
		offset +=  sizeof(struct ether_header);
	}

	// Check if this is an IPv4 packet, if not, return because for now we only support IPV4
	// TODO: Implement IPv6
	if (ether_type != ETHERTYPE_IP) {
		return NULL;
	}


	// Check if there is enough data for the IP header
	if (length - offset < sizeof(struct ip)) {
		return NULL;
	}

	// Set the IP header pointer
	struct ip* ip_header = (struct ip*)(data + offset);

	// Check if the IP header version is IPv4, for now we only support IPv4
	// TODO: Implement IPv6
	if (ip_header->ip_v != IPVERSION) {
		return NULL;
	}

	// Check if the enclosing protocol is UDP, GTP is carried in UDP
	if (ip_header->ip_p != IPPROTO_UDP) {
		return NULL;
	}

	// Set the UDP header pointer to the end of the IP header, The IP header length is in units of 4 octets
	offset +=  ip_header->ip_hl * 4;

	// Check if there is enough data for the UDP header
	if (length - offset < sizeof(struct udphdr)) {
		return NULL;
	}

	// Set the UDP header pointer
	struct udphdr* udp_header = (struct udphdr*)(data + offset);

	// Check for GTP-U or GTP-C
	//if (ntohs(udp_header->uh_sport) != GTP_U_UDP_PORT && ntohs(udp_header->uh_dport) != GTP_U_UDP_PORT &&
	//	ntohs(udp_header->uh_sport) != GTP_C_UDP_PORT && ntohs(udp_header->uh_dport) != GTP_C_UDP_PORT) {
	//	return NULL;
	//}

	// Set the GTP V1 header pointer to the end of the UDP header
	offset +=  sizeof(struct udphdr);

	// Check if there is enough data for the GTP v1 header
	if (length - offset < sizeof(struct gtpv1hdr)) {
		return NULL;
	}

	// Set the UDP header pointer
	struct gtpv1hdr* gtpv1_header = (struct gtpv1hdr*)(data + offset);

	// Check for GTP Version 1
	if (gtpv1_header->flag_typever != GTP_V1_TYPEVER) {
		return NULL;
	}

	// OK, we have now got to the GTP v1 header
	return gtpv1_header;
}

int i = 0;
/**
 *provides processing to the packets collected using the PCAP library (classification and stats).
 */
void classify(classify_data cd, const struct pcap_pkthdr *header, const char *packet)
{
	unsigned int sub_protocol;
	unsigned int application;
	enum direction packetDirection = NOT_YET_DEFINED;
	const struct ether *ethernet = (struct ether *) packet;
	struct iphdr *iph = (struct iphdr *) &packet[sizeof(struct ether)];
	struct ipoque_flow_struct *flow;
	struct ipoque_unique_flow_struct *flow_unique;
	const void *ipv4_ptr;
	u16 ipsize;
	u8 new_element = 0;
	unsigned int protocol;
	u32 rdt_flow_start;
	u32 rdt_flow_end;
	u16 type;
	type = ethernet->type;
	u32 theIPForHashSearch = 0;
	int size = header->caplen - sizeof(struct ether);

	//TODO need to update this to go through a list of known macs
	int macloop = 0;
	unsigned char * data = (unsigned char *) ethernet;
	long theSourceMacAddress = readByteArray(data,6,0);
	long theDestinationMacAddress = readByteArray(data,6,6);

	//get the GTP header this allows us to ignore VLANs
	struct gtpv1hdr* gtpv1hdr = gtpv1_get_header(header->caplen,(const unsigned char *) packet);
	int GTPFlags = gtpv1hdr->flag_options;
	int IPLocation=0;
	//account for the two sizes of GTP header
	if(GTPFlags > 0){
		IPLocation = 0x0c;
	}else{
		IPLocation = 0x08;
	}
	int theLengthOfTheGTPHeader = readByteArray((unsigned char*)&(gtpv1hdr->length),2,0);
	unsigned char* theGTPHeaderIndex = (unsigned char *) gtpv1hdr;
	unsigned char *ipHeaderIndex = &theGTPHeaderIndex[IPLocation];

	u16 timestamp = ((uint64_t) header->ts.tv_sec) * IPQ_TICK_RESOLUTION + header->ts.tv_usec / (1000000 / IPQ_TICK_RESOLUTION);

	if (type == htons(ETH_P_8021Q)) {
		size = size - 4;

		iph = (struct iphdr *) &packet[sizeof(struct ether)+4];
	//	printf("VLAN!");
	}

	if (type == htons(0x8847)) {
		//printf("packet is of type 0x8847");
	}

	if (header->caplen >= sizeof(struct ether)) {
		rdtscl(rdt_flow_start);

		unsigned char* thePacket = ipHeaderIndex;


		ipv4 * thePointer = (ipv4 *) &thePacket[0xc];

		if(macOfKnowElement == theSourceMacAddress ) {
			packetDirection = HEADING_TO_USER_EQUIPMENT;
			theIPForHashSearch = thePointer->sourceAddress;
			packetsDown++;
		} else {
			packetDirection = HEADING_TO_INTERNET;
			theIPForHashSearch = thePointer->destinationAddress;
			packetsUp++;
		}

		unsigned int theInnerSrc=thePointer->sourceAddress;
		unsigned int theInnerDst=thePointer->destinationAddress;

		if (cd->connection_toh != NULL) {
			ipoque_to_hash_set_timestamp(cd->connection_toh, timestamp);
		}


		flow = NULL;
		int size = header->caplen - sizeof(struct ether);

		flow = (struct ipoque_flow_struct *)ipoque_get_current_flow_decapsulate(
				cd->ipq,
				cd->connection_toh,
				iph,
				size,
				&new_element);

		rdtscl(rdt_flow_end);

		//helper_print_packet_details(iph, header, packet, 1);

		if(flow != NULL && new_element != 0)
		{
			numFlows++;

			bzero(flow, ipoque_pace_get_sizeof_flow_data(cd->ipq));

		}

		if (cd->subscriber_toh != NULL) {
			ipoque_to_hash_set_timestamp(cd->subscriber_toh, timestamp);
		}

		struct ipoque_id_struct *src = NULL;
		struct ipoque_id_struct *dst = NULL;

		uint8_t *iph_p;
		iph_p = (uint8_t *) iph;
		src = (struct ipoque_id_struct*) ipq_get_id((u8 *) & theInnerSrc, 0,cd);
		dst = (struct ipoque_id_struct*) ipq_get_id((u8 *) & theInnerDst, 0,cd);

		protocol = ipoque_detection_process_packet_fastpath(cd->ipq,
				flow,
				iph_p,
				(header->caplen - sizeof(struct ether)),
				timestamp);

		if (protocol == IPOQUE_DETECTION_FASTPATH_NOT_USED) {
			protocol = ipoque_detection_process_packet_slowpath(cd->ipq, src, dst);
			sub_protocol = ipoque_detection_get_protocol_subtype(cd->ipq);
			application = ipoque_pace_get_application_id(cd->ipq);

		}
	}

	incrementTheUsersSummaryCounters(protocol, theIPForHashSearch, header->caplen);

}

extern int freePacketCount;
/*
 * Print out the running totals of the stats.  Since there is no
 * mutex, there may occasionally be strange values.
 */
void classify_print_log(FILE *outputfile)
{
	int i;

	MapMutex::getInstance()->lockMapMutex();
//	for( UE_maptype::const_iterator iter = ueMap.begin(); iter != ueMap.end(); ++iter ){
//		PDPSession * s = iter->second;
//		//fprintf(outputfile," UE_IP: %x, ukn: %lu, dns: %lu, ssl: %lu, igmp: %lu, steam: %lu, mdns: %lu, google: %lu, afp: %lu, aimini: %lu, antsp2p: %lu, avi: %lu, Blackberry: %lu, dhcp: %lu, Fiesta: %lu, Flash: %lu, ftp: %lu, gameKit: %lu, goober: %lu, gre: %lu, gtp: %lu, GW: %lu, H323 %lu, hamachi VPN: %lu, HTTP: %lu, gTalk: %lu, veohTV %lu, icmp: %lu, imo: %lu, iptv: %lu, jap: %lu, kerberos: %lu, ldap: %lu, mailPOP: %lu, mailSMTP: %lu, meebo: %lu, mpeg: %lu, msn: %lu, msSQL: %lu, mySQL: %lu, netbios: %lu, netflix: %lu, nfs: %lu, oovoo: %lu, orb: %lu, osp: %lu, pandora: %lu, ppp: %lu, ps3: %lu, quake: %lu, skype: %lu, telnet: %lu, teamspeak: %lu, viber: %lu, WOW: %lu, wii: %lu, xbox: %lu,  yahoo: %lu, zatto: %lu  \n",s->ue_addr,s->unknownPackets, s->dnsPackets,s->sslPackets,s->igmpPackets, s->steamPackets, s->mdnsPackets, s->googlePackets, s->afpPackets,s->aiminiPackets,s->antsp2pPackets,s->aviPackets,s->blackBerryPackets,s->dhcpPackets,s->fiestaPackets,s->flashPackets,s->ftpPackets,s->gameKitPackets,s->gooberPackets,s->grePackets,s->gtpPackets,s->guildWarsPackets,s->H323Packets,s->hamachiVPNPackets,s->HTTPPackets,s->gTalkPackets,s->veohTVPackets,s->icmpPackets,s->imoPackets,s->iptvPackets,s->japPackets,s->kerberosPackets,s->ldapPackets,s->mailIMAPPackets,s->mailPOPPackets,s->mailSMTPPackets,s->meeboPackets,s->mpegPackets,s->msnPackets,	s->msSQLPackets,s->mySQLPackets,s->netbiosPackets,s->netflixPackets,s->nfsPackets,s->oovooPackets,s->orbPackets,s->ospfPackets,s->pandoraPackets,s->pppPackets,	s->ps3Packets,s->quakePackets,s->skypePackets,s->telnetPackets,s->teamspeakPackets,	s->viberBytes,s->viberPackets,s->WOWPackets,s->wiiPackets,s->xboxPackets,s->yahooPackets,s->zattoPackets);
//		fprintf(outputfile,"UE_IP: %x", s->ue_addr);
//	}


 	MapMutex::getInstance()->unlockMapMutex();
	fprintf(outputfile," the total bytes was: %ul", total);
	fprintf(outputfile," the total flows was: %i\n",numFlows);
	fprintf(outputfile," the number of free packets in the packetbuffer is ...... %i\n", freePacketCount);
	fprintf(outputfile," The number of unallocated packets was %ull \n", unalocatedPackets);
	fprintf(outputfile," The number of allocated packets was %ull \n", alocatedPackets);


	fputc('\n', outputfile);
}

void helper_print_packet_details(const struct iphdr *iph, const struct pcap_pkthdr *header, const char *packet, int print_packet){

	u32 sip = ntohl(iph->saddr);
	u32 dip = ntohl(iph->daddr);

	printf("sip: %d,",sip);
	printf("%x \n",iph);

	int start = 0; // starting offset
	int end = header->caplen; // ending offset
	int i;
	if (print_packet){
		for (i = start & ~15; i < end; i++)
		{
			if  ((i & 15) == 0)
				printf("%04x ",i);
			printf((i<start)?"   ":"%02x%c",(unsigned char)packet[i],((i+1)&15)?' ':'\n');
		}
		if ((i & 15) != 0)
			printf("\n");
	}
	printf("headerlength: %i \n", header->caplen);
	printf("source address: %x \n",ntohl(iph->saddr));
	printf("dest address: %x \n", ntohl(iph->daddr));
	printf("source address: %x \n", sip);
	printf("dest address: %x \n", dip);

}
