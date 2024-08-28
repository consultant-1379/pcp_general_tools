#ifndef GTPIE_H
#define GTPIE_H
//#pragma pack(1) //vital to get bit fields to line up correctly
#define debug 0

#include <string>

// These values are defined in 3GPP TS 23.003, 3GPP TS 29.060 and ITU-T E.164
// (the extra digit is the string terminator)


#define IMSI_MAX_CHARS		(16+1)
#define IMEI_MAX_CHARS		(16+1)
#define MSISDN_MAX_CHARS	(15+1)
#define MNC_MAX_CHARS		(3+1)
#define MCC_MAX_CHARS		(3+1)
#define APN_MAX_CHARS		(100+1)

// esirich: DEFTFTS-1879 these values are output to indicate that a
// given data item has not been read from GTP
#define EMPTY_INT_STRING	"\\N"
#define IMSI_INIT_STRING	"\\N"
#define IMEI_INIT_STRING	"\\N"
#define MSISDN_INIT_STRING	"\\N"
#define MNC_INIT_STRING		"\\N"
#define MCC_INIT_STRING		"\\N"
#define APN_INIT_STRING		"\\N"


using std::string;

class DecodedMsg {

 public:
 
// esirich changed several values to strings for DEFTFTS-1825
   DecodedMsg();
   double timestamp;
   unsigned long src_addr; // from ip addr fields 
   unsigned long dst_addr;
   char rat_present;
   const char *rat;
   char imsi_present;
   char imsi[IMSI_MAX_CHARS];
   char imei[IMEI_MAX_CHARS];   
   unsigned int teid;
   char teid_d_present;
   unsigned int teid_d;
   char teid_c_present;
   unsigned int teid_c;
   int nsapi;
   int dtflag;
   char apn_present;
   char apn[APN_MAX_CHARS];
   char addr1_present, addr2_present;
   unsigned int addr1, addr2;
   char msisdn[MSISDN_MAX_CHARS];
   int cause;
   
   unsigned int ue_addr;
   
   char mnc[MNC_MAX_CHARS];
   char mcc[MCC_MAX_CHARS];
   int lac, rac;
   int cid, sac;
   
   int arp, delay_class, reliability_class, precedence;
   string traffic_class;
   int thp;
   
   int max_ul, max_dl;
   int gbr_ul, gbr_dl;
   
   int sdu;   
};

int DecodeIMSI_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg);

int DecodeIMEISV_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg);

int DecodeMSISDN_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg);

// Micheal Lawless commented commented this out in the .cc file - comment by Luke Potter
//int DecodePDPContext_IE(unsigned char *p, int pos, int datalen);

unsigned int ReadMaxBitrate(unsigned int i);

unsigned int ReadExtensionBitrate(unsigned int i);

int DecodeIE(unsigned char *p, int pos, int datalen,struct DecodedMsg *pmsg) ;

#endif
