#ifndef gtp_ie_gtpv2_h_included
#define gtp_ie_gtpv2_h_included
//#pragma pack(1) //vital to get bit fields to line up correctly
#include <string>
#include "GTPv1_packetFields.h"
//esirich added this for the sizes of the string values (DEFTFTS-1825)
#include "gtp_ie.h"
using std::string;

void SetLog(bool);
void DecodeUserLocationInformation(unsigned char *p, int pos, struct DecodedMsg_V2 *pmsg);
long reverseArrayData(unsigned char * data, int arraySize, bool reverse);
long readByteArray(unsigned char * data, int arraySize, int location);


class Bearer {

 public: 
    Bearer();
    
    int present;
    FTEID fteid[16];
};


class DecodedMsg_V2 {
private:
	DecodedMsg_V2(const DecodedMsg_V2 &rhs) {
		imsi_present        = rhs.imsi_present;
		apn_present         = rhs.apn_present;
		addr1_present       = rhs.addr1_present;
		addr2_present       = rhs.addr2_present;
		msisdn_present      = rhs.msisdn_present;
		cause_present       = rhs.cause_present;
		ue_addr_present     = rhs.ue_addr_present;
		src_addr            = rhs.src_addr;
		dst_addr 		    = rhs.dst_addr;
		eps_bearer_id       = rhs.eps_bearer_id;
		delay_value_present = rhs.delay_value_present;
		delay_value 	    = rhs.delay_value;
		memcpy(mcc, rhs.mcc, MCC_MAX_CHARS);
		memcpy(mnc, rhs.mnc, MNC_MAX_CHARS);
		rai                 = rhs.rai;
		sai                 = rhs.sai;
		cgi                 = rhs.cgi;
		lac                 = rhs.lac;
		tai                 = rhs.tai;
		ecgi                = rhs.ecgi;
		memcpy(mei, rhs.mei, IMEI_MAX_CHARS);
		nsapi               = rhs.nsapi;
		dtFlag              = rhs.dtFlag;
		max_ul              = rhs.max_ul;
		max_dl              = rhs.max_dl;
		gbr_ul              = rhs.gbr_ul;
		gbr_dl              = rhs.gbr_dl;
		arp                 = rhs.arp;
		S1U_TEID            = rhs.S1U_TEID;
		teid                = rhs.teid;
		ue_addr             = rhs.ue_addr;
		timestamp           = rhs.timestamp;
		addr1               = rhs.addr1;
		addr2               = rhs.addr2;
		mei_present         = rhs.mei_present;
		cause               = rhs.cause;
		memcpy(imsi, rhs.imsi, IMSI_MAX_CHARS);
		memcpy(msisdn, rhs.msisdn, MSISDN_MAX_CHARS);
	}

 public:
 
   DecodedMsg_V2();

   double timestamp;
   
   unsigned long src_addr; // from ip addr fields 
   unsigned long dst_addr;
   
   char imsi_present;
   char imsi[IMSI_MAX_CHARS];
   
   unsigned int teid;
   
   //Michael the size of this effects performance
   Bearer bearer[1][16]; // first dimension tells the instance
   
   FTEID fteid[16];
   
   int eps_bearer_id;
      
   // char teid_d_present;
   // unsigned int teid_d;

   // char teid_c_present;
   // unsigned int teid_c;

   // char nsapi_present;
   // unsigned char nsapi;
   
   char delay_value_present;
   int delay_value;
   
   char apn_present;
   char apn[APN_MAX_CHARS];
   
   char addr1_present, addr2_present;
   unsigned int addr1, addr2;
   
   char msisdn_present;
   char msisdn[MSISDN_MAX_CHARS];
   
   char mei_present;
   char mei[IMEI_MAX_CHARS];
   
   char cause_present;
   unsigned char cause;
   
   char ue_addr_present;
   unsigned int ue_addr;

   string RATType; //added here but not initialised in constructor also need to be put in PDPsession
   char mnc[MNC_MAX_CHARS];
   char mcc[MCC_MAX_CHARS];
   int lac, rac;
   int rai,sai,cgi,tai,ecgi;
   int nsapi;
   int dtFlag;
   long max_ul;
   long max_dl;
   long gbr_ul;
   long gbr_dl;
   int arp;
   int S1U_TEID;
};



int DecodeIMSI_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg_V2 *pmsg);


int DecodeMSISDN_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg_V2 *pmsg);

int DecodePDPContext_IE(unsigned char *p, int pos, int datalen);

int DecodeIE(unsigned char *p, int pos, int datalen,struct DecodedMsg_V2 *pmsg) ;
#endif
