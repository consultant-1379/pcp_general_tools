#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <string.h>
#include <iostream>
#include "include/gtp_ie.h"
#include "include/GTPv1_packetFields.h"

using std::cerr;
using std::endl;

DecodedMsg::DecodedMsg() {
	imsi_present = 0;
	teid_d_present = teid_c_present = 0;
	apn_present = addr1_present = addr2_present = 0;
	src_addr = dst_addr = 0;

	ue_addr = 0;

	bzero(mnc, MNC_MAX_CHARS);
	strcpy(mnc, MNC_INIT_STRING);
	bzero(mcc, MCC_MAX_CHARS);
	strcpy(mcc, MCC_INIT_STRING);
	lac = rac = cid = sac = -1;

	addr1 = addr2 = 0;
	cause = -1;

	rat_present = 0;
	rat = "UNKNOWN";

	dtflag = 0;
	
	bzero(apn, APN_MAX_CHARS);
	strcpy(apn, APN_INIT_STRING);

	bzero(imsi, IMSI_MAX_CHARS);
	strcpy(imsi, IMSI_INIT_STRING);
	bzero(imei, IMEI_MAX_CHARS);
	strcpy(imei, IMEI_INIT_STRING);
	bzero(msisdn, MSISDN_MAX_CHARS);
	strcpy(msisdn, MSISDN_INIT_STRING);
	nsapi = 0;

	sdu = -1;
	max_ul = max_dl = gbr_ul = gbr_dl = -1;
	thp = arp = delay_class = reliability_class = precedence = -1;
	teid = teid_c = teid_d = 0;
	timestamp = 0.0;
	traffic_class = "";
}


// esirich: DEFTFTS-1825 convert TBCD to ASCII digits -- see ETSI ETR 060
static const char *tbcd="0123456789*#abc\0";

int DecodeIMSI_IE(unsigned char *p, int pos, int datalen,
		struct DecodedMsg *pmsg) {

	int i;

	pmsg->imsi_present = 1;
	bzero(pmsg->imsi, IMSI_MAX_CHARS);
	strcpy(pmsg->imsi, IMSI_INIT_STRING);

	for (i = 0; i < 8 && pos + i + 1 < datalen; i++) {

		int d1 = p[pos + i + 1] & 0x0f;
		int d2 = (p[pos + i + 1] & 0xf0) / 16;

// esirich: DEFTFTS-1825 store the BCD digits as a string
		pmsg->imsi[(i<<1)] = tbcd[d1];
		pmsg->imsi[(i<<1) + 1] = tbcd[d2];

	}

	if (debug)
		printf("IMSI: %s\n", pmsg->imsi);

	return pos + 9;
}

int DecodeIMEISV_IE(unsigned char *p, int pos, int datalen,
		struct DecodedMsg *pmsg) {

	int i;

	bzero(pmsg->imei, IMEI_MAX_CHARS);
	strcpy(pmsg->imei, IMEI_INIT_STRING);

	pos += 2;

	for (i = 0; i < 8 && pos + i + 1 < datalen; i++) {

		int d1 = p[pos + i + 1] & 0x0f;
		int d2 = (p[pos + i + 1] & 0xf0) / 16;

		pmsg->imei[(i<<1)] = tbcd[d1];
		pmsg->imei[(i<<1) + 1] = tbcd[d2];

	}

	return pos + 9;
}

int DecodeMSISDN_IE(unsigned char *p, int pos, int datalen,
		struct DecodedMsg *pmsg) {

	int i;
	int len = NetworkShortAt(p+pos+1);

	bzero(pmsg->msisdn, MSISDN_MAX_CHARS);
	strcpy(pmsg->msisdn, MSISDN_INIT_STRING);

	for (i = 0; i < len - 1 && pos + i + 4 < datalen; i++) {

		int d1 = p[pos + i + 4] & 0x0f;
		int d2 = (p[pos + i + 4] & 0xf0) / 16;

		pmsg->msisdn[(i<<1)] = tbcd[d1];
		pmsg->msisdn[(i<<1) + 1] = tbcd[d2];

	}

	//printf("MSISDN: %llu\n", pmsg->msisdn);

	return pos + 3 + len;
}

// was in place but not called Michael Lawless Friday 13th July 2012
//int DecodePDPContext_IE(unsigned char *p, int pos, int datalen) {
//
//	unsigned short int length =NetworkShortAt(p+2);
//
//	return pos + length;
//}
//Rory - severe doubts about this

//Replaced with NetworkIntAt function in utils in order to remove manual bit shifting Michael Lawless 23_07_2012
//unsigned int ReadReverseInt(unsigned char *p, int pos) {
//	return (p[pos] << 24) + (p[pos + 1] << 16) + (p[pos + 2] << 8) + p[pos + 3];
//}

unsigned int ReadMaxBitrate(unsigned int i) {
	/*
	 *
	 */
	int b = 0;
	if (i == 0 || i == 0xff)
		b = 0;
	else if (i <= 0x3f)
		b = i * 1000;
	else if (i <= 0x7f)
		b = (64 + 8 * (i - 0x40)) * 1000;
	else
		b = (576 + 64 * (i - 0x80)) * 1000;

	return b;
}

unsigned int ReadExtensionBitrate(unsigned int i) {
	int b = 0;
	if (i == 0 || i == 0xff)
		b = 0;
	else if (i <= 0x4a)
		b = 8600000 + i * 100000;
	else if (i <= 0xba)
		b = 16e6 + (i - 0x4a) * 1e6;
	else
		b = 128 * 1e6 + (i - 0xba) * 2e6;

	return b;
}

// returns new pos
int DecodeIE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) {

	// printf("IE: %i\n", p[pos]);

	int ie = p[pos];

	switch (ie) {

	case 1:
		// cause
		pmsg->cause = p[pos + 1];
		if (debug)
			printf("Cause %u\n", pmsg->cause);
		return pos + 2;

	case 2:
		// IMSI
		return DecodeIMSI_IE(p, pos, datalen, pmsg);

	case 3: {
		if (debug)
			printf("Routing Area Identity: ");

// esirich DEFTFTS-1825 read MCC/MNC as TBCD strings

		decodeMCC(p + pos + 1, pmsg->mcc);
		decodeMNC(p + pos + 2, pmsg->mnc);

		int lac = NetworkShortAt(p+pos+4);
		int rac = p[pos + 6];

		if (lac != 65534 && lac != 0)
			pmsg->lac = lac;
		if (rac != 255)
			pmsg->rac = rac;

		if (debug)
			printf("MCC %i MNC %i LAC %i RAC %i\n", pmsg->mcc, pmsg->mnc,
					pmsg->lac, pmsg->rac);

		return pos + 7;
	}

	case 8:
		//printf("Reordering required %i\n", p[pos+1]&1);
		return pos + 2;

	case 14:
		//printf("Recovery: %i\n", p[pos+1]);
		return pos + 2;

	case 15:
		// APN selection mode
		return pos + 2;

	case 16:

		// TEID_d
		pmsg->teid_d_present = 1;
		pmsg->teid_d = NetworkIntAt(p+pos+1);

		//printf("teid dataI 0x%x\n", pmsg->teid_d);

		return pos + 5;

	case 17:
		// TEID_C
		pmsg->teid_c_present = 1;
		pmsg->teid_c = NetworkIntAt(p+pos+1);

		//printf("teid C 0x%x\n", pmsg->teid_c);

		return pos + 5;

	case 19:
		if (debug)
			printf("Teardown indication\n");
		return pos + 2;

	case 20:
		// NSAPI
		pmsg->nsapi = p[pos + 1];

		//printf("nsapi %i\n", pmsg->nsapi);

		return pos + 2;

	case 26:
		// charging characteristics
		return pos + 3;

	case 127:
		// charging id
		//printf("Charging id - skip\n");
		return pos + 5;

	case 128: {
		// IP address type
		//printf("IP address type\n");
		int l = NetworkShortAt(p+pos+1);
		if (l == 2) {
			//printf("empty address\n");
			return pos + 3 + l;
		}

		if (l != 6) {
			//printf("ERROR Unknown address type\n");
			return pos + 3 + l;
		}

		int i;
		pmsg->ue_addr = 0;
		for (i = 0; i < 4; i++)
			pmsg->ue_addr = pmsg->ue_addr * 256 + p[pos + 5 + i];
		//unsigned char* c=(unsigned char*)&(pmsg->ue_addr);
		//printf("ue_addr: %i.%i.%i.%i\n", c[3], c[2], c[1], c[0]);

		return pos + 3 + l;
	}

	case 131: {
		// apn name
		int l = NetworkShortAt(p+pos+1);

		int i = 0;
		int part_len;
		int c = 0;
		while (i < l) {
			part_len = p[pos + 3 + i];
			memcpy(pmsg->apn + c, p + pos + 4 + i, part_len);
			c += part_len;

			i += part_len + 1;
			if (i < l)
				pmsg->apn[c++] = '.';
		}

		pmsg->apn[c] = '\0';
		//printf("apn: %s\n", pmsg->apn);

		pmsg->apn_present = 1;

		return pos + 3 + l;
	}

	case 132: {
		//printf("Protocol Configuration Options -- skipped\n");
		int l = NetworkShortAt(p+pos+1);
		return pos + 3 + l;
	}

	case 133: {
		// PDP context
		int i;
		if (pmsg->addr1_present == 0) {
			pmsg->addr1 = 0;
			for (i = 0; i < 4; i++)
			pmsg->addr1 = pmsg->addr1 * 256 + p[pos + 3 + i];
			pmsg->addr1_present = 1;
			//unsigned char *c = (unsigned char*)&(pmsg->addr1);
			//printf("addr1: %i.%i.%i.%i\n", c[3], c[2], c[1], c[0]);
		} else {
			pmsg->addr2 = 0;
			for (i = 0; i < 4; i++)
				pmsg->addr2 = pmsg->addr2 * 256 + p[pos + 3 + i];
			pmsg->addr2_present = 1;
			//    unsigned char *c = (unsigned char*)&(pmsg->addr2);
			//printf("addr2: %i.%i.%i.%i\n", c[3], c[2], c[1], c[0]);
		}

		return pos + 7;
	}

	case 134:
		// msisdn
		return DecodeMSISDN_IE(p, pos, datalen, pmsg);

	case 135: {
		// qos
		int l = NetworkShortAt(p+pos+1);
		if (debug)
			printf("QOS - (length=%i) \n", l);

		pmsg->arp = p[pos + 3];
		if (debug)
			printf("   ARP=%i \n", pmsg->arp);

		pmsg->delay_class = (p[pos + 4] & 0xf8) / 8;
		if (debug)
			printf("   delay class %i\n", pmsg->delay_class);

		pmsg->reliability_class = p[pos + 4] & 0x07;
		if (debug)
			printf("   reliability class %i\n", pmsg->reliability_class);

		int oo = (p[pos + 5] & 0xf0) / 16;
		int peak = 8 * 1000 << (oo - 1);
		if (debug)
			printf("   peak tp %i\n", peak);

		pmsg->precedence = p[pos + 5] & 0x07;
		if (debug)
			printf("   precedence %i\n", pmsg->precedence);

		int uu = p[pos + 6];
		int mean = 0;
		if (uu < 31)
			mean = 8 * 100 << (uu - 1);
		if (debug)
			printf("   mean %i\n", mean);

		int traffic_class_number = (p[pos + 7] & 0xe0) >> 5;
		string tc = "-";
		switch (traffic_class_number) {
		case 0:
			tc = "subscribed/reserved";
			break;
		case 1:
			tc = "conversational";
			break;
		case 2:
			tc = "streaming";
			break;
		case 3:
			tc = "interactive";
			break;
		case 4:
			tc = "background";
			break;
		case 5:
			tc = "reserved";
			break;
		}

		pmsg->traffic_class = tc;

		if (l == 4)
			return pos + l + 3;

		pmsg->sdu = p[pos + 8] * 10;
		if (debug)
			printf("   max sdu size %i\n", pmsg->sdu);

		int max_ul = ReadMaxBitrate(p[pos + 9]);
		if (max_ul == 8640000 && l >= 17) {
			max_ul = ReadExtensionBitrate(p[pos + 18]);
			if (debug)
				printf("   extension bw\n");
		}
		if (debug)
			printf("   max_ul %i \n", max_ul);

		int max_dl = ReadMaxBitrate(p[pos + 10]);
		if (max_dl == 8640000 && l >= 15) {
			max_dl = ReadExtensionBitrate(p[pos + 16]);
			if (debug)
				printf("   extension bw\n");
		}
		if (debug)
			printf("   max_dl %i \n", max_dl);

		pmsg->thp = p[pos + 12] & 0x07;
		if (debug)
			printf("   thp %i\n", pmsg->thp);

		int gbr_ul = ReadMaxBitrate(p[pos + 13]);
		if (gbr_ul == 8640000 && l >= 18) {
			if (debug)
				printf("   extension bw\n");
			gbr_ul = ReadExtensionBitrate(p[pos + 19]);
		}
		if (debug)
			printf("   gbr_ul %i \n", gbr_ul);

		int gbr_dl = ReadMaxBitrate(p[pos + 14]);
		if (gbr_dl == 8640000 && l >= 16) {
			if (debug)
				printf("   extension bw\n");
			gbr_dl = ReadExtensionBitrate(p[pos + 17]);
		}
		if (debug)
			printf("   gbr_dl %i \n", gbr_dl);

		pmsg->max_ul = max_ul;
		pmsg->max_dl = max_dl;
		pmsg->gbr_ul = gbr_ul;
		pmsg->gbr_dl = gbr_dl;

		//if(l==12) return pos+l+3;

		return pos + l + 3;
	}

	case 137: {
		if (debug)
			printf("TFT\n");
		int l = NetworkShortAt(p+pos+1);
		return pos + l + 3;
	}

	case 148: {
		// common flags
		int l = NetworkShortAt(p+pos+1);
		return pos + l + 3;
	}

	case 151: {
		int l = NetworkShortAt(p+pos+1);
		int rat = p[pos + 3];
		const char *rt = "-";
		switch (rat) {
		case 0:
			rt = "RESERVED";
			break;
		case 1:
			rt = "WCDMA";
			break;
		case 2:
			rt = "GSM";
			break;
		case 3:
			rt = "WLAN";
			break;
		case 4:
			rt = "GAN";
			break;
		case 5:
			rt = "LTE";
			break;  // LTE code may need a check
		}
		pmsg->rat = rt;
		pmsg->rat_present = 1;

		if (debug)
			printf("RAT type %s\n", rt);
		return pos + l + 3;
	}

	case 152: {
		int l = NetworkShortAt(p+pos+1);
		int type = p[pos + 3];

// esirich DEFTFTS-1825 read MCC/MNC as TBCD strings
		decodeMCC(p + pos + 4, pmsg->mcc);
		decodeMNC(p + pos + 5, pmsg->mnc); 

		if (debug)
			printf("MCC %i MNC %i\n", pmsg->mcc, pmsg->mnc);

		if (type == 0) {
			pmsg->lac = NetworkShortAt(p+pos+7);
			pmsg->cid = NetworkShortAt(p+pos+9);

			if (debug)
				printf("Location type 0 lac %i cid %i\n", pmsg->lac, pmsg->cid);
		} else if (type == 1) {
			pmsg->lac = NetworkShortAt(p+pos+7);
			pmsg->sac = NetworkShortAt(p+pos+9);
			if (debug)
				printf("Location type 1 lac %i sac %i\n", pmsg->lac, pmsg->sac);
		} else if (type == 2) {
			pmsg->lac = NetworkShortAt(p+pos+7);
			pmsg->rac  = NetworkShortAt(p+pos+9);
			if (debug)
				printf("Location type 2 lac %i rac %i\n", pmsg->lac, pmsg->rac);
		} else {
			if (debug)
				printf("UNKNOWN location type %i\n", type);
		}

		return pos + l + 3;
	}

	case 153: {
		// timezone
		int l = NetworkShortAt(p+pos+1);
		return pos + l + 3;
	}

	case 154:
		// IMEI
		return DecodeIMEISV_IE(p, pos, datalen, pmsg);

	case 182: {
		int l = NetworkShortAt(p+pos+1);

		if (debug)
			printf("DT Flags: ");

		char flag = p[pos + 3];
		if (flag & 1) {
			pmsg->dtflag = 1;
			if (debug)
				printf("Direct Tunnel Flag ");
		}
		if (flag & 2)
			if (debug)
				printf("GCSI Flag ");
		if (flag & 4)
			if (debug)
				printf("Error Indication from RNC ");

		if (debug)
			printf("\n");

		return pos + l + 3;
	}

	case 191: {
		int l = NetworkShortAt(p+pos+1);//

		//int pvi = p[pos+3]&0x01;
		//int pl = (p[pos+3]&0x3c) / 4;
		//int pci = (p[pos+3]&0x40) / 64;

		//printf("Evolved alloc/ret: pre-emption vuln %i priority %i pr-emp cap. %i\n", pvi, pl, pci);

		return pos + l + 3;
	}

	case 251: {
		// charging gateway
		int l = NetworkShortAt(p+pos+1);
		return pos + l + 3;
	}

	case 255: {
		//printf("Private extension\n");
		int l = NetworkShortAt(p+pos+1);
		return pos + l + 3;
	}

	default:
		printf("IE not decoded: %i\n", ie);
		return datalen;
	}

	return 0;

}
