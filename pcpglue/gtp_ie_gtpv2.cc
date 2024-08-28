#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <string.h>
#include <time.h>

#include "include/gtp_ie_gtpv2.h"
#include "include/GTPv1_packetFields.h"
#include "include/Information_Elements_GTPv2.h"

bool plog;

long readByteArray(unsigned char * data, int arraySize, int location){
	long dataValue=0;
	for(int i=0; i<arraySize ;++i){
		dataValue = dataValue*256 +data[i+location];
	}
	return dataValue;
}

void SetLog(bool i) {
	plog = i;
}

Bearer :: Bearer() {
	present = 0;
}

DecodedMsg_V2 :: DecodedMsg_V2() {
	imsi_present=0;
	apn_present=addr1_present=addr2_present=0;
	msisdn_present=cause_present=ue_addr_present=0;
	src_addr = dst_addr = 0;
	eps_bearer_id=-1;
	delay_value_present = delay_value = 0;
	bzero(mcc, MCC_MAX_CHARS);
	strcpy(mcc, MCC_INIT_STRING);
	bzero(mnc, MNC_MAX_CHARS);
	strcpy(mnc, MNC_INIT_STRING);
	rai=sai=cgi=lac=tai=ecgi=-1;
	bzero(mei, IMEI_MAX_CHARS);
	strcpy(mei, IMEI_INIT_STRING);
	nsapi=-1;
	dtFlag=-1;
	max_ul = max_dl = gbr_ul = gbr_dl=-1;
	arp=-1;
	S1U_TEID =-1;
	teid = -1;
	ue_addr = -1;
	timestamp = 0.0;
	addr1 = 0;
	addr2 = 0;
	mei_present = 0;
	cause = 0;
	bzero(imsi, IMSI_MAX_CHARS);
	strcpy(imsi, IMSI_INIT_STRING);
	bzero(msisdn, MSISDN_MAX_CHARS);
	strcpy(msisdn, MSISDN_INIT_STRING);
	bzero(apn, APN_MAX_CHARS);
	strcpy(apn, APN_INIT_STRING);
}

int DecodeS1_UInformation(unsigned char *p, int pos, struct DecodedMsg_V2 *pmsg){
	S1_U_Data_Forwarding* S1UData = (S1_U_Data_Forwarding*) (p+pos);

	pmsg->S1U_TEID = NetworkIntAt(p + pos + sizeof(S1_U_Data_Forwarding) + (S1UData->servingGWAddressLength) );

	int n = ntohs(S1UData->length);

	return pos + n + 4;
}

void DecodeUserLocationInformation(unsigned char *p, int pos, struct DecodedMsg_V2 *pmsg) {

	UserLocationInformation* mapPtr = (UserLocationInformation*) &p[pos];
	int positionInInformationElement = 0;
	int baseSizeOfULI_IE = 5;
	if(mapPtr->CellGlobalIdentiferFlag){
		CellGlobalIdentifer* CGIPtr = (CellGlobalIdentifer*) &p[baseSizeOfULI_IE+positionInInformationElement];
		decodeMCC(p+pos+baseSizeOfULI_IE+positionInInformationElement, pmsg->mcc);
		decodeMNC(p+pos+baseSizeOfULI_IE+positionInInformationElement+1, pmsg->mnc);
		positionInInformationElement += sizeof(CellGlobalIdentifer);
		pmsg->lac = ntohs(CGIPtr->LocationAreaCode);
		pmsg->cgi = ntohs(CGIPtr->CellIdentity);
	}
	if(mapPtr->ServiceAreaIdentiferFlag){
		ServiceAreaIdentifer* SAIPtr = (ServiceAreaIdentifer*) &p[baseSizeOfULI_IE+positionInInformationElement];
		decodeMCC(p+pos+baseSizeOfULI_IE+positionInInformationElement, pmsg->mcc);
		decodeMNC(p+pos+baseSizeOfULI_IE+positionInInformationElement+1, pmsg->mnc);
		positionInInformationElement +=  sizeof(ServiceAreaIdentifer);
		pmsg->lac = ntohs(SAIPtr->LocationAreaCode);
		pmsg->sai = ntohs(SAIPtr->ServiceAreaCode);
	}
	if(mapPtr->RoutingAreaIdentityFlag){
		RoutingAreaIdentity* RAIPtr = (RoutingAreaIdentity*) &p[baseSizeOfULI_IE+positionInInformationElement];
		decodeMCC(p+pos+baseSizeOfULI_IE+positionInInformationElement, pmsg->mcc);
		decodeMNC(p+pos+baseSizeOfULI_IE+positionInInformationElement+1, pmsg->mnc);
		positionInInformationElement +=  sizeof(RoutingAreaIdentity);
		pmsg->lac = ntohs(RAIPtr->LocationAreaCode);
		pmsg->rai = ntohs(RAIPtr->RoutingAreaCode);
	}
	if(mapPtr->TrackingAreaIdentityFlag){
		TrackingAreaIdentity* TAIPtr = (TrackingAreaIdentity*) &p[baseSizeOfULI_IE+positionInInformationElement];
		decodeMCC(p+pos+baseSizeOfULI_IE+positionInInformationElement, pmsg->mcc);
		decodeMNC(p+pos+baseSizeOfULI_IE+positionInInformationElement+1, pmsg->mnc);
		positionInInformationElement +=  sizeof(TrackingAreaIdentity);
		pmsg->tai = ntohs(TAIPtr->TrackingAreaCode);
	}
	if(mapPtr->E_UTRANCellGlobalIdentifierFlag){
		E_UTRANCellGlobalIdentifier* ECGIPtr = (E_UTRANCellGlobalIdentifier*) &p[baseSizeOfULI_IE+positionInInformationElement];
		decodeMCC(p+pos+baseSizeOfULI_IE+positionInInformationElement, pmsg->mcc);
		decodeMNC(p+pos+baseSizeOfULI_IE+positionInInformationElement+1, pmsg->mnc);

		unsigned char *pp = p + baseSizeOfULI_IE+positionInInformationElement + 3;
		int i = *(int *)(pp);
		i&= 0xFFFFFFF; 	//This is a 28 bit field where the MSB is the 4th bit of a byte  and the LSB is the 1st bit of
		//the last byte. See 3GPP 29.274 section 8.21.5 Michael Lawless
		positionInInformationElement +=  sizeof(E_UTRANCellGlobalIdentifier);
		pmsg->ecgi = i;
	}
	if(mapPtr->LocationAreaIdentifierFlag){
		LocationAreaIdentifier* LAIPtr = (LocationAreaIdentifier*) &p[baseSizeOfULI_IE+positionInInformationElement];
		decodeMCC(p+pos+baseSizeOfULI_IE+positionInInformationElement, pmsg->mcc);
		decodeMNC(p+pos+baseSizeOfULI_IE+positionInInformationElement+1, pmsg->mnc);
		positionInInformationElement +=  sizeof(LocationAreaIdentifier);
		pmsg->lac = ntohs(LAIPtr->LocationAreaCode);
	}
}
// can replace above with calls built like below
//char* getCGI(char* &startPoint, UserLocationInformation* informationElement){
//	if (informationElement->CellGlobalIdentiferFlag){
//		char * oldStartPoint = startPoint;
//		startPoint += sizeof(CellGlobalIdentifer);
//		return oldStartPoint;
//	}
//	else{
//		return 0;
//	}
//}

// esirich: DEFTFTS-1825 convert TBCD to ASCII digits -- see ETSI ETR 060
static const char *tbcd="0123456789*#abc\0";

int DecodeIMSI_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg_V2 *pmsg) {

	int i;

	pmsg->imsi_present=1;
	bzero(pmsg->imsi, IMSI_MAX_CHARS);
	strcpy(pmsg->imsi, IMSI_INIT_STRING);

	int n = NetworkShortAt(p+pos+1);

	for(i=0; i<n && (i << 1) < IMSI_MAX_CHARS; i++) {
		int d1 = p[pos+i+4]&0x0f;
		int d2 = (p[pos+i+4]&0xf0)/16;

		pmsg->imsi[(i<<1)] = tbcd[d1];
		pmsg->imsi[(i<<1) + 1] = tbcd[d2];
	}

	return pos + n + 4;
}


int DecodeMSISDN_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg_V2 *pmsg) {

	int i;

	pmsg->msisdn_present=1;
	bzero(pmsg->msisdn, MSISDN_MAX_CHARS);
	strcpy(pmsg->msisdn, MSISDN_INIT_STRING);

	int n = NetworkShortAt(p+pos+1);

	for(i=0; i<n && (i << 1) < MSISDN_MAX_CHARS; i++) {
		int d1 = p[pos+i+4]&0x0f;
		int d2 = (p[pos+i+4]&0xf0)/16;

		pmsg->msisdn[(i << 1)] = tbcd[d1];
		pmsg->msisdn[(i << 1) + 1] = tbcd[d2];
	}

	return pos + n + 4;
}

int DecodeMEI_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg_V2 *pmsg) {

	int i;

	pmsg->mei_present=1;
	bzero(pmsg->mei, IMEI_MAX_CHARS);
	strcpy(pmsg->mei, IMEI_INIT_STRING);

	int n = NetworkShortAt(p+pos+1);
	for(i=0; i<n; i++) {
		int d1 = p[pos+i+4]&0x0f;
		int d2 = (p[pos+i+4]&0xf0)/16;

		pmsg->mei[(i << 1)] = tbcd[d1];
		pmsg->mei[(i << 1) + 1] = tbcd[d2];
	}

	return pos + n + 4;
}


int DecodeIndication_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg_V2 *pmsg) {

	INDICATION_IE* IndicationPtr = (INDICATION_IE*) (p+pos);
	pmsg->dtFlag = IndicationPtr->DirectTunnelFlag;

	int i;
	int n = NetworkShortAt(p+pos+1);
	return pos + n + 4;
}

int DecodeFTEID_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg_V2 *pmsg) {

	fullyQuilifedTEID* FTEID_DataPtr = (fullyQuilifedTEID*) (p+pos);

	unsigned short l = ntohs(FTEID_DataPtr->length);
	int instance = FTEID_DataPtr->instance;
	int v4Flag = FTEID_DataPtr->V4;
	int v6Flag = FTEID_DataPtr->V6;
	int interfaceType = FTEID_DataPtr->interfaceType;
	int TEID_GRE_Key = ntohl(FTEID_DataPtr->TEID_GRE_Key);

	if(v4Flag) {
		pmsg->fteid[instance].teid =TEID_GRE_Key;
		pmsg->fteid[instance].addr = NetworkIntAt(p+pos+9);
	}

	return pos + l + 4;

}  

int DecodeBearerContext_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg_V2 *pmsg) {

	int n = NetworkShortAt(p+pos+1);

	int instance = p[pos+3] & 15;

	if(plog) printf("instance=%i\n", instance);

	unsigned char *p_group = p+pos+4;
	int datalen_group = n - 4;
	int pos_group=0;
	//DecodedMsg_V2 msg_group;

	if(plog) printf("GROUP DECODE +++++++++++++++++++++++++++++++\n");

	while(pos_group<datalen_group) {
		pos_group = DecodeIE(p_group, pos_group, datalen_group, pmsg);
	}


	if(plog) printf("END GROUP DECODE +++++++++++++++++++++++++++++++\n");

	// copy fteids from group decoded msg into the parent message appropriate bearer fteid list
	int id = pmsg->eps_bearer_id;

	if(pmsg->eps_bearer_id == -1) pmsg->eps_bearer_id = id;

	if(plog) printf("eps_bearer_id = %i, instance = %i\n", id, instance);

	if(id!=-1) {

		pmsg->bearer[instance][id].present = 1;
		//TODO sizeof


		for(int i=0; i<LENGTHOF(pmsg->fteid)-1; i++) {

			if(pmsg->fteid[i].teid==0) continue;

			pmsg->bearer[instance][id].fteid[i] = pmsg->fteid[i];

			if(plog) printf("bearer %i [%i] ", id, i);
			//if(plog) pmsg->bearer[instance][id].fteid[i].print();
		}
	}

	if(plog) printf("BearerContext END\n");

	return pos + n + 4;
}   

int DecodeAPN_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg_V2 *pmsg) {

	// apn name
	int n = NetworkShortAt(p+pos+1);

	int i=0;

	int part_len;
	int j;
	int c=0;
	while(i<n) {
		part_len = p[pos+4+i];
		memcpy(pmsg->apn+c, p+pos+5+i, part_len);
		c+=part_len;

		i+=part_len+1;
		if(i<n) pmsg->apn[c++]='.';
	}

	pmsg->apn[c]='\0';
	if(plog) printf("apn: %s\n", pmsg->apn);

	pmsg->apn_present=1;

	return pos + n + 4;
}

int decode_AMBR(unsigned char *p,int pos, int datalen, struct DecodedMsg_V2 *pmsg){
	//TODO
	return 0;
}

int DecodePDPContext_IE(unsigned char *p, int pos, int datalen) {
	unsigned short int length = NetworkShortAt(p+2);

	return pos + length;
}

// returns new pos
int DecodeIE(unsigned char *p, int pos, int datalen,struct DecodedMsg_V2 *pmsg) {

	int n = NetworkShortAt(p+pos+1);
	int ie = p[pos];

	switch (ie) {

	case 0: {
		// Reserved0
		return pos + n + 4;
	}

	case 1:
		// IMSI
		return DecodeIMSI_IE(p, pos, datalen, pmsg);

	case 2: {
		// Cause
		pmsg->cause_present=1;
		pmsg->cause = p[pos+4];
		return pos + n + 4;
	}

	case 71:
		// apn
		return DecodeAPN_IE(p, pos, datalen, pmsg);

	case 72: {
		// AMBR
		decode_AMBR(p,pos,datalen,pmsg);
		return pos + n + 4;

	}

	case 73: {
		// EPS bearer id
		pmsg->eps_bearer_id = p[pos+4] & 15;
		return pos + n + 4;
	}

	case 75:
		return DecodeMEI_IE(p, pos, datalen, pmsg);


	case 76:
		// msisdn
		return DecodeMSISDN_IE(p, pos, datalen, pmsg);

	case 77:
		// indication
		return DecodeIndication_IE(p, pos, datalen, pmsg);

	case 78: {
		// Protocol configuration options
		return pos + n + 4;
	}

	case 79: {
		// PDN Address allocation
		int type = p[pos+4];
		if(type == 1) {
			pmsg->ue_addr_present = 1;
			pmsg->ue_addr = NetworkIntAt(p + pos+5);
		}

		return pos + n + 4;
	}

	case 80: {
		// Bearer QoS
		BearerQualityOfService_IE* QOSPtr = (BearerQualityOfService_IE*) (p+pos);
		ARP* arpPtr = (ARP*) (p+pos);
		pmsg->arp	 = arpPtr->ARPData;
		unsigned char * data = (unsigned char *)QOSPtr+6;
		pmsg->max_dl = readByteArray(data, 5,0);
		pmsg->max_ul = readByteArray(data, 5,5);
		pmsg->gbr_dl = readByteArray(data, 5,10);
		pmsg->gbr_ul = readByteArray(data, 5,15);

		return pos + n + 4;
	}

	case 82: {
		// RAT Type

		int RATType = p[pos+4];
		string theType;
		switch(RATType){
		case 0: theType="<reserved>";		break;
		case 1: theType="UTRAN";   			break;
		case 2: theType="GERAN";			break;
		case 3: theType="WLAN";				break;
		case 4: theType="GAN";				break;
		case 5: theType="HSPA Evolution"; 	break;
		case 6: theType="EUTRAN";			break;
		//case 7-255:theType="<spare>"; break;
		}
		pmsg->RATType = theType;

		return pos + n + 4;

	}

	case 83: {
		// Serving network (MNC+MCC)
		decodeMCC(p+pos+4, pmsg->mcc);
		decodeMNC(p+pos+5, pmsg->mnc);
		return pos + n + 4;

	}

	case 86: {
		// User Location Information
		DecodeUserLocationInformation(p, pos, pmsg);
		return pos + n + 4;
	}


	case 87: {
		// FTEID
		return DecodeFTEID_IE(p, pos, datalen, pmsg);
	}

	case 91:{
		return DecodeS1_UInformation(p,pos,pmsg);
	}

	case 92: {
		// Delay Value
		pmsg->delay_value = p[pos+4];
		pmsg->delay_value_present = 1;
		if(plog) printf("Delay Value %i\n", pmsg->delay_value);
		return pos + n + 4;
	}

	case 93: {
		// Bearer context
		return DecodeBearerContext_IE(p, pos, datalen, pmsg);
	}

	case 95: {
		// Charging characteristics
		return pos + n + 4;
	}

	case 99: {
		// PDN type
		return pos + n + 4;
	}

	case 110: {
		// PDU numbers
		PDU_Numbers_IE* pduPtr = (PDU_Numbers_IE*) (p+pos);
		pmsg->nsapi = ntohl(pduPtr->NSAPI);

		return pos + n + 4;
	}

	case 116: {
		return pos + n + 4;
	}

	case 117: {
		return pos + n + 4;
	}

	case 127: {
		return pos + n + 4;
	}

	case 128: {
		// Selection mode
		return pos + n + 4;
	}

	default:
		return pos+n+4;
	}

	return 0;

}
