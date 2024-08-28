/*
 *
 *  Created on: 12 Jul 2012
 *      Author: emilawl
 */
#include "include/GTPv1_packetFields.h"
#include <iostream>
using std::cerr;
using std::endl;
extern ofstream* v1_out;
int PDPSession::instanceCounter = 0 ;
int PDPSession::deleteCounter = 0;

//char addrbuff[1000]; // globally used buffer (non thread-safe!)
void PDPSession::printUpdate(){

	v1_out->precision(3);
	v1_out->setf(std::ios::fixed);
	// in case we did not see the request

	if(time_update_request==0) time_update_request = time_update_response;
	*v1_out << "UPDATE,"
			<< time_update_request << ','
			<< startTime << ','
			<< imsi << ','
			<< (rat.empty() ? EMPTY_INT_STRING : rat) << ','
			<< nsapi << ','
			<< dtflag << ','
			<< mcc << ','
			<< mnc << ','
			<< printIFGE0(lac)
			<< printIFGE0(rac)
			<< printIFGE0(cid)
			<< printIFGE0(sac)
			<< printIFGE0(arp)
			<< printIFGE0(delay_class)
			<< printIFGE0(reliability_class)
			<< printIFGE0(precedence)
			<< (traffic_class.empty() ? EMPTY_INT_STRING : traffic_class) << ","
			<< printIFGE0(thp)
			<< printIFGE0(max_ul)
			<< printIFGE0(max_dl)
			<< printIFGE0(gbr_ul)
			<< printIFGE0(gbr_dl)
// esirich DEFTFTS-1879 add empty string output
			<< EMPTY_INT_STRING ","		//ecgi
			<< EMPTY_INT_STRING ","		//time_update_request
			<< EMPTY_INT_STRING ","		//time_update_response
			<< EMPTY_INT_STRING ","		//update_cause
			<< EMPTY_INT_STRING ","		//apn
			<< EMPTY_INT_STRING ","		//default_bearer_id
			<< EMPTY_INT_STRING 		//ue_addr
			<< endl;

}

void PDPSession::printPDPSession() {

	v1_out->precision(3);
	v1_out->setf(std::ios::fixed);

	*v1_out << "ACTIVATE,"
			  << startTime << ',';

		if(time_pdn_response>0) *v1_out << time_pdn_response - startTime << ',' ;
		else *v1_out << EMPTY_INT_STRING << ",";

		if(pdn_cause == 128) *v1_out << "SUCCESS,";
		else if(pdn_cause == -1) *v1_out << "TIMEOUT,";
		else *v1_out << "REJECT,";

		*v1_out << pdp_type << ',';
		
		if(!rat.empty()) {
			*v1_out << rat << ',';
		} else {
			*v1_out << EMPTY_INT_STRING << ",";
		}

		if(pdn_cause !=128) {
			//TODO implement array of values
			// get value from map print it else print no cause code
			const char *c;
			switch(pdn_cause) {
			case 192: c = "NON-EXISTENT"; break;
			case 193: c = "INVALID MESSAGE FORMAT";break;
			case 194: c = "IMSI NOT KNOWN";break;
			case 195: c = "MS IS GPRS DETACHED";break;
			case 196: c = "MS IS NOT GPRS RESPONDING";break;
			case 197: c = "MS REFUSES";break;
			case 198: c = "VERSION NOT SUPPORTED";break;
			case 199: c = "NO RESOURCES AVAILABLE";break;
			case 200: c = "SERVICE NOT SUPPORTED";break;
			case 201: c = "MANDATORY IE INCORRECT";break;
			case 202: c = "MANDATORY IE MISSING";break;
			case 203: c = "OPTIONAL IE INCORRECT";break;
			case 204: c = "SYSTEM FAILURE";break;
			case 205: c = "ROAMING RESTRICTION";break;
			case 206: c = "P-TMSI SIGNATURE MISMATCH";break;
			case 207: c = "GPRS CONNECTION SUSPENDED";break;
			case 208: c = "AUTHENTICATION FAILURE";break;
			case 209: c = "USER AUTHENTICATION FAILED";break;
			case 210: c = "CONTEXT NOT FOUND";break;
			case 211: c = "ALL DYNAMIC PDP ADDRESSES ARE OCCUPIED";break;
			case 212: c = "NO MEMORY IS AVAILABLE";break;
			case 213: c = "RELOCATION FAILURE";break;
			case 214: c = "UNKNOWN MANDATORY EXTENSION HEADER";break;
			case 215: c = "SEMANTIC ERROR IN THE TFT OPERATION";break;
			case 216: c = "SYNTACTIC ERROR IN THE TFT OPERATION";break;
			case 217: c = "SEMANTIC ERRORS IN PACKET FILTERS";break;
			case 218: c = "SYNTACTIC ERRORS IN PACKET FILTERS";break;
			case 219: c = "MISSING OR UNKNOWN APN";break;
			case 220: c = "UNKNOWN PDP ADDRESS OR PDP TYPE";break;
			case 221: c = "PDP CONTEXT WITHOUT TFT ALREADY ACTIVATED";break;
			case 222: c = "APN ACCESS DENIED - NO SUBSCRIPTION";break;
			case 223: c = "APN RESTRICTION TYPE INCOMPATIBILITY WITH CURRENTLY ACTIVE PDP CONTEXTS";break;
			case 224: c = "MS MBMS CAPABILITIES INSUFFICIENT";break;
			case 225: c = "INVALID CORRELATION-ID";break;
			case 226: c = "MBMS BEARER CONTEXT SUPERSEDED";break;
			case 227: c = "BEARER CONTROL MODE VIOLATION";break;
			case 228: c = "COLLISION WITH NETWORK INITIATED REQUEST";break;
			case 229: c = "APN CONGESTION";break;
			case 230: c = "BEARER HANDLING NOT SUPPORTED";break;
			default: c = "INVALID CAUSE CODE";
			}
			*v1_out << c << ',';
		} else *v1_out << "NOCAUSECODE,";

		*v1_out << mcc << ','
			<< mnc << ','
			<< printIFGE0(lac)
			<< printIFGE0(rac)
			<< printIFGE0(cid)
			<< printIFGE0(sac)
			<< imsi << ','
			<< imei << ','
			<< IPAddress(ggsn_d.addr) << ','
			<< apn << ','
			<< msisdn << ','
			<< nsapi << ','
			<< IPAddress(ue_addr) << ','
			<< printIFGE0(arp)
			<< printIFGE0(delay_class)
			<< printIFGE0(reliability_class)
			<< printIFGE0(precedence)
			<< (traffic_class.empty() ? EMPTY_INT_STRING : traffic_class) << ","
			<< printIFGE0(thp)
			<< printIFGE0(max_ul)
			<< printIFGE0(max_dl)
			<< printIFGE0(gbr_ul)
			<< printIFGE0(gbr_dl)
			<< printIFGE0(sdu)
// esirich DEFTFTS-1879 "\\N" added to output
			<< EMPTY_INT_STRING ","			//ecgi
			<< EMPTY_INT_STRING "," 		//default_bearer_id
			<< EMPTY_INT_STRING "," 		//mme.addr
			<< EMPTY_INT_STRING "," 		//mme.teid
			<< EMPTY_INT_STRING "," 		//sgw_c.addr
			<< EMPTY_INT_STRING "," 		//sgw_c.teid
			<< EMPTY_INT_STRING "," 		//sgw_d.teid
			<< EMPTY_INT_STRING "," 		//enb.addr
			<< EMPTY_INT_STRING "," 		//enb.teid
			<< EMPTY_INT_STRING ","			//sreq_flag
			<< EMPTY_INT_STRING 			//paging_flag
//used to have the same number of fields in V1 and V2 Michael Lawless 07/08/2012
			<< endl;
	}


// esirich: DEFTFTS-1825 convert TBCD to ASCII digits -- see ETSI ETR 060
static const char *tbcd="0123456789*#abc\0";

// esirich DEFTFTS-1825 read MCC/MNC as TBCD strings

void decodeMNC(unsigned char *p, char *mnc){
		mnc[0] = tbcd[p[1] & 0x0f];
		mnc[1] = tbcd[(p[1] & 0xf0) >> 4];
		mnc[2] = tbcd[(p[0] & 0xf0) >> 4];
		mnc[3] = 0;
}

void decodeMCC(unsigned char *p, char *mcc){
		mcc[0] = tbcd[p[0] & 0x0f];
		mcc[1] = tbcd[(p[0] & 0xf0) >> 4];
		mcc[2] = tbcd[p[1] & 0x0f];
		mcc[3] = 0;

}

unsigned int extractIpAddress(unsigned char* p){
	return  ntohl(*(unsigned int*)p);
}

unsigned short extractPortFromPacket(unsigned char* p){
	return  ntohs(*(unsigned short*)p);
}

//char * FTEID::straddr() {
//	if(addr>0) {
//		unsigned char *a = (unsigned char*)&addr;
//		sprintf(addrbuff, "%i.%i.%i.%i", a[3],a[2],a[1],a[0]);
//	} else addrbuff[0]=0;
//
//
//	return addrbuff;
//}


PacketCounter* PacketCounter::theInstance = 0;


