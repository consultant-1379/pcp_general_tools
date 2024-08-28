/************************************************************************
* COPYRIGHT (C) Ericsson 2012                                           *
* The copyright to the computer program(s) herein is the property       *
* of Telefonaktiebolaget LM Ericsson.                                   *
* The program(s) may be used and/or copied only with the written        *
* permission from Telefonaktiebolaget LM Ericsson or in accordance with *
* the terms and conditions stipulated in the agreement/contract         *
* under which the program(s) have been supplied.                        *
*************************************************************************
*************************************************************************
* File: simulator.c
* Date: Oct 8, 2012
* Author: LMI/LXR/PE Simon Richardson
************************************************************************/


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <time.h>

#include "gtp_hack.h"
#include "traffic.h"

#include "events.h"
#include "config.h"

// esirich: move the state machine's states to an enum in config.h

/**********************************************************************
 * the normal way for the state machine to operate is like this:-
 * 
 * IDLE -> CONNECTING, and produce a createPDPContextRequest
 * CONNECTING -> CONNECTED, and produce a createPDPContextResponse
 * CONNECTED -> UPDATING, and produce an updatePDPContextRequest
 * UPDATING -> CONNECTED, and produce an updatePDPContextResponse
 * CONNECTED -> DISCONNECTING, and produce a deletePDPContextRequest
 * DISCONNECTING -> IDLE, and produce a deletePDPContextResponse
 * 
 * In the CONNECTED state, traffic flows are replayed as G-PDUs.
 **********************************************************************/

#define ONE_IN(prob)	(1 == (random()%(prob)))
// Octect are reversed here :  By design or error; not sure
#define MAKE_INT(str)	(((str[0] & 0x00FF))\
						|((str[1] & 0x00FF) << 8)\
						|((str[2] & 0x00FF) << 16)\
						|((str[3] & 0x00FF) << 24))

//for char teid_d_ggsn[4] = teid_d with octects [0][1][2][3] @ g_PDU write; [3] is the Least Significant Bit/octect; [0] is the Most Significat /Bit/ Octect  
#define MAKE_INT_2(str)	(((str[3] & 0x00FF))\
						|((str[2] & 0x00FF) << 8)\
						|((str[1] & 0x00FF) << 16)\
						|((str[0] & 0x00FF) << 24))

#define WRITE_32(p, x)	{((char *)p)[0]=(((x)>>24)& 0x0FF);\
						((char *)p)[1]=(((x)>>16)& 0x0FF);\
						((char *)p)[2]=(((x)>>8)& 0x0FF);\
						((char *)p)[3]=((x)&0x0FF);}
                    
static int num_ueip_in_timeout; 
static int DEFINED_GTP_SEQ_MAX_NUM_STATES=8;
static int printOnce=0;

void printTEID_C(char* theTEID) {
    
    printf(" teid_c = ");
    int idx;
    for(idx=0;idx<4; idx++) { 
        if(theTEID[idx] <10 && theTEID[idx] >= 0)
            printf("00%d",theTEID[idx] & 0xff);
        else if(theTEID[idx] <100 && theTEID[idx] >= 10)
            printf("00%d",theTEID[idx] & 0xff);
        else
            printf("%d",theTEID[idx] & 0xff);
    }

    printf(" (0x");
    for(idx=0;idx<4; idx++) { 
        if((theTEID[idx]  & 0xff) <= 0xF)
            printf("0%x",theTEID[idx] & 0xff);
        else
            printf("%x",theTEID[idx] & 0xff);
    }
    printf(")\n");

}

void printTEID(char* theTEID) {
    
    int idx;
    for(idx=0;idx<4; idx++) { 
        if(theTEID[idx] <10 && theTEID[idx] >= 0)
            printf("00%d",theTEID[idx] & 0xff);
        else if(theTEID[idx] <100 && theTEID[idx] >= 10)
            printf("00%d",theTEID[idx] & 0xff);
        else
            printf("%d",theTEID[idx] & 0xff);
    }

    printf(" (0x");
    for(idx=0;idx<4; idx++) { 
        if((theTEID[idx]  & 0xff)  <= 0xF)
            printf("0%x",theTEID[idx] & 0xff);
        else
            printf("%x",theTEID[idx] & 0xff);
    }
    printf(")\n");

}
void printTEID_D(char* theTEID) {
    printf(" teid_d = ");
    printTEID(theTEID);

}

void printGGSN_IP(char* theGGSN_IP) {
	int idx;
    for(idx=0;idx<4; idx++) printf("%d.",theGGSN_IP[idx] & 0xff);
    printf("\n");
}

void printUEIP(char* theUEIP) {
	int idx;
    for(idx=2;idx<6; idx++) printf("%d.",theUEIP[idx] & 0xff);
    printf("\n");
}

/*
 *  Print relevant info for debug
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment for the request
 *   - gtpState : shriing of the method it was called from
 *   - teid_c : control plane teid
 *   - teid_d : user plane teid
 */
void printInfo(int UE, const char* gtpState, char* teid_c, char* teid_d) {
    
    printf("gtpState = %s\n ueip = ", gtpState);
    int idx;
    for(idx=0;idx<4; idx++) printf("%d.",config_UE_buffer[UE].ip[idx] & 0xff);
    printf("\n");
    
    printf(" Seq Number = %d\n",config_UE_buffer[UE].seqNum);
    

    printTEID_C(teid_c);
    printTEID_D(teid_d);
    
    printf(" GGSN IP = ");
    for(idx=0;idx<4; idx++) printf("%d.",gtp_GGSN_ip[idx] & 0xff);
    printf("\n");
    
    printf(" SGSN IP = ");
    for(idx=0;idx<4; idx++) printf("%d.",gtp_SGSN_ip[idx] & 0xff);
    printf("\n");

    
    

    printf(" UE (previous) state = %d\n",config_UE_buffer[UE].UE_state);
    
    if(config_UE_buffer[UE].UE_state != 4) { // deletePDPContextResponse 
		int  lac, lac1, lac2, rac;
		lac1 = (config_RAI_list[config_UE_buffer[UE].rai][3]<< 8) ;
		lac2 = (config_RAI_list[config_UE_buffer[UE].rai][4] & 0xff);
		lac = lac1+lac2;
		rac = (config_RAI_list[config_UE_buffer[UE].rai][5] & 0xff);
		
		printf(" LAC = %d\n",lac);
		if(config_UE_buffer[UE].UE_state == 3)  
			printf(" CI = %d\n",rac);
		else
			printf(" RAC = %d\n",rac);

	}
    
}
/*
 * generate and send a create PDP context request message for the UE
 * in the config_UE_buffer
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * for the request
 */
static void createPDPContextRequest(int UE)
{
	char teid_c[4], teid_d_sgsn[4];
	char apn[128]; // esirich DEFTFTS-2667: fix the APN length bug.
	char uli[8];

    memcpy(teid_c, config_UE_buffer[UE].ip, 4); // ericker: reuse the ue ip as the teid - through config we have guaranteed this to be unique across instances
    unsigned int ip;
    memcpy(&ip,  config_UE_buffer[UE].ip, 4);

	teid_d_sgsn[0] = ~teid_c[0];
	teid_d_sgsn[1] = ~teid_c[1];
	teid_d_sgsn[2] = ~teid_c[2];
	teid_d_sgsn[3] = ~teid_c[3];
	

    
	// set up APN string to include 1st byte length (redundant!)
	apn[0] = strlen(config_UE_buffer[UE].access_point_name);
	strncpy(apn + 1, config_UE_buffer[UE].access_point_name, apn[0]);
	
	write_gtp_start(1, 16, htonl((int)ip), 0x32, config_UE_buffer[UE].seqNum << 16); //Create context request
	write_gtp_IE(0x02, 8, config_UE_buffer[UE].imsi); // IMSI
	write_gtp_IE(0x03, 6, config_RAI_list[config_UE_buffer[UE].rai]); // RAI
	write_gtp_IE(0x0E, 1, "\xB8"); // recovery
	write_gtp_IE(0x10, 4, teid_d_sgsn);// TEID 1
	write_gtp_IE(0x11, 4, teid_c);// TEID C
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x1A, 2, "\x04\x00");//Charging characteristics
	write_gtp_IE(0x80, 2, "\xf1\x21");//end user address
	write_gtp_IE(0x83, apn[0] + 1, apn);//APN
	write_gtp_IE(0x84, 0x1d,"\x80\xc0\x23\x06\x01\x01\x00\x06"
							"\x00\x00\x80\x21\x10\x01\x01\x00"
							"\x10\x81\x06\x00\x00\x00\x00\x83"
							"\x06\x00\x00\x00\x00");// protocol config options
	write_gtp_IE(0x85, 4, gtp_SGSN_ip);//SGSN signalling -- TODO change these to reflect SGSN address
	write_gtp_IE(0x85, 4, gtp_SGSN_ip);//SGSN user
	write_gtp_IE(0x86, config_UE_buffer[UE].msisdn[0], 
					1 + config_UE_buffer[UE].msisdn);//MSISDN
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x97, 1, "\x01"); //RAT type

	// Write the ULI information in
	uli[0] = 0;	// Geographic location type = 1, CGI
	memcpy(uli+1, config_RAI_list[config_UE_buffer[UE].rai], 5); // Copy MCC,MNC,LAC
	uli[6] = 0; // Swap the RAI's byte order to become the Cell Identity
	uli[7] = config_RAI_list[config_UE_buffer[UE].rai][5];

	write_gtp_IE(0x98, 8, uli);// location information
	write_gtp_IE(0x99, 2, "\x23\x00"); // timezone
	write_gtp_IE(0x9A, config_UE_buffer[UE].imei[0], 
					1 + config_UE_buffer[UE].imei); // IMEI
	write_gtp_end(GTP_UP);
}

/*
 * generate and send a create PDP context response message for the UE 
 * in the config_UE_buffer
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * for the request
 */
static void createPDPContextResponse(int UE)
{
	char teid_c[4], teid_d_ggsn[4];
	char euid[6]={0xf1, 0x21};
    unsigned int ip;
    
    printf("------------------------------------------\n");
    memcpy(&ip,  config_UE_buffer[UE].ip, 4);

    memcpy(euid+2, config_UE_buffer[UE].ip, 4);

    memcpy(teid_c, config_UE_buffer[UE].ip, 4); // ericker: reuse the ue ip as the teid - through config we have guaranteed this to be unique across instances
	teid_d_ggsn[0] = ~teid_c[3];
	teid_d_ggsn[1] = ~teid_c[2];
	teid_d_ggsn[2] = ~teid_c[1];
	teid_d_ggsn[3] = ~teid_c[0];
	
    if(config_create_GTPC_sequence) {
        const char gtpState[]="createPDPContextResponse\0";
        printInfo(UE, gtpState, teid_c, teid_d_ggsn);
    }
    
	write_gtp_start(1, 17, htonl((int)ip), 0x32, config_UE_buffer[UE].seqNum << 16); //Create context response
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(0x10, 4, teid_d_ggsn);// TEID 1
	write_gtp_IE(0x11, 4, teid_c);// TEID C
	write_gtp_IE(0x7F, 4, teid_d_ggsn); // charging ID
	write_gtp_IE(0x80, 6, euid);//end user address
	write_gtp_IE(0x84, 0x1d,"\x80\xc0\x23\x06\x01\x01\x00\x06"
							"\x00\x00\x80\x21\x10\x01\x01\x00"
							"\x10\x81\x06\x00\x00\x00\x00\x83"
							"\x06\x00\x00\x00\x00");// protocol config options
	write_gtp_IE(0x85, 4, gtp_GGSN_ip);//GGSN signalling
	write_gtp_IE(0x85, 4, gtp_GGSN_ip);//GGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0xFB, 4, "\xC0\xA8\x00\x01");
	write_gtp_end(GTP_DOWN);
  config_UE_buffer[UE].seqNum++;
}

/*
 * generate and send an update PDP context request message for the UE
 * in the config_UE_buffer
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * for the request
 */
static void updatePDPContextRequest(int UE, int mode)
{
	char teid_c[4], teid_d_sgsn[4];
    char user_loc_info[8];
    int jj;

	//WRITE_32(teid_c, UE);

    memcpy(teid_c, config_UE_buffer[UE].ip, 4); // ericker: reuse the ue ip as the teid - through config we have guaranteed this to be unique across instances

	teid_d_sgsn[0] = ~teid_c[0];
	teid_d_sgsn[1] = ~teid_c[1];
	teid_d_sgsn[2] = ~teid_c[2];
	teid_d_sgsn[3] = ~teid_c[3];

    
    unsigned int ip;
    memcpy(&ip,  config_UE_buffer[UE].ip, 4);
    write_gtp_start(1, 18, htonl((int)ip), 0x32, config_UE_buffer[UE].seqNum << 16); //Update context request
        
	write_gtp_IE(0x03, 6, config_RAI_list[config_UE_buffer[UE].rai]); // RAI
	write_gtp_IE(0x0E, 1, "\x51"); // recovery
    printf("----------------------------------------\n");
    if((mode==2) &&  (config_create_GTPC_sequence)) { //new TEID_D
        new_teid_d_sgsn[0] = teid_d_sgsn[0];
        new_teid_d_sgsn[1] = teid_d_sgsn[1];
        new_teid_d_sgsn[2] = teid_d_sgsn[2];
        new_teid_d_sgsn[3] = 0x11;  
        write_gtp_IE(0x10, 4, new_teid_d_sgsn);// TEID 1
        printf("gtpState =  updatePDPContextRequest \n new teid_d_sgsn = ");
        printTEID(new_teid_d_sgsn);
    }else {
        write_gtp_IE(0x10, 4, teid_d_sgsn);// TEID 1
        printf("gtpState =  updatePDPContextRequest \n teid_d_sgsn = ");
        printTEID(teid_d_sgsn);
    }

    if((mode==1) &&  (config_create_GTPC_sequence)) { //new TEID_C
        new_teid_c[0] = teid_c[0] +1 ;
        new_teid_c[1] = teid_c[1];
        new_teid_c[2] = teid_c[2];
        new_teid_c[3] = teid_c[3];   
        write_gtp_IE(0x11, 4, new_teid_c);// TEID C
    }
    write_gtp_IE(0x14, 1, "\x05"); //NSAPI
    
    if((mode==1) &&  (config_create_GTPC_sequence)) { //new SGSN IP and TEID_C
    	memcpy(gtp_SGSN_ip, gtp_new_SGSN_ip, 4);
    }
   
    write_gtp_IE(0x85, 4, gtp_SGSN_ip);//SGSN signalling
    write_gtp_IE(0x85, 4, gtp_SGSN_ip);//SGSN user
    
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x94, 1, "\x10"); // common flags
	write_gtp_IE(0x97, 1, "\x01"); //RAT type
	//write_gtp_IE(0x98, 8, "\x01\x23\x45\x67\x89\xAB\xCD\xEF");// location information
    //write_gtp_IE(0x98, 8, "\x02\x01\x23\x45\x67\x85\xbf\x11");// location information
    
    // User Location Information IE; Geographic Location field 0x00 included and it holds the Cell Global Identification (CGI) of where the user currently is registered
    user_loc_info[0]= 0x00;
    user_loc_info[1] = config_RAI_list[config_UE_buffer[UE].rai][0];
    user_loc_info[2] = config_RAI_list[config_UE_buffer[UE].rai][1];
    user_loc_info[3] = config_RAI_list[config_UE_buffer[UE].rai][2];
    user_loc_info[4] = config_RAI_list[config_UE_buffer[UE].rai][3];
    user_loc_info[5] = config_RAI_list[config_UE_buffer[UE].rai][4];
    user_loc_info[6] = 0x00;
    user_loc_info[7] = config_RAI_list[config_UE_buffer[UE].rai][5];
    //printf("user_loc_info[0] = %0x\n", user_loc_info[0]) ;
    //for(ii=1;ii<=6;ii++) printf("user_loc_info[%d] = %0x, config_RAI_list[config_UE_buffer[UE].rai][%d] = %0x\n", ii, user_loc_info[ii] & 0xff,ii-1, config_RAI_list[config_UE_buffer[UE].rai][ii-1] & 0xff) ;
    //printf("user_loc_info[7] = %0x\n", user_loc_info[7] & 0xff) ;
    write_gtp_IE(0x98, 8, user_loc_info);// location information
	write_gtp_IE(0x99, 2, "\x23\x00"); // timezone
	write_gtp_end(GTP_UP);

    
}

/*
 * generate and send an update PDP context response message for the UE
 * in the config_UE_buffer
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * for the request
 */
static void updatePDPContextResponse(int UE, int mode)
{
	char teid_c[4], teid_d_ggsn[4];
    char new_ip_dot_decimal[4];
    unsigned int ip, jj;
	
    memcpy(teid_c, config_UE_buffer[UE].ip, 4); // ericker: reuse the ue ip as the teid - through config we have guaranteed this to be unique across instances

	teid_d_ggsn[0] = ~teid_c[3];
	teid_d_ggsn[1] = ~teid_c[2];
	teid_d_ggsn[2] = ~teid_c[1];
	teid_d_ggsn[3] = ~teid_c[0];
    printf("------------------------------------------\n");
    printf("gtpState =  updatePDPContextResponse \n teid_d_ggsn = ");
    printTEID(teid_d_ggsn);
    if((mode==2) &&  (config_create_GTPC_sequence)) { //new GGSN IP
		printf(" new gtp_GGSN_ip (GTP-U) = ");
		printGGSN_IP(gtp_new_GGSN_ip);
	}
	else{
		printf(" gtp_GGSN_ip (GTP-U) = ");
		printGGSN_IP(gtp_GGSN_ip);
	}
    
    printf("\n");
    if((mode==1) &&  (config_create_GTPC_sequence)) { //new TEID_C
        memcpy(&ip,  new_teid_c, 4);
    }
    else {
        memcpy(&ip,  config_UE_buffer[UE].ip, 4);
    }
   
    if(config_create_GTPC_sequence) {
        const char gtpState[]="updatePDPContextResponse\0";
        if(mode==1) { 
             printInfo(UE, gtpState, new_teid_c, teid_d_ggsn);
         }
         else {
             printInfo(UE, gtpState, teid_c, teid_d_ggsn);
         }
	}


    
    write_gtp_start(1, 19, htonl((int)ip), 0x32, config_UE_buffer[UE].seqNum << 16); //Update context response
    
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(0x10, 4, teid_d_ggsn);// TEID 1
    if((mode==1) &&  (config_create_GTPC_sequence)) { //new TEID_C
        write_gtp_IE(0x11, 4, new_teid_c);// TEID C
    }
	write_gtp_IE(0x7F, 4, teid_d_ggsn); // charging ID
	
	write_gtp_IE(0x85, 4, gtp_GGSN_ip);//GGSN signalling -> cant change this - see section 7.3.4 
	if((mode==2) &&  (config_create_GTPC_sequence)) { //new GGSN IP
		write_gtp_IE(0x85, 4, gtp_new_GGSN_ip);//GGSN user
    }
    else {
		write_gtp_IE(0x85, 4, gtp_GGSN_ip);//GGSN user
	}
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_end(GTP_DOWN);
    config_UE_buffer[UE].seqNum++;
}


/*
 * generate and send an update PDP context request message for the UE
 * in the config_UE_buffer
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * for the request
 */
static void updatePDPContextRequest_ggsn_initiated(int UE, int pdateMode)
{   
    unsigned int ip;
    char euid[6]={0xf1, 0x21};
    char teid_c[4];
    char teid_d_ggsn[4];
	
	
    memcpy(teid_c, config_UE_buffer[UE].ip, 4); // ericker: reuse the ue ip as the teid - through config we have guaranteed this to be unique across instances
    
    // Just for printing; not needed for Update Request
    teid_d_ggsn[0] = ~teid_c[3];
	teid_d_ggsn[1] = ~teid_c[2];
	teid_d_ggsn[2] = ~teid_c[1];
	teid_d_ggsn[3] = ~teid_c[0];
	
    memcpy(euid+2, config_UE_buffer[UE].ip, 4);
    memcpy(&ip,  config_UE_buffer[UE].ip, 4);
    
    euid[2] = 200; // change UEIP
    
    printf("----------------------------------------\n");   
    if(config_create_GTPC_sequence) {
        const char gtpState[]="updatePDPContextRequest_ggsn_initiated\0";
		printInfo(UE, gtpState, teid_c, teid_d_ggsn);
		printf(" UEIP = ");
		printUEIP(euid);
        
	}
    write_gtp_start(1, 18, htonl((int)ip), 0x32, config_UE_buffer[UE].seqNum << 16); //Update context request   
	write_gtp_IE(0x0E, 1, "\x51"); // recovery
    write_gtp_IE(0x14, 1, "\x05"); //NSAPI
    write_gtp_IE(0x80, 6, euid);//end user address
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x94, 1, "\x10"); // common flags
	write_gtp_end(GTP_DOWN);

    
}

/*
 * generate and send an update PDP context response message for the UE
 * in the config_UE_buffer
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * for the request
 */
static void updatePDPContexResponse_ggsn_initiated(int UE, int updateMode)
{
	char teid_c[4], teid_d_sgsn[4];
    char user_loc_info[8];
    unsigned int ip;
	
    memcpy(teid_c, config_UE_buffer[UE].ip, 4); // ericker: reuse the ue ip as the teid - through config we have guaranteed this to be unique across instances

	teid_d_sgsn[0] = ~teid_c[0];
	teid_d_sgsn[1] = ~teid_c[1];
	teid_d_sgsn[2] = ~teid_c[2];
	teid_d_sgsn[3] = ~teid_c[3];

    memcpy(&ip,  config_UE_buffer[UE].ip, 4);
    printf("----------------------------------------\n");
    if(config_create_GTPC_sequence) {
        const char gtpState[]="updatePDPContexResponse_ggsn_initiated\0";
		printInfo(UE, gtpState, teid_c, teid_d_sgsn);
        
	}

    
    write_gtp_start(1, 19, htonl((int)ip), 0x32, config_UE_buffer[UE].seqNum << 16); //Update context response
    
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(0x10, 4, teid_d_sgsn);// TEID 1
	write_gtp_IE(0x85, 4, gtp_SGSN_ip);//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	user_loc_info[0]= 0x00;
    user_loc_info[1] = config_RAI_list[config_UE_buffer[UE].rai][0];
    user_loc_info[2] = config_RAI_list[config_UE_buffer[UE].rai][1];
    user_loc_info[3] = config_RAI_list[config_UE_buffer[UE].rai][2];
    user_loc_info[4] = config_RAI_list[config_UE_buffer[UE].rai][3];
    user_loc_info[5] = config_RAI_list[config_UE_buffer[UE].rai][4];
    user_loc_info[6] = 0x00;
    user_loc_info[7] = config_RAI_list[config_UE_buffer[UE].rai][5];
    write_gtp_IE(0x98, 8, user_loc_info);// location information
	write_gtp_IE(0x99, 2, "\x23\x00"); // timezone
	write_gtp_end(GTP_UP);
    config_UE_buffer[UE].seqNum++;
}
/*
 * generate and send an delete PDP context request message for the UE
 * in the config_UE_buffer
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * for the request
 */
static void deletePDPContextRequest(int UE, int mode)
{
	unsigned int ip;
    if((mode==1) &&  (config_create_GTPC_sequence)){ //new TEID_C
        memcpy(new_teid_c, config_UE_buffer[UE].ip, 4); // ericker: reuse the ue ip as the teid - through config we have guaranteed this to be unique across instances
        memcpy(gtp_SGSN_ip, gtp_new_SGSN_ip, 4);
        
        new_teid_c[0] = new_teid_c[0] +1 ;
        memcpy(&ip,  new_teid_c, 4);
    }
    else {
        memcpy(&ip,  config_UE_buffer[UE].ip, 4);
    }
	write_gtp_start(1, 0x14, htonl((int)ip), 0x32, config_UE_buffer[UE].seqNum << 16);
	write_gtp_IE(0x13, 1, "\xFF"); //teardown ind
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_end(GTP_UP);
}

/*
 * generate and send an delete PDP context response message for the UE
 * in the config_UE_buffer
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * for the request
 */
static void deletePDPContextResponse(int UE, int mode)
{
	unsigned int ip;
	
    printf("------------------------------------------\n");
    if(config_create_GTPC_sequence) {
        // efitleo: TEID not needed for delete, but just want it for printInfo
        char teid_c[4], teid_d_ggsn[4];
        memcpy(teid_c, config_UE_buffer[UE].ip, 4); // ericker: reuse the ue ip as the teid - through config we have guaranteed this to be unique across instances

        teid_d_ggsn[0] = ~teid_c[3];
        teid_d_ggsn[1] = ~teid_c[2];
        teid_d_ggsn[2] = ~teid_c[1];
        teid_d_ggsn[3] = ~teid_c[0];
        

        const char gtpState[]="deletePDPContextResponse\0";
        if(mode==1) { 
             printInfo(UE, gtpState, new_teid_c, teid_d_ggsn);
         }
         else {
             printInfo(UE, gtpState, teid_c, teid_d_ggsn);
         }
    }
    
    if((mode==1) &&  (config_create_GTPC_sequence)){ //new TEID_C
        memcpy(&ip,  new_teid_c, 4);
    }
    else {
        memcpy(&ip,  config_UE_buffer[UE].ip, 4);
    }
   
	write_gtp_start(1, 0x15, htonl((int)ip), 0x32, config_UE_buffer[UE].seqNum << 16);
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_end(GTP_DOWN);
  config_UE_buffer[UE].seqNum++;
}

/*
 * generate and send a PDU message for the UE in the config_UE_buffer
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * for the request
 */
static unsigned long long milliseconds_running;

static void g_PDU(int UE, int mode)
{
	char buffer[GTP_FRAME_LEN + 100]; // just in case
	int length, down, delay;
	char teid_c[4], teid_d_ggsn[4], teid_d_sgsn[4];
    memcpy(teid_c, config_UE_buffer[UE].ip, 4);
    

    teid_d_ggsn[0] = ~teid_c[3];
    teid_d_ggsn[1] = ~teid_c[2];
    teid_d_ggsn[2] = ~teid_c[1];
    teid_d_ggsn[3] = ~teid_c[0];

    if((mode==2) &&  (config_create_GTPC_sequence)) { //new TEID_D
		teid_d_sgsn[0] = ~teid_c[0];
		teid_d_sgsn[1] = ~teid_c[1];
		teid_d_sgsn[2] = ~teid_c[2];
		teid_d_sgsn[3] = 0x11;

		memcpy(gtp_GGSN_ip, gtp_new_GGSN_ip, 4); // used in write_gtp_end
	}
	else{
		teid_d_sgsn[0] = ~teid_c[0];
		teid_d_sgsn[1] = ~teid_c[1];
		teid_d_sgsn[2] = ~teid_c[2];
		teid_d_sgsn[3] = ~teid_c[3];
	}
    if(!printOnce) {
		printf("------------------------------------------\n");
		printf("gtpState =  g_PDU \n teid_d_sgsn = ");
		printTEID(teid_d_sgsn);
		
		unsigned int teid_d_sgsn_int = MAKE_INT_2(teid_d_sgsn) & 0x0FFFFFFFF ;
		printf(" teid_d_sgsn (as integer)  = %u \n", teid_d_sgsn_int);
		
				
		printf(" teid_d_ggsn = ");
		printTEID(teid_d_ggsn);
		
		unsigned int teid_d_ggsn_int = MAKE_INT_2(teid_d_ggsn) & 0x0FFFFFFFF;
		printf(" teid_d_ggsn (as integer)  = %u \n", teid_d_ggsn_int);
		printf(" gtp_GGSN_ip (GTP-U) = ");
		printGGSN_IP(gtp_GGSN_ip);
        printf("------------------------------------------\n");
        printOnce=1;
        
    }
    if(mode==3) { // Change UEIP
		
		char euid[4];
		memcpy(euid, config_UE_buffer[UE].ip, 4);
		euid[0] = 200; // change UEIP ; This changes for GTP-U 
		length = traffic_get_packet(
					config_UE_buffer[UE].trafficFlow,
					config_UE_buffer[UE].trafficFlowPacket,
					euid,
					buffer, &down, &delay);
	}
	else {
		length = traffic_get_packet(
						config_UE_buffer[UE].trafficFlow,
						config_UE_buffer[UE].trafficFlowPacket,
						config_UE_buffer[UE].ip,
						buffer, &down, &delay);
	}
	


	if(!length)
	{
		config_UE_buffer[UE].trafficFlowPacket = 0;
		config_UE_buffer[UE].trafficFlow = 0;
		return;
	}
	
	config_UE_buffer[UE].trafficFlowPacket++;
	make_IP_checksum(buffer);
			
	if(down)
	{
		write_gtp_start(1, 0xFF, MAKE_INT_2(teid_d_sgsn) & 0x0FFFFFFFF, 0x10, 0x1234); 
        write_gtp_PDU(length, buffer);
		write_gtp_end(GTP_DOWN);
	}
	else
	{	
        write_gtp_start(1, 0xFF, MAKE_INT_2(teid_d_ggsn) & 0x0FFFFFFFF, 0x10, 0x1235); 
		write_gtp_PDU(length, buffer);
		write_gtp_end(GTP_UP);
	}
	
	config_UE_buffer[UE].next_packet_milliseconds 
			= milliseconds_running + delay;
}


/*
 * given a UE, move the state machine on to the next state and send
 * any packets generated by the state change.
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * whose state machine is to be updated
 */
static int defined_gtpc_sequence_next_UE_state(int UE, time_t timestamp, int state, int updateMode)
{
	int j;
    switch(state)
	{
        case 0 : // UE_STATE_IDLE: /* issue create PDP context request */
            config_UE_buffer[UE].rai = 0;
            createPDPContextRequest(UE);
            config_UE_buffer[UE].UE_state = UE_STATE_CONNECTING;
            EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,	config_UE_buffer[UE].rai, timestamp);
            config_UE_buffer[UE].firstTimeUsed = 1;
        break;

        case 1: //UE_STATE_CONNECTING: /* issue create PDP context response */
            if(config_UE_buffer[UE].firstTimeUsed == 0) {
                printf("CONNECTING-firstTimeUsed==0: ueip = %0x\n",config_UE_buffer[UE].ip);
            }
            createPDPContextResponse(UE);
            config_UE_buffer[UE].UE_state = UE_STATE_CONNECTED;
            EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,	config_UE_buffer[UE].rai, timestamp);
        break;

        case 2: // UE_STATE_CONNECTED: /* Send Packet packets */
            if(config_UE_buffer[UE].trafficFlowPacket)  // if you are already sending a flow, send the next packet from the flow
            {
                g_PDU(UE,updateMode);
            }
            else
            { /* start a new flow */
                config_UE_buffer[UE].trafficFlow = random()%traffic_get_stream_count();			
                g_PDU(UE,updateMode);
            }
        break;
        
        case 3: // UE_STATE_CONNECTED: /* issue update PDPContext Request  */
             /* cell handover */
            config_UE_buffer[UE].rai = 1;
            updatePDPContextRequest(UE, updateMode);
            config_UE_buffer[UE].UE_state = UE_STATE_UPDATING;
            EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,config_UE_buffer[UE].rai, timestamp);
            
        break;
        
        case 4: //  UE_STATE_UPDATING : /* updatePDPContextResponse */
             //new SGSN IP and TEID_C
            updatePDPContextResponse(UE, updateMode);
            config_UE_buffer[UE].UE_state = UE_STATE_CONNECTED;
            EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,	config_UE_buffer[UE].rai, timestamp);
        break;
        case 5: // UE_STATE_CONNECTED: /* issue delete PDP context request */
            
            /* disconnect session */
            deletePDPContextRequest(UE, updateMode);
            config_UE_buffer[UE].UE_state = UE_STATE_DISCONNECTING;
            EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,config_UE_buffer[UE].rai, timestamp);
        break;
        
        
        case 6: // UE_STATE_DISCONNECTING: /* issue delete PDP context response */
            deletePDPContextResponse(UE, updateMode);
            config_UE_buffer[UE].UE_state = UE_STATE_IDLE;
            config_UE_buffer[UE].timeLastUsed = timestamp; // this is seconds since epoch
            EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,config_UE_buffer[UE].rai, timestamp);
        break;
        
        
        case 7: // UE_STATE_CONNECTED: /* issue update PDPContext Request for GGSN INITIATED  */
             // New UEIP
            config_UE_buffer[UE].rai = 1;
            updatePDPContextRequest_ggsn_initiated(UE, updateMode);
            config_UE_buffer[UE].UE_state = UE_STATE_UPDATING;
            EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,config_UE_buffer[UE].rai, timestamp);
            
        break;
        
        case 8: //  UE_STATE_UPDATING : /* update PDPContext Response for GGSN INITIATED */
             // new UEIP
            updatePDPContexResponse_ggsn_initiated(UE, updateMode);
            config_UE_buffer[UE].UE_state = UE_STATE_CONNECTED;
            EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,	config_UE_buffer[UE].rai, timestamp);
        break;
        

        default:
            printf("UNKOWN UE STATE FOR DEFINED GTP-C SEQUENCE STATE");
            break;
	}
}
/*
 * given a UE, move the state machine on to the next state and send
 * any packets generated by the state change.
 * 
 * Parameters:-
 *   - UE: the index into the config_UE_buffer to the user equipment 
 * whose state machine is to be updated
 */
static int next_UE_state(int UE, time_t timestamp)
{
    time_t cur_time_then;
	switch(config_UE_buffer[UE].UE_state)
	{
	case UE_STATE_IDLE: /* issue create PDP context request */
		config_UE_buffer[UE].rai = random() % config_RAI_list_count;
		createPDPContextRequest(UE);
		config_UE_buffer[UE].UE_state = UE_STATE_CONNECTING;
		EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,
					config_UE_buffer[UE].rai, timestamp);
		config_UE_buffer[UE].firstTimeUsed = 1;
	break;

	case UE_STATE_CONNECTING: /* issue create PDP context response */
		if(config_UE_buffer[UE].firstTimeUsed == 0) {
			printf("CONNECTING-firstTimeUsed==0: ueip = %0x\n",config_UE_buffer[UE].ip);
		}
		createPDPContextResponse(UE);
		config_UE_buffer[UE].UE_state = UE_STATE_CONNECTED;
		EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,
					config_UE_buffer[UE].rai, timestamp);
	break;

	case UE_STATE_CONNECTED: /* issue delete PDP context request */
		if(config_UE_buffer[UE].firstTimeUsed == 0) {
			printf("UPDATE-firstTimeUsed==0: ueip = %0x\n",config_UE_buffer[UE].ip);
		}
		if(config_UE_buffer[UE].trafficFlowPacket)  // if you are already sending a flow, send the next packet from the flow
		{
			g_PDU(UE,0);
		}
		else if(ONE_IN(10))
		{ /* cell handover */
			config_UE_buffer[UE].rai = random() % config_RAI_list_count;
			updatePDPContextRequest(UE,0);
			config_UE_buffer[UE].UE_state = UE_STATE_UPDATING;
			EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,
						config_UE_buffer[UE].rai, timestamp);
		}
		else if(ONE_IN(10))
		{ /* disconnect session */
			deletePDPContextRequest(UE,0);
			config_UE_buffer[UE].UE_state = UE_STATE_DISCONNECTING;
			EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,
						config_UE_buffer[UE].rai, timestamp);
		}
		else
		{ /* start a new flow */
			config_UE_buffer[UE].trafficFlow = random()%traffic_get_stream_count();			
			g_PDU(UE,0);
		}
	break;
	
	case UE_STATE_UPDATING:
		if(config_UE_buffer[UE].firstTimeUsed == 0) {
			printf("UPDATING-firstTimeUsed==0: ueip = %0x\n",config_UE_buffer[UE].ip);
		}
		updatePDPContextResponse(UE,0);
		config_UE_buffer[UE].UE_state = UE_STATE_CONNECTED;
		EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,
					config_UE_buffer[UE].rai, timestamp);
	break;

	case UE_STATE_DISCONNECTING: /* issue delete PDP context response */
		if(config_UE_buffer[UE].firstTimeUsed == 0) {
			printf("DISCONNECTING-firstTimeUsed==0: ueip = %0x\n",config_UE_buffer[UE].ip);
		}
		deletePDPContextResponse(UE,0);
		config_UE_buffer[UE].UE_state = UE_STATE_IDLE;
        config_UE_buffer[UE].timeLastUsed = timestamp; // this is seconds since epoch
        num_ueip_in_timeout++;
        //printf("UE_STATE_DISCONNECTING : ueip = %0x : time last used = %llu (seconds)\n",config_UE_buffer[UE].ip, config_UE_buffer[UE].timeLastUsed);
        //printf("UE_STATE_DISCONNECTING; deletePDPContextRequest  %0x\n", config_UE_buffer[UE].ip);
		EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,
					config_UE_buffer[UE].rai, timestamp);
	break;

	default:
		if(config_UE_buffer[UE].firstTimeUsed == 0) {
			printf("DEFAULT-firstTimeUsed==0: ueip = %0x\n",config_UE_buffer[UE].ip);
		}
		config_UE_buffer[UE].UE_state = UE_STATE_IDLE;
		EVENTS_QUEUE_ADD(UE, config_UE_buffer[UE].UE_state,
					config_UE_buffer[UE].rai, timestamp);
		printf("DEFAULT UE STATE HANDLED");
		break;
	}
}

/*
 * This updates the GTP parameter variables with the values read
 * from the configuration files
 * 
 * Parameters: 
 *   (none)
 */

static void gtp_read_config(void)
{
	memcpy(gtp_GGSN_mac, config_GGSN_mac, 6);
	memcpy(gtp_SGSN_mac, config_SGSN_mac, 6);
	memcpy(gtp_GGSN_ip, config_GGSN_ip, 4);
	memcpy(gtp_SGSN_ip, config_SGSN_ip, 4);
	gtpc_GGSN_port = config_GGSNc_port;
	gtpc_SGSN_port = config_SGSNc_port;
	gtpu_GGSN_port = config_GGSNu_port;
	gtpu_SGSN_port = config_SGSNu_port;
    

    gtp_new_SGSN_ip[0] = gtp_SGSN_ip[0]+1;
    gtp_new_SGSN_ip[1] = gtp_SGSN_ip[1];
    gtp_new_SGSN_ip[2] = gtp_SGSN_ip[2];
    gtp_new_SGSN_ip[3] = gtp_SGSN_ip[3];
    
    gtp_new_GGSN_ip[0] = gtp_GGSN_ip[0]+1;
    gtp_new_GGSN_ip[1] = gtp_GGSN_ip[1];
    gtp_new_GGSN_ip[2] = gtp_GGSN_ip[2];
    gtp_new_GGSN_ip[3] = gtp_GGSN_ip[3];
    
        
}

void check_OK_To_send_packet(unsigned long long *mS_running, unsigned long long next_pkt_mS,  struct timeval *startTime){
    // Wait to play out the packets in real time 
    struct timeval now;
    while(*mS_running  < next_pkt_mS)
    {
        usleep(1*1000);  
        gettimeofday(&now, NULL); 
        *mS_running = ((now.tv_sec - startTime->tv_sec) * 1000 + ((now.tv_usec - startTime->tv_usec) / 1000)); 
    }
}

/*
 * Do a GTP-C delete Request / Response. 
 * 
 * Parameters:
 *   - mS_running: integer for passing back the time taken for the sequence to run
 */
void defined_GTPC_sequence_delete(unsigned long long* mS_running, int updateMode) {
    
    struct timeval now, then;
    int UE_NUM=0; 
    unsigned long long milliseconds_running;
    milliseconds_running = *mS_running; //lazy 
    gettimeofday(&then, NULL);
    
    defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 5, updateMode);
    defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 6, updateMode);
            
    // even though this is a delete, I want to contine to send packets, to show no merge in in PCP filewriter
    // PCP will not process flow unless bytes are bing processed.
    do {
        gettimeofday(&now, NULL);
        milliseconds_running = ((now.tv_sec - then.tv_sec) * 1000 + ((now.tv_usec - then.tv_usec) / 1000)); 
        check_OK_To_send_packet(&milliseconds_running, config_UE_buffer[UE_NUM].next_packet_milliseconds,&then);
        
        if(!config_max_rate || config_max_rate * milliseconds_running > gtp_write_bytes * 8)
        {   
            //printf("milliseconds_running Before =%llu , next_packet_milliseconds = %llu \n",milliseconds_running, config_UE_buffer[UE_NUM].next_packet_milliseconds);    
            //printf("config_max_rate = %ld , TARGET bits   = %llu , ACTUAL bits written = %llu \n",config_max_rate, (config_max_rate * milliseconds_running), gtp_write_bytes );    
            defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 2, updateMode);
        }
            
    }while (!config_lifetime || milliseconds_running < config_lifetime);
    
    //+1 so that milliseconds_running is not zero for final print statemenmt
    *mS_running = milliseconds_running +1; 
}

/*
 * Do a GTP-C Update Request / Response and send some GTP-U packets. 
 * 
 * Parameters:
 *   - mS_running: integer for passing back the time taken for the sequence to run
 */
void defined_GTPC_sequence_update(unsigned long long* mS_running, int updateMode) {
    
    struct timeval now, then;
    int UE_NUM=0; 
    unsigned long long milliseconds_running;
    milliseconds_running = *mS_running; //lazy 
    gettimeofday(&then, NULL);
    
    defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 3, updateMode);
    defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 4, updateMode);
            
    do {
        gettimeofday(&now, NULL);
        milliseconds_running = ((now.tv_sec - then.tv_sec) * 1000 + ((now.tv_usec - then.tv_usec) / 1000)); 
        check_OK_To_send_packet(&milliseconds_running, config_UE_buffer[UE_NUM].next_packet_milliseconds,&then);
        
        if(!config_max_rate || config_max_rate * milliseconds_running > gtp_write_bytes * 8)
        {   
            //printf("milliseconds_running Before =%llu , next_packet_milliseconds = %llu \n",milliseconds_running, config_UE_buffer[UE_NUM].next_packet_milliseconds);    
            //printf("config_max_rate = %ld , TARGET bits   = %llu , ACTUAL bits written = %llu \n",config_max_rate, (config_max_rate * milliseconds_running), gtp_write_bytes );    
            defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 2, updateMode);
        }
            
    }while (!config_lifetime || milliseconds_running < config_lifetime);
    
    //+1 so that milliseconds_running is not zero for final print statemenmt
    *mS_running = milliseconds_running +1; 
}

/*
 * Do a GTP-C GGSN INITIATED Update Request / Response and send some GTP-U packets. 
 * 
 * Parameters:
 *   - mS_running: integer for passing back the time taken for the sequence to run
 */
void defined_GTPC_sequence_ggsn_initiated_update(unsigned long long* mS_running, int updateMode ) {
    
    struct timeval now, then;
    int UE_NUM=0; 
    unsigned long long milliseconds_running;
    milliseconds_running = *mS_running; //lazy 
    gettimeofday(&then, NULL);
    
    defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 7, updateMode);
    defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 8, updateMode);
            
    do {
        gettimeofday(&now, NULL);
        milliseconds_running = ((now.tv_sec - then.tv_sec) * 1000 + ((now.tv_usec - then.tv_usec) / 1000)); 
        check_OK_To_send_packet(&milliseconds_running, config_UE_buffer[UE_NUM].next_packet_milliseconds,&then);
        
        if(!config_max_rate || config_max_rate * milliseconds_running > gtp_write_bytes * 8)
        {   
            //printf("milliseconds_running Before =%llu , next_packet_milliseconds = %llu \n",milliseconds_running, config_UE_buffer[UE_NUM].next_packet_milliseconds);    
            //printf("config_max_rate = %ld , TARGET bits   = %llu , ACTUAL bits written = %llu \n",config_max_rate, (config_max_rate * milliseconds_running), gtp_write_bytes );    
            defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 2, updateMode);
        }
            
    }while (!config_lifetime || milliseconds_running < config_lifetime);
    
    //+1 so that milliseconds_running is not zero for final print statemenmt
    *mS_running = milliseconds_running +1; 
}

/*
 * Do a GTP-C Create Request / Response and send some GTP-U packets. 
 * 
 * Parameters:
 *   - mS_running: integer for passing back the time taken for the sequence to run
 */
void defined_GTPC_sequence_create(unsigned long long* mS_running) {
    
    struct timeval now, then;
    int UE_NUM=0; 
    unsigned long long milliseconds_running;
    milliseconds_running = *mS_running; //lazy 
    gettimeofday(&then, NULL);
    
    defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 0,0);
    defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 1,0);
    
            
    do {
        gettimeofday(&now, NULL);
        milliseconds_running = ((now.tv_sec - then.tv_sec) * 1000 + ((now.tv_usec - then.tv_usec) / 1000)); 
        check_OK_To_send_packet(&milliseconds_running, config_UE_buffer[UE_NUM].next_packet_milliseconds,&then);
        
        if(!config_max_rate || config_max_rate * milliseconds_running > gtp_write_bytes * 8)
        {   
            //printf("milliseconds_running Before =%llu , next_packet_milliseconds = %llu \n",milliseconds_running, config_UE_buffer[UE_NUM].next_packet_milliseconds);    
            //printf("config_max_rate = %ld , TARGET bits   = %llu , ACTUAL bits written = %llu \n",config_max_rate, (config_max_rate * milliseconds_running), gtp_write_bytes );    
            defined_gtpc_sequence_next_UE_state(UE_NUM, now.tv_sec, 2,0);
        }
            
    }while (!config_lifetime || milliseconds_running < config_lifetime);
    
    //+1 so that milliseconds_running is not zero for final print statemenmt
    *mS_running = milliseconds_running +1; 
}
/*
 * Read the configuration, open the output and start sending the 
 * simulated packets
 * 
 * Parameters:
 *   - arg_count: count of the command line arguments
 *   - args: array of command line arguments as strings
 */
 
int main(int arg_count, char *args[])
{
	struct timeval now, then, cur_time_now;
	int UE_count;
	int print_interval=5;
    unsigned long long reference;
    unsigned long long total_interval;
    int imsi_count_printed=1;
    unsigned long long ueip_timeout = 120;  // seconds; dont re-use UEIP with in this time to allow IPOQUE time out the UEIP.
    unsigned long long ueip_seconds;
    
    num_ueip_in_timeout =0; 
    printf("\n\nGn Simulator, Version 1.0.5\n\n");

// It is the config_read that knows all about how to read the
// command line arguments.  The information is written into global
// variables declared in config.h	
	if(config_read(arg_count, args))
	{
		return(1);
	}

	/*efitleo */
	/* read a pcap and play it back */
	if(config_replay_pcap)
	{
		if(replay_pcap())
		{
			return(0);			
		}
	}
	else{ //Do normal simulator stuff
        printf("UEIP Timeout = %llu seconds\n", ueip_timeout );
		UE_count =  config_UE_buffer_count;
	
		if(UE_count <= 0)
		{ // esirich: I saw this needed fixing :-)
			fprintf(stderr, "No user equipments defined in config file\n");
			return(2);
		}
		fprintf(stdout, "Number of UE's = %ld \n",UE_count);
		gtp_read_config();

// esirich: add separate control output		
		if(config_write_filename_control)
		{
			write_pcap_start_control(config_write_filename_control);
		}
		else if(config_write_interface_control)
		{
			write_pcap_start_interface_control(config_write_interface_control);
		}
		
		
			
		if(config_write_filename)
		{
			write_pcap_start(config_write_filename);
			if(config_write_upstream)
			{
				write_pcap_start_upstream(config_write_upstream);
			}
		}
		else if(config_write_interface)
		{
			write_pcap_start_interface(config_write_interface);
			if(config_write_upstream)
			{
				write_pcap_start_interface_upstream(config_write_upstream);
			}
		}

		if(!traffic_get_stream_count())
		{
			fprintf(stderr, "Cannot read any traffic files\n");
			return(2);
		}

		config_lifetime *= 1000;
		gettimeofday(&then, NULL);
		events_queue_start_thread();

		//efileo: print num us used
		if(config_imsi_count_interval)
		{
			print_interval=config_imsi_count_interval;
		
		}
		reference = milliseconds_running; 
		imsi_count_printed=1;
        

        if(config_create_GTPC_sequence) {
                // efitleo: replay out the packtes once only in Normal GTP Sequence sequence
                int UE_NUM=0, i;   
                config_UE_buffer[UE_NUM].UE_state = UE_STATE_IDLE;
                
                switch (config_create_GTPC_sequence)

                {
                case 0 :
                    printf("Unknown GTP-C config input ; -GTPC = % d (can not be zero)\n", config_create_GTPC_sequence);
                break;
                
                case 1 :
                    config_UE_buffer[UE_NUM].seqNum = 1000000001;
                    defined_GTPC_sequence_create(&milliseconds_running);
                break;
                
                case 2 : // Location Update
                    config_UE_buffer[UE_NUM].seqNum = 1000000002;
                    defined_GTPC_sequence_update(&milliseconds_running, 0);
                break;
                
                case 3 : 
                    config_UE_buffer[UE_NUM].seqNum = 1000000003;
                    defined_GTPC_sequence_delete(&milliseconds_running, 0);
                break;
                
                case 4 : // SGSN IP CHanged & TEID_C
                    config_UE_buffer[UE_NUM].seqNum = 1000000002;
                    defined_GTPC_sequence_update(&milliseconds_running, 1);
                break;
                                
                case 5 : 
                    config_UE_buffer[UE_NUM].seqNum = 1000000003;
                    defined_GTPC_sequence_delete(&milliseconds_running, 1);
                break;
                
                case 6 : // TEID_D & GGSN User IP
                    config_UE_buffer[UE_NUM].seqNum = 1000000002;
                    defined_GTPC_sequence_update(&milliseconds_running, 2);
                break;

                case 7 : // TEID_D & GGSN User IP
                    config_UE_buffer[UE_NUM].seqNum = 1000000003;
                    defined_GTPC_sequence_delete(&milliseconds_running, 2);
                break;

                case 8 : // GGSN INITIATED UPDATE
                    config_UE_buffer[UE_NUM].seqNum = 1000000002;
                    defined_GTPC_sequence_ggsn_initiated_update(&milliseconds_running, 3);
                break;
                
                case 9 : // GGSN INITIATED UPDATE has new UEIP; Just get need g_PDU to have new UEIP for pcap
                    config_UE_buffer[UE_NUM].seqNum = 1000000003;
                    defined_GTPC_sequence_delete(&milliseconds_running, 3);
                break;
                                
                default :
                    printf("Unknown GTP-C config input ; -GTPC = % d \n", config_create_GTPC_sequence); 
                break;
                }
                
                
        }
        else {
            do
            {
                int next_UE, i, last_milliseconds_running, loop_rate = 1000;
                
                for(i=0; i<loop_rate; i++)
                {
                    // efitleo: Check if UE has ben used in the last ueip_timeout seconds...
                    // TODO: set the ueip_timeout seconds to be a config parameter
                    //next_UE = random() % UE_count;
               
                    int valid_ueip = 0;
                    do{
                        next_UE = random() % UE_count;
                        if((config_UE_buffer[next_UE].UE_state == UE_STATE_IDLE) && (config_UE_buffer[next_UE].timeLastUsed !=0)) {
                            gettimeofday(&cur_time_now, NULL);
                            ueip_seconds = cur_time_now.tv_sec - config_UE_buffer[next_UE].timeLastUsed;
                            //printf("next ueip = %0x : time last used = %llu (seconds): current time = %llu (seconds): Difference = %llu (seconds)\n",config_UE_buffer[next_UE].ip, config_UE_buffer[next_UE].timeLastUsed, cur_time_now.tv_sec, ueip_seconds);
                            if(ueip_seconds > ueip_timeout) {
                                valid_ueip = 1;
                                config_UE_buffer[next_UE].timeLastUsed = 0;
                                num_ueip_in_timeout--;
                            }
                        }
                        else {
                            valid_ueip = 1;
                        }
                    }while (!valid_ueip);
    // esirich: check if next packet is ready to send			
                    if(config_UE_buffer[next_UE].next_packet_milliseconds
                            < milliseconds_running)
                    {
                        if(!config_max_rate || config_max_rate * milliseconds_running > gtp_write_bytes * 8)
                        {
                            next_UE_state(next_UE, now.tv_sec);
                            config_UE_buffer[next_UE].touch = now.tv_sec;
                        }
                    }
                }
                
                gettimeofday(&now, NULL);
                milliseconds_running = (now.tv_sec - then.tv_sec) * 1000
                                     + (now.tv_usec - then.tv_usec) / 1000;
                                     

    // esirich: replay pcaps in real time								 
    /* try to tweak the loop rate to run one loop per millisecond */
                last_milliseconds_running = milliseconds_running 
                                            - last_milliseconds_running;
                if(last_milliseconds_running > 1)
                { /* more than one -> divide by number of milliseconds */
                    loop_rate /= last_milliseconds_running;
                }
                else if(0 == last_milliseconds_running)
                { /* zero -> double it and add 1000 */
                    loop_rate += loop_rate + 1000;
                }

                //printf("Processed %d IMSI's\n", num_UE_used);
                last_milliseconds_running = milliseconds_running;
                if(config_imsi_count_interval)
                {
                    // efitleo: print number of IMSI's used in a certain interval
                    if( milliseconds_running > (reference + (print_interval*1000)))
                    {
                        int i, count = 0;
                        double percent_used;
                        time_t oldest = now.tv_sec;
                        
                        for(i = 0; i < UE_count; i++)
                        {
                            if(config_UE_buffer[i].UE_state != UE_STATE_IDLE)
                            {
                                oldest = config_UE_buffer[i].touch < oldest ? config_UE_buffer[i].touch : oldest;
                                count++;
                            }
                        }
                        percent_used = (((double)count/(double)UE_count)*100);
                        // print first time or if not fully used
                        if ((percent_used < (double) 100 ) || imsi_count_printed)
                        {
                            total_interval = (milliseconds_running + (milliseconds_running - reference))/1000;
                            printf("Processed %d IMSI's out of a possible max of %d [%.2f \%] in %llu seconds(%llu s) \n", count, UE_count, (((double)count/(double)UE_count)*100),print_interval, total_interval);
                            printf("%d UE IP's out of a max of %d UE IP's in timeout at this [snapshot of] time\n", num_ueip_in_timeout,UE_count);
                            printf("Oldest untouched, active session: %d (%d seconds old)\n", oldest, now.tv_sec - oldest);
                            reference=milliseconds_running;
                            imsi_count_printed=0; // only print first time if at 100 %
                        }
                        
                        
                    }
                }
            }
            while(!config_lifetime || milliseconds_running < config_lifetime);
        }

		write_pcap_end();
		
		events_queue_stop_thread();
				
		printf("Wrote %llu packets, %llu bytes in %d seconds (%llu mS) (%llu kbit/sec) with %llu re-sends\n", 
					gtp_write_packets, 
					gtp_write_bytes, 
					(int) (milliseconds_running / 1000), milliseconds_running,
					(unsigned long)(8*gtp_write_bytes/milliseconds_running),
					gtp_write_misses);

		return(0);
	}
}
