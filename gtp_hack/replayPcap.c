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
* File: replayPcap.c
* Date: Nov 23, 2012
* Author: LMI/LXR/PE Leo Fitzpatrick
************************************************************************/
/***********************************************************************
 * Reads a pcap file from the command line, determines up or downstream 
 * by referenceing a user supplied GGSN address and plays it out through 
 * the upstream and down stream interfaces
************************************************************************/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include  <sys/types.h>                        
#include  <sys/socket.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>



#include "traffic.h"
#include "gtp_hack.h"
#include "config.h"

static void replay_buffer_packets(void);
static void replay_save_buffer(u_char *user, 
						const struct pcap_pkthdr *h, const u_char *bytes);
size_t replay_get_stream_count(void);
static int replay_send_packet();
static void replay_write_pcap(char *payload, int length, int upstream);
void replay_pcap_start_interface(char *interface);
void replay_pcap_start_interface_upstream(char *interface);
static void replay_print_ueip_list();


/*
 * Wait for keyboard input 
 * Function found on internet
 * 
*/ 
int kbhit(void)
{
    struct timeval tv;
    fd_set read_fd;

    tv.tv_sec=0;
    tv.tv_usec=0;
    FD_ZERO(&read_fd);
    FD_SET(0,&read_fd);

    if(select(1, &read_fd, NULL, NULL, &tv) == -1)
    return 0;

    if(FD_ISSET(0,&read_fd))
    return 1;

return 0;
}



/*
 * Waits for keyboard to be pressed or for file done.txt to appear in current directory
 * 
 * 
*/ 


void wait_for_signal(char *doneFileName) {
    
    //printf("\nWaiting for %s or Press ENTER to continue\n\n",done_fname);
    printf("WAIT FOR SIGNAL = %s\n\n",doneFileName);
   
    do{
        //int acc = access(doneFileName, F_OK );
        //printf("acc = %d , %s \n",acc, doneFileName);
        sleep(1);
	} while(access(doneFileName, F_OK ) == -1 );
 	
    printf("Writing out PCAP\n");
 
    if(access( doneFileName, F_OK ) == 0) {
        int status = remove(doneFileName);
 
        if( status == 0 )
          printf("%s deleted successfully.\n",doneFileName);
        else
        {
           printf("Unable to delete control file:  %s\n",doneFileName);
           perror("Error");
        }
    }
}

/*
 * Creates file done.txt in the current directory as a signal to next simulator to write
 * 
 * 
*/ 
void send_signal(char *doneFileName){
    
     char cmd[500] = "touch \0";
     
     strncat(cmd, (char* )doneFileName, strlen(doneFileName));
     
     printf("SEND SIGNAL = %s \n", cmd);
     int status = system(cmd);
     if( status == 0 )
       printf("%s created successfully.\n",doneFileName);
     else
     {
       printf("Unable to create control file:  %s\n",doneFileName);
       perror("Error");
     }
     //system("touch ready.txt");
     
}

/*
 * traffic points to arrays of character strings, each one containing
 * a packet.  There is an array of packets for every pcap file read.
 * 
 * The number of files read is stored in traffic_file_count
 */
static char ***pcap_traffic;
static int replay_file_count;
static pcap_t *pd, *pd_up;
// total number of bytes/packets sent
unsigned long long pcap_write_packets, pcap_write_bytes;
unsigned long long pcap_read_packets, pcap_read_bytes, pcap_not_read_packets;

static char errbuf[PCAP_ERRBUF_SIZE];
static u_int32_t **ueip_list;
static int ueip_count;
static int MAX_NUMBER_UEIPs = 300000;
static int PROGRESS_REPORT_UEIPs =1000;
static unsigned long ds_ggsn;
static unsigned long us_ggsn;
    
int replay_pcap()
{
	time_t now, then;
	unsigned long long total_pcap_write_packets, total_pcap_write_bytes;
	int print_interval=5, interval;
	double reference;
	char c;
	
	// Read the PCap File
	if(!replay_get_stream_count())
	{
		fprintf(stderr, "Cannot read any pcap files\n");
		// Not freeing memory as we intend to exit now; no Shared memory
		return(2);
	}
	fprintf(stderr, "Read %llu packets, %llu bytes, %llu packets not read [ggsn not listed] \n",pcap_read_packets, pcap_read_bytes, pcap_not_read_packets);
	
    // Open Interface for  writing output to.
	if(config_write_interface)
	{
		replay_pcap_start_interface(config_write_interface);
		if(config_write_upstream)
		{
			replay_pcap_start_interface_upstream(config_write_upstream);
		}
	}
	else {
		fprintf(stderr, "No Interface set up to output data on\n");
		// Not freeing memory as we intend to exit now; no Shared memory
		return(2);
	}
    

    char done_fname[500]="\0";
    //printf("config_use_wait_signal = %d\n", config_use_wait_signal);
    
    if((config_traffic_file_count==1) && (config_use_wait_signal))
    {
        strcpy(done_fname, config_traffic_files[0].filename);
        strcat(done_fname, "_done.txt");
        printf("WAIT FOR SIGNAL = %s \n",done_fname);
        wait_for_signal(done_fname);
    }
    else 
    {
       if(config_use_wait_signal) printf("Can't implement WAIT FOR SIGNAL on multiple pcaps\n");
    }
 
	time(&then);
	time(&now);
	total_pcap_write_packets=0;
	total_pcap_write_bytes=0;
	reference = now; 
    int loopctr;
    loopctr =0;
	while(!config_lifetime || difftime(now, then) < config_lifetime)
	{
        //printf("Loop count = %d\n",loopctr++);
		// Write the packets to the interface
		if(replay_send_packet())
		{
			fprintf(stderr, "Cannot write pcap file to output\n");
			fprintf(stderr, "LAST FILE: Wrote %llu packets, %llu bytes \n",pcap_write_packets, pcap_write_bytes);
			fprintf(stderr, "TOTAL    :Wrote %llu packets, %llu bytes in %d seconds (%llu kbit/sec) \n",
					total_pcap_write_packets, total_pcap_write_bytes,(int) difftime(now, then),
					(unsigned long)(total_pcap_write_bytes/(difftime(now, then)*125)));
			// Not freeing memory as we intend to exit now;  no Shared memory
			return(2);
		}
		if(config_lifetime) time(&now);
		total_pcap_write_packets += pcap_write_packets;
		total_pcap_write_bytes +=pcap_write_bytes;
	
		if( now  > (reference + print_interval))
		{
			fprintf(stderr, "Wrote %llu packets, %llu bytes in %d seconds (%llu kbit/sec) \n",
					total_pcap_write_packets, total_pcap_write_bytes,(int) difftime(now, then),
					(unsigned long)(total_pcap_write_bytes/(difftime(now, then)*125)));
			reference = now;
		}
        if(config_lifetime == 1) break;
    }
    fprintf(stderr, "Wrote %llu packets, %llu bytes in %d seconds (%llu kbit/sec) \n",
					total_pcap_write_packets, total_pcap_write_bytes,(int) difftime(now, then),
					(unsigned long)(total_pcap_write_bytes/(difftime(now, then)*125)));
    printf("config_use_wait_signal = %d\n", config_use_wait_signal);
    if((config_traffic_file_count==1) && (config_use_wait_signal))
    {
        printf("SEND SIGNAL = %s \n",done_fname);
        send_signal(done_fname);
    }
    else 
    {
         if(config_use_wait_signal) printf("Can't implement SEND SIGNAL on multiple pcaps\n");
    }
    return 0;
	
}

/*
 * Return the number of streams that are available in the traffic buffer
 *
 * Parameters:-
 *    (none)
 */
size_t replay_get_stream_count(void)
{
	if(!replay_file_count || !pcap_traffic)
	{
		replay_buffer_packets();
	}

	return(replay_file_count);
}



/*
 * this reads the packets in the files into the traffic buffer
 * 
 * Parameters:-
 *    (none)
 *  
 * variables:-
 *   - replay_this_file: index to the file in the traffic buffer
 *   - replay_this_packet: index to the packet in the traffic buffer
 *
 */
static int replay_this_file;
static int replay_this_packet;

static void replay_buffer_packets(void)
{
	int i, count = 0;

	if(replay_file_count && pcap_traffic) return;
	
	pcap_read_packets=0; 
	pcap_read_bytes=0;
	pcap_not_read_packets=0;
    ueip_count = 0;
    if(config_replay_count_ueip) {
        PROGRESS_REPORT_UEIPs = config_replay_count_ueip;
    }
    
    us_ggsn=0;
    ds_ggsn=0;
	for(i = 0; i < config_traffic_file_count; i++)
	{
		pcap_t *pd;
		
		if(!i)
		{
			pcap_traffic = (char ***) malloc(sizeof(char **));
		}
		else
		{
			pcap_traffic = (char ***) realloc(pcap_traffic, i * sizeof(char **));
		}

		pd = pcap_open_offline(config_traffic_files[i].filename, errbuf);
		
		if(!pd)
		{
			fprintf(stderr, "%s failed to buffer: %s\n", 
					config_traffic_files[i].filename,
					errbuf);

			pcap_close(pd);
			break;
		}
		
		replay_this_file = count;
		replay_this_packet = 0;
		
		switch(pcap_loop(pd, -1, replay_save_buffer, NULL))
		{
		default:
			fprintf(stderr, "problem buffering %s: %s\n",
					config_traffic_files[i].filename,
					pcap_geterr(pd)
					);
		case 0: break;
		}
		
		if(replay_this_packet)
		{
			count++;
		}
		else
		{
			fprintf(stderr, "no packets read from %s:"
					" is the source IP address correct?\n",
					config_traffic_files[i].filename);
		}
		
		pcap_close(pd);
	}
	
	replay_file_count = count;
    replay_print_ueip_list();
    printf("FOUND %u Upstream and %u downstream GGSN Addressed\n",us_ggsn,ds_ggsn);
    
}


/*
 * This is called by the pcap_loop function with each packet found
 * in the pcap file.  It saves each packet in memory ready to be read
 * by the simulator.
 * 
 * Parameters:-
 *   - user: not used
 *   - h: packet header information
 *   - bytes: packet payload  
 */


#define VLAN_OFFSET     (12)
#define ETHERNET_LENGTH (14)
#define VLAN_LENGTH      (4)
#define IP_SRC_LOCATION (12)
#define IP_DST_LOCATION (16)
#define GTP_FLAG_OFFSET (29) 
#define GTP_SRC_LOCATION30 (19)
#define GTP_DST_LOCATION30 (23)
#define GTP_SRC_LOCATION32 (23)
#define GTP_DST_LOCATION32 (27)


#define IS_VLAN_HEADER(buf)	((buf)[0]==0x81 && (buf)[1]==0x00)
static struct timeval pcap_packet_last_timestamp;

/*
 * Searchs list for UEIP
 * returns 0 if not found, returns 1 if found
 */
static int replay_search_for_ueip(u_int32_t ueip_to_search_for){
    
    int i;
    for(i =0; i< ueip_count; i++){
        if (ueip_to_search_for == *ueip_list[i] ){
            return 1;
        }
    }
    return 0;
    
} 

/*
 * prints list of UEIP's
 */
static void replay_print_ueip_list(){
    
    if(config_replay_count_ueip) {
        int i;
        struct in_addr ueipAddr;
        char *ueipStr;
        FILE *fp;
        char ueip_filename[strlen(config_replay_pcap) + 10];
        strcpy(ueip_filename, config_replay_pcap);
        strcat(ueip_filename, "_ueip.txt");
        fp=fopen(ueip_filename, "w");
        printf("UEIP printed to file : %s\n",ueip_filename);


        for(i =0; i< ueip_count; i++){
           ueipAddr.s_addr = htonl(*ueip_list[i]);
           ueipStr = inet_ntoa(ueipAddr);
           fprintf(fp, "UEIP = %0x [%s]; \n",*ueip_list[i], ueipStr);
        }
        fprintf(fp, "Number of UEIP's in file %s = %d; \n",config_replay_pcap, ueip_count);
        printf("Number of UEIP's in file %s = %d; \n",config_replay_pcap, ueip_count);
        
        if(ueip_count >= MAX_NUMBER_UEIPs) {
            fprintf(fp, "MAX NUMBER OF UEIP ALLOWED IN INTERNAL BUFFER REACHED [%d / %d]; \n",ueip_count,MAX_NUMBER_UEIPs);
            printf("MAX NUMBER OF UEIP ALLOWED IN INTERNAL BUFFER REACHED [%d / %d]; \n",ueip_count,MAX_NUMBER_UEIPs);
            }
        fclose(fp);
    }
    
} 
static void replay_save_buffer(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	int packet_size,IP_src_offset, IP_dst_offset,i,j,downstream=-1,gtp_dst_offset, gtp_src_offset, gtp_flag_offset,mac_src_offset, mac_dst_offset;
	
	char *local_src;
    int microseconds;
    u_int32_t ueip;
    u_char gtp_flag32[1]= {0x32};
    char *ueipStr;
    u_char ueip_char[4]; 
    u_char mac_src_char[6];  
    u_char mac_dst_char[6];  
    static int print_once;

    

    mac_src_offset = 6;
    mac_dst_offset = 0;
	//memcpy(mac_src_char, bytes + mac_src_offset, 6);
    //memcpy(mac_dst_char, bytes + mac_dst_offset, 6);
    //printf("MAC Source Addr = %0x:%0x:%0x:%0x:%0x:%0x \n", mac_src_char[0], mac_src_char[1], mac_src_char[2], mac_src_char[3], mac_src_char[4], mac_src_char[5] );
    //printf("MAC Destination Addr = %0x:%0x:%0x:%0x:%0x:%0x \n", mac_dst_char[0], mac_dst_char[1], mac_dst_char[2], mac_dst_char[3], mac_dst_char[4], mac_dst_char[5]);
  
    
//  packet size is packet length; need full frame	
	packet_size = h->caplen;
//  check Ethernet frame type and go into the VLAN frame if present
    if(IS_VLAN_HEADER(bytes + VLAN_OFFSET))
	{
		IP_src_offset = ETHERNET_LENGTH + VLAN_LENGTH + IP_SRC_LOCATION; // = 30;
		IP_dst_offset = ETHERNET_LENGTH + VLAN_LENGTH + IP_DST_LOCATION; // = 34;
        gtp_flag_offset = ETHERNET_LENGTH + VLAN_LENGTH + GTP_FLAG_OFFSET; // 47
        
	
	}
	else //VLAN Not present
	{
		IP_src_offset = ETHERNET_LENGTH + IP_SRC_LOCATION; // = 26;
		IP_dst_offset = ETHERNET_LENGTH + IP_DST_LOCATION; // = 30;
        gtp_flag_offset = ETHERNET_LENGTH + GTP_FLAG_OFFSET; // 43

	}
   
   if(!memcmp(bytes + gtp_flag_offset -1, gtp_flag32,1)){   // bytes start at 0, gtp_flag_offset has first byte as 1
        gtp_src_offset = gtp_flag_offset + GTP_SRC_LOCATION32; //70
        gtp_dst_offset = gtp_flag_offset + GTP_DST_LOCATION32; //74
        
   }
   else{ // gtp flag is 30
       gtp_src_offset = gtp_flag_offset + GTP_SRC_LOCATION30; //66
       gtp_dst_offset = gtp_flag_offset + GTP_DST_LOCATION30; //70
   }

   for(i=0; i<max_num_ggsn;i++) {
        
        if(config_replay_mac_addr) {
            if(!memcmp(bytes + mac_src_offset, config_pcap_ggsns[i],6)) {     //mac addr so 6 bytes stored in config_pcap_ggsns
                    // its downstream
                    //printf("MACTHING DOWNSTREAM MAC GGSN Addr = %0x:%0x:%0x:%0x:%0x:%0x \n", config_pcap_ggsns[i][0], config_pcap_ggsns[i][1], config_pcap_ggsns[i][2], config_pcap_ggsns[i][3], config_pcap_ggsns[i][4], config_pcap_ggsns[i][5] );
                    downstream=0;
                    ds_ggsn++;            
                    if(config_replay_count_ueip) memcpy(ueip_char,bytes + gtp_dst_offset, 4);
                    break;
            }
            if(!memcmp(bytes + mac_dst_offset, config_pcap_ggsns[i],6)) {     //mac addr so 6 bytes stored in config_pcap_ggsns
                    // its upstream
                    //printf("MACTHING UPSTREAM MAC GGSN Addr = %0x:%0x:%0x:%0x:%0x:%0x \n", config_pcap_ggsns[i][0], config_pcap_ggsns[i][1], config_pcap_ggsns[i][2], config_pcap_ggsns[i][3], config_pcap_ggsns[i][4], config_pcap_ggsns[i][5] );
                    us_ggsn++;
                    downstream=1;
                    if(config_replay_count_ueip) memcpy(ueip_char,bytes + gtp_src_offset, 4);
                    break;
            }

        }
        else { 
       
            if(!memcmp(bytes + IP_src_offset, config_pcap_ggsns[i],4)) {     //ipv4 so 4 bytes stored in config_pcap_ggsns
                    // its downstream
                    downstream=0;
                    ds_ggsn++;
                    if(config_replay_count_ueip) memcpy(ueip_char,bytes + gtp_dst_offset, 4);
                    break;
            }
            if(!memcmp(bytes + IP_dst_offset, config_pcap_ggsns[i],4)) {     //ipv4 so 4 bytes stored in config_pcap_ggsns
                    // its upstream
                    downstream=1;
                    us_ggsn++;
                    if(config_replay_count_ueip) memcpy(ueip_char,bytes + gtp_src_offset, 4);
                    break;
            }
        }
	}
    if(config_replay_count_ueip) {
        //printf("UEIP = %0x %0x %0x %0x \n",ueip_char[0], ueip_char[1], ueip_char[2], ueip_char[3] );
        ueip = (ueip_char[0] << 24 ) | (ueip_char[1] << 16) | (ueip_char[2] << 8) | (ueip_char[3]) ;
        
        // FOR DEBUG
        //struct in_addr ueipAddr;
        //ueipAddr.s_addr = htonl(ueip);
        //ueipStr = inet_ntoa(ueipAddr);
        //printf("UEIP = %0x [%s]; \n",ueip, ueipStr);
        //printf("GTP Flag offset [%d] %0x; GTP Offset Src:dest = [%d :%d] \n",gtp_flag_offset, bytes[gtp_flag_offset-1], gtp_src_offset, gtp_dst_offset);
        
        if(ueip_count < MAX_NUMBER_UEIPs) { // don't overrun the allocated memory
            if (!replay_search_for_ueip(ueip)) { //not found in list        
                if(!ueip_count) {
                    ueip_list = (u_int32_t **) calloc(MAX_NUMBER_UEIPs +2,sizeof(u_int32_t *));
                    ueip_list[ueip_count] = (u_int32_t *) calloc(4,sizeof(u_int32_t));
                }
                else{
                     ueip_list[ueip_count] = (u_int32_t *) calloc(4,sizeof(u_int32_t));
                }
                *ueip_list[ueip_count] = ueip;
                //printf("UEIP = %0x [%s]; \n",*ueip_list[ueip_count], ueipStr);
                ueip_count++;
                print_once =0;
            }
            if(((ueip_count % PROGRESS_REPORT_UEIPs) == 0) && (!print_once)){
                printf("Processing UEIP # %d / %d \n",ueip_count,MAX_NUMBER_UEIPs);
                print_once =1;
            }
        }
    }
	   
// if the packet is not to or given list of GGSN's, don't buffer it
	if(downstream == -1) {
		pcap_not_read_packets++;
		return;
	}

// allocate buffer storage
	if(!replay_this_packet)
	{
		pcap_traffic[replay_this_file] = (char **) malloc(sizeof(char *)*2);
	}
	else
	{
		pcap_traffic[replay_this_file] = (char **) realloc(pcap_traffic[replay_this_file],(replay_this_packet + 2) * sizeof(char *));
	}

// allocate the packet length plus FIVE bytes
//  0 & 1 are for packet length
//  2 is for down stream
//  3 + 4 are for delay

	pcap_traffic[replay_this_file][replay_this_packet] 	= (char *) malloc(packet_size + 5); 

// encode packet length in first two bytes
		
	pcap_traffic[replay_this_file][replay_this_packet][0] = packet_size >> 8;
	pcap_traffic[replay_this_file][replay_this_packet][1] = packet_size & 0xFF;

// encode IP offset in the next byte

	pcap_traffic[replay_this_file][replay_this_packet][2] = downstream;

//  copied from Simon stuff
// calculate millsecond offset since last packet and encode in last two byte
	if(!replay_this_packet)
	{
		microseconds = 0;
        pcap_traffic[replay_this_file][replay_this_packet][3] = 0;
        pcap_traffic[replay_this_file][replay_this_packet][4] = 0;
        //printf("0: microseconds = %d\n", microseconds);
	}
	else
	{
		microseconds = (h->ts.tv_sec - pcap_packet_last_timestamp.tv_sec) * 1000000
					 + (h->ts.tv_usec - pcap_packet_last_timestamp.tv_usec);
					 
		if(microseconds > 65535) microseconds = 65535;

        // delay before sending current packet

        pcap_traffic[replay_this_file][replay_this_packet][3] = microseconds >> 8;
        pcap_traffic[replay_this_file][replay_this_packet][4] = microseconds & 0xFF;
        //printf("1:h->ts.tv_sec = %d ; h->ts.tv_usec = %d ; microseconds = %d\n", h->ts.tv_sec, h->ts.tv_usec, microseconds);
        //printf("1:pcap_packet_last_timestamp.tv_sec = %d ; pcap_packet_last_timestamp.tv_usec = %d ; microseconds = %d\n",pcap_packet_last_timestamp.tv_sec, pcap_packet_last_timestamp.tv_usec, microseconds);

	}
	memcpy(&(pcap_packet_last_timestamp), &(h->ts), sizeof(struct timeval));


// copy IP frame out of Ethernet frame
	memcpy(pcap_traffic[replay_this_file][replay_this_packet] + 5,	bytes, packet_size);
   
   pcap_read_packets++;
   pcap_read_bytes += packet_size;
// NULL-terminate the list	
	pcap_traffic[replay_this_file][++replay_this_packet] = NULL;
}

/*
 * 
 * Delay routine used to delay sending the packet 
 * 
 */
 
void replay_delaySendingPacket(unsigned long long *time_current_microseconds,unsigned long long *time_last_microseconds, int *delay_microseconds )
{
    //printf("BEFORE: time_current_microseconds = %llu, time_last_microseconds = %llu, difference = %d, delay_microseconds = %d \n", *time_current_microseconds, *time_last_microseconds,(*time_current_microseconds - *time_last_microseconds), *delay_microseconds);
              
    struct timeval currentTime;
    while(*time_current_microseconds < *time_last_microseconds + *delay_microseconds){
         gettimeofday(&currentTime, NULL);
         *time_current_microseconds = (currentTime.tv_sec * 1000000) + currentTime.tv_usec;
    }
    //printf("AFTER: time_current_microseconds = %llu, time_last_microseconds = %llu, difference = %d, delay_microseconds = %d \n", *time_current_microseconds, *time_last_microseconds,(*time_current_microseconds - *time_last_microseconds), *delay_microseconds);
    
}

/*
 * 
 * Return the time in microseconds
 * 
 */
 
unsigned long long replay_get_current_time_microsecond()
{
     struct timeval current_t;
     gettimeofday(&current_t, NULL);
     return ((current_t.tv_sec * 1000000) + current_t.tv_usec);
}

/*
 * Fetch the packet, get its length , determine up or down stream
 * write the packet to an interface.
 * 
 * Parameters:-
 */


static int replay_send_packet()
{
	int stream_no,packet_no,length,downstream, pkt_delay_microseconds;
	
    struct timeval current_time;
	pcap_write_packets=0;
    pcap_write_bytes = 0;
    unsigned long long time_current_packet_microseconds, time_last_packet_sent_microseconds,start_time_microseconds, time_to_send_all_packets_microseconds;
    unsigned long long target_bits_sent, total_bytes_sent, config_max_rate_bits_per_second;
    
    start_time_microseconds = replay_get_current_time_microsecond();
    config_max_rate_bits_per_second = config_max_rate*1000;
    total_bytes_sent =0;
                
	for(stream_no = 0; stream_no < replay_file_count; stream_no++)
	{
        time_last_packet_sent_microseconds = 0;
		for(packet_no = 0; (pcap_traffic[stream_no][packet_no] != NULL); packet_no++)
		{
			length=-1;
			if((!pcap_traffic) || (!pcap_traffic[stream_no][packet_no])){
				fprintf(stderr, "No packets to send\n");
				return(3);
			}	
			
			downstream = 0;
				
			if(pcap_traffic[stream_no][packet_no][2] == 1)
			{
				downstream = 1;
			}
			
			length = (pcap_traffic[stream_no][packet_no][0] << 8) 
					| ((pcap_traffic[stream_no][packet_no][1]) & 0x00FF);

			if(length <=0)
			{
				fprintf(stderr, "Trying to send zero length packet\n");
				return(3);
			}
            
            if(!config_max_rate) { // replay pcap at speed it was recorded
                // get the packet delay
                pkt_delay_microseconds = (pcap_traffic[stream_no][packet_no][3] << 8) | ((pcap_traffic[stream_no][packet_no][4]) & 0x00FF);

                // wait the requied time
                //printf("BEFORE: current_time [sec:us] = %llu : %llu, time_current_packet_microseconds = %llu, time_last_packet_sent_microseconds = %llu, difference = %d, pkt_delay = %d \n", current_time.tv_sec, current_time.tv_usec, time_current_packet_microseconds, time_last_packet_sent_microseconds,(time_current_packet_microseconds - time_last_packet_sent_microseconds), pkt_delay_microseconds );                
                time_current_packet_microseconds = replay_get_current_time_microsecond();
                replay_delaySendingPacket(&time_current_packet_microseconds, &time_last_packet_sent_microseconds, &pkt_delay_microseconds);
                
                //printf("AFTER: current_time [sec:us] = %llu : %llu, time_current_packet_microseconds = %llu, time_last_packet_sent_microseconds = %llu, difference = %d, pkt_delay = %d \n", current_time.tv_sec, current_time.tv_usec, time_current_packet_microseconds, time_last_packet_sent_microseconds,(time_current_packet_microseconds - time_last_packet_sent_microseconds), pkt_delay_microseconds );
                //printf("\n");
                replay_write_pcap(pcap_traffic[stream_no][packet_no]+5,length,downstream);
                time_last_packet_sent_microseconds = time_current_packet_microseconds;
                
            }
            else{ // Replay Pcap at rate determined by -m option.
            
                //printf("-m: Sending packet Number %d\n", packet_no);
                time_to_send_all_packets_microseconds = replay_get_current_time_microsecond() - start_time_microseconds;
                target_bits_sent =  (unsigned long long) ((float) config_max_rate_bits_per_second * ((float) time_to_send_all_packets_microseconds / (float)1000000));
                
                if(target_bits_sent > (total_bytes_sent*8)) {
                    total_bytes_sent += length;                    
                    replay_write_pcap(pcap_traffic[stream_no][packet_no]+5,length,downstream);
                    //printf("-m : [Pkt # %d] target_bits_sent [%llu] : total BITS sent = %llu \n", packet_no, target_bits_sent, (total_bytes_sent*8));
                    //printf("-m : [Pkt # %d] target_bits_sent [%llu] = config_max_rate_bits_per_second [%llu] x time_to_send_all_packets_microseconds[%llu], \n", packet_no, target_bits_sent, config_max_rate_bits_per_second, time_to_send_all_packets_microseconds);

                }
                else{ //sending to fast...
                    packet_no--; //Resend same packet next time
                }
            }
            
		}
	}
	
	return 0;
}

/*
 * write a packet using the pcap library
 * 
 * Parameters:- 
 *   - payload : the buffer containing the packet
 *   - length  : how many bytes are in the packet
 *   - upstream: indicates if packet is an up stream or down stream packet
 */
static void replay_write_pcap(char *payload, int length, int upstream)
{
	static struct pcap_pkthdr header;

    pcap_write_packets++;
    pcap_write_bytes += length;

        /* write packet to savefile */
	if(pd)
	{
		if(upstream && pd_up)
		{
			pcap_sendpacket(pd_up, payload, length);
		}
		else
		{
			pcap_sendpacket(pd, payload, length);
		}
	}
}

/*
 * set up the output interface that will receive the simulated traffic
 * 
 * Parameters:- 
 *   - interface: the network interface to dump the output data
 */

void replay_pcap_start_interface(char *interface)
{
	if(!pd)
	{
		pd = pcap_open_live(interface, 65535, 0, 1, errbuf);
		
		if(!pd)
		{
			perror(errbuf);
			exit(255);
		}
	}
}


/*
 * set up the output interface that will receive the upstream simulated 
 * traffic (if required)
 * 
 * Parameters:- 
 *   - interface: the network interface to dump the output data
 */

void replay_pcap_start_interface_upstream(char *interface)
{
	if(!pd_up)
	{
		pd_up = pcap_open_live(interface, 65535, 0, 1, errbuf);
		
		if(!pd_up)
		{
			perror(errbuf);
			exit(255);
		}
	}
}

