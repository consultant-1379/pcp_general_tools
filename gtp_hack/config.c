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
* File: config.c
* Date: Oct 8, 2012
* Author: LMI/LXR/PE Simon Richardson
************************************************************************/

#define CONFIG_C
#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


/**********************************************************************
 * This reads config files and populates some global memory with the
 * information read.  It is implemented as a recursive-descent parser.
 * 
 * Each line consists of a symbol (one of sgsn/ggsn/traffic/location/ue)
 * followed by some parameters separated by commas.  Each line defines
 * one config item.
 * 
 * The format of the config file/s is/are something like this:-
 *
 * sgsn, ip.dotted.quad.address, port, mac:colon:hex:values:for:address
 *
 * ggsn, ip.dotted.quad.address, port, mac:colon:hex:values:for:address
 * 
 * traffic, "pcapfile", ip.dotted.quad.address
 * 
 * location, "mcc", "mnc", lac, rac
 * 
 * ue,"imsi",ip.dotted.quad.address,"my.access.point","msisdn","imei"
 * 
 *
 **********************************************************************/

#define LINE_MAX 100
int config_replay_mac_addr;
/*
 * This takes a string of digits and creates a new character buffer
 * with the digits encoded as T-BCD at the offset in the buffer.
 * The bytes before the offset are left as zero.
 * 
 * Parameters:-
 *    - digits: a string of digits (also recognises * # A B C)
 *    - offset: offset from the start of the encoded string to write
 */
static char *config_encode_TBCD(const char *digits, int offset)
{
	int length, i;
	char *ret;
	
	length = (strlen(digits) + 1)/2 + offset;
	
	if(length <= 0) return(0);
	
	ret = calloc(sizeof(char), length + 1);
	
	if(!ret) return(0);
	
	for(i = 0; i < strlen(digits); i++)
	{
		int val;

		switch(digits[i])
		{
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			val = digits[i] - '0';
		break;
		
		case '*':
			val = 0x000A;
		break;
		
		case '#':
			val = 0x000B;
		break;
		
		case 'A': case 'a':
			val = 0x000C;
		break;
		
		case 'B': case 'b':
			val = 0x000D;
		break;
		
		case 'C': case 'c':
			val = 0x000E;
		break;
		
		default:
			val = 0x000F;
		break;
		}

		if(i & 1)
		{
			ret[offset + (i/2)] |= val << 4;
		}
		else
		{
			ret[offset + (i/2)] |= val;
		}
	}
	
	return(ret);
}




/**********************************************************************
 * These are the terminal symbols in the config file
 */
typedef enum
{
	LINETYPE_INVALID = 0,
	LINETYPE_GGSN,
	LINETYPE_SGSN,
	LINETYPE_LOCATION,
	LINETYPE_TRAFFIC,
	LINETYPE_UE,
	LINETYPE_COUNT
} linetype;

/*
 * read the line type symbol from the start of a config line and return
 * the line type.
 * 
 * Parameters:-
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 */
static linetype config_parse_linetype(char **line)
{
	while(**line && isspace(**line)) (*line)++;
	
	if(!**line) return(LINETYPE_INVALID);
	
	if(!strncasecmp(*line, "GGSN", 4))
	{
		*line += 4;
		while(**line && isspace(**line)) (*line)++;
		return(LINETYPE_GGSN);
	}
	if(!strncasecmp(*line, "SGSN", 4))
	{
		*line += 4;
		while(**line && isspace(**line)) (*line)++;
		return(LINETYPE_SGSN);
	}
	if(!strncasecmp(*line, "LOCATION", 8))
	{
		*line += 8;
		while(**line && isspace(**line)) (*line)++;
		return(LINETYPE_LOCATION);
	}
	if(!strncasecmp(*line, "TRAFFIC", 7))
	{
		*line += 7;
		while(**line && isspace(**line)) (*line)++;
		return(LINETYPE_TRAFFIC);
	}
	if(!strncasecmp(*line, "UE", 2))
	{
		*line += 2;
		while(**line && isspace(**line)) (*line)++;
		return(LINETYPE_UE);
	}
	
	return(LINETYPE_INVALID);
}

/*
 * read some piece of syntactic sugar contained in a string and report 
 * an error and return nonzero if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 *    - sugar: pointer to the syntactic sugar as a string
 */
static int config_parse_sugar(char *filename, int row, char **line, char *sugar)
{
	while(**line && isspace(**line)) (*line)++;
	if(strncasecmp(*line, sugar, strlen(sugar)))
	{
		fprintf(stderr, "Error:%s:%d: %s expected\n",
				filename, row, sugar);
		return(2);
	}
	
	*line += strlen(sugar);
	
	return(0);
}

/*
 * read a sequence of characters enclosed in "these" into the string 
 * buffer and report an error and return nonzero if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 *    - string: pointer to the buffer to receive the string
 * 
 * WARNING: there is no limit to the size of the string: make sure it
 * is as big as the line buffer!
 */
static int config_parse_string(char *filename, int row, char **line, char *string)
{
	int isescape = 0;
	while(**line && isspace(**line)) (*line)++;

	if(**line != '\"')
	{
		fprintf(stderr, "Error:%s:%d: \" expected\n",
				filename, row);
		return(2);
	}
	
	(*line)++;
	
	while(**line && (isescape || **line != '\"'))
	{
		if(!isescape && **line == '\\')
		{
			isescape = 1;
		}
		else
		{
			if(isescape)
			{
				switch(**line)
				{
				case '\0':
					*(string++) = 0;
				break;

				case '\n':
					*(string++) = '\n';
				break;

				case '\r':
					*(string++) = '\r';
				break;

				case '\t':
					*(string++) = '\t';
				break;

				default:
					*(string++) = **line;				
				}
			}
			else
			{
				*(string++) = **line;
			}
			isescape = 0;
		}
		
		(*line)++;
	}
	
	*(string) = 0;

	if(**line == '\"')
	{
		(*line)++;
	}
	else
	{
		fprintf(stderr, "Error:%s:%d: missing \" at end of string\n",
				filename, row);
		return(2);
	}
	
	return(0);
}


/*
 * read an integer and write it into the value pointed to by *integer:
 * report an error and return nonzero if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 *    - integer: pointer to the integer where the value is written
 */
static int config_parse_int(char *filename, int row, char **line, int *integer)
{
	while(**line && isspace(**line)) (*line)++;

	if(config_replay_mac_addr)
	{
		*integer = strtol(*line, line, 16);
		return(0);
	}
    
    if(!strncasecmp(*line, "0X", 2))
	{
		*line += 2;
		*integer = strtol(*line, line, 16);
		return(0);
	}
	
	if(**line == '0')
	{
		*line += 1;
		*integer = strtol(*line, line, 8);
		return(0);
	}
	
	if(isdigit(**line))
	{
		*integer = strtol(*line, line, 10);
		return(0);
	}
	
	
	return(2);
}

/*
 * read a character and write it into the value pointed to by *integer:
 * report an error and return nonzero if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 *    - integer: pointer to the character where the value is written
 */
static int config_parse_char(char *filename, int row, char **line, char *integer)
{
	int x, r;
	
	r = config_parse_int(filename, row, line, &x);
	
	if(!r)
	{
		if(x > 255 || x < -128)
		{
			fprintf(stderr, "Error:%s:%d: byte value out of range\n",
						filename, row);
			
			return(1);
		}

		*integer = (char) x;
	}
	
	return(r);
}

/*
 * read an IPv4 address into the 4 chars pointed to by *ip and report 
 * an error and return nonzero if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 *    - ip: pointer to 4 chars to store the IP address
 */
static int config_parse_ip(char *filename, int row, char **line, char *ip)
{
	if(config_parse_char(filename, row, line, ip + 0)
	|| config_parse_sugar(filename, row, line, ".")
	|| config_parse_char(filename, row, line, ip + 1)
	|| config_parse_sugar(filename, row, line, ".")
	|| config_parse_char(filename, row, line, ip + 2)
	|| config_parse_sugar(filename, row, line, ".")
	|| config_parse_char(filename, row, line, ip + 3))
	{
		return(1);
	}
	
	return(0);
}
		
/*
 * read a mac address into the 6 chars pointed to by *mac and report 
 * an error and return nonzero if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 *    - mac: pointer to the 6 chars to store the mac address
 */
static int config_parse_mac(char *filename, int row, char **line, char *mac)
{
    if(config_parse_char(filename, row, line, mac + 0)
	|| config_parse_sugar(filename, row, line, ":")
	|| config_parse_char(filename, row, line, mac + 1)
	|| config_parse_sugar(filename, row, line, ":")
	|| config_parse_char(filename, row, line, mac + 2)
	|| config_parse_sugar(filename, row, line, ":")
	|| config_parse_char(filename, row, line, mac + 3)
	|| config_parse_sugar(filename, row, line, ":")
	|| config_parse_char(filename, row, line, mac + 4)
	|| config_parse_sugar(filename, row, line, ":")
	|| config_parse_char(filename, row, line, mac + 5))
	{
		return(1);
	}
	
	return(0);
}


/*
 * read the SGSN data into the global variables and return nonzero 
 * if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 * 
 * Global variables:-
 *    - config_SGSN_mac: the mac address of the SGSN Ethernet port
 *    - config_SGSNc_port: the IP port of the SGSN control plane
 *    - config_SGSNu_port: the IP port of the SGSN user plane
 *    - config_SGSN_ip: the IPv4 address of the SGSN
 */

char config_SGSN_mac[6];
int config_SGSNc_port;
int config_SGSNu_port;
char config_SGSN_ip[4];

static int config_parse_sgsn(char *filename, int row, char **line)
{
	if(config_parse_sugar(filename, row, line, ",")
	|| config_parse_ip(filename, row, line, config_SGSN_ip)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_int(filename, row, line, &config_SGSNc_port)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_int(filename, row, line, &config_SGSNu_port)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_mac(filename, row, line, config_SGSN_mac))
	{
		return(1);
	}

	return(0);
}

/*
 * read the GGSN data into the global variables and return nonzero 
 * if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 * 
 * Global variables:-
 *    - config_GGSN_mac: the mac address of the GGSN Ethernet port
 *    - config_GGSNc_port: the IP port of the GGSN control plane
 *    - config_GGSNu_port: the IP port of the GGSN user plane
 *    - config_GGSN_ip: the IPv4 address of the GGSN
 */

char config_GGSN_mac[6];
int config_GGSNc_port;
int config_GGSNu_port;
char config_GGSN_ip[4];

static int config_parse_ggsn(char *filename, int row, char **line)
{
	if(config_parse_sugar(filename, row, line, ",")
	|| config_parse_ip(filename, row, line, config_GGSN_ip)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_int(filename, row, line, &config_GGSNc_port)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_int(filename, row, line, &config_GGSNu_port)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_mac(filename, row, line, config_GGSN_mac))
	{
		return(1);
	}

	return(0);
}


/*
 * read the traffic data into the global variables and return nonzero 
 * if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 * 
 * Global variables:-
 *    - config_traffic_files: structure containing filenames and source
 * IPv4 addresses of the traffic files
 *    - config_traffic_file_count: the number of traffic files found
 */

struct traffic_file_struct *config_traffic_files;
int config_traffic_file_count;

static int config_parse_traffic(char *filename, int row, char **line)
{
	struct traffic_file_struct *data;
	char string[LINE_MAX];


	if(!config_traffic_file_count)
	{
		config_traffic_files = (struct traffic_file_struct *)
					malloc(sizeof(struct traffic_file_struct));
	}
	else
	{
		config_traffic_files = (struct traffic_file_struct *)
				realloc(config_traffic_files, (config_traffic_file_count + 1)
						* sizeof(struct traffic_file_struct));
	}
	
	data = config_traffic_files + config_traffic_file_count;

	if(config_parse_sugar(filename, row, line, ",")
	|| config_parse_string(filename, row, line, string)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_ip(filename, row, line, data->local_ip))
	{
		return(1);
	}
	
	data->filename = strdup(string);
	
	config_traffic_file_count++;
	return(0);
}

/*
 * read the location data into the global variables and return nonzero 
 * if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 * 
 * Global variables:-
 *    - config_RAI_list: structure containing filenames and source
 * IPv4 addresses of the traffic files
 *    - config_RAI_list_count: the number of traffic files found
 */

char **config_RAI_list;
int config_RAI_list_count;

static int config_parse_location(char *filename, int row, char **line)
{
	char mcc[LINE_MAX], mnc[LINE_MAX];
	int lac, rac;
	char string[6];


	if(!config_RAI_list_count)
	{
		config_RAI_list = (char **)
					malloc(sizeof(char *));
	}
	else
	{
		config_RAI_list = (char **)
				realloc(config_RAI_list, (config_RAI_list_count + 1)
						* sizeof(char *));
	}
	
	if(config_parse_sugar(filename, row, line, ",")
	|| config_parse_string(filename, row, line, mcc)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_string(filename, row, line, mnc)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_int(filename, row, line, &lac)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_int(filename, row, line, &rac))
	{
		return(1);
	}

	string[0] = ((mcc[1] - '0') << 4) | ((mcc[0]-'0') & 0x0F) ;
	string[1] = ((mnc[2] - '0') << 4) | ((mcc[2]-'0') & 0x0F) ;
	string[2] = ((mnc[1] - '0') << 4) | ((mnc[0]-'0') & 0x0F) ;
	string[3] = lac >> 8;
	string[4] = lac;
	string[5] = rac;

	config_RAI_list[config_RAI_list_count] = (char *) malloc(6);
	memcpy(config_RAI_list[config_RAI_list_count], string, 6);
	
	config_RAI_list_count++;
	return(0);
}


/*
 * read the user equipment data into the global variables and return 
 * nonzero if it can't be found
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: pointer to a string pointer which indexes the part of 
 * the line that is being parsed.
 * 
 * Global variables:-
 *    - config_UE_buffer: structure containing information about the
 * user equipment
 *    - config_UE_buffer_count: the number of traffic files found
 */

struct UE_struct *config_UE_buffer;
int config_UE_buffer_count;

static int config_parse_ue(char *filename, int row, char **line)
{
	struct UE_struct *data;
	char imei[LINE_MAX], apn[LINE_MAX], imsi[LINE_MAX], msisdn[LINE_MAX];

	strcpy(imsi, "0000000000000000");

	if(!config_UE_buffer_count)
	{
		config_UE_buffer = (struct UE_struct *)
					malloc(sizeof(struct UE_struct));
	}
	else
	{
		config_UE_buffer = (struct UE_struct *)
				realloc(config_UE_buffer, (config_UE_buffer_count + 1)
						* sizeof(struct UE_struct));
	}
	
	data = config_UE_buffer + config_UE_buffer_count;

	if(config_parse_sugar(filename, row, line, ",")
	|| config_parse_string(filename, row, line, imsi)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_ip(filename, row, line, data->ip)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_string(filename, row, line, apn)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_string(filename, row, line, msisdn)
	|| config_parse_sugar(filename, row, line, ",")
	|| config_parse_string(filename, row, line, imei))
	{
		return(1);
	}
	
	data->imsi = config_encode_TBCD(imsi, 0);
	data->access_point_name = strdup(apn);
	data->msisdn = config_encode_TBCD(msisdn, 2);
	data->msisdn[0] = 1 + (strlen(msisdn) + 1)/2;
	data->msisdn[1] = 0x91;
	data->imei = config_encode_TBCD(imei, 1);
	data->imei[0] = (strlen(imei) + 1)/2;
    data->timeLastUsed =0;
    data->UE_state = UE_STATE_IDLE;
    data->firstTimeUsed = 0;

  data->seqNum = rand();	
	config_UE_buffer_count++;
	return(0);
}



/*
 * parse a whole config line and report an error and return nonzero if
 * the line doesn't parse correctly
 * 
 * Parameters:-
 *    - filename: string for error reporting
 *    - row: integer for error reporting
 *    - line: string pointer which indexes the part of the line that 
 * is being parsed.
 */

static int config_parse_line(char *filename, int row, char *line)
{
	switch(config_parse_linetype(&line))
	{
	case LINETYPE_GGSN:
		if(config_parse_ggsn(filename, row, &line)) return(1);
	break;
	
	case LINETYPE_SGSN:
		if(config_parse_sgsn(filename, row, &line)) return(1);
	break;
	
	case LINETYPE_LOCATION:
		if(config_parse_location(filename, row, &line)) return(1);
	break;
	
	case LINETYPE_TRAFFIC:
		if(config_parse_traffic(filename, row, &line)) return(1);
	break;
	
	case LINETYPE_UE:
		if(config_parse_ue(filename, row, &line)) return(1);
	break;
	
	default:
		fprintf(stderr, "Error:%s:%d: couldn't recognise config line type\n",
				filename, row);
		return(2);
	}
	
	return(0);
}

/*
 * Parse a whole config file and return nonzero if it doesn't parse
 * correctly.
 * 
 * Parameters:-
 *    - filename: name of the file to be read
 */
static int config_parse_file(char *filename)
{
	srand(time(NULL));
	static FILE *cfile;
	char linebuf[LINE_MAX], *line;
	int row, errors = 0;

	cfile = fopen(filename, "r");
	if(!cfile) return(-1);
	
	for(row = 0; !feof(cfile) && !ferror(cfile) 
				&& fgets(linebuf, LINE_MAX, cfile); row++)
	{
		for(line = linebuf; *line && isspace(*line); line++)
			;
		
		if(*line && *line != '#')
		{
			if(config_parse_line(filename, row, line))
			{
				errors++;
			}
		}
	}
	
	fclose(cfile);
	cfile = 0;
	return(errors);
}

/*
 * Print a help message
 * 
 * Parameters:-
 *    (none)
 */

static void config_print_help(char *name)
{
	printf("Call as \n %s [switches] [config-files]\n", name);
	printf("where switches are one or more of:- \n");
	printf(" -cf/--control-file <pcap file name> to output cotrol plane traffic\n");
	printf(" -ci/--control-interface <device> to output cotrol plane traffic\n");
	printf(" -ici/--imsi_count_interval <time in seconds> print the number of IMSI's that are not in the IDLE state in this time period; Prints only if % < 100%\n");
	printf(" -e/--eventstream <filename> to output events list to a file\n");
	printf(" -f/--file <filename>  to output to a file\n");
	printf(" -i/--interface <device> to output (downstream) to a device\n");
	printf(" -m/--maxrate <kbit/sec> to throttle total output\n");
	printf(" -t/--time <seconds> to run before exiting\n");
	printf(" -u/--upstream <device> to output (upstream) traffic to another device\n");
	printf(" -o/--override_default_delay_between_packets <inter packet delay in milli seconds> for setting delay between packets extracted from pcaps like stream_5min where inter packet delay can be in minutes\n");
    printf(" -GTPC /--create_GTPC_sequence <1 = create PDP Request /response; 2 = update PDP Request /response; 3 = delete PDP Request /response>  \n");
    printf(" -r/--replay <pcap file name> -g --ggsn <list of ggsn's comma seperated> \n");
    printf(" -h/--help to print this message and exit\n");


	
	printf("\n\nTO REPLAY PCAP FILES\n", name);
	printf("\n\nCall as \n\n%s -r <pcap file name> -g <list of comma separated ggsn IP> [-t <seconds> to run before exiting] \n\n", name);
	printf("where:- \n");
	printf(" -r/--replay <pcap file name>\n");
	printf(" -g --ggsn <list of ggsn's comma separated> \n");
    printf(" -m/--maxrate <kbit/sec> to throttle total output\n");
    printf("NOTE:\n    NO -m means pcap will be replayed in real time\n\n");
    
    
	printf(" -t/--time <seconds> to run before exiting\n");
    printf("NOTE:\n     -t=1 means replay pcap file once only\n");
    printf("     no -t option means replay pcap file forever\n\n");
    
    printf(" -cUEIP/--count_total_ueip <Number> of UEIP to process before printing progress\n");
    printf("NOTE:\n     -cUEIP will slow down loading of large pcaps\n");
    printf("     UEIP's will be printed to the file <pcap file name>_ueip.txt\n\n");
    
    printf(" -s --signal  WAIT FOR SIGNAL Mode in use.\n");
    printf("NOTE:\n     Hence the PCAP will load and wait for <pcap filename>_done.txt to be created in same directory as simulator is run before replay of the pcap will continue\n");
    printf("     Use in conjunction with the script: replayPCAPS-09Sept13-v2.bsh \n\n");
		
		
	printf("EXAMPLE\n");
	printf("simulator -r \"/shared_app/pcapFiles/stream28_23032012_1K_packets.pcap\" -g \"203.78.47.209\",\"203.78.47.210\",\"203.78.47.211\",\"203.78.47.212\",\"203.78.47.213\"  -i eth1 -u eth2 -t 10 -m 2000000 -cUEIP 10000\n\n");
	
	
}

/*
 * Parse commad line parameters, 
 *         -r for a file name 
 *         -g for a <list> pf comma seperated ggsn addresses
 * 
 * Note: in future -r may ahve a list of pcap files and so this can be 
 *       used to read a number of pcaps
 *       For now, just reads one, so config_traffic_file_count == 1
 * Parameters:-
 *             *pcap_filename is the pcap file name
 *             *ggsnAddr is the list of comma seperated ggsn addresses 
 * 				
 */
u_char **config_pcap_ggsns;
int max_num_ggsn;

static int config_parse_pcap(char *pcap_filename, char *ggsnAddr)
{
	struct traffic_file_struct *data;
	char string[LINE_MAX];
	int index=0,i;
	unsigned char tmp;

    max_num_ggsn=0;

	if(!config_traffic_file_count)
	{
		config_traffic_files = (struct traffic_file_struct *)
					malloc(sizeof(struct traffic_file_struct));
	}
	else
	{
		config_traffic_files = (struct traffic_file_struct *)
				realloc(config_traffic_files, (config_traffic_file_count + 1)
						* sizeof(struct traffic_file_struct));
	}
	
	data = config_traffic_files + config_traffic_file_count;
	data->filename = strdup(pcap_filename);
	
	config_traffic_file_count++;
	
	// count number of comma's and use this to set array size for malloc
	max_num_ggsn=0;
	// if length ggsnAdddr is not zero, then ther e is at least one ggsn addr 
	if(strlen(ggsnAddr) >0) {
		max_num_ggsn++;
	}
	for(i=0;i<strlen(ggsnAddr);i++) {
		if(ggsnAddr[i] == ','){
			max_num_ggsn++;
		}
	}

	config_pcap_ggsns = (u_char **) calloc(max_num_ggsn + 2, sizeof(u_char *));
	// Process list of GGSN in for -g "123.123.123.123","123.123.123.123","123.123.123.123" so one last read is expected
    // Process list of GGSN in for -mac -g "5c:5e:ab:20:c5","5c:5e:ab:20:c6","5c:5e:ab:20:c6" so one last read is expected
	
	// First a ggsn.
	// row is command line in this case, so row =0
	// IP size is array of 4 bytes
    if(config_replay_mac_addr) {
         printf("PROCESSING MAC ADDR\n");
         config_pcap_ggsns[0] = (u_char *) calloc(6,sizeof(u_char));
         if(config_parse_mac(pcap_filename, 0, &ggsnAddr, config_pcap_ggsns[0])){
		 // free memory ; recall config_pcap_ggsns is a pointer to an array of pointers
		 // we are going to exit on this fail condition, so no need to free memory
		 return(1);
        }
    }
    else{
        printf("PROCESSING IP ADDR\n");
        config_pcap_ggsns[0] = (u_char *) calloc(4,sizeof(u_char));
       	if(config_parse_ip(pcap_filename, 0, &ggsnAddr, config_pcap_ggsns[0])){
		// free memory ; recall config_pcap_ggsns is a pointer to an array of pointers
		// we are going to exit on this fail condition, so no need to free memory
		return(1);
        }
    }

	
	for(index=1; (!(config_parse_sugar(pcap_filename, 0, &ggsnAddr, ","))); index++){
		if(config_replay_mac_addr) {
            config_pcap_ggsns[index] = (u_char *) calloc(6,sizeof(u_char));
            if(config_parse_mac(pcap_filename, 0, &ggsnAddr, (u_char *) config_pcap_ggsns[index])){
			// free memory ; recall config_pcap_ggsns is a pointer to an array of pointers
			// we are going to exit on this fail condition, so no need to free memory
			return(1);
            }
        }
        else{
            config_pcap_ggsns[index] = (u_char *) calloc(4,sizeof(u_char));
            if(config_parse_ip(pcap_filename, 0, &ggsnAddr, (u_char *) config_pcap_ggsns[index])){
			// free memory ; recall config_pcap_ggsns is a pointer to an array of pointers
			// we are going to exit on this fail condition, so no need to free memory
			return(1);
            }
        }
		
		if(index == (max_num_ggsn-1)){  //all done, no more ggsn's to read
			break;
		}
		
		if(index >= max_num_ggsn)
		{
			fprintf(stderr, "Error:%s too many GGSN in %s, MAX of %d expected\n", pcap_filename,ggsnAddr,max_num_ggsn);
			return(2);
		}
		
	}
     for(i=0; i<max_num_ggsn;i++) {
        
        if(config_replay_mac_addr) {
            printf("GGSN Address [mac] = %0x:%0x:%0x:%0x:%0x:%0x \n", config_pcap_ggsns[i][0], config_pcap_ggsns[i][1], config_pcap_ggsns[i][2], config_pcap_ggsns[i][3], config_pcap_ggsns[i][4], config_pcap_ggsns[i][5] );
        }
        else {
            printf("GGSN Address [IP] = %d:%d:%d:%d \n", config_pcap_ggsns[i][0], config_pcap_ggsns[i][1], config_pcap_ggsns[i][2], config_pcap_ggsns[i][3]);
        }
    }
        
  
	return(0);
}



/*
 * Read the configuration data from the configuration files and the
 * switches on the command line.  Configuration files are read and 
 * global variables are set.
 * 
 * Parameters:-
 *    - arg_count: count of the command-line arguments
 *    - args: array of strings containing the command-line arguments
 * 
 * Global Variables:-
 *    - config_write_filename: name of the file to write pcap to
 *    - config_write_interface: name of the network interface to write 
 * pcap to
 *    - config_lifetime: how long to write data for, or zero to write
 * forever (default).
 */




char *config_write_filename;
char *config_write_interface;
char *config_write_upstream;
// esirich: add separate control output
char *config_write_filename_control;
char *config_write_interface_control;
char *config_replay_pcap;
char *config_replay_ggsn_addr;
int config_lifetime;
char *config_event_output;
long int config_max_rate;
int config_imsi_count_interval;
int config_replay_count_ueip;
int config_use_wait_signal;
int config_interPacket_delay_mS;
int config_create_GTPC_sequence;


int config_read(int arg_count, char *args[])
{
	int i,j;
	config_replay_mac_addr = 0;
	config_use_wait_signal = 0;
    config_create_GTPC_sequence = 0;
    
	if(arg_count < 2)
	{
		config_print_help(args[0]);
		return(255);
	}
	
	for(i = 1; i < arg_count; i++)
	{
		if(!strcasecmp(args[i], "-h")
		|| !strcasecmp(args[i], "--help"))
		{
			config_print_help(args[0]);
			return(255);
		}
// esirich: add separate control output		
		else if(!strcasecmp(args[i], "-cf")
			 || !strcasecmp(args[i], "--control-file"))
		{
			if(config_write_interface_control || config_write_filename_control)
			{
				fprintf(stderr, "Only one -cf or -ci allowed!\n");
				return(254);
			}

			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-cf missing filename!\n");
				return(254);
			}
			
			config_write_filename_control = args[++i];
		}
// esirich: add separate control output		
		else if(!strcasecmp(args[i], "-ci")
			 || !strcasecmp(args[i], "--control-interface"))
		{
			if(config_write_interface_control || config_write_filename_control)
			{
				fprintf(stderr, "Only one -cf or -ci allowed!\n");
				return(254);
			}

			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-cf missing filename!\n");
				return(254);
			}
			
			config_write_interface_control = args[++i];
		}
        
		else if(!strcasecmp(args[i], "-GTPC")
			 || !strcasecmp(args[i], "--create_GTPC_sequence"))
		{
            char *end;
			if(config_create_GTPC_sequence)
			{
				fprintf(stderr, "Only one -GTPC allowed!\n");
				return(254);
			}
			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-GTPC missing data rate!\n");
				return(254);
			}
            
            config_create_GTPC_sequence = strtol(args[++i], &end, 10);
			
			if(*end)
			{
				fprintf(stderr, "-GTPC \"%s\" is not an integer\n", args[i+1]);
				return(254);
			}
            if(!config_create_GTPC_sequence)  // ==0
			{
				fprintf(stderr, "-GTPC \"%d\" can not be zero\n", config_create_GTPC_sequence);
				return(254);
			}
            
		}        
		else if(!strcasecmp(args[i], "-f")
			 || !strcasecmp(args[i], "--file"))
		{
			if(config_write_interface || config_write_filename)
			{
				fprintf(stderr, "Only one -f or -i allowed!\n");
				return(254);
			}

			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-f missing filename!\n");
				return(254);
			}
			
			config_write_filename = args[++i];
		}
		else if(!strcasecmp(args[i], "-i")
			 || !strcasecmp(args[i], "--interface"))
		{
			if(config_write_interface || config_write_filename)
			{
				fprintf(stderr, "Only one -f or -i allowed!\n");
				return(254);
			}
			
			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-i missing device name!\n");
				return(254);
			}
			
			config_write_interface = args[++i];
		}
		else if(!strcasecmp(args[i], "-u")
			 || !strcasecmp(args[i], "--upstream"))
		{
			if(config_write_upstream)
			{
				fprintf(stderr, "Too many -u options!\n");
				return(254);
			}
			
			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-u missing file/device name!\n");
				return(254);
			}
			
			config_write_upstream = args[++i];
		}
		else if(!strcasecmp(args[i], "-e")
			 || !strcasecmp(args[i], "--eventstream"))
		{
			if(config_event_output)
			{
				fprintf(stderr, "Too many -e options!\n");
				return(254);
			}
			
			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-e missing file/pipe name!\n");
				return(254);
			}
			
			config_event_output = args[++i];
		}
		else if(!strcasecmp(args[i], "-m")
			 || !strcasecmp(args[i], "--maxrate"))
		{
			char *end;

			if(config_max_rate)
			{
				fprintf(stderr, "Too many -m options!\n");
				return(254);
			}
			
			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-m missing data rate!\n");
				return(254);
			}
			
			config_max_rate = strtol(args[++i], &end, 10);
			
			if(*end)
			{
				fprintf(stderr, "-m \"\" is not an integer\n",
							args[i - 1]);
				return(254);
			}
			
		}
        else if(!strcasecmp(args[i], "-o")
			 || !strcasecmp(args[i], "--override_default_delay_between_packets"))
		{
			char *end;

			if(config_interPacket_delay_mS)
			{
				fprintf(stderr, "Too many -o options!\n");
				return(254);
			}
			
			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-o missing delay time (in milliseconds\n");
				return(254);
			}
			
			config_interPacket_delay_mS = (int) strtol(args[++i], &end, 10);
			
			if(*end)
			{
				fprintf(stderr, "-o \"\" is not an integer\n", args[i - 1]);
				return(254);
			}
			
		}
		else if(!strcasecmp(args[i], "-s")
			 || !strcasecmp(args[i], "--signal"))
		{
			char *end;

			if(config_use_wait_signal)
			{
				fprintf(stderr, "Too many -s options!\n");
				return(254);
			}
			if(!config_replay_pcap)
			{
				fprintf(stderr, "A PCAP file must be supplied via -r !\n");
				return(254);
			}
            printf("\nWAIT FOR SIGNAL Mode in use.\n");
			printf("Hence the PCAP will load and wait for <pcap filename>_done.txt to be created in same directory as simulator is run before replay of the pcap will continue\n");
			printf("Use in conjunction with the script: replayPCAPS-09Sept13-v2.bsh \n\n");
			config_use_wait_signal = 1;
			
		}
		else if(!strcasecmp(args[i], "-ici")
			 || !strcasecmp(args[i], "--imsi_count_interval"))
		{

			if(config_imsi_count_interval)
			{
				fprintf(stderr, "Too many -ici options!\n");
				return(254);
			}
			
			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-ici missing interval in seconds!\n");
				return(254);
			}
			
			if(!sscanf(args[++i], "%d", &config_imsi_count_interval))
			{
				fprintf(stderr, "-ici \"\" is not an integer\n");
				return(254);
			}
			
		}
		
		else if(!strcasecmp(args[i], "-cUEIP")
			 || !strcasecmp(args[i], "--count_total_ueip"))
		{

			if(config_imsi_count_interval)
			{
				fprintf(stderr, "Too many -cUEIP options!\n");
				return(254);
			}
			
			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-cUEIP missing printout progress interval in ~ueip's!\n");
				return(254);
			}
			
			if(!sscanf(args[++i], "%d", &config_replay_count_ueip))
			{
				fprintf(stderr, "-cUEIP \"\" is not an integer\n");
				return(254);
			}
			
		}
		
		else if(!strcasecmp(args[i], "-t")
			 || !strcasecmp(args[i], "--time"))
		{
			if(config_lifetime)
			{
				fprintf(stderr, "Only one -t allowed!\n");
				return(254);
			}
			
			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-t missing time!\n");
				return(254);
			}
			
			if(!sscanf(args[++i], "%d", &config_lifetime))
			{
				fprintf(stderr, "-t/--time should be followed by time in seconds\n");
				return(254);
			}
		}
		/* efitleo */
		else if(!strcasecmp(args[i], "-r")
			 || !strcasecmp(args[i], "--replay"))
		{
			if(config_replay_pcap)
			{
				fprintf(stderr, "Only one -r allowed!\n");
				return(254);
			}
			
			for(j=0;j<arg_count;j++) {
				
				if(!strcasecmp(args[j], "-g")
						|| !strcasecmp(args[j], "--ggsn")){
						break; //matching ggsn, so OK
					}
				if(j-1 == arg_count) {
				fprintf(stderr, "A GGSN Addres must be supplied via -g !\n");
				return(254);
				}
			}
			
			
			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-r missing pcap filename!\n");
				return(254);
			}
			
			config_replay_pcap = args[++i];
			
		}
        
		
		else if(!strcasecmp(args[i], "-g")
			 || !strcasecmp(args[i], "--ggsn"))
		{
			if(config_replay_ggsn_addr)
			{
				fprintf(stderr, "Only one -g allowed!\n");
				return(254);
			}
			
			if(!config_replay_pcap)
			{
				fprintf(stderr, "A PCAP file must be supplied via -r !\n");
				return(254);
			}

			for(j=0;j<arg_count;j++) {
				
				if(!strcasecmp(args[j], "-i")
						|| !strcasecmp(args[j], "--ggsn")){
						break; //matching ggsn, so OK
					}
				if(j-1 == arg_count) {
				fprintf(stderr, "An interface name must be supplied via -i and optionally seperate upstream via -u !\n");
				return(254);
				}
			}

			if(i + 1 == arg_count)
			{
				fprintf(stderr, "-g missing ggsn ip!\n");
				return(254);
			}
			
			config_replay_ggsn_addr = args[++i];
            fprintf(stderr, "ggsn Address = %s \n", config_replay_ggsn_addr);
            if(strstr(config_replay_ggsn_addr, ":")){
                fprintf(stderr, "ggsn Addresses will be expected in  mac address format!\n");
                config_replay_mac_addr=1;
            }
			
			if((config_replay_pcap) && (config_replay_ggsn_addr) )
			{
				config_parse_pcap(config_replay_pcap, config_replay_ggsn_addr);
			}
		}
		
		else
		{
			if((config_replay_pcap) || (config_replay_ggsn_addr) ) {
				fprintf(stderr, "Cannot have config file with -r option  to replay config file present\"%s\"\n", args[i]);
				return(253);
			}
			if(config_parse_file(args[i]))
			{
				fprintf(stderr, "Cannot parse config file \"%s\"\n", args[i]);
				return(253);
			}
		}
	}
	
	return(0);
}
