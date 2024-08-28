
#include "gtp_hack.h"

int main(void)
{
	write_pcap_start("./brown.pcap");
//General:-
// (packet 1,2) - Duff version number (29.060 section 6)
    write_gtp_start(6, 0, 0, 0x10); write_gtp_end(GTP_UP);
	write_gtp_start(7, 0, 0, 0x10); write_gtp_end(GTP_DOWN);
// (packet 3,4) - Duff protocol type (29.060 section 6)
    write_gtp_start(1, 6, 0, 0x00); write_gtp_end(GTP_UP);
	write_gtp_start(1, 7, 0, 0x00); write_gtp_end(GTP_DOWN);
// (packet 5,6) - Duff message type
// - duff message formats (e.g. not listed in 29.060 7.1 table 1)
    write_gtp_start(1, 10, 0, 0x10); write_gtp_end(GTP_UP);
	write_gtp_start(1, 11, 0, 0x10); write_gtp_end(GTP_DOWN);
// (packet 7,8) - duff lengths (e.g. <12, or some value over 65,000)
    write_gtp_start(1, 0x10, 0, 0x10); 
    gtp_length = 8;
    write_gtp_end(GTP_UP);
	write_gtp_start(1, 0x11, 0, 0x10); 
    gtp_length = GTP_FRAME_LEN;
	write_gtp_end(GTP_DOWN);
// (packet 9) - duff sequence numbers
// (packet 10) - truly zero-length information element	
    write_gtp_start(1, 0x10, 0, 0x10); 
	write_gtp_IE(0x83, 0, ""); // zero-length APN
    write_gtp_end(GTP_UP);
	write_gtp_start(1, 0x11, 0, 0x10); 
	write_gtp_IE(0xFB, 0, ""); // zero-length charging gateway address
	write_gtp_end(GTP_DOWN);

//(16) In "Create PDP Context Request":-
// (packet 11) - out-of-order type elements including wierd one
	write_gtp_start(1, 16, 0, 0x10);
	write_gtp_IE(240, 5, "fnord"); // unknown IE
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_end(GTP_UP);
// (packet 12) - Only mandatory parameters
	write_gtp_start(1, 16, 0, 0x10);
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_end(GTP_UP);
// (packet 13) - some parameters duplicated
	write_gtp_start(1, 16, 0, 0x10);
	write_gtp_IE(0x02, 8, "\x10\x32\x54\x76\x98\x10\x32\x54"); // IMSI 012345678912345
	write_gtp_IE(0x03, 6, "\x01\x23\x45\x67\x89\xab"); // RAI:MCC=103; MNC=542; LAC=26505; RAC=171
	write_gtp_IE(0x0E, 1, "\xB8"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x11, 4, "\x76\x54\x32\x10");// TEID C
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x1A, 2, "\x04\x00");//Charging characteristics
	write_gtp_IE(0x80, 2, "\xf1\x21");//end user address
	write_gtp_IE(0x83, 18, "\x11" "access.point.name");//APN
	write_gtp_IE(0x84, 0x1d,"\x80\xc0\x23\x06\x01\x01\x00\x06"
							"\x00\x00\x80\x21\x10\x01\x01\x00"
							"\x10\x81\x06\x00\x00\x00\x00\x83"
							"\x06\x00\x00\x00\x00");// protocol config options
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x86, 6, "\x91\x21\x43\x65\x87\x09");//MSISDN
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x97, 1, "\x01"); //RAT type
	write_gtp_IE(0x98, 8, "\x01\x23\x45\x67\x89\xAB\xCD\xEF");// location information
	write_gtp_IE(0x99, 2, "\x23\x00"); // timezone
	write_gtp_IE(0x9A, 8, "\x10\x32\x54\x76\x98\x10\x32\x54"); // IMEI 012345678912345
	write_gtp_IE(0x02, 8, "\x10\x32\x54\x76\x98\x10\x32\x54"); // IMSI 012345678912345
	write_gtp_IE(0x03, 6, "\x01\x23\x45\x67\x89\xab"); // RAI:MCC=103; MNC=542; LAC=26505; RAC=171
	write_gtp_IE(0x0E, 1, "\xB8"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x11, 4, "\x76\x54\x32\x10");// TEID C
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x1A, 2, "\x04\x00");//Charging characteristics
	write_gtp_IE(0x80, 2, "\xf1\x21");//end user address
	write_gtp_IE(0x83, 18, "\x11" "access.point.name");//APN
	write_gtp_IE(0x84, 0x1d,"\x80\xc0\x23\x06\x01\x01\x00\x06"
							"\x00\x00\x80\x21\x10\x01\x01\x00"
							"\x10\x81\x06\x00\x00\x00\x00\x83"
							"\x06\x00\x00\x00\x00");// protocol config options
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x86, 6, "\x91\x21\x43\x65\x87\x09");//MSISDN
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x97, 1, "\x01"); //RAT type
	write_gtp_IE(0x98, 8, "\x01\x23\x45\x67\x89\xAB\xCD\xEF");// location information
	write_gtp_IE(0x99, 2, "\x23\x00"); // timezone
	write_gtp_IE(0x9A, 8, "\x10\x32\x54\x76\x98\x10\x32\x54"); // IMEI 012345678912345
	write_gtp_end(GTP_UP);
// (packet 14) - duff parameters
	write_gtp_start(1, 16, 0, 0x10);
	write_gtp_IE(0x02, 8, "\x10\x32\x54\x76\x98\xBA\xDC\xFE"); // IMSI 0123456789ABCDEF
	write_gtp_IE(0x03, 6, "\x01\x23\x45\x67\x89\xab"); // RAI:MCC=103; MNC=542; LAC=26505; RAC=171
	write_gtp_IE(0x0E, 1, "\xB8"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x11, 4, "\x76\x54\x32\x10");// TEID C
	write_gtp_IE(0x14, 1, "\xFF"); //duff NSAPI
	write_gtp_IE(0x1A, 2, "\x04\x00");//Charging characteristics
	write_gtp_IE(0x80, 2, "\xf1\x21");//end user address
	write_gtp_IE(0x83, 0, "");//APN
	write_gtp_IE(0x84, 0x1d,"\x80\xc0\x23\x06\x01\x01\x00\x06"
							"\x00\x00\x80\x21\x10\x01\x01\x00"
							"\x10\x81\x06\x00\x00\x00\x00\x83"
							"\x06\x00\x00\x00\x00");// protocol config options
	write_gtp_IE(0x85, 0, "");//SGSN signalling
	write_gtp_IE(0x85, 5, "\x7F\x00\x00\x01\x23");//SGSN user
	write_gtp_IE(0x86, 9, "\xF1\x21\x43\x65\x87\x09\xBA\xDC\xFE");//MSISDN
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x97, 1, "\xFF"); //RAT type
	write_gtp_IE(0x98, 8, "\x01\x23\x45\x67\x89\xAB\xCD\xEF");// location information
	write_gtp_IE(0x99, 2, "\x9A\x00"); // timezone of doom
	write_gtp_IE(0x9A, 32, "\xFF\xEE\xDD\xCC\xBB\xAA\x32\x54"
							"\x10\x32\x54\x76\x98\x10\x32\x54"
							"\x10\x32\x54\x76\x98\x10\x32\x54"
							"\x10\x32\x54\x76\x98\x10\x32\x54"); // IMEI of doom
	write_gtp_end(GTP_UP);
//
//(17) In "Create PDP Context Response":-
// (packet 15, 16, 17) - Some error responses
    write_gtp_start(1, 0x11, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\xdb"); //cause "Missing or unknown APN"
    write_gtp_end(GTP_DOWN);
    write_gtp_start(1, 0x11, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\xC1"); //cause "Invalid message format"
    write_gtp_end(GTP_DOWN);
    write_gtp_start(1, 0x11, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\xe6"); //cause "Bearer handling not supported"
    write_gtp_end(GTP_DOWN);
// (packet 18) - out-of-order type elements including wierd one
    write_gtp_start(1, 0x11, 0x76543210, 0x10); 
	write_gtp_IE(241, 5, "fnord"); // unknown IE
	write_gtp_IE(0xFB, 4, "\xC0\xA8\x00\x01");
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x84, 0x1d,"\x80\xc0\x23\x06\x01\x01\x00\x06"
							"\x00\x00\x80\x21\x10\x01\x01\x00"
							"\x10\x81\x06\x00\x00\x00\x00\x83"
							"\x06\x00\x00\x00\x00");// protocol config options
	write_gtp_IE(0x80, 8, "\xf1\x21\xC0\xA8\x0D\x17\x12\x32");//end user address
	write_gtp_IE(0x7f, 4, "\xFE\xDC\xBA\x98");// Charging ID
	write_gtp_IE(0x11, 4, "\x76\x54\x32\x10");// TEID C
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
    write_gtp_end(GTP_DOWN);
// (packet 19) - Only mandatory parameters
    write_gtp_start(1, 0x11, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
    write_gtp_end(GTP_DOWN);
// (packet 20) - some parameters duplicated
    write_gtp_start(1, 0x11, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x11, 4, "\x76\x54\x32\x10");// TEID C
	write_gtp_IE(0x7f, 4, "\xFE\xDC\xBA\x98");// Charging ID
	write_gtp_IE(0x80, 6, "\xf1\x21\xC0\xA8\x0D\x17");//end user address
	write_gtp_IE(0x84, 0x1d,"\x80\xc0\x23\x06\x01\x01\x00\x06"
							"\x00\x00\x80\x21\x10\x01\x01\x00"
							"\x10\x81\x06\x00\x00\x00\x00\x83"
							"\x06\x00\x00\x00\x00");// protocol config options
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0xFB, 4, "\xC0\xA8\x00\x01");
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x11, 4, "\x76\x54\x32\x10");// TEID C
	write_gtp_IE(0x7f, 4, "\xFE\xDC\xBA\x98");// Charging ID
	write_gtp_IE(0x80, 6, "\xf1\x21\xC0\xA8\x0D\x17");//end user address
	write_gtp_IE(0x84, 0x1d,"\x80\xc0\x23\x06\x01\x01\x00\x06"
							"\x00\x00\x80\x21\x10\x01\x01\x00"
							"\x10\x81\x06\x00\x00\x00\x00\x83"
							"\x06\x00\x00\x00\x00");// protocol config options
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0xFB, 4, "\xC0\xA8\x00\x01");
    write_gtp_end(GTP_DOWN);
// (packet 21) - duff parameters
    write_gtp_start(1, 0x11, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x11, 4, "\x76\x54\x32\x10");// TEID C
	write_gtp_IE(0x7f, 4, "\xFE\xDC\xBA\x98");// Charging ID
	write_gtp_IE(0x80, 8, "\xf1\x21\xC0\xA8\x0D\x17\x12\x32");//end user address
	write_gtp_IE(0x84, 0x1d,"\x80\xc0\x23\x06\x01\x01\x00\x06"
							"\x00\x00\x80\x21\x10\x01\x01\x00"
							"\x10\x81\x06\x00\x00\x00\x00\x83"
							"\x06\x00\x00\x00\x00");// protocol config options
	write_gtp_IE(0x85, 5, "\x7F\x00\x00\x01\x23");//SGSN signalling
	write_gtp_IE(0x85, 0, "");//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0xFB, 4, "\xC0\xA8\x00\x01");
    write_gtp_end(GTP_DOWN);
// 
//(18) In "Update PDP Context Request":-
// (packet 22) - out-of-order type elements including wierd one
    write_gtp_start(1, 0x12, 0x76543210, 0x10); 
	write_gtp_IE(242, 5, "fnord"); // unknown IE
	write_gtp_IE(0xB6, 1, "\x01"); // direct tunnel flags
	write_gtp_IE(0x99, 2, "\x23\x00"); // timezone
	write_gtp_IE(0x98, 8, "\x01\x23\x45\x67\x89\xAB\xCD\xEF");// location information
	write_gtp_IE(0x97, 1, "\x01"); //RAT type
	write_gtp_IE(0x94, 1, "\x10"); // common flags
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x86, 6, "\x91\x21\x43\x65\x87\x09");//MSISDN
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x0E, 1, "\x81"); // recovery
	write_gtp_IE(0x03, 6, "\x01\x23\x45\x67\x89\xab"); // RAI:MCC=103; MNC=542; LAC=26505; RAC=171
    write_gtp_end(GTP_UP);
// (packet 23) - Only mandatory parameters
    write_gtp_start(1, 0x12, 0x76543210, 0x10); 
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
    write_gtp_end(GTP_UP);
// (packet 24) - some parameters duplicated
    write_gtp_start(1, 0x12, 0x76543210, 0x10); 
	write_gtp_IE(0x03, 6, "\x01\x23\x45\x67\x89\xab"); // RAI:MCC=103; MNC=542; LAC=26505; RAC=171
	write_gtp_IE(0x0E, 1, "\x81"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x86, 6, "\x91\x21\x43\x65\x87\x09");//MSISDN
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x94, 1, "\x10"); // common flags
	write_gtp_IE(0x97, 1, "\x01"); //RAT type
	write_gtp_IE(0x98, 8, "\x01\x23\x45\x67\x89\xAB\xCD\xEF");// location information
	write_gtp_IE(0x99, 2, "\x23\x00"); // timezone
	write_gtp_IE(0xB6, 1, "\x01"); // direct tunnel flags
	write_gtp_IE(0x03, 6, "\x01\x23\x45\x67\x89\xab"); // RAI:MCC=103; MNC=542; LAC=26505; RAC=171
	write_gtp_IE(0x0E, 1, "\x81"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x86, 6, "\x91\x21\x43\x65\x87\x09");//MSISDN
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x94, 1, "\x10"); // common flags
	write_gtp_IE(0x97, 1, "\x01"); //RAT type
	write_gtp_IE(0x98, 8, "\x01\x23\x45\x67\x89\xAB\xCD\xEF");// location information
	write_gtp_IE(0x99, 2, "\x23\x00"); // timezone
	write_gtp_IE(0xB6, 1, "\x01"); // direct tunnel flags
    write_gtp_end(GTP_UP);
// (packet 24) - duff parameters
    write_gtp_start(1, 0x12, 0x76543210, 0x10); 
	write_gtp_IE(0x03, 6, "\x01\xFF\x45\xFF\x89\xab"); // RAI:MCC=103; MNC=542; LAC=26505; RAC=171
	write_gtp_IE(0x0E, 1, "\x81"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x14, 1, "\xFF"); //duff NSAPI
	write_gtp_IE(0x85, 6, "\x7F\x00\x00\x01\x3F\x97");//SGSN signalling
	write_gtp_IE(0x85, 2, "\x7F\x01");//SGSN user
	write_gtp_IE(0x86, 9, "\xF1\x21\x43\x65\x87\x09\xBA\xDC\xFE");//MSISDN
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x94, 1, "\x10"); // common flags
	write_gtp_IE(0x97, 1, "\xFF"); //RAT type
	write_gtp_IE(0x98, 8, "\x01\x23\x45\x67\x89\xAB\xCD\xEF");// location information
	write_gtp_IE(0x99, 2, "\x9A\x00"); // timezone of doom
	write_gtp_IE(0xB6, 1, "\x01"); // direct tunnel flags
    write_gtp_end(GTP_UP);
//
//(19) In "Update PDP Context Response":-
// (packet 26, 27, 28) - Some error responses
    write_gtp_start(1, 0x13, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\xC0"); //cause "Non-Existent"
    write_gtp_end(GTP_DOWN);
    write_gtp_start(1, 0x13, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\xd9"); //cause "Semantic Errors in Packet Filters"
    write_gtp_end(GTP_DOWN);
    write_gtp_start(1, 0x13, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\xE3"); //cause "Bearer Control Mode Violation"
    write_gtp_end(GTP_DOWN);
// (packet 29) - out-of-order type elements including wierd one
    write_gtp_start(1, 0x13, 0x76543210, 0x10); 
	write_gtp_IE(243, 5, "fnord"); // unknown IE
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x7f, 4, "\xFE\xDC\xBA\x98");// Charging ID
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
    write_gtp_end(GTP_DOWN);
// (packet 30) - Only mandatory parameters
    write_gtp_start(1, 0x13, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
    write_gtp_end(GTP_DOWN);
// (packet 31) - some parameters duplicated
    write_gtp_start(1, 0x13, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x7f, 4, "\xFE\xDC\xBA\x98");// Charging ID
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x7f, 4, "\xFE\xDC\xBA\x98");// Charging ID
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
    write_gtp_end(GTP_DOWN);
// (packet 32) - duff parameters
    write_gtp_start(1, 0x13, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(0x0E, 1, "\x05"); // recovery
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x7f, 4, "\xFE\xDC\xBA\x98");// Charging ID
	write_gtp_IE(0x85, 16, "\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00");//SGSN signalling
	write_gtp_IE(0x85, 1, "\x01");//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
    write_gtp_end(GTP_DOWN);
//
//(20) In "Delete PDP Context Request":-
// (packet 33) - out-of-order type elements including wierd one
    write_gtp_start(1, 0x14, 0x76543210, 0x10); 
	write_gtp_IE(244, 5, "fnord"); // unknown IE
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
    write_gtp_IE(0x13, 1, "\xFF"); //teardown ind
    write_gtp_end(GTP_UP);
// (packet 34) - Only mandatory parameters
    write_gtp_start(1, 0x14, 0x76543210, 0x10); 
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
    write_gtp_end(GTP_UP);
// (packet 35) - some parameters duplicated
    write_gtp_start(1, 0x14, 0x76543210, 0x10); 
    write_gtp_IE(0x13, 1, "\xFF"); //teardown ind
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
    write_gtp_IE(0x13, 1, "\xFF"); //teardown ind
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
    write_gtp_end(GTP_UP);
// (packet 36) - duff parameters/
    write_gtp_start(1, 0x14, 0x76543210, 0x10); 
    write_gtp_IE(0x13, 1, "\x55"); //duff Teardown ind
	write_gtp_IE(0x14, 1, "\xFF"); //duff NSAPI
    write_gtp_end(GTP_UP);
//
//(21) In "Delete PDP Context Response":-
// (packet 37,38, 39) - Some error responses
    write_gtp_start(1, 0x15, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\xC9"); //cause "Mandatory IE incorrect"
    write_gtp_end(GTP_DOWN);
    write_gtp_start(1, 0x15, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\xCA"); //cause "Mandatory IE missing"
    write_gtp_end(GTP_DOWN);
    write_gtp_start(1, 0x15, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\xCB"); //cause "Optional IE incorrect"
    write_gtp_end(GTP_DOWN);
// (packet 40) - out-of-order type elements including wierd one
    write_gtp_start(1, 0x15, 0x76543210, 0x10); 
	write_gtp_IE(245, 5, "fnord"); // unknown IE
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
    write_gtp_end(GTP_DOWN);
// (packet 41) - some parameters duplicated
    write_gtp_start(1, 0x15, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
    write_gtp_end(GTP_DOWN);
// (packet 42) - duff parameters	
    write_gtp_start(1, 0x15, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\xF0"); //cause "for future use"
    write_gtp_end(GTP_DOWN);
	write_pcap_end();
}
