
#include "gtp_hack.h"

/*****************************************
 * This produces a pcap file containing GTP-C traffic which has the
 * mandatory fields only.  It is used to test that the GTP decoder
 * deals with empty fields correctly.
 */

int main(void)
{
	write_pcap_start("./empty.pcap");
//
//(16) In "Create PDP Context Request":-
// (packet 12) - Only mandatory parameters
	write_gtp_start(1, 16, 0, 0x10);
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x11, 4, "\x76\x54\x32\x10");// TEID C
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
	write_gtp_end(GTP_UP);
//
//(17) In "Create PDP Context Response":-
// (packet 19) - Only mandatory parameters
    write_gtp_start(1, 0x11, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
	write_gtp_IE(0x11, 4, "\x76\x54\x32\x10");// TEID C
    write_gtp_end(GTP_DOWN);
// 
//(18) In "Update PDP Context Request":-
// (packet 23) - Only mandatory parameters
    write_gtp_start(1, 0x12, 0x76543210, 0x10); 
	write_gtp_IE(0x10, 4, "\x01\x23\x45\x67");// TEID 1
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN signalling
	write_gtp_IE(0x85, 4, "\x7F\x00\x00\x01");//SGSN user
	write_gtp_IE(0x87, 15, "\x02\x13\x92\x1F\x73\x96\xd1\xfe\x74\x82\x40\x40\x00\x5c\x00");//QOS profile
    write_gtp_end(GTP_UP);
//
//(19) In "Update PDP Context Response":-
// (packet 30) - Only mandatory parameters
    write_gtp_start(1, 0x13, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
    write_gtp_end(GTP_DOWN);
//
//(20) In "Delete PDP Context Request":-
// (packet 34) - Only mandatory parameters
    write_gtp_start(1, 0x14, 0x76543210, 0x10); 
	write_gtp_IE(0x14, 1, "\x05"); //NSAPI
    write_gtp_end(GTP_UP);
//
//(21) In "Delete PDP Context Response":-
// (packet 37,38, 39) - Some error responses
// (packet 40) - Only mandatory parameters
    write_gtp_start(1, 0x15, 0x76543210, 0x10); 
	write_gtp_IE(1, 1, "\x80"); //cause "Request accepted"
    write_gtp_end(GTP_DOWN);
//
	write_pcap_end();
}
