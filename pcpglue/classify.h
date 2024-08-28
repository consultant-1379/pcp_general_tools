

#ifndef CLASSIFY_H
# define CLASSIFY_H
# include <pcap.h>

/*
 * Wrapper for the classifier.  The classify data is stored as an 
 * incomplete type so that it is agnostic about the underlying 
 * classification engine.
 */
typedef struct classify_data_struct *classify_data;

typedef struct ether {
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short int type;
} ether_t;

classify_data classify_start(void);

void classify_end(classify_data cd);

void classify(classify_data cd, const struct pcap_pkthdr *h, const char *bytes);

void classify_print_log(FILE *output);



//
// Ethernet definitions
//
#define TAG_ETHER_802_1_Q_LENGTH 4  // The length of a 802.1Q tag in octets

//
// GTP-C and GTP-U ports
//
#define GTP_C_UDP_PORT	2123
#define GTP_U_UDP_PORT	2152

//
// GTP versions
//
#define GTP_V1_TYPEVER 3      // GTP V1 is the version and GTP is the type

//
// Mandatory part of the GTP header
//
struct gtpv1hdr {
	u_char	flag_options:3,   // Extension, Sequence Number, and N-PDU flags
			flag_reserved:1,  // Reserved for future use
			flag_typever:4;   // The GTP message type and version
	u_char  message_type;     // The GTP message type
	u_short length;           // Total length excluding initial mandatory header (length includes optional fields)
	u_int   teid;             // The TEID (Tunnel End Point Identifier)
};

//
// Macros to get GTP Type and Version
//
#define GTP_TYPE(flag_typever)		((flag_typever) >> 1)
#define GTP_VER(flag_typever)		((flag_typever) & 0x01)

//
// Macros to get GTP option flags
//
#define GTP_EXT_FLAG(flag_options)		(((flag_options) & 0x04) >> 2)
#define GTP_SEQ_FLAG(flag_options)		(((flag_options) & 0x02) >> 1)
#define GTP_NPDU_FLAG(flag_options)		(((flag_options) & 0x01))

//
// Optional part of the GTP-U header
// This field follows the gtpv1 struct if any of the extension header, sequence number, or N-PDU bits are set,
// if any of those bits are set, all the optional field must appear. The values only make sense if the respective
// bit is set
struct gtpv1hdropt {
	u_short sequence_no;     // The sequence number of the GTP packet
	u_char  npdu_no;         // The N-PDU number
	u_char  next_exthdrtype; // The next extension header type
};

//
// This function returns a pointer to a GTPv1 header in a packet in a data buffer
//
// Parameters:
//  const unsigned int length: The amount of data present in the data buffer
//  const unsigned char* data: A pointer to the packet data
//
// Return:
//  gtpv1hdr*: A pointer to a GTP V1 header if a GTP V1 packet is present, NULL otherwise
//
struct gtpv1hdr* gtpv1_get_header(const unsigned int length, const unsigned char* data);

#endif
