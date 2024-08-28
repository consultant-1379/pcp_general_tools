/* written by klaus degner, ipoque GmbH
 * klaus.degner@ipoque.com
 */

#ifndef __IPOQUE_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE IPQ_API.H
#endif

#ifndef __IPQ_DECAPSULATION_H__
#define __IPQ_DECAPSULATION_H__


#ifdef __KERNEL__
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#else
#include <linux/if_ether.h>
#endif							/* __KERNEL__ */

typedef enum ipq_decaps_protocol_enum {
	IPQ_NEXT_UNKNOWN = 0,
	IPQ_NEXT_L2_ETHERNET,
	IPQ_NEXT_L3_IPv4,
	IPQ_NEXT_L3_IPv6,
	IPQ_NEXT_L4_TCP,
	IPQ_NEXT_L4_UDP,
	IPQ_NEXT_L4_OTHER,
	IPQ_NEXT_L7,
} ipq_decaps_protocol_enum_t;

#define IPQ_MAX_VLAN_LABELS		5
#define IPQ_MAX_MPLS_LABELS		5

typedef struct ipq_iso_layer_2_info_data {
	u16 offset;
	u16 length;
	enum ipq_decaps_protocol_enum next;

	u8 vlan_count;
	u8 mpls_count;

	u16 vlan_label[IPQ_MAX_VLAN_LABELS];
	u16 mpls_label[IPQ_MAX_MPLS_LABELS];
} ipq_iso_layer_2_info_data_t;



/* this is the main l2 decapsulation function
 * return value == 0: l2data and decap_data are valid, < 0 they are NOT valid (here values -1 to -99), > 1: reqiures more data (current_accessible_data_length too small)
 * input values
 *  - packet_data_at_l2 : pointer to the packet
 *  - current_accessible_data_length : packet length for access
 *  - current_complete_data_length : complete packet length
 *  - type : type of packet, currently only IPQ_NEXT_L2_ETHERNET is supported
 *  - l2data: l2 info, see structure for access 
 */

static inline int ipoque_detection_get_l2_data(const u8 * packet_data_at_l2, const u16 current_accessible_data_length,
											   const u16 current_complete_data_length,
											   enum ipq_decaps_protocol_enum type,
											   struct ipq_iso_layer_2_info_data *l2data)
{
	const u16 type_max_length = current_accessible_data_length - 2;

	switch (type) {

	case IPQ_NEXT_L2_ETHERNET:

		l2data->vlan_count = 0;
		l2data->mpls_count = 0;
		l2data->offset = 12;	/* length of MAC SRC and MAC DST */
		while (type_max_length >= l2data->offset) {
			const u16 etype = ntohs(((u16 *) (&packet_data_at_l2[l2data->offset]))[0]);
			switch (etype) {
			case ETH_P_IP:
				/* this add is safe due max length */
				l2data->offset += 2;
				l2data->length = current_complete_data_length - l2data->offset;
				l2data->next = IPQ_NEXT_L3_IPv4;
				return 0;
				break;
			case ETH_P_IPV6:
				/* this add is safe due max length */
				l2data->offset += 2;
				l2data->length = current_complete_data_length - l2data->offset;
				l2data->next = IPQ_NEXT_L3_IPv6;
				return 0;
				break;
			case ETH_P_8021Q:
				if ((l2data->offset + 4) > type_max_length)
					return -1;

				if (l2data->vlan_count < IPQ_MAX_VLAN_LABELS) {
					l2data->vlan_label[l2data->vlan_count] =
						ntohs(((u16 *) (&packet_data_at_l2[l2data->offset + 2]))[0]);
					l2data->vlan_count++;
				}
				l2data->offset += 4;
				/* and loop again */
				break;
			case ETH_P_PPP_SES:
				/* TODO etypeoffset += 4; */
				return -2;
				break;
			case ETH_P_MPLS_UC:
				/* this add is safe due max length */
				l2data->offset += 2;
				l2data->length = current_complete_data_length - l2data->offset;

				while(1)
				{
					if ((l2data->offset + 4) > l2data->length)
						return -1;

					/* store mpls label */
					if (l2data->mpls_count < IPQ_MAX_MPLS_LABELS) {
						l2data->mpls_label[l2data->mpls_count] =
							ntohl(((u32 *) (&packet_data_at_l2[l2data->offset]))[0]) >> 12;
						l2data->mpls_count++;
					}
					/* check for bottom of label stack */
					if ((packet_data_at_l2[l2data->offset + 2] & 0x01) == 1)
					{
						break;
					}
					/* not the bottom, check next level */
					l2data->offset += 4;
				}

				/* this add is safe due max length */
				l2data->offset += 4;
				l2data->length = current_complete_data_length - l2data->offset;

				/* bottom of stack ...
				 * we do not really know what to expect after this point
				 * so we try to make an educated guess */

				if(sizeof(struct iphdr) < l2data->length) {
					/* check for IP */
					struct iphdr *iph = (struct iphdr *)(&packet_data_at_l2[l2data->offset]);
					if (iph->version == 4) {
						if (ntohs(iph->tot_len) <= l2data->length) {
							/* looks like an IPv4 header */
							l2data->next = IPQ_NEXT_L3_IPv4;
							return 0;
						}
					} else
					if (iph->version == 6 && sizeof(struct ip6_hdr) < l2data->length) {
						struct ip6_hdr *ip6h = (struct ip6_hdr *)iph;
						if (ntohs(ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ip6_hdr) <= l2data->length) {
							/* looks like an IPv6 header */
							l2data->next = IPQ_NEXT_L3_IPv6;
							return 0;
						}
					}
				}

				/* no IP ... so act as if ethernet */
				if (l2data->length >= sizeof(struct ether_header)) {
					/* and loop again */
					break;
				} else {
					return -3;
				}
				return 0;
				break;
			default:
				return -4;
			}
		}

		if (current_accessible_data_length < current_complete_data_length) {
			return 1;
		}
		/* packet to small */
		return -5;
		break;

	default:
		return -6;
	}
}



typedef struct ipq_iso_layer_3_info_data {
	u16 offset;
	u16 length;
	u8 requires_pace_detection;

	u8 *l3_src_ptr;
	u8 *l3_dst_ptr;
	u8 l3_src_len;
	u8 l3_dst_len;
	enum ipq_decaps_protocol_enum next;

	/* todo more information here for decaps stuff */

} ipq_iso_layer_3_info_data_t;


static inline int ipoque_detection_get_l3_data(const u8 * packet_data_at_l3, const u16 current_accessible_data_length,
											   const u16 current_complete_data_length,
											   const enum ipq_decaps_protocol_enum type,
											   struct ipq_iso_layer_3_info_data *l3data)
{

	switch (type) {
	case IPQ_NEXT_L3_IPv4:
		{
			const struct iphdr *iph = (const struct iphdr *) packet_data_at_l3;

			/* check header length and offset, header must be at least 20 bytes long, ipv4 header length >= 4 and ihl * 4 <= current_data_length */
			if (current_accessible_data_length < 20 || current_accessible_data_length < (iph->ihl << 2)) {
				if (current_complete_data_length >= 20 && current_complete_data_length >= (iph->ihl << 2)) {
					return 1;
				}
				/* ipv4 header too short */
				return -100;
			}

			if (iph->version != 4) {
				/* wrong version */
				return -102;
			}

			if (current_complete_data_length < ntohs(iph->tot_len)) {
				/* packet too small */
				return -101;
			}
			/* set offset and header to next level */
			l3data->offset = iph->ihl << 2;
			l3data->length = ntohs(iph->tot_len) - l3data->offset;
			l3data->requires_pace_detection = 0;

			l3data->l3_src_ptr = (u8 *) & iph->saddr;
			l3data->l3_src_len = 4;
			l3data->l3_dst_ptr = (u8 *) & iph->daddr;
			l3data->l3_dst_len = 4;

			switch (iph->protocol) {
			case IPPROTO_TCP:
				l3data->next = IPQ_NEXT_L4_TCP;
				return 0;
			case IPPROTO_UDP:
				l3data->next = IPQ_NEXT_L4_UDP;
				return 0;
			default:
				l3data->requires_pace_detection = 1;
				l3data->next = IPQ_NEXT_L4_OTHER;
				return 0;
			}
		}
		break;
	case IPQ_NEXT_L3_IPv6:
		{
			const struct ipv6hdr *ip6h = (const struct ipv6hdr *) packet_data_at_l3;
			u16 pl_len;
			u16 l3_len;
			/* check header length and offset, header must be at least sizeof(struct ipv6hdr) */
			if (current_accessible_data_length < sizeof(struct ipv6hdr)) {
				if (current_complete_data_length >= sizeof(struct ipv6hdr)) {
					return 1;
				}
				/* ipv6 header too short */
				return -110;
			}

			if (ip6h->version != 6) {
				/* wrong version */
				return -102;
			}

			pl_len = ntohs(ip6h->payload_len);
			l3_len = pl_len + sizeof(struct ipv6hdr);

			if (current_complete_data_length < pl_len || current_complete_data_length < l3_len) {
				/* packet too small */
				return -111;
			}
			/* set offset and header to next level */
			l3data->offset = sizeof(struct ipv6hdr);
			l3data->length = pl_len;
			l3data->requires_pace_detection = 0;

			l3data->l3_src_ptr = (u8 *) & ip6h->saddr;
			l3data->l3_src_len = sizeof(ip6h->saddr);
			l3data->l3_dst_ptr = (u8 *) & ip6h->daddr;
			l3data->l3_dst_len = sizeof(ip6h->daddr);

#ifdef __KERNEL__
			switch (ip6h->nexthdr) {
#else
			switch (ip6h->protocol) {
#endif
			case IPPROTO_TCP:
				l3data->next = IPQ_NEXT_L4_TCP;
				return 0;
			case IPPROTO_UDP:
				l3data->next = IPQ_NEXT_L4_UDP;
				return 0;
			default:
				l3data->requires_pace_detection = 1;
				l3data->next = IPQ_NEXT_L4_OTHER;
				return 0;
			}

		}
	default:
		return -198;
	}
	return -199;
}

typedef struct ipq_iso_layer_4_info_data {
	u16 offset;
	u16 length;

	/* both values are in HOST BYTE ORDER */
	u16 src_port;
	u16 dst_port;

	u8 requires_pace_detection;
	enum ipq_decaps_protocol_enum next;
} ipq_iso_layer_4_info_data_t;


static inline int ipoque_detection_get_l4_data(const u8 * packet_data_at_l4, const u16 current_accessible_data_length,
											   const u16 current_complete_data_length,
											   const enum ipq_decaps_protocol_enum type,
											   struct ipq_iso_layer_4_info_data *l4data)
{
	switch (type) {
	case IPQ_NEXT_L4_TCP:
		{
			const struct tcphdr *tcph = (const struct tcphdr *) packet_data_at_l4;
			/* requires at least 14 bytes for tcp sport and dport and doff access */
			if (current_accessible_data_length < 14 || current_accessible_data_length < (tcph->doff << 2)) {
				if (current_complete_data_length >= 14 && current_complete_data_length >= (tcph->doff << 2)) {
					/* not enough data... */
					return 1;
				}
				/* tcp header too short */
				return -200;
			}

			l4data->src_port = ntohs(tcph->source);
			l4data->dst_port = ntohs(tcph->dest);
			l4data->requires_pace_detection = 1;
			l4data->next = IPQ_NEXT_L7;
			l4data->offset = tcph->doff << 2;
			l4data->length = current_complete_data_length - l4data->offset;
			return 0;
		}
		break;
	case IPQ_NEXT_L4_UDP:
		{
			const struct udphdr *udph = (const struct udphdr *) packet_data_at_l4;
			/* requires at least 14 bytes for ucp sport and dport and doff */

			if (current_accessible_data_length < 4) {
				if (current_complete_data_length >= 4) {
					/* not enough data... */
					return 1;
				}
				/* tcp header too short */
				return -201;
			}

			l4data->src_port = ntohs(udph->source);
			l4data->dst_port = ntohs(udph->dest);
			l4data->requires_pace_detection = 1;
			l4data->next = IPQ_NEXT_L7;
			l4data->offset = 8;
			l4data->length = current_complete_data_length - l4data->offset;
			return 0;
		}
		break;
	default:
		return -202;
	}
	return -203;
}

#endif
