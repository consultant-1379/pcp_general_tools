/* written by klaus degner, ipoque GmbH
 * klaus.degner@ipoque.com
 */

#ifndef __IPOQUE_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE IPQ_API.H
#endif

#ifndef __IPQ_APPLICATION_LEVEL_FIREWALL_MODE_H__
#define __IPQ_APPLICATION_LEVEL_FIREWALL_MODE_H__

#ifdef __cplusplus
extern "C" {
#endif

/* debug functions */

	/**
	 * function returns a pointer to the static exclude bitmask for tcp
	 * @param ipoque_struct the detection module, not NULL
	 * @return pointer to the bitmask
	 */
	IPOQUE_PROTOCOL_BITMASK *ipoque_get_static_excluded_tcp_bitmask(struct
																	ipoque_detection_module_struct
																	*ipoque_struct);

	/**
	 * function returns a pointer to the static exclude bitmask for udp
	 * @param ipoque_struct the detection module, not NULL
	 * @return pointer to the bitmask
	 */
	IPOQUE_PROTOCOL_BITMASK *ipoque_get_static_excluded_udp_bitmask(struct
																	ipoque_detection_module_struct
																	*ipoque_struct);

	/**
	 * function returns a pointer to the static exclude bitmask for none tcp, none udp
	 * @param ipoque_struct the detection module, not NULL
	 * @return pointer to the bitmask
	 */
	IPOQUE_PROTOCOL_BITMASK *ipoque_get_static_excluded_non_tcp_udp_bitmask(struct
																			ipoque_detection_module_struct
																			*ipoque_struct);

#ifdef __cplusplus
}
#endif
#endif
