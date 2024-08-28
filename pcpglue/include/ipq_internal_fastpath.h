/* written by klaus degner, ipoque GmbH
 * klaus.degner@ipoque.com
 */

#ifndef __IPOQUE_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE IPQ_API.H
#endif

#ifndef __IPQ_INTERNAL_FASTPATH_H__
#define __IPQ_INTERNAL_FASTPATH_H__

#ifdef __cplusplus
extern "C" {
#endif

#define IPOQUE_DETECTION_FASTPATH_ON		0
#define IPOQUE_DETECTION_FASTPATH_OFF		1

	/**
 	 * set the fastpath mode, default is IPOQUE_DETECTION_FASTPATH_ON
	 * @param ipoque_struct the detection module, not NULL
	 * @param ipoque_fastpath_mode fastpath mode, possible: IPOQUE_DETECTION_FASTPATH_ON, IPOQUE_DETECTION_FASTPATH_OFF
	 * @return != 0 error
	 */
	u8 ipoque_set_internal_fastpath_mode(struct ipoque_detection_module_struct
										 *ipoque_struct, u8 ipoque_fastpath_mode);

	/**
 	 * get the fastpath mode
	 * @param ipoque_struct the detection module, not NULL
	 * @return returns current fastpath mode
	 */
	u8 ipoque_get_internal_fastpath_mode(struct ipoque_detection_module_struct
										 *ipoque_struct);

#ifdef __cplusplus
}
#endif
#endif
