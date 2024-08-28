/* written by klaus degner, ipoque GmbH
 * klaus.degner@ipoque.com
 */

#ifndef __IPOQUE_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE IPQ_API.H
#endif

#ifndef __IPQ_GENERIC_FINAL_STATE_MACHINE_H__
#define __IPQ_GENERIC_FINAL_STATE_MACHINE_H__

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * Resets the final state machine.
	 * @param ipoque_struct the detection module, not NULL
	 */
	void ipoque_detection_reset_fsm_engine(struct
										   ipoque_detection_module_struct
										   *ipoque_struct);

	/**
	 * returns the number of succesfully parsed rules
	 * @param ipoque_struct the detection module, not NULL
	 * @param ptr pointer to the text to parse
	 * @param len length of the text to parse
	 * @param ipoque_malloc allocation function pointer, not NULL
	 * @return returns the number parsed rules
	 */
	u32 ipoque_detection_load_fsm_pattern(struct ipoque_detection_module_struct
										  *ipoque_struct, u8 * ptr, u32 len,
										  void *(*ipoque_malloc) (unsigned long size));

#ifdef __cplusplus
}
#endif
#endif
