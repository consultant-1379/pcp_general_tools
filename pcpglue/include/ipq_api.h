/* written by klaus degner, ipoque GmbH
 * klaus.degner@ipoque.com
 */

/* SPECIFIC COMPILE DIRECTIVES
 * if IPOQUE_CUST1 is defined,
 *    this module will compile this module for customer 1 only
 * if IPOQUE_USE_PRX_PROTOCOLS_ONLY is defined, this module will compile PRX detections only
 * with no definitions, this will be compiled for all protocols (also all beta/testing modules)
 */

#ifndef __IPOQUE_API_INCLUDE_FILE__
#define __IPOQUE_API_INCLUDE_FILE__
#ifdef __cplusplus
extern "C" {
#endif

/* two different PACE version numbers: change synchronously */
#define IPOQUE_PACE_VERSION		"1.44"
/* IPOQUE_PACE_VERSION_NUMBER format: XXXXYYYYZZZZ (without leading 0's) */
#define IPOQUE_PACE_VERSION_NUMBER 100440000

	/* this number indicates that the current library must not be loaded
	 * by a PACE version older than this number */
#define IPOQUE_PACE_DYNAMIC_UPGRADE_COMPATIBLE_VERSION_NUMBER 100420000

	/**
	 * API version number
	 *
	 * the version is increased whenever the API changes, it may or
	 * may not be binary compatible if the number changes
	 */
#define IPOQUE_PACE_API_VERSION 24

/* basic definitions (u64, u32, timestamp size,...) */
#include "ipq_basic_def.h"

/* protocol definitions for customers who need a subset of protocols only */
#if defined( IPOQUE_CUST1 )
#  include "ipq_protocols_cust1.h"
#elif defined( IPOQUE_USE_CUST2_PROTOCOLS_ONLY )
#  include "ipq_protocols_cust2.h"
#elif defined( IPOQUE_USE_PRX_PROTOCOLS_ONLY )

#  define IPOQUE_PACE_API_MK1     /* PRX uses Mk1 for now */
#  include "ipq_protocols_prx.h"

#elif defined( IPOQUE_USE_CUST3_PROTOCOLS_ONLY )
#  include "ipq_protocols_cust3.h"
#elif defined( IPOQUE_USE_CUST4_PROTOCOLS_ONLY )
#  include "ipq_protocols_cust4.h"
#else
#  include "ipq_protocols_default.h"
#endif

#include "ipq_protocol_subtypes.h"

#include "ipq_protocol_groups.h"

#include "ipq_applications.h"

/* macros for protocol / bitmask conversation if needed */
#include "ipq_macros.h"

/* this include file is deprecated with using the library with > 64 protocols */
#include "ipq_bitmask_definitions.h"

#include "ipq_public_functions.h"

#include "ipq_debug_functions.h"

#include "ipq_timeorderedhash.h"

#include "ipq_paro.h"

#ifdef IPOQUE_INTEGRATE_DECAPSULATION_CODE
#include "ipq_decapsulation.h"
#endif

/* fastpath definitions
 * the ipoque library uses an internal fastpath function by default
 * it is prepared to use a NPU fastpath in future
 */

#ifdef IPOQUE_USE_INTERNAL_FASTPATH
#include "ipq_internal_fastpath.h"
#endif							/* IPOQUE_USE_INTERNAL_FASTPATH */

#include "ipq_application_level_firewall_mode.h"

#ifdef IPOQUE_GENERIC_FINAL_STATE_MACHINE
#include "ipq_generic_final_state_machine.h"
#endif							/* IPOQUE_GENERIC_FINAL_STATE_MACHINE */

//#ifdef IPOQUE_USER_DEFINED_PROTOCOLS
#include "ipq_user_defined_protocols.h"
//#endif                                /* IPOQUE_USER_DEFINED_PROTOCOLS */



#ifdef __cplusplus
}
#endif
#endif							/* __IPOQUE_API_INCLUDE_FILE__ */
