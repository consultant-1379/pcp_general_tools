/* written by klaus degner, ipoque GmbH
 * klaus.degner@ipoque.com
 */
/* OSDPI-START */
#ifndef __IPOQUE_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE IPQ_API.H
#endif

#ifndef __IPQ_PUBLIC_FUNCTIONS_H__
#define __IPQ_PUBLIC_FUNCTIONS_H__

#ifdef __cplusplus
extern "C" {
#endif
/* OSDPI-END */

/* get flow and id size */

/* PUBLIC FUNCTIONS, API DOCUMENTATION IN MANPAGES ONLY !! */

/* OSDPI-START */
	/**
	 * struct for a unique ipv4 flow address
	 */
	typedef struct ipoque_unique_flow_ipv4_address_struct {
		/**
		 * lower ip
		 */
		u32 lower_ip;
		/**
		 * upper ip
		 */
		u32 upper_ip;
		/* we need 3 dummies to fill up to ipv6 address size */
		/**
		 * this is only needed to become the same size like a unique ipv6 struct
		 */
		u64 dummy[3];
	} ipoque_unique_flow_ipv4_address_struct_t;

	/**
	 * struct for a unique ipv6 flow address
	 */
	typedef struct ipoque_unique_flow_ipv6_address_struct {
		/**
		 * lower ip
		 */
		u64 lower_ip[2];
		/**
		 * upper ip
		 */
		u64 upper_ip[2];
	} ipoque_unique_flow_ipv6_address_struct_t;

	/**
	 * struct for a unique ipv4 and ipv6 5-tuple (ip,ip,port,port,protocol)
	 */
	typedef struct ipoque_unique_flow_ipv4_and_6_struct {
		/* only ip addresses are different, to minimize compare operations for hash tables, store ipv4 or ipv6 always in the first bit */
		/**
		 * saves if it is a ipv6, if it false so it is a ipv4
		 */
		u16 is_ip_v6;
		/**
		 * the protocol, 16 bit wide for alignemt reasons
		 */
		u16 protocol;			/* for alignment reason, protocol is 16 bit, not 8 bit */
		/**
		 * the port of the lower ip address
		 */
		u16 lower_port;
		/**
		 * the port of the upper ip address
		 */
		u16 upper_port;
		union {
			/**
			 * the ipv4 flow address struct. use the same memory area like ipv6 (union)
			 */
			struct ipoque_unique_flow_ipv4_address_struct ipv4;
			/**
			 * the ipv6 flow address struct. use the same memory area like ipv4 (union)
			 */
			struct ipoque_unique_flow_ipv6_address_struct ipv6;
		} ip;
	} ipoque_unique_flow_ipv4_and_6_struct_t;

	typedef enum {

		IPQ_LOG_ERROR,
		IPQ_LOG_TRACE,
		IPQ_LOG_DEBUG
	} ipq_log_level_t;

	typedef void (*ipoque_debug_function_ptr) (u32 protocol,
											   void *module_struct, ipq_log_level_t log_level, const char *format, ...);

#ifdef IPOQUE_PACE_API_MK1

	/**
	 * This function returns the size of the flow struct
	 * DO NOT use this function when using the dynamic upgrade mode or CDPs, use ipoque_detection_get_sizeof_dynamic_ipoque_flow_struct for this
	 * @return the size of the flow struct
	 * @see ipoque_detection_get_sizeof_dynamic_ipoque_flow_struct
	 */
	u32 ipoque_detection_get_sizeof_ipoque_flow_struct(void);

	/**
	 * This function returns the size of the id struct
	 * DO NOT use this function when using the dynamic upgrade mode or CDPs, use ipoque_detection_get_sizeof_dynamic_ipoque_id_struct for this
	 * @return the size of the id struct
	 * @see ipoque_detection_get_sizeof_dynamic_ipoque_id_struct
	 */
	u32 ipoque_detection_get_sizeof_ipoque_id_struct(void);

#endif

#ifdef IPOQUE_CUST1
	/**
	 * This function returns a new initialized detection module. (IPOQUE_CUST1)
	 * @param ticks_per_second the ticks per second
	 * @param ticks_per_second_jiffies ticks per second with jiffies
	 * @param ipoque_malloc function pointer to a allocator for ram of the detection module
	 * @param ipoque_debug_printf a function pointer to a debug output function
	 * @return the initialized detection module
	 */
	struct ipoque_detection_module_struct *ipoque_init_detection_module(u32 ticks_per_second,
																		u32 ticks_per_second_jiffies, void
																		*(*ipoque_malloc)
																		 (unsigned
																		  long size),
																		ipoque_debug_function_ptr ipoque_debug_printf);
#else

	/**
	 * This function returns a new initialized detection module. (!IPOQUE_CUST1)
	 * @param ticks_per_second Timestamp resloution on the packet processing engine.
	 * It must be at least 10 (for 0.1 ms), recommended is 1000 for 1.0 ms.
	 * The timestamp must have 32 bit resolution.
	 * @param ipoque_malloc function pointer to a memory allocator, must not be NULL
	 * @param ipoque_debug_printf a function pointer to a debug output function, not NULL
	 * @return returns a pointer to the initialized structure if the call succeeded or NULL if it failed.
	 * It must be freed by ipoque_exit_detection_module at cleanup.
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 * NOTES SMP Handling
	 * The ipoque detection is SMP thread safe as long as every thread uses its own ipoque detection structure. If a structure
	 * has been successful created with ipoque_init_detection_module and initialized  with  ipoque_set_protocol_detection_bitmask,
	 * it can be cloned with ipoque_clone_root_detection_module to process multiple packets at the same time on different threads.
	 * See ipoque_detection_process_packet for more restrictions.
	 */
	struct ipoque_detection_module_struct *ipoque_init_detection_module(u32 ticks_per_second, void
																		*(*ipoque_malloc)
																		 (unsigned
																		  long size),
																		ipoque_debug_function_ptr ipoque_debug_printf);

	/**
	 * This function returns a new initialized detection module. (!CUST1)
	 * @param ticks_per_second the timestamp resolution per second (like 1000 for millisecond resolution)
	 * must be not zero
	 * @param ipoque_malloc function pointer to a memory allocator, will be used to allocate memory if not NULL
	 * @param userptr user defined pointer for allocation function, will be passed to ipoque_malloc if ipoque_malloc is not NULL
	 * one of the allocators needs to be not NULL or the initialization fails
	 * @param ipoque_debug_printf a function pointer to a debug output function, must be valid and not NULL
	 * @return the initialized detection module or NULL if failed
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	struct ipoque_detection_module_struct *ipoque_init_detection_module_ext(u32 ticks_per_second, void
																			*(*ipoque_malloc)
																			 (unsigned
																			  long size, void *userptr),
																			void *userptr,
																			ipoque_debug_function_ptr
																			ipoque_debug_printf);
#endif
/* OSDPI-END */

	/**
	 * This function returns a clone of the root detection module for SMP handling.
	 * @param root the root detection module, not NULL
	 * @param ipoque_malloc function pointer to a memory allocator
	 * @param ipoque_debug_printf a function pointer to a debug output function, can be NULL
	 * @return the clone of the root detection module or NULL if failed. It must be freed
       by ipoque_exit_detection_module at cleanup.
	 */
	struct ipoque_detection_module_struct
	*ipoque_clone_root_detection_module(struct ipoque_detection_module_struct
										*root,
										void *(*ipoque_malloc) (unsigned long
																size),
										void (*ipoque_debug_printf) (const char *format, ...));

	/**
	 * This function returns a clone of the root detection module for
	 * SMP handling. It's an extended function which also requires a
	 * free function pointer. It is recommended to use always use
	 * function instead of ipoque_clone_root_detection_module, and it
	 * is required to use this function if the dynamic upgrade feature
	 * is used.
	 *
	 * @param root the root detection module, not NULL
	 * @param ipoque_malloc function pointer to a memory allocator
	 * @param ipoque_free function pointer to a memory free funciton
	 * @param userptr pointer to memory functions
	 * @return the clone of the root detection module or NULL if failed. It must be freed
       by ipoque_exit_detection_module at cleanup.
	 */
	struct ipoque_detection_module_struct
	*ipoque_clone_root_detection_module_ext(struct ipoque_detection_module_struct *root,
											void *(*ipoque_malloc) (unsigned long size, void *userptr),
											void (*ipoque_free) (void *ptr, void *userptr), void *userptr);

	/**
	 * This function destroys the detection module
	 * @param ipoque_struct the detection module to get destroyed, can be NULL
	 * @param ipoque_free function pointer to a memory free function, not NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void
	 ipoque_exit_detection_module(struct ipoque_detection_module_struct
								  *ipoque_struct, void (*ipoque_free) (void *ptr));

	/**
	 * This function destroys the detection module
	 * @param ipoque_struct the to clearing detection module, can be NULL
	 * @param userptr user defined pointer for allocation function, not NULL
	 * @param ipoque_free function pointer to a memory free function, see validity of userptr
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void
	 ipoque_exit_detection_module_ext(struct ipoque_detection_module_struct
									  *ipoque_struct, void (*ipoque_free) (void *ptr, void *userptr), void *userptr);

	/**
	 * This function sets the protocol bitmask2 and therefore selectively activates protocol detections
	 * @param ipoque_struct the detection module, not NULL
	 * @param detection_bitmask the protocol bitmask, not NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void
	 ipoque_set_protocol_detection_bitmask2(struct
											ipoque_detection_module_struct
											*ipoque_struct, const IPOQUE_PROTOCOL_BITMASK * detection_bitmask);
/* OSDPI-END */
/* THIS FUNCTION WILL BE DEPRECATED AND WILL NOT WORK WITH MORE THAN 64 PROTOCOLS
 * PLEASE SWITCH TO ipoque_set_protocol_detection_bitmask2
 */
	/**
	 * This function sets the protocol bitmask
	 *
	 * THIS FUNCTION WILL BE DEPRECATED AND WILL NOT WORK WITH MORE THAN 64 PROTOCOLS
	 * PLEASE SWITCH TO ipoque_set_protocol_detection_bitmask2
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param detection_bitmask the protocol bitmask, not NULL
	 */
	void
	 ipoque_set_protocol_detection_bitmask(struct
										   ipoque_detection_module_struct
										   *ipoque_struct, IPOQUE_PROTOCOL_BITMASK detection_bitmask);

	/**
	 * This function returns the protocol detection bitmask
	 * @param ipoque_struct the detection module, not NULL
	 * @param detection_bitmask the protocol bitmask where the result will be stored, not NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void
	 ipoque_get_protocol_detection_bitmask(struct
										   ipoque_detection_module_struct
										   *ipoque_struct, IPOQUE_PROTOCOL_BITMASK * detection_bitmask);

	/**
	 * This function returns the ID of the subprotocol of the last packet.
	 * @param ipoque_struct the detection module, not NULL
	 * @return the ID of the subprotocol or 0. See ipq_api for available subtypes.
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	unsigned int
	 ipoque_detection_get_protocol_subtype(struct
										   ipoque_detection_module_struct
										   *ipoque_struct);
	/**
	 * This function returns the excluded bitmask. All protocols which are set here will not be detected anymore for this connection
	 * This function must be called after processing. It is valid until the next call of ipoque_detection_process_packet
	 * @param ipoque_struct the detection module, not NULL
	 * @return the pointer to the excluded bitmask
	 * @see ipoque_detection_process_packet
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const IPOQUE_PROTOCOL_BITMASK *ipoque_get_excluded_bitmask(struct
															   ipoque_detection_module_struct
															   *ipoque_struct);
#ifdef IPOQUE_CUST1
	/**
	 * This function will processes one packet and returns the ID of the detected protocol.
	 * This is the main packet processing function. (IPOQUE_CUST1)
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow void pointer to the connection state machine
	 * @param packet the packet as unsigned char pointer with the length of packetlen. the pointer must point to the Layer 3 (IP header)
	 * @param packetlen the length of the packet, 20 or greater
	 * @param current_tick the current timestamp for the packet
	 * @param current tick high res timestamp
	 * @param src void pointer to the source subscriber state machine, can be NULL
	 * @param dst void pointer to the destination subscriber state machine, can be NULL
	 */
	unsigned int
	 ipoque_detection_process_packet(struct ipoque_detection_module_struct
									 *ipoque_struct, void *flow,
									 const unsigned char *packet,
									 const unsigned short packetlen,
									 const IPOQUE_TIMESTAMP_COUNTER_SIZE current_tick,
									 const IPOQUE_TIMESTAMP_COUNTER_SIZE current_tick_jiffies, void *src, void *dst);
#else
/* OSDPI-START */
	/**
	 * This function will processes one packet and returns the ID of the detected protocol.
	 * This is the main packet processing function. (!IPOQUE_CUST1)
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow Pointer to the flow structure for every connection. This must be present for every IPv4 TCP or UDP packet. If it is the first packet of a
	 * new flow, it must be initialized to zero. The size of this structure is given by the function
	 * ipoque_detection_get_sizeof_ipoque_flow_struct. (See ipoque_detection_get_sizeof_ipoque_flow_struct) It can be set to NULL for non-TCP/UDP traffic.
	 * @param packet Pointer to the layer-3 packet header (generally the IPv4 header).
	 * @param packetlen Number of bytes which can be safely accessed starting from the layer-3 header. This must be at least the size of the IPv4 packet (20 bytes)
	 * or the packet will get marked as invalid and the return value of ipoque_detection_process_packet will be IPOQUE_PROTOCOL_UNKNOWN
	 * @param current_tick Current 32-bit timestamp in resolution given by ipoque_init_detection_module(). Must not decrease, overflow allowed.
	 * @param src void pointer to the source subscriber state machine, see dst
	 * @param dst Pointer to tracking information for every internal user. This will be, in most scenarios, the internal IP address range. It must have the
	 * size of sizeof(struct ipoque_id_struct) and must be initialized to zero for a new user. If SRC or DST is an external user, it should be
	 * set to NULL. If the internal user cannot be determined, all internal and external users should be tracked. If both will be set to NULL,
	 * some advanced detections might not work.
	 * @return returns the detected ID of the protocol, see ipq_api for available protocol numbers.
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	unsigned int
	 ipoque_detection_process_packet(struct ipoque_detection_module_struct
									 *ipoque_struct, void *flow,
									 const unsigned char *packet,
									 const unsigned short packetlen,
									 const IPOQUE_TIMESTAMP_COUNTER_SIZE current_tick, void *src, void *dst);

/* OSDPI-END */
#endif

#define IPOQUE_DETECTION_FASTPATH_NOT_USED 0xFFFFFFFF

#ifdef IPOQUE_CUST1
	unsigned int ipoque_detection_process_packet_fastpath(struct ipoque_detection_module_struct
														  *ipoque_struct, void *flow,
														  const unsigned char *packet,
														  const unsigned short packetlen,
														  const IPOQUE_TIMESTAMP_COUNTER_SIZE current_tick,
														  const IPOQUE_TIMESTAMP_COUNTER_SIZE current_tick_jiffies);
#else
	/**
	 *
	 * for parameter description see ipoque_detection_process_packet
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	unsigned int ipoque_detection_process_packet_fastpath(struct ipoque_detection_module_struct
														  *ipoque_struct, void *flow,
														  const unsigned char *packet,
														  const unsigned short packetlen,
														  const IPOQUE_TIMESTAMP_COUNTER_SIZE current_tick);
#endif

	/**
	 *
	 * for parameter description see ipoque_detection_process_packet
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	unsigned int ipoque_detection_process_packet_slowpath(struct ipoque_detection_module_struct
														  *ipoque_struct, void *src, void *dst);

	/**
	 * This function returns the host, user and content type for an http connection.
	 *
	 * ATTENTION: This function must be called as long as the packet is accessible in the main memory, because it will point into the packet to the
	 * strings.
	 * @param ipoque_struct the detection module, not NULL
	 * @param host double pointer to the host string, pointer will be set by this function, NULL when no host available
	 * @param hostlen length of the host string
	 * @param content double pointer to the content string, pointer will be set by this function, NULL when no content available
	 * @param contentlen length of the content string
	 * @param user_agent double pointer to the useragent string, pointer will be set by this function, NULL when no user_agent available
	 * @param user_agentlen length of the user agent string
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_detection_get_http_host_user_and_content_type(struct
															  ipoque_detection_module_struct
															  *ipoque_struct, unsigned char
															  **host, u16 * hostlen, unsigned char
															  **content, u16 * contentlen, unsigned char
															  **user_agent, u16 * user_agentlen);

	/**
	 * This function returns the http host
	 * @param ipoque_struct the detection module, not NULL
	 * @param host double pointer to the host string, pointer will be set by this function, NULL when no host available
	 * @param hostlen length of the host string
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_detection_get_http_host(struct ipoque_detection_module_struct
										*ipoque_struct, unsigned char
										**host, u16 * hostlen);

	/**
	 * This function returns the http request url
	 * @param ipoque_struct the detection module, not NULL
	 * @param url double pointer to the url string, pointer will be set by this function, NULL when no url available
	 * @param urllen length of the url string
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_detection_get_http_request_url(struct
											   ipoque_detection_module_struct
											   *ipoque_struct, unsigned char **url, u16 * urllen);

	/**
	 * This function returns the http request method
	 * @param ipoque_struct the detection module, not NULL
	 * @param method double pointer to the method string, pointer will be set by this function, NULL when no method available
	 * @param methodlen length of the method string
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_detection_get_http_request_method(struct
												  ipoque_detection_module_struct
												  *ipoque_struct, unsigned char **method, u16 * methodlen);

	enum ipoque_http_request_method_enum {
		IPOQUE_HTTP_REQUEST_METHOD_NOT_SET = 0,
		IPOQUE_HTTP_REQUEST_METHOD_GET = 1,
		IPOQUE_HTTP_REQUEST_METHOD_POST = 2,
		IPOQUE_HTTP_REQUEST_METHOD_OPTIONS = 3,
		IPOQUE_HTTP_REQUEST_METHOD_HEAD = 4,
		IPOQUE_HTTP_REQUEST_METHOD_PUT = 5,
		IPOQUE_HTTP_REQUEST_METHOD_DELETE = 6,
		IPOQUE_HTTP_REQUEST_METHOD_CONNECT = 7,
		IPOQUE_HTTP_REQUEST_METHOD_PROPFIND = 8,
		IPOQUE_HTTP_REQUEST_METHOD_REPORT = 9,
		IPOQUE_HTTP_REQUEST_METHOD_TRACE = 10,
		IPOQUE_HTTP_REQUEST_METHOD_MKCOL = 11,
		IPOQUE_HTTP_REQUEST_METHOD_PROPPATCH = 12,
		IPOQUE_HTTP_REQUEST_METHOD_COPY = 13,
		IPOQUE_HTTP_REQUEST_METHOD_MOVE = 14,
		IPOQUE_HTTP_REQUEST_METHOD_LOCK = 15,
		IPOQUE_HTTP_REQUEST_METHOD_UNLOCK = 16
	};

	/**
	 * This function returns the http request method
	 * @param ipoque_struct the detection module, not NULL
	 * @return request method as ipoque_http_request_method_enum
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	enum ipoque_http_request_method_enum ipoque_detection_get_http_request_method_enum(struct
																					   ipoque_detection_module_struct
																					   *ipoque_struct);

	/**
	 * This function returns the http response code and the response string
	 * @param ipoque_struct the detection module, not NULL
	 * @param response_code numeric code of the response, 0 when no response available
	 * @param response double pointer to the response string, pointer will be set by this function, NULL when no response available
	 * @param responselen length of the response string
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_detection_get_http_response(struct ipoque_detection_module_struct *ipoque_struct, u32 * response_code,
											unsigned char **response, u16 * responselen);

	/**
	 * This function returns the encoded http content
	 * @param ipoque_struct the detection module, not NULL
	 * @param encoding double pointer to the content encoding string, pointer will be set by this function, NULL when no encoding available
	 * @param encodinglen length of the content encoding string
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_detection_get_http_content_encoding(struct
													ipoque_detection_module_struct
													*ipoque_struct, unsigned char **encoding, u16 * encodinglen);

	/**
	 * This function returns the encoded http transfer
	 * @param ipoque_struct the detection module, not NULL
	 * @param encoding double pointer to the transfer encoding string, pointer will be set by this function, NULL when no encoding available
	 * @param encodinglen length of the transfer encoding string
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_detection_get_http_transfer_encoding(struct
													 ipoque_detection_module_struct
													 *ipoque_struct, unsigned char **encoding, u16 * encodinglen);

	/**
	 * This function returns the pointer to the http content and its length by the functions parameters.
	 * @param ipoque_struct the detection module, not NULL
	 * @param conntent double pointer to the content string, pointer will be set by this function, NULL when no content available
	 * @param contentlen length of the content length string
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_detection_get_http_content_length(struct
												  ipoque_detection_module_struct
												  *ipoque_struct, unsigned char **content, u16 * contentlen);



#ifdef IPOQUE_PROTOCOL_HTTP
	/**
	 * This function checks if the previously processed packet belongs to a HTTP connection.
	 * @param ipoque_struct the detection module, not NULL
	 * @return != 0 if the previously processed packet belongs to a HTTP connection, 0 otherwise
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u8 ipoque_detection_is_http_connection(struct
										   ipoque_detection_module_struct
										   *ipoque_struct);
#endif

#ifdef IPOQUE_USE_PRX_PROTOCOLS_ONLY
/* mail extract function, this function needs to be called for every smtp packet, if whished */
#define IPOQUE_DETECTION_MAIL_TYPE_FROM		0
#define IPOQUE_DETECTION_MAIL_TYPE_TO		1

	/**
	 * This function returns the smtp mail address
	 * @param ipoque_struct the detection module, not NULL
	 * @param mailaddr double pointer to the mail address string, pointer will be set by this function, NULL when no mailaddr available
	 * @param mailaddrlen length of the mail address string
	 * @param mailtype is either IPOQUE_DETECTION_MAIL_TYPE_FROM or IPOQUE_DETECTION_MAIL_TYPE_TO, depending on sender or receiver
	 */
	void ipoque_detection_get_smtp_mail_address(struct
												ipoque_detection_module_struct
												*ipoque_struct, u8 ** mailaddr, u16 * mailaddrlen, u8 * mailtype);

	/**
	 * This function returns the next pop mail with mail address and mail type.
	 * This function can be called multiple times per packet if it returns a valid mail address.
	 * The tmp_store is used to distinguish between multiple addresses within one mail.
	 * @param ipoque_struct the detection module, not NULL
	 * @param mailaddr double pointer to the mail address string, pointer will be set by this function, NULL when no mailaddr available
	 * @param mailaddrlen length of the mail address string
	 * @param mailtype is either IPOQUE_DETECTION_MAIL_TYPE_FROM or IPOQUE_DETECTION_MAIL_TYPE_TO, depending of sender or receiver
	 * @param tmp_store is a temporary storage, must be initialized with 0 before the first call for each packet
	 */
	void ipoque_detection_get_next_pop_mail_address(struct
													ipoque_detection_module_struct
													*ipoque_struct,
													u8 ** mailaddr, u16 * mailaddrlen, u8 * mailtype, u16 * tmp_store);
#endif							/* IPOQUE_USE_PRX_PROTOCOLS_ONLY */


#ifdef IPOQUE_ENABLE_AGGRESSIVE_DETECTION
	/**
	 * This function enables or disables aggressive detection
	 * this will enable detection of a few protocols after the first packet
	 * the default is DISABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param flag != 0 ENABLES or  == 0 DISABLES the aggressive detection
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_detection_set_aggressive_detection(struct ipoque_detection_module_struct *ipoque_struct, u8 flag);
#endif

#ifdef IPOQUE_ENABLE_MIDSTREAM_DETECTION
	/**
	 * This function enables or disables midstream detection
	 * this will enable detection of a few protocols when the setup of the connection is not available
	 * default is DISABLED
	 * @param ipoque_struct the detection module
	 * @param flag != 0 ENABLES or  == 0 DISABLES the midstream detection
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_detection_set_midstream_detection(struct ipoque_detection_module_struct *ipoque_struct, u8 flag);
#endif

#if defined(IPOQUE_PROTOCOL_CITRIX) && defined(IPOQUE_USE_CITRIX_CONNECTION_TRACKING)

	/**
	 * This function returns the citrix parameters
	 * @param ipoque_struct the detection module, not NULL
	 * @param citrix_application_name double pointer to the citrix application string, pointer will be set by this function, NULL when no citrix application name available
	 * @param citrix_application_name_len length of the citrix application string
	 * @param citrix_user_name double pointer to the citrix user name string, pointer will be set by this function, NULL when no citrix user name available
	 * @param citrix_user_name_len length of the citrix user name string
	 * @param citrix_ip the ipv4 address of the citrix request
	 * @param citrix_port the port of the citrix request
	 * @param citrix_cgp_port the cgp port of the citrix request
	 */
	void ipoque_detection_get_citrix_parameters(struct
												ipoque_detection_module_struct
												*ipoque_struct, unsigned char
												**citrix_application_name, u8 * citrix_application_name_len, unsigned char
												**citrix_user_name,
												u8 * citrix_user_name_len,
												u32 * citrix_ip, u16 * citrix_port, u16 * citrix_cgp_port);
#endif							/* defined(IPOQUE_PROTOCOL_CITRIX) && defined(IPOQUE_USE_CITRIX_CONNECTION_TRACKING) */

/* audio call detection
 * set this parameter to get the audio calls marked for MSN, YAHOO and Skype
 * if not set, default calls with MSN and yahoo will be marked as SIP traffic and skype traffic as skype unknown
 */
#define IPOQUE_DISABLE_AUDIO_CALL_DETECTION	0
#define IPOQUE_ENABLE_AUDIO_CALL_DETECTION	1

	/**
	 * This function enables or disables the audio detection.
	 * The audio call detection is used in many protocols which use e.g. SIP for their audio calls.
	 * If this feature is enabled, they will be marked as the protocol which has caused the audio connection.
	 * Default is ENABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param param 1 ENABLES and 0 DISABLES the audio detection, other values have no effect
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_protocol_audio_detection(struct
											 ipoque_detection_module_struct
											 *ipoque_struct, u8 param);

/* IM file transfer detection
 * set this parameter to mark OSCAR/AIM/MSN/IRC/JABBER filetransfers as a different Subprotocol
 * if not set, the subprotocol will be unknown
 */
#define IPOQUE_DISABLE_IM_FILETRANSFER_DETECTION	0
#define IPOQUE_ENABLE_IM_FILETRANSFER_DETECTION		1

	/**
	 * This function enables or disables the Instant Messaging filetransfer detection.
	 * The function is deprecated, file transfer detection is always enabled and reported as subprotocol
	 * default is ENABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param param ENABLES or DISABLES the im filetransfer detection
	 */
	static inline void ipoque_set_im_filetransfer_detection(struct
															ipoque_detection_module_struct
															*ipoque_struct __attribute__ ((unused)),
															u8 param __attribute__ ((unused))) {
		/* DEPRECATED: this function no longer affects file transfer detection */
	}
#ifdef IPOQUE_DETECTION_SUPPORT_ASYMETRIC_DETECTION
/* asymmetric detection
 * set this parameter to use asymmetric detection mode which improves detection if only one
 * direction of the traffic is known
 */
#define IPOQUE_DISABLE_ASYMMETRIC_DETECTION	        0
#define IPOQUE_ENABLE_ASYMMETRIC_DETECTION		1
	/**
	 * This function enables or disables the asymmetric detection
	 * default is DISABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param param 1 ENABLES and 0 DISABLES the asymmetric detection, other values have no effect
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_asymmetric_detection(struct
										  ipoque_detection_module_struct
										  *ipoque_struct, u8 param);
#endif							/* IPOQUE_DETECTION_SUPPORT_ASYMETRIC_DETECTION */

/* statistical detection
 * disabling the statistical detection will improve performance but the detection rate of
 * encrypted protocols such as bittorrent and openvpn will be a lot worse
 */
#define IPOQUE_DISABLE_STATISTICAL_DETECTION	        0
#define IPOQUE_ENABLE_STATISTICAL_DETECTION		1

	/**
	 * This function enables or disables the statistical detection for fully encrypted and obfuscated protocols
	 * enabling this feature causes a minor performance penalty
	 * default is ENABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param param 1 ENABLES and 0 DISABLES the statistical detection, other values have no effect
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_statistical_detection(struct
										  ipoque_detection_module_struct
										  *ipoque_struct, u8 param);

/* rtp correlation
 * disabling rtp correlation will always classify rtp as rtp instead of the protocol it
 * originates from (sip, yahoo, msn, oscar or jabber)
 */
#define IPOQUE_DISABLE_RTP_CORRELATION	        0
#define IPOQUE_ENABLE_RTP_CORRELATION	        1

	/**
	 * This function enables or disables the rtp correlation to protocol which has created the rtp connection (if possible)
	 * E.g. it will correlate RTP to SIP, if the rtp connection setup has been done by SIP
	 * default is ENABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param param 1 ENABLES and 0 DISABLES the rtp correlation, other values have no effect
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_rtp_correlation(struct
									ipoque_detection_module_struct
									*ipoque_struct, u8 param);

/* rdt correlation
 * disabling rdt correlation will always classify rdt as rdt instead of the protocol it
 * originates from (rstp, h323, orb, ...)
 */
#define IPOQUE_DISABLE_RDT_CORRELATION	        0
#define IPOQUE_ENABLE_RDT_CORRELATION	        1

	/**
	 * This function enables or disables the rdt correlation to protocol which has created the rdt connection (if possible)
	 * E.g. it correlates RDT to RTSP, if the rdt connection setup has been done by RTSP
	 * default is ENABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param param 1 ENABLES and 0 DISABLES the rdt correlation, other values have no effect
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_rdt_correlation(struct ipoque_detection_module_struct
									*ipoque_struct, u8 param);

/* flash correlation
 * disabling flash correlation will always classify flash as flash instead of the protocol it
 * originates from (Veoh, youtube, Iplayer, ...)
 */
#define IPOQUE_DISABLE_FLASH_CORRELATION	        0
#define IPOQUE_ENABLE_FLASH_CORRELATION             1

	/**
	 * This function enables or disables the flash correlation to the protocol which has created the flash connection (if possible)
	 * E.g. it correlates FLASH to VEOH, if the flash connection setup has been done by VEOH
	 * default is ENABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param param 1 ENABLES and 0 DISABLES the flash correlation, other values have no effect
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_flash_correlation(struct ipoque_detection_module_struct
									  *ipoque_struct, u8 param);


/* rtsp correlation
 * disabling rtsp correlation will always classify rtsp as rtsp instead of the protocol it
 * originates from (for example orb)
 */
#define IPOQUE_DISABLE_RTSP_CORRELATION	        0
#define IPOQUE_ENABLE_RTSP_CORRELATION	        1

	/**
	 * This function enables or disables the rtsp correlation to the protocol which has created the rtsp connection (if possible)
	 * E.g. it correlates RTSP to ORB, if the rtsp connection setup has been done by ORB
	 * default is ENABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param param 1 ENABLES and 0 DISABLES the rtsp correlation, other values have no effect
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_rtsp_correlation(struct ipoque_detection_module_struct
									 *ipoque_struct, u8 param);


	/**************************************************************************/
	/* gamekit SIP correlation
	 * disabling gamekit SIP correlation will always classify SIP as SIP instead of the protocol it
	 * originates from (gamekit)
	 */
#define IPOQUE_DISABLE_GAMEKIT_SIP_CORRELATION	        0
#define IPOQUE_ENABLE_GAMEKIT_SIP_CORRELATION	        1

	/**
	 * This function enables or disables the gamekit SIP correlation to the protocol gamekit
	 * which has created the SIP connection (if possible)
	 * default is ENABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param param 1 ENABLES and 0 DISABLES the gamekit SIP correlation, other values have no effect
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_gamekit_sip_correlation(struct
											ipoque_detection_module_struct
											*ipoque_struct, u8 param);
	/**************************************************************************/

	/**************************************************************************/
	/* RADIUS detection mode
	 * set RADIUS detection mode to fast or full mode
	 * fast mode means detection only on standard ports
	 * full mode means detection on all ports which is much slower
	 */

	typedef enum {
		IPOQUE_RADIUS_FAST_MODE = 0,
		IPOQUE_RADIUS_FULL_MODE = 1
	} ipoque_radius_detection_mode_t;

	/**
	 * This function sets the RADIUS detection mode
	 * default is FAST
	 * @param ipoque_struct the detection module, not NULL
	 * @param param detection mode
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_radius_detection_mode(struct
										  ipoque_detection_module_struct
										  *ipoque_struct, ipoque_radius_detection_mode_t param);
	/**************************************************************************/


#ifdef IPOQUE_DECAPSULATE_PLAIN_TUNNELS
/*
 *  plain tunnel decapsulation
 * this mode describes how the detection should deal with plain tunnels
 * Plain tunnels are: GRE, IP in IP
 * the level determines the maximum number of protocols which need to be decapsulated
 * the default setting is 0, which equals no decapsulation
 * a setting of 1 would decapsulate ONE GRE or IP in IP tunnel
 */

	/**
	 * This function sets the decapsulation level for plain tunnels. If set to != 0, PACE will try to decapsulate tunnels until this depth.
	 * Supported tunnels are e.g. GRE, IP in IP, IPv4 in IPv6, IPv6 in IPv4 and many more
	 * @param ipoque_struct the detection module, not NULL
	 * @param level the level depth to decapsulate
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_plain_tunnel_decapsulation_level(struct
													 ipoque_detection_module_struct
													 *ipoque_struct, u32 level);
	/**
	 * This function returns the current decapsulation level for plain tunnels
	 * @param ipoque_struct the detection level, not NULL
	 * @return the level depth to decapsulate
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u32 ipoque_get_plain_tunnel_decapsulation_level(struct
													ipoque_detection_module_struct
													*ipoque_struct);
#endif							/* IPOQUE_DECAPSULATE_PLAIN_TUNNELS */

#ifdef IPOQUE_INTER_DETECTION_MESSAGING

	/**
	 *  message type
	 */
	enum ipoque_messaging_target_type {
		IPOQUE_MESSAGE_FLOW,
		IPOQUE_MESSAGE_SRC,
		IPOQUE_MESSAGE_DST
	};

	typedef void (*ipoque_messaging_callback) (enum ipoque_messaging_target_type type, const void *msgptr, u32 msglen,
											   void *userdata);


	/**
	 * This function sets a callback for detection messages.
	 * @param ipoque_struct the detection module, not NULL
	 * @param callback the function pointer to the callback
	 * @param userdata void pointer to the user data. The user data will be passed to the callback
	 */
	void ipoque_set_detection_messaging_callback(struct
												 ipoque_detection_module_struct
												 *ipoque_struct, ipoque_messaging_callback callback, void *userdata);

	/**
	 * This function handles a messages from other PACE systems
	 * @param ipoque_struct the detection module, not NULL
	 * @param typeptr void pointer to the type, not NULL
	 * @param msgptr void pointer to the message from another PACE instance, not NULL
	 * @param msglen the length of the PACE message
	 * @return 0 if the message was handled successfully != 0 otherwise
	 * 1,2,10 = message invalid
	 * 3 = messagetype not defined
	 * 11 = typeptr invalid
	 */
	u8 ipoque_messaging_process(struct ipoque_detection_module_struct
								*ipoque_struct, void *typeptr, const void *msgptr, u32 msglen);


	/**
	 * This function sets the current timestamp inside the detection module
	 * and should be called before ipoque_messaging_process with the current timestamp
	 * @param ipoque_struct the detection module, not NULL
	 * @param ts the timestamp
	 */
	void ipq_set_current_timestamp(struct ipoque_detection_module_struct
								   *ipoque_struct, IPOQUE_TIMESTAMP_COUNTER_SIZE ts);

#endif							/* IPOQUE_INTER_DETECTION_MESSAGING */

#ifdef IPOQUE_ENABLE_GTP_C_USER_TRACKING
#define DISABLE_GTP_C_USER_TRACKING	0
#define ENABLE_GTP_C_USER_TRACKING	1
	/**
	 * This function activates the gtp connection tracking.
	 * @param ipoque_struct the detection module, not NULL
	 * @param ipoque_malloc a function pointer to the malloc function
	 * @param state the state
	 * @param maximum_number_of_parrallel_connections the maximum of parallel connections
	 * @param timeout the duration before break
	 * @return returns != 0 if an error occurred
	 */
	int ipoque_set_gtp_c_connection_tracking(struct
											 ipoque_detection_module_struct
											 *ipoque_struct,
											 void *(*ipoque_malloc) (unsigned
																	 long size),
											 void (*ipoque_free) (void *ptr),
											 u8 state,
											 u32
											 maximum_number_of_parrallel_connections,
											 IPOQUE_TIMESTAMP_COUNTER_SIZE timeout);

	/**
	 * This function returns a pointer to the msisdn.
	 * @param ipoque_struct the detection module
	 * @param gtp_msisdn_len pointer to the length of the msisdn
	 * @param gtp_msisdn_end_user_ip IP of the end user for the msisdn
	 * @return returns a pointer to the msisdn, null if it does not exist
	 */
	const u8 *ipoque_detection_get_gtp_c_mapping(struct
												 ipoque_detection_module_struct
												 *ipoque_struct, u16 * gtp_msisdn_len, u32 * gtp_msisdn_end_user_ip);
#endif							/* IPOQUE_ENABLE_GTP_C_USER_TRACKING */


#ifdef IPOQUE_DETECTION_MEASURE_TCP_FLOW_LATENCY

	/**
	 * This is the struct for storing information about the latency of a flow.
	 */
	typedef struct flow_latency_struct {
		/**
		 * diff_syn_synack_possible a flag that shows if a syn command and the current synack was seen
		 */
		u32 diff_syn_synack_possible:1;
		/**
		 * diff_synack_ack_possible a flag that shows if a synack command and the current ack was seen
		 */
		u32 diff_synack_ack_possible:1;
		/**
		 * diff_syn_synack time difference between syn and synack command
		 */
		IPOQUE_TIMESTAMP_COUNTER_SIZE diff_syn_synack;
		/**
		 * diff_synack_ack time difference between synack and ack command
		 */
		IPOQUE_TIMESTAMP_COUNTER_SIZE diff_synack_ack;
	} flow_latency_struct_t;

	/**
	 * This function returns the latency of the flow.
	 * @param ipoque_struct the detection module with all informations about the detection context, not NULL
	 * @param flow void pointer for the buffer, the flow is in, not NULL
	 * @return returns the flow_latency_struct
	 */
	const struct flow_latency_struct *ipoque_detection_get_flow_latency_result(struct ipoque_detection_module_struct
																			   *ipoque_struct, void *flow);
#endif

#ifdef IPOQUE_ENABLE_FLOW_OOO_COUNTER
	/**
	 * Struct containing counter for tcp retransmission and ooo-packets of a flow
	 */
	typedef struct ipoque_flow_ooo_counter_struct {
		/**
		 * flow_ooo_counter number of out of order packets
		 */
		u16 flow_ooo_counter;

		/**
		 * flow_retransmission_counter number of retransmission packets
		 */
		u16 flow_retransmission_counter;
	} ipoque_flow_ooo_count_struct_t;

	/**
	 * This function returns counter for the tcp retransmission and out of order-packets of the last flow
	 * @param ipoque_struct the detection module with all informations about the detection context, not NULL
	 * @return pointer to the flow_ooo_counter_struct, NULL if flow is not tcp
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const struct ipoque_flow_ooo_counter_struct *ipoque_pace_get_ooo_counter(struct ipoque_detection_module_struct *ipoque_struct);
#endif

#ifdef IPOQUE_ENABLE_TCP_RETRANSMISSION_COUNTER
	/**
	 * This function returns the number of all packets which are retransmitted.
	 * @param ipoque_struct the detection module with all informations about the detection context, not NULL
	 * @return the number of all packets which are retransmitted.
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u64 ipoque_detection_get_global_number_retransmitted_packets(struct ipoque_detection_module_struct *ipoque_struct);
#endif

#ifdef IPOQUE_DETECTION_SUPPORT_NONLINEAR_PROCESSING

#define IPOQUE_DETECTION_NEED_LINEARIZATION	0xFFFFFFFF

	/**
	 *  This function tries to run the protocol detection with non-linearized packets.
	 *  It checks the flow state machine for required actions. If no action is required, the detected protocol will be returned.
	 *  If not, this function will return IPOQUE_DETECTION_NEED_LINEARIZATION. the caller must call ipoque_detection_process_packet_now_linearized after the packet has been linearized
	 *  @param ipoque_struct the detection module, not NULL
	 *  @param flow the final state machine of the connection
	 *  @param packet the packet as unsigned char pointer with the length of packetlen. the pointer must point to the Layer 3 (IP header)
	 *  @param accessible_packetlen the length of the packet which can be accessed
	 *  @param real_packetlen the real length of the packet
	 *  @param current_tick the timestamp
	 *  @return return the protocol or IPOQUE_DETECTION_NEED_LINEARIZATION
	 */

	static inline unsigned int
	 ipoque_detection_process_packet_nonlinear_check(struct ipoque_detection_module_struct
													 *ipoque_struct __attribute__ ((unused)), void *flow
													 __attribute__ ((unused)), const unsigned char *packet
													 __attribute__ ((unused)), const unsigned short accessible_packetlen
													 __attribute__ ((unused)), const unsigned short real_packetlen
													 __attribute__ ((unused)),
													 const IPOQUE_TIMESTAMP_COUNTER_SIZE current_tick
													 __attribute__ ((unused)), void *src
													 __attribute__ ((unused)), void *dst __attribute__ ((unused))) {
		/* NOT SUPPORTED YET, TODO use FP here */
		return IPOQUE_DETECTION_NEED_LINEARIZATION;
	}

	/**
	 * This function will process one packet AFTER linearization and returns the ID of the detected protocol.
	 * IT MUST be called after the function ipoque_detection_process_packet_nonlinear_check when the packet has been linearized
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow void pointer to the connection state machine
	 * @param packet the packet as unsigned char pointer with the length of packetlen. the pointer must point to the Layer 3 (IP header)
	 * @param packetlen the length of the packet
	 * @param current_tick the current timestamp for the packet
	 * @param src void pointer to the source subscriber state machine, can be NULL
	 * @param dst void pointer to the destination subscriber state machine, can be NULL
	 * @return returns the detected ID of the protocol
	 */
	static inline unsigned int
	 ipoque_detection_process_packet_now_linearized(struct ipoque_detection_module_struct
													*ipoque_struct, void *flow,
													const unsigned char *packet,
													const unsigned short packetlen,
													const IPOQUE_TIMESTAMP_COUNTER_SIZE current_tick, void *src,
													void *dst) {
		/* NOT SUPPORTED YET */
		return ipoque_detection_process_packet(ipoque_struct, flow, packet, packetlen, current_tick, src, dst);
	}

#endif							/* IPOQUE_DETECTION_SUPPORT_NONLINEAR_PROCESSING */

#ifdef IPOQUE_PACE_API_MK1

	/**
	 * This function returns the number of supported protocols including "generic ip traffic".
	 * @return (IPOQUE_MAX_SUPPORTED_PROTOCOLS + 1)
	 */
	u16 get_number_of_protocols(void);



	/**
	 * This function returns the number of implemented protocols by the detection.
	 * @return (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 1)
	 */
	u16 get_number_of_implemented_protocols(void);

	/**
	 * This function returns the number of slots which are reserved for custom protocols
	 * it may return 0 when no slots are available or custom protocols are not supported
	 * @return (IPOQUE_MAX_SUPPORTED_PROTOCOLS) - (IPOQUE_LAST_IMPLEMENTED_PROTOCOL);
	 */
	u16 get_number_of_slots(void);

	/**
	 * This function returns the name of the protocol.
	 * @return the char string of the protocol name
	 * @param protocol_id the ID of the existing protocol for which the name of the protocol is asked. See ipq_protocols_default.h.
	 */
	const char *get_protocol(u16 protocol_id);

	/**
	 *  This function returns the protocol id of a protocol name.
	 *  @return the protocol number for the existing protocol name or 0.
	 *  @param protocol_string the protocol name for which the protocol number was asked, not NULL
	 */
	u16 get_protocol_number(char *protocol_string);

	/**
	 * This function returns the number of supported sub protocols including "unknown" for the given protocol.
	 * @return must return 0 when no sub protocols are supported or must return number of sub protocols including the unknown sub protocol with sub_protocol_id == 0
	 * @param protocol_id the ID of the protocol for which the number of subprotocols is asked. See ipq_protocols_default.h.
	 */
	u16 get_number_of_subprotocols(u16 protocol_id);

	/**
	 * This function returns the name of the sub protocol for the given protocol.
	 * @return the char string of the sub protocol name or NULL if not existing
	 * @param protocol_id the ID of the protocol. See ipq_protocols_default.h.
	 * @param subprotocol_id the ID of the existing subprotocol. See ipq_protocols_default.h.
	 * @see ipq_protocols_default.h
	 */
	const char *get_sub_protocol(u16 protocol_id, u16 subprotocol_id);

#ifdef IPOQUE_PROTOCOL_DESCRIPTION_STRING
	/**
	 * This function returns a description for the given protocol.
	 * @return the char string of the protocol description
	 * @param protocol_id the ID of the existing protocol. See ipq_protocols_default.h.
	 */
	const char *get_protocol_description(u16 protocol_id);
#endif

#endif /* API Mk1 */

#ifdef IPOQUE_PROTOCOL_DHCP

	/**
	 * struct for the dhcp information (IPv4)
	 */
	struct ipoque_dhcp_v4_information_struct {
		/**
		 * type of message: 0 -> dhcp "start", 1-> dhcp "stop"
		 */
		u32 type;
		/**
		 * ip address is host byte order
		 */
		u32 ip;
		/**
		 * dhcp lease time in seconds, only valid for dhcp start
		 */
		u32 lease_time;
		/**
		 * pointer to mac address, 6 bytes long
		 */
		const u8 *mac;
	};

	/**
	 * This function returns the dhcp accounting information, if available
	 * the buffer is available until the next packet processing is done
	 * @return pointer to the information struct, NULL, if no information is available
	 * @param ipoque_struct the struct for the detection mode. This structure contains
	 * the extracted metadata if available, not NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const struct ipoque_dhcp_v4_information_struct *ipoque_get_dhcp_v4_information(struct ipoque_detection_module_struct
																				   *ipoque_struct);

#endif							/* IPOQUE_PROTOCOL_DHCP */


#ifdef IPOQUE_PROTOCOL_OPENVPN

#define IPOQUE_OPENVPN_AGGRESSIVE_DETECTION		0
#define IPOQUE_OPENVPN_SAFE_DETECTION			1

	/**
	 * This function sets the OPENVPN mode.
	 * if set to IPOQUE_OPENVPN_AGGRESSIVE_DETECTION, PACE will detect all kind of openvpn connections, including rare one. This might cause a higher false positive rate.
	 * if set to IPOQUE_OPENVPN_SAFE_DETECTION, PACE will detect just a part of all openvpn connections, but it will avoid a higher missdetection rate.
	 * default is IPOQUE_OPENVPN_AGGRESSIVE_DETECTION
	 * @param ipoque_struct the struct for the detection module, not NULL
	 * @param openvpn_mode the mode can be IPOQUE_OPENVPN_AGGRESSIVE_DETECTION, default is IPOQUE_OPENVPN_SAFE_DETECTION.
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */

	void ipoque_openvpn_set_detection_mode(struct ipoque_detection_module_struct *ipoque_struct, const u8 openvpn_mode);

#endif

#ifdef IPOQUE_PROTOCOL_GENVOICE

	/**
	 * This function enables the generic voice search for a number of protocols
	 * bitmask settings: 0 --> no generic voice detection
	 * IPSEC --> search for voice connections in IPSEC --> might relabel IPSEC connections
	 * ALL --> search in all protocols for generic voice traffic
	 *
	 * this option will decrease the PACE performance significantly for the marked protocols
	 * it is recommended to search in specific tunnels only, because P2P, HTTP, FTP,.. are not known as tunnel protocols
	 *
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param generic_voice_search_bitmask the bitmask. See function description
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_generic_voice_mode(struct ipoque_detection_module_struct *ipoque_struct,
									   const IPOQUE_PROTOCOL_BITMASK * generic_voice_search_bitmask);
#endif


#if defined (IPOQUE_DETECTION_MEASURE_ASYMETRIC_CONNECTION_SETUP) && defined(IPOQUE_DETECTION_SUPPORT_ASYMETRIC_DETECTION)

	enum ipoque_asymmetric_connection_status_enum {
		IPOQUE_CONNECTION_STATUS_SYMMETRIC = 0,
		IPOQUE_CONNECTION_STATUS_ASYMMETRIC = 1,
		IPOQUE_CONNECTION_STATUS_UNKNOWN = 2,
	};

	/**
	 * This function returns whether it is an asymmetric or symmetric connection
	 * it is recommended to call this at connection end
	 * it uses a complex heuristic for tcp connections and a basic one for all other protocols
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow pointer to the connection state machine, not NULL
	 */
	enum ipoque_asymmetric_connection_status_enum ipoque_get_asymmetric_connection_status(const struct
																						  ipoque_detection_module_struct
																						  *ipoque_struct,
																						  const void *flow);

#endif

#ifdef IPOQUE_USE_PRX_PROTOCOLS_ONLY
	enum ipoque_call_information_enum {
		IPOQUE_CALL_UNKNOWN = 0,
		IPOQUE_CALL_SETUP = 1,
		IPOQUE_CALL_START = 2,
		IPOQUE_CALL_END = 3
	};

	/**
     * struct for call information
     */
	struct ipoque_call_information_buffer {
		/**
         * save where the call comes from
         */
		const u8 *call_from;
		/**
         * save where the call goes to
         */
		const u8 *call_to;
		/**
         * save the call id
         */
		const u8 *call_id;
		/**
         * save the size of the call_from buffer
         */
		u16 call_from_size;
		/**
         * save the size of the call_to buffer
         */
		u16 call_to_size;
		/**
         * save the size of the call_id buffer
         */
		u16 call_id_size;
	};

/**
 * This function returns the call information. It is valid until the next call of ipoque_detection_process_packet.
 * @param ipoque_struct the detection module, not NULL
 * @param call_information_buffer the result_struct for the call information. See the ipoque_call_information_buffer, not NULL
 * @return the Call INFORMATION STATUS
 */
	enum ipoque_call_information_enum ipoque_get_call_information(const struct ipoque_detection_module_struct
																  *ipoque_struct, struct ipoque_call_information_buffer
																  *call_information_buffer);
#endif

#if defined(IPOQUE_PROTOCOL_SIP) && defined(IPOQUE_DETECTION_DECODE_SIP_CONNECTIONS)
	enum ipoque_sip_information_enum {
		IPOQUE_SIP_CALL_UNKNOWN = 0,
		IPOQUE_SIP_CALL_SETUP = 1,
		IPOQUE_SIP_CALL_START = 2,
		IPOQUE_SIP_CALL_END = 3
	};

#ifdef IPOQUE_CUST1
	enum ipoque_voice_information_enum {
		IPOQUE_VOICE_CALL_UNKNOWN = 0,
		IPOQUE_VOICE_CALL_START = 1,
		IPOQUE_VOICE_CALL_END = 2,
		IPOQUE_VOICE_SIP_START = 3,
		IPOQUE_VOICE_SIP_END = 4
	};

	/**
	 * Customer specific voice extraction
	 * @param ipoque_struct the detection module, not NULL
	 * @return voice type
	 */

	enum ipoque_voice_information_enum ipoque_voice_information(struct ipoque_detection_module_struct *ipoque_struct);

#endif

	/**
	 * struct for sip information
	 */
	struct ipoque_sip_information_buffer {
		/**
		 * save where the call comes from
		 */
		const u8 *call_from;
		/**
		 * save where the call goes to
		 */
		const u8 *call_to;
		/**
		 * save the call id
		 */
		const u8 *call_id;
		/**
		 * save the size of the call_from buffer
		 */
		u16 call_from_size;
		/**
		 * save the size of the call_to buffer
		 */
		u16 call_to_size;
		/**
		 * save the size of the call_id buffer
		 */
		u16 call_id_size;
	};

	/**
	 * This function returns the sip information. It is valid until the next call of ipoque_detection_process_packet.
	 * @param ipoque_struct the detection module, not NULL
	 * @param sip_information_buffer the result_struct for the sip information. See the ipoque_sip_information_buffer, not NULL
	 * @return the SIP INFORMATION STATUS
	 */
	enum ipoque_sip_information_enum ipoque_get_sip_information(const struct ipoque_detection_module_struct
																*ipoque_struct, struct ipoque_sip_information_buffer
																*sip_information_buffer);

#endif

#ifdef IPOQUE_MEASURE_RTP_PERFORMANCE
	/* the following function gives a report in terms of the following struct
	 * telling about the quality of an rtp connection */

	/**
	 * struct for rtp performance data
	 */
	struct ipoque_rtp_performance_data_struct {

		/* these values are calculated with the help of the rtcp packets. */
		/**
		 * this value gives the percent part of the max lost packets
		 */
		u32 max_packets_lost_percentual;
		/**
		 * this value gives the percent part of the min lost packets
		 */
		u32 min_packets_lost_percentual;
		/**
		 * this value gives the percent part of the average lost packets
		 */
		u32 average_packets_lost_percentual;
		/**
		 * this value gives the max jitter
		 */
		u32 max_jitter;
		/**
		 * this value gives the min jitter
		 */
		u32 min_jitter;
		/**
		 * this value gives the average jitter
		 */
		u32 average_jitter;
		/**
		 * this value gives the number of packets
		 */
		u32 packet_number;
		/* theses values are calculated with the help of the rtp packets */
		/**
		 * this value gives the average rtp jitter
		 */
		u32 rtp_average_jitter;
		/**
		 * this value gives the rtp fraction
		 */
		u8 rtp_fraction;

	};

	/**
	 * This function calculates the global values in the ipoque_rtp_performance_data_struct.
	 * Each call will reset the internal global counters. If this is called every second, it returns the rtp performance calculation per second
	 * @param ipoque_struct the detection module, not NULL
	 * @param data the structure which will be filled with the calculated values, not NULL
	 */
	void ipoque_get_rtp_performance_data(struct ipoque_detection_module_struct *ipoque_struct,
										 struct ipoque_rtp_performance_data_struct *data);

	/** structure containing the data from a reception report block in an RTCP sender or receiver report
     * packet (see RFC3550, section 6.4, for the meaning of the fields)
     *
     * all fields use host by order */
	struct ipoque_rtcp_reception_report_struct {
		u32 direction;			/**< direction of the SR/RR packet */
		u8 fraction_lost;		/**< fraction of RTP packets lost since last SR or RR (scaled to 0..255) */
		u32 packets_lost;		/**< number of RTP packets since beginning of reception */
		u32 jitter;				/**< interarrival jitter */
		u32 lsr;				/**< last sender report timestamp */
		u32 dlsr;				/**< delay since (reception of) last sender report */
	};

	/**
	 * If the current packet is an RTCP sender report or receiver report packet, save the packet's direction
	 * and the LSR and DLSR fields from the first reception report block to result and return 1.
	 * Otherwise, return 0.
	 */
	u8 ipoque_get_rtcp_reception_report(struct ipoque_detection_module_struct *ipoque_struct,
										struct ipoque_rtcp_reception_report_struct *result);

	struct ipoque_rtp_flow_stats_struct {
		u32 packets_sent[2];	/**< number of packets sent, for each direction */
		u32 packets_lost[2];	/**< number of packets lost, for each direction */
		u8 payload_type;		/**< payload type of most recent packet */
	};

	/**
	 * For one RTP flow, get counts of packets sent and lost, and payload type.
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow a pointer to the connection state machine, not NULL
	 * @param result pointer to a structure that receives the results, not NULL
	 */
	void ipoque_get_rtp_flow_stats(struct ipoque_detection_module_struct *ipoque_struct, const void *flow,
								   struct ipoque_rtp_flow_stats_struct *result);
	/**
	 * Reset packet counters of an RTP flow to zero.
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow a pointer to the connection state machine, not NULL
	 */
	void ipoque_reset_rtp_flow_stats(struct ipoque_detection_module_struct *ipoque_struct, void *flow);
#endif

#ifdef IPOQUE_DETECTION_SUPPORT_UNDETECTED_PROTOCOL_DETECTION

	typedef enum {
		IPOQUE_DISABLE_UNDETECTED_PROTOCOL_DETECTION,
		IPOQUE_ENABLE_UNDETECTED_PROTOCOL_DETECTION
	} ipoque_undetected_protocol_mode_t;

	/**
	 * enables or disables undetected protocol detection and 
	 * sets the timeout after which unknown traffic should be marked by as undetected
	 * the value is parsed in milliseconds
	 * if the timer, which is used for pace, has a smaller resolution, the timeout will be rounded to this value
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param mode enable or disable detection
	 * @param timeout_mseconds the timeout in milliseconds, 0 will also disable the undetected protocol detection
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_set_undetected_timeout(struct ipoque_detection_module_struct *ipoque_struct,
									   ipoque_undetected_protocol_mode_t mode, u32 timeout_mseconds);

	/**
	 * This function returns the setting for the timeout. See ipoque_set_undetected_timeout
	 * @param ipoque_struct the detection module, not NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u32 ipoque_get_undetected_timeout(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * This function returns the state of the undetected protocol detection
	 * @param ipoque_struct the detection module, not NULL
	 * @return state of detection (either IPOQUE_ENABLE_UNDETECTED_PROTOCOL_DETECTION
	 *    or IPOQUE_DISABLE_UNDETECTED_PROTOCOL_DETECTON
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	ipoque_undetected_protocol_mode_t ipoque_get_undetected_mode(struct ipoque_detection_module_struct *ipoque_struct);
#endif

#ifdef IPOQUE_PROTOCOL_SSL
#ifdef IPOQUE_ENABLE_SSL_DECODE

	/**
	 * the struct for ssl decoding
	 */
	struct ipoque_ssl_decode_struct {
#define IPOQUE_SSL_DECODE_NOERROR	0
#define IPOQUE_SSL_DECODE_NOHELLO	1
#define IPOQUE_SSL_DECODE_TLSFAIL	2
#define IPOQUE_SSL_DECODE_NOCERT	3
#define IPOQUE_SSL_DECODE_PARSEFAIL	4
#define IPOQUE_SSL_DECODE_PARSEPART	5
		/**
		 * contains a error code. Possible values are IPOQUE_SSL_DECODE_NOERROR, IPOQUE_SSL_DECODE_NOHELLO,
		 * IPOQUE_SSL_DECODE_TLSFAIL, IPOQUE_SSL_DECODE_NOCERT, IPOQUE_SSL_DECODE_PARSEFAIL or IPOQUE_SSL_DECODE_PARSEPART.
		 */
		u8 error;
		/**
		 * the serial number as byte pointer
		 */
		const u8 *serial_number;
		/**
		 * the validity not before as byte pointer
		 */
		const u8 *validity_not_before;
		/**
		 * the validity not after as byte pointer
		 */
		const u8 *validity_not_after;
		/**
		 * the name of the country as byte pointer
		 */
		const u8 *country_name;
		/**
		 * the postal code as byte pointer
		 */
		const u8 *postal_code;
		/**
		 * the name of the state or the name of the province as byte pointer
		 */
		const u8 *state_or_province_name;
		/**
		 * the name of the locality as byte pointer
		 */
		const u8 *locality_name;
		/**
		 * the street address as byte pointer
		 */
		const u8 *street_address;
		/**
		 * name of the organization as byte pointer
		 */
		const u8 *organization_name;
		/**
		 * name of the organization unit as byte pointer
		 */
		const u8 *organizational_unit_name;
		/**
		 * common name as byte pointer
		 */
		const u8 *common_name;
		/**
		 * length of the serial number
		 */
		u16 serial_number_len;
		/**
		 * length of the validity not before
		 */
		u16 validity_not_before_len;
		/**
		 * length of the validity not after
		 */
		u16 validity_not_after_len;
		/**
		 * length of the country name
		 */
		u16 country_name_len;
		/**
		 * length of the postal code
		 */
		u16 postal_code_len;
		/**
		 * length of the province or state name
		 */
		u16 state_or_province_name_len;
		/**
		 * length of the locality name
		 */
		u16 locality_name_len;
		/**
		 * length of the street address
		 */
		u16 street_address_len;
		/**
		 * the length of the organization name
		 */
		u16 organization_name_len;
		/**
		 * the length of the organization unit name
		 */
		u16 organizational_unit_name_len;
		/**
		 * length of the common name
		 */
		u16 common_name_len;
	};


	/**
	 * can be called for every SSL packet
	 * this function will fill a static ipoque_ssl_decode_struct and return it
	 * if a specific information is not given in the SSL handshake, all pointers will be set to NULL and all length values will be 0
	 * if no certificate could be found, parsing the certificate failed or the certificate could only be parsed partially
	 * this is indicated by the error variable of the ipoque_ssl_decode_struct
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @return the result of the ssl decode
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const struct ipoque_ssl_decode_struct *ipoque_decode_ssl(struct ipoque_detection_module_struct *ipoque_struct);
#endif
#endif

#ifdef IPOQUE_ENABLE_SEAMLESS_UPGRADE

#define IPOQUE_FLOW_DUMP_DATA_SIZE  128

	/**
	 * struct for the flow dump
	 */
	struct ipoque_flow_dump_struct {
		/**
		 * buffer for the flow data
		 */
		u8 data[IPOQUE_FLOW_DUMP_DATA_SIZE];
	};

	/**
	 * This function dumps the flow informations in the given flow_dump_struct
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow a void pointer to the connection state machine, not NULL
	 * @param data the flow_dump_struct where to dump in, not NULL
	 */
	void ipoque_dump_flow_information(struct ipoque_detection_module_struct *ipoque_struct,
									  const void *flow, struct ipoque_flow_dump_struct *data);

	/**
	 * This function reloads the flow dump. See ipoque_dump_flow_information
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow a void pointer to the connection state machine, not NULL
	 * @param data the flow_dump_struct where to dump in, not NULL
	 */
	void ipoque_reload_flow_information(struct ipoque_detection_module_struct *ipoque_struct,
										void *flow, const struct ipoque_flow_dump_struct *flow_dump);

#define IPOQUE_ID_DUMP_DATA_SIZE  128

	/**
	 * buffer for the dump id
	 */
	struct ipoque_id_dump_struct {
		/**
		 * byte array for the dump buffer.
		 */
		u8 data[IPOQUE_ID_DUMP_DATA_SIZE];
	};

	/**
	 * This function dumps the id informations in the given id_dump_struct
	 * @param ipoque_struct the detection module, not NULL
	 * @param id a void pointer to the subscriber state machine, not NULL
	 * @param data the id_dump_struct where to dump in, not NULL
	 */
	void ipoque_dump_id_information(struct ipoque_detection_module_struct *ipoque_struct,
									void *id, struct ipoque_id_dump_struct *data);

	/**
	 * This function reloads the id dump. See ipoque_dump_id_information
	 * @param ipoque_struct the detection module, not NULL
	 * @param id a void pointer to the subscriber state machine, not NULL
	 * @param data the id_dump_struct where to dump in, not NULL
	 */
	void ipoque_reload_id_information(struct ipoque_detection_module_struct *ipoque_struct,
									  void *id, const struct ipoque_flow_dump_struct *id_dump);

#endif


#ifdef IPOQUE_ENABLE_CORRELATING_FLOW_ID

	/**
	 * This function sets an id for a flow. A flow may change its id to the id of another flow when it is correlated
	 * to the protocol of that other flow.
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow the flow to set the id for, if NULL nothing happens
	 * @param id the id to set
	 */
	void ipoque_detection_set_flow_id(struct ipoque_detection_module_struct *ipoque_struct, void *flow, u64 id);

	/**
	 * This function retrieves the id of a flow. A flow may change its id to the id of another flow when it is correlated
	 * to the protocol of that other flow.
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow the flow to get the id of
	 * @return id of the flow or 0 if flow is NULL
	 */
	u64 ipoque_detection_get_flow_id(struct ipoque_detection_module_struct *ipoque_struct, void *flow);

	/**
	 * This function updates the ID of the given flow. A flow may
	 * change its ID to the ID of another flow when it is correlated
	 * to the protocol of that other flow. Stored IDs for correlation
	 * are updated as well on both given subscriber structures.
	 * 
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow the flow to set the ID for, if NULL nothing happens
	 * @param src the source subscriber, can be NULL
	 * @param dst the desctination subscriber, can be NULL
	 * @param id the id to set
	 */
	void ipoque_detection_update_flow_id(struct ipoque_detection_module_struct *ipoque_struct, void *flow, void *src, void *dst, u64 id);

#endif							/* IPOQUE_ENABLE_CORRELATING_FLOW_ID */



	/**
	 * This function will return a pointer to the layer 3 header of the previously processed packet.
	 * If there was no valid layer 3 header in the packet this function will return NULL.
	 * @param ipoque_struct the detection module, NULL results in a NULL pointer result
	 * @param l3_protocol the integer value referenced by this pointer will be set to the layer 3 protocol number, passing NULL is allowed
	 * @return a pointer to the layer 3 header
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const u8 *ipoque_detection_get_l3_header(struct ipoque_detection_module_struct *ipoque_struct, u8 * l3_protocol);

	/**
	 * This function will return a pointer to the layer 4 header of the previously processed packet.
	 * @param ipoque_struct the detection module, NULL results in a NULL pointer result
	 * @param l4_protocol the integer value referenced by this pointer will be set to the layer 4 protocol number, passing NULL is allowed
	 * @return a pointer to the layer 4 header
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const u8 *ipoque_detection_get_l4_header(struct ipoque_detection_module_struct *ipoque_struct, u8 * l4_protocol);

	/**
	 * This function will return a pointer to the payload of the previously processed packet.
	 * @param ipoque_struct the detection module
	 * @return a pointer to the packet payload or NULL if ipoque_struct is NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const u8 *ipoque_detection_get_payload(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * This function will return the length of the payload for the previously processed packet.
	 * @param ipoque_struct the detection module
	 * @return the length of the packet payload or 0 if ipoque_struct is NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u16 ipoque_detection_get_payload_length(struct ipoque_detection_module_struct *ipoque_struct);

#ifdef IPOQUE_PROTOCOL_TUNNELVOICE
	/**
	 * Free the flow from a tunnelvoice
	 * @param ipoque_struct the detection module, not NULL
	 * @param flow_struct the flow to free, not NULL
	 * @param is_marked returns whether a flow has been detected, not NULL
	 * @param max_calls returns the maximum number of calls, not NULL
	 * @param voip_ratio returns ratio of voip packets, not NULL
	 * @param voip_packet_ratio returns the ratio of bytes, not NULL
	 */
	void ipoque_detection_tunnelvoice_free_flow(void *ipoque_struct, void *flow_struct, u8 * is_marked, u8 * max_calls,
												u32 * voip_ratio, u32 * voip_packet_ratio);

	/**
	 * This function MUST BE CALLED immediately after detection init. This function needs ipoque_struct, mem_size,
	 * malloc_func and free_func.
	 * If one of the other parameters is 0, default values will be used.
	 * @param ipoque_struct the detection module, if NULL nothing gets initialized
	 * @param mem_size memory size for prealloc [bytes]
	 * @param prot_bitmask protocols which should scanned for tunnelvoice [Default: 0]
	 * @param malloc_func ptr to malloc func (malloc/kmalloc), not NULL
	 * @param free_func ptr to free func (free/kfree), not NULL
	 */
	int ipoque_detection_tunnelvoice_init(struct ipoque_detection_module_struct *ipoque_struct, u64 mem_size,
										  IPOQUE_PROTOCOL_BITMASK prot_bitmask, void *(*malloc_func) (unsigned long),
										  void (*free_func) (void *));

	/**
	 * This function MUST BE CALLED to deinit the tunnelvoice detection module.
	 * @param ipoque_struct the detection module, not NULL
	 * @param used_memory_pecentage returns used memory in percent [0-100], can be NULL
	 */
	void ipoque_detection_tunnelvoice_exit(void *ipoque_struct, u8 * used_memory_pecentage);

	/**
	 * This function returns the number of bytes required for tunnelvoice initialization so that the number of active flows can be tracked.
	 * @param ipoque_struct the detection module, not NULL
	 * @param number_of_active_tunnel_voice_flows number of maximum trackable flows
	 * @return number of bytes required for tunnelvoice initialization
	 */
	u64 ipoque_detection_tunnelvoice_get_memsize_for_flows(struct ipoque_detection_module_struct *ipoque_struct,
														   u64 number_of_active_tunnel_voice_flows);

	/**
	 * This function returns the number of currently used flows in the tunnelvoice memory block.
	 * @param ipoque_struct the detection module, not NULL
	 * @return number of currently used flows
	 */
	u64 ipoque_detection_tunnelvoice_get_number_of_used_flows(struct ipoque_detection_module_struct *ipoque_struct);
#endif

#ifdef IPOQUE_ENABLE_DEFRAG_ENGINE

	enum ipoqe_defrag_checksum_enum {
		IPOQUE_DEFRAG_CHECKSUM_IGNORE_WRONG_IP_CHECKSUM,
		IPOQUE_DEFRAG_CHECKSUM_DISCARD_WRONG_IP_CHECKSUM,
		IPOQUE_DEFRAG_CHECKSUM_MARK_WRONG_IP_CHECKSUM_AS_WRONG,
	};

	/**
	 * Initializes the pace defrag engine
	 * @param ipoque_struct the detection module, not NULL
	 * @param memory maximum memory in Bytes for defrag engine, if realloc is set to != NULL, it is the initial memory
	 * the defrag engine can handle as many packets as fit into the allocated memory, the maximum packet size is restricted to u16
	 * @param timeout timeout in ticks for each fragment. It is recommended to keep this as low as possible ( maximum 1 second )
	 * @param checksum checksum setting for defrag engine
	 * @param hash_malloc allocation function for hash table, not NULL
	 * @param hash_realloc reallocation function for hash table, if set to != NULL, reallocation will be enabled
	 * @param hash_free free function for hash table, not NULL
	 * @param allocation_userptr allocation for defrag engine, not NULL
	 * @return returns 0 for success, otherwise for any initialization error
	 */
	u8 ipoque_detection_init_defragment_engine(struct ipoque_detection_module_struct *ipoque_struct,
											   u64 memory, u32 timeout, enum ipoqe_defrag_checksum_enum checksum,
											   void *(*hash_malloc) (unsigned long size, void *userptr),
											   void *(*hash_realloc) (void *ptr, unsigned long size, void *userptr),
											   void (*hash_free) (void *ptr, void *userptr), void *allocation_userptr);

	/**
	 * Initializes the pace defrag engine with additional user defined key
	 * @param ipoque_struct the detection module, not NULL
	 * @param memory maximum memory in Bytes for defrag engine, if realloc is set to != NULL, it is the initial memory
	 * @param timeout timeout in ticks for each fragment. It is recommended to keep this as low as possible ( maximum 1 second )
	 * a value of 0 will mark every packet as too old
	 * @param checksum checksum setting for defrag engine
	 * @param additional_user_key_len number of bytes for the additional key
	 * @param hash_malloc allocation function for hash table, not NULL
	 * @param hash_realloc reallocation function for hash table, if set to != NULL, reallocation will be enabled
	 * @param hash_free free function for hash table, not NULL
	 * @param allocation_userptr allocation for defrag engine, not NULL
	 * @return returns 0 for success, otherwise for any initialization error
	 */
	u8 ipoque_detection_init_defragment_engine_ext(struct ipoque_detection_module_struct *ipoque_struct,
												   u64 memory, u32 timeout, enum ipoqe_defrag_checksum_enum checksum,
												   u32 additional_user_key_len,
												   void *(*hash_malloc) (unsigned long size, void *userptr),
												   void *(*hash_realloc) (void *ptr, unsigned long size, void *userptr),
												   void (*hash_free) (void *ptr, void *userptr),
												   void *allocation_userptr);

	enum ipoque_defrag_enum {
		IPOQUE_DEFRAG_NOT_FRAGMENTED = 0,
		IPOQUE_DEFRAG_DISCARD_DUE_WRONG_CHECKSUM,
		IPOQUE_DEFRAG_FRAGMENT_NOT_COMPLETE,
		IPOQUE_DEFRAG_FRAGMENT_COMPLETE,
	};

	struct ipoque_defrag_return_struct {
		enum ipoque_defrag_enum result;
		unsigned char *defrag_packet;
		unsigned short defrag_packetlen;
	};
	/**
	 * processes one ip packet, up to now, only ipv4 is supported
	 * @param ipoque_struct the detection module, NOT null
	 * @param packet pointer to the ip packet, NOT null
	 * @param packetlen length of the packet which can be accessed
	 * @param current_tick current timestamp, must be larger than the previous timestamp
	 * @return returns a structure which returns a state and if the state is IPOQUE_DEFRAG_FRAGMENT_COMPLETE, the pointer and length of the defragmented packet
	 */
	const struct ipoque_defrag_return_struct *ipoque_detection_defrag(struct ipoque_detection_module_struct
																	  *ipoque_struct, const unsigned char *packet,
																	  const unsigned short packetlen, u32 current_tick);

	/**
	 * processes one ip packet, up to now, only ipv4 is supported
	 * extended function to handle user key for fragment tracking
	 *
	 * @param ipoque_struct the detection module, NOT null
	 * @param packet pointer to the ip packet, NOT null
	 * @param packetlen length of the packet which can be accessed
	 * @param current_tick current timestamp
	 * @param user_key pointer to memory containing the additional key for fragment tracking, can be NULL
	 * @return returns a structure which returns a state and if the state is IPOQUE_DEFRAG_FRAGMENT_COMPLETE, the pointer and length of the defragmented packet
	 */
	const struct ipoque_defrag_return_struct *ipoque_detection_defrag_ext(struct ipoque_detection_module_struct
																		  *ipoque_struct, const unsigned char *packet,
																		  const unsigned short packetlen,
																		  u32 current_tick, u8 * user_key);

	/**
	 * exit of defragmentation engine
	 * @param ipoque_struct the detection module, not NULL
	 */
	void ipoque_detection_exit_defragment_engine(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * profiling of defragmentation engine
	 * @param ipoque_struct the detection module, not NULL
	 * @param used_elements number of currently used elements, not NULL
	 * @param allocated_elements number of currently allocated elements, NOT null
	 */
	void ipoque_detection_defrag_status(struct ipoque_detection_module_struct *ipoque_struct, u64 * used_elements,
										u64 * allocated_elements);

#endif

	/************************************************
	 * API and library version                      *
	 ************************************************/

	typedef struct ipoque_pace_api_version {
		/**
		 * API version, increased whenever the API changes
		 */
		u32 api_version;
	} ipoque_pace_api_version_t;

	/**
	 * query API version. The API version will be increased if the API
	 * has been changed, i.e., some public functions or structures have
	 * been changed.
	 *
	 * @return API version structure
	 */
	ipoque_pace_api_version_t ipoque_pace_get_api_version(void);

	typedef struct ipoque_pace_version {
		/**
		 * the major PACE version
		 */
		u16 major_version;

		/**
		 * the minor PACE version
		 */
		u16 minor_version;

		/**
		 * an optional patch version
		 */
		u16 patch_version;

		/**
		 * a string representation "MAJOR.MINOR.PATCH"
		 */
		char version_string[32];

		/**
		 * same as version_string but a build ID may be appended
		 */
		char build_string[32];
	} ipoque_pace_version_t;


#define IPOQUE_DETECTED_PROTOCOL_CHANGED 0x01
#define IPOQUE_DETECTED_SUBPROTOCOL_CHANGED 0x02
#define IPOQUE_DETECTED_APPLICATION_CHANGED 0x04
#define IPOQUE_REAL_PROTOCOL_CHANGED 0x08
#define IPOQUE_REAL_SUBPROTOCOL_CHANGED 0x10
#define IPOQUE_EXCLUDED_BM_CHANGED 0x20

    typedef struct ipoque_detection_result {
        /**
         * pointer to a excluded_protocol_bitmask
         */
        IPOQUE_PROTOCOL_BITMASK *excluded_protocol_bitmask;

        /**
         * the application id of the flow
         */
        u32 application_id;

        /**
         * the protocol id of the last protocol found in the protocol history of the last processed packet
         */
        u16 detected_protocol;

        /**
         * the protocol id of the last real protocol found in the protocol history of the last processed packet
         */
        u16 real_protocol;

        /**
         * bitmask which contains information which value in this struct have changed since last packet
         */
        u8 result_changed_bm;

        /**
         * the protocol id of the last subprotocol found in the protocol history of the last processed packet
         */
        u8 detected_subprotocol;

        /**
         * the protocol id of the last real subprotocol found in the protocol history of the last processed packet
         */
        u8 real_subprotocol;

    } ipoque_detection_result_t;

	/**
	 * query the PACE release version. The PACE version is described
	 * by a major and minor number and optionally a third patch
	 * number. The returned structure also contains a character
	 * representation of the version number.
	 *
	 * @return PACE version structure
	 */
	ipoque_pace_version_t ipoque_pace_get_version(void);

	/**
	 * query the PACE release version by filling the given
	 * structure. The PACE version is described by a major and minor
	 * number and optionally a third patch number. The returned
	 * structure also contains a character representation of the
	 * version number.
	 *
	 * @param version structure to be filled
	 */
	void ipoque_pace_fill_version(struct ipoque_pace_version *version);

	/**
	 * query the PACE version of the currently active library. In case
	 * of enabled dynamic upgrade, it's the version of the last
	 * activated library, otherwise it's the version of the main
	 * library. The PACE version is described by a major and minor
	 * number and optionally a third patch number. The returned
	 * structure also contains a character representation of the
	 * version number.
	 *
	 * @param ipoque_struct the struct for the detection module, not NULL
	 * @return a pointer to a static PACE version structure
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const ipoque_pace_version_t *ipoque_pace_get_active_version(struct ipoque_detection_module_struct *ipoque_struct);

    /**
     * query the detection result of the last processed packet.
     * The detection result contains the detected protocol, real protocol, subprotocol, real subprotocol,
     * aplication and excluded_protocol_bitmask.
     * Real protocol and real subprotocol are not set if the protocol history size is <= 1
     * @param ipoque_struct the struct for the detection module, not NULL
     * @return a pointer to a static PACE detection result structure
     */
    const ipoque_detection_result_t *ipoque_pace_get_detection_result(struct ipoque_detection_module_struct
                                                                 *ipoque_struct);

#ifdef IPOQUE_PROTOCOL_SKYPE

	typedef enum {
		IPOQUE_SKYPE_SAFE_DETECTION = 0,
		IPOQUE_SKYPE_AGGRESSIVE_DETECTION = 1
	} ipoque_skype_detection_mode_t;

	/**
	 * This function sets the Skype detection mode.
	 *
	 * if set to IPOQUE_SKYPE_AGGRESSIVE_DETECTION, PACE will use a
	 * more aggressive mode to detect all skype flows. This might
	 * cause a higher false positive rate.
	 *
	 * if set to IPOQUE_SKYPE_SAFE_DETECTION, PACE will use the
	 * regular detection mode to avoid a higher missdetection rate.
	 *
	 * default is IPOQUE_SKYPE_SAFE_DETECTION
	 *
	 * @param ipoque_struct the struct for the detection module, not NULL
	 * @param mode the mode either IPOQUE_SKYPE_AGGRESSIVE_DETECTION or IPOQUE_SKYPE_SAFE_DETECTION.
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */

	void ipoque_skype_set_detection_mode(struct ipoque_detection_module_struct *ipoque_struct,
										 const ipoque_skype_detection_mode_t mode);

#endif

#ifdef IPOQUE_PACE_DYNAMIC_UPGRADE

	enum ipoque_dynamic_upgrade_mode_enum {
		IPOQUE_DYNAMIC_UPGRADE_DISABLED = 0,
		IPOQUE_DYNAMIC_UPGRADE_ENABLED
	};

	/**
	 * This function will activate the dynamic upgrade feature
	 * @param ipoque_struct the detection module
	 * @param mode @see ipoque_dynamic_upgrade_mode_enum
	 * @param ipoque_dlopen function pointer to POSIX compatible dlopen function
	 * @param ipoque_dlsym function pointer to POSIX compatible dlsym function
	 * @param ipoque_dlclose function pointer to POSIX compatible dlclose function
	 * @param ipoque_malloc function pointer to memory allocator, not NULL
	 * @param ipoque_free function pointer to memory free function, not NULL
	 * @param userptr pointer given to all function pointer function as additional argument
	 * @return returns 0 on success, != 0 on error
	 * 1: ipoque_struct == NULL
	 * 2: POSIX compatible functions not initialized
	 * 3: failed to initialize memory
	 */
	u8 ipoque_pace_dynamic_upgrade_set_mode(struct ipoque_detection_module_struct *ipoque_struct,
											enum ipoque_dynamic_upgrade_mode_enum mode,
											void *(*ipoque_dlopen) (const char *filename, int flag, void *userptr),
											void *(*ipoque_dlsym) (void *handle, const char *symbol, void *userptr),
											int (*ipoque_dlclose) (void *handle, void *userptr),
											void *(*ipoque_malloc) (unsigned long size, void *userptr),
											void (*ipoque_free) (void *ptr, void *userptr), void *userptr);

	enum ipoque_dynamic_load_return_enum {
		IPOQUE_DYNAMIC_LOAD_RET_SUCCESSFUL,
		IPOQUE_DYNAMIC_LOAD_RET_FAILURE,
		IPOQUE_DYNAMIC_LOAD_RET_ALLOCATION_FAILED,
		IPOQUE_DYNAMIC_LOAD_RET_LIBRARY_NOT_FOUND,
		IPOQUE_DYNAMIC_LOAD_RET_LIBRARY_INCOMPLETE,
		IPOQUE_DYNAMIC_LOAD_RET_LIBRARY_INITIALIZATION_FAILED,
		IPOQUE_DYNAMIC_LOAD_RET_LIBRARY_NOT_NEWER,
		IPOQUE_DYNAMIC_LOAD_RET_LIBRARY_STATE_MACHINE_TOO_BIG,
		IPOQUE_DYNAMIC_LOAD_RET_NOT_COMPATIBLE
	};

	/**
	 * This function will try to load a given library
	 * @param ipoque_struct the detection module, not NULL
	 * @param filename the filename of the library, point to existing library
	 * @param ipoque_malloc function pointer to memory allocator, not NULL
	 * @param ipoque_free function pointer to memory free function, not NULL
	 * @param userptr pointer given to all function pointer function as additional argument
	 * @param force_upgrade set to 1 to force upgrade even if given library is not newer, 0 for normal operation with version check
	 * @return returns enum ipoque_dynamic_load_return_enum indicating success or failure
	 */
	enum ipoque_dynamic_load_return_enum ipoque_pace_dynamic_upgrade_load_library(struct ipoque_detection_module_struct
																				  *ipoque_struct, const char *filename,
																				  void *(*ipoque_malloc) (unsigned long
																										  size,
																										  void
																										  *userptr),
																				  void (*ipoque_free) (void *ptr,
																									   void *userptr),
																				  void *userptr, u8 force_upgrade);

	/**
	 * This function will use the newly loaded library version from the master instance to update a cloned instance.
	 * @param cloned_ipoque_struct the cloned detection module, not NULL
	 * @param master_ipoque_struct the master detection module, not NULL
	 * @param ipoque_malloc function pointer to memory allocator, not NULL
	 * @param ipoque_free function pointer to memory free function, not NULL
	 * @param userptr pointer given to all function pointer function as additional argument
	 * @return returns enum ipoque_dynamic_load_return_enum indicating success or failure
	 */
	enum ipoque_dynamic_load_return_enum ipoque_pace_update_cloned_library(struct ipoque_detection_module_struct *cloned_ipoque_struct,
																		   struct ipoque_detection_module_struct *master_ipoque_struct,
																		   void *(*ipoque_malloc) (unsigned long
																								   size,
																								   void
																								   *userptr),
																		   void (*ipoque_free) (void *ptr,
																								void *userptr),
																		   void *userptr);


	enum ipoque_dynamic_activate_return_enum {
		IPOQUE_DYNAMIC_ACTIVATE_RET_SUCCESSFUL,
		IPOQUE_DYNAMIC_ACTIVATE_RET_NEWEST_VERSION_ALREADY_RUNNING,
	};

	/**
	 * This function will activate the previously loaded library
	 * @param ipoque_struct the detection module, not NULL
	 * @return returns enum ipoque_dynamic_activate_return_enum indicating success or failure
	 */
	enum ipoque_dynamic_activate_return_enum ipoque_pace_dynamic_upgrade_activate_loaded_library(struct
																								 ipoque_detection_module_struct
																								 *ipoque_struct);

	/**
	 * this function sets the amount of bytes reserved for future
	 * updates in the flow and id data structure.
	 *
	 * The default value is about 10% of the size of the
	 * corresponding structures.
	 * 
	 * This function must be called before enabling the dynamic
	 * upgrade. It will fail if it will be called after enabling the
	 * upgrade.
	 *
	 * @param ipoque_struct the detection module
	 * @param reserve_bytes the number of bytes reserved for dynamic upgrades
	 * @return 0 if values has been set successfully, != 0 otherwise
	 * 1: ipoque_struct == NULL
	 * 2: dynamic upgrade already enabled
	 */
	u8 ipoque_pace_set_dynamic_reserve_space(struct ipoque_detection_module_struct *ipoque_struct, u32 reserve_bytes);

	/**
	 * this function releases the library code from unused libraries
	 * by calling dlclose and freeing some no longer used memory. This
	 * function can be called at any time. If cloned detection modules
	 * are used, this function must be called for each clone first
	 * before calling it for the master instance.
	 *
	 * @param ipoque_struct the detection module
	 * @param ipoque_free function pointer to memory free function, not NULL
	 * @param userptr pointer given to all function pointer function as additional argument
	 * @return returns the number of released libraries or -1 on error
	 */
	int ipoque_pace_remove_inactive_libraries(struct ipoque_detection_module_struct *ipoque_struct,
											  void (*ipoque_free_ext)(void *ptr, void *userptr), void *userptr);

	/**
	 * This function releases all memory from old libraries
	 * considering a given age. There must not exists any flow, or
	 * subscriber that is older than the given age. Due to timestamp
	 * wraparound it is recommended to call this function on a regular
	 * basis (once per day or similar large intervals which are still
	 * at least two times smaller than the wraparound cycle.
	 *
	 * @param ipoque_struct the detection module
	 * @param ipoque_free function pointer to memory free function, not NULL
	 * @param userptr pointer given to all function pointer function as additional argument
	 * @param age the timestamp of the oldest flow or subscriber. Flows/subscriber older than this
	 *        timestamp can no longer be handled.
	 * @return returns the number of released libraries or -1 on error
	 */
	int ipoque_pace_release_memory_from_old_libraries(struct ipoque_detection_module_struct *ipoque_struct,
													  void (*ipoque_free_ext)(void *ptr, void *userptr), void *userptr,
													  const IPOQUE_TIMESTAMP_COUNTER_SIZE age);

#ifdef __KERNEL__
	typedef void *(*ipoque_pace_lookup_function_t) (const char *symbol_name, void *user_ptr);

	int ipoque_pace_register_function_lookup(ipoque_pace_lookup_function_t f,
											 void *user_ptr);
#endif

#endif

	/**
	 * this function returns the size of the internal memory required to store flow information.
	 *
	 * If called with a NULL argument, the function returns the number of bytes required for the library
	 * without several runtime features enabled (like dynamic upgrade or CDPs). If a valid ipoque_struct
	 * is given, the size depends on the settings of this instance. If dynamic upgrade is enabled, the
	 * size of the structure for dynamic upgrade including spare bytes is returned.
	 *
	 * @param ipoque_struct initialized ipoque_struct or NULL
	 * @return the size of the flow data
	 */
	u32 ipoque_pace_get_sizeof_flow_data(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * this function returns the size of the internal memory required to store id information.
	 *
	 * If called with a NULL argument, the function returns the number of bytes required for the library
	 * without several runtime features enabled (like dynamic upgrade or CDPs). If a valid ipoque_struct
	 * is given, the size depends on the settings of this instance. If dynamic upgrade is enabled, the
	 * size of the structure for dynamic upgrade including spare bytes is returned.
	 *
	 * @param ipoque_struct initialized ipoque_struct or NULL
	 * @return the size of the id data
	 */
	u32 ipoque_pace_get_sizeof_id_data(struct ipoque_detection_module_struct *ipoque_struct);

/* OSDPI-START */
#define IPOQUE_PACE_ONLY_IPV4 ( 1 << 0 )
#define IPOQUE_PACE_ONLY_IPV6 ( 1 << 1 )
#define IPOQUE_PACE_ONLY_COMPLETE_L4_PAYLOAD ( 1 << 2 )

	/**
	 * query the pointer to the layer 4 packet. If no additional flags
	 * concering fragments are given, the function will succeed if the
	 * IP packet is not fragmented or the apcket is the first fragment. If the
	 * flag IPOQUE_PACE_ONLY_COMPLETE_L4_PAYLOAD is used, then this
	 * function will also fail for the first fragment.
	 *
	 * @param l3 pointer to the layer 3 data
	 * @param l3_len length of the layer 3 data
	 * @param l4_return filled with the pointer the layer 4 data if return value == 0, unmodified otherwise
	 * @param l4_len_return filled with the length of the layer 4 data if return value == 0, unmodified otherwise
	 * @param l4_protocol_return filled with the protocol of the layer 4 data if return value == 0, unmodified otherwise
	 * @param flags limits operation. Possible values are IPOQUE_PACE_ONLY_IPV4 or IPOQUE_PACE_ONLY_IPV6 to limit to
	 *        ipv4 or ipv6 packets; IPOQUE_PACE_ONLY_COMPLETE_L4_PAYLOAD can be set to let the function fail also on
	 *        the first of multiple fragments; 0 is default
	 * @return 0 if correct layer 4 data could be found, != 0 otherwise
	 */
	u8 ipoque_pace_get_l4(const u8 * l3, u16 l3_len, const u8 ** l4_return, u16 * l4_len_return,
						  u8 * l4_protocol_return, u32 flags);
/* OSDPI-END */

	/**
	 * query the pointer to the layer 7 packet
	 *
	 * @param l3 pointer to the layer 3 data, may be NULL
	 * @param l3_len length of the layer 3 data, may be 0
	 * @param l4 pointer to the layer 4 data
	 * @param l4_len length of the layer 4 data
	 * @param l4_protocol protocol of the layer 4 data
	 * @param l7_return filled with the pointer the layer 7 data if return value == 0, undefined otherwise
	 * @param l7_len_return filled with the length of the layer 7 data if return value == 0, undefined otherwise
	 * @return 0 if correct layer 7 data could be found, != 0 otherwise
	 */
	u8 ipoque_pace_get_l7(const u8 * l3, u16 l3_len, const u8 * l4, u16 l4_len, u8 l4_protocol, const u8 ** l7_return,
						  u16 * l7_len_return);

/* OSDPI-START */
	/**
	 * build the unique key of a flow
	 *
	 * @param l3 pointer to the layer 3 data
	 * @param l3_len length of the layer 3 data
	 * @param l4 pointer to the layer 4 data, not NULL
	 * @param l4_len length of the layer 4 data
	 * @param l4_protocol layer 4 protocol
	 * @param key_return filled with the unique key if return value == 0, undefined otherwise
	 * @param dir_return filled with a direction flag (0 or 1), can be NULL
	 * @param flags limit operation on ipv4 or ipv6 packets, possible values are IPOQUE_PACE_ONLY_IPV4 or IPOQUE_PACE_ONLY_IPV6; 0 means any
	 * @return 0 if key could be built, != 0 otherwise
	 */
	u8 ipoque_pace_build_key(const u8 * l3, u16 l3_len, const u8 * l4, u16 l4_len, u8 l4_protocol,
							 struct ipoque_unique_flow_ipv4_and_6_struct *key_return, u8 * dir_return, u32 flags);
/* OSDPI-END */

	/**
	 * decapsulate one tunnel
	 *
	 * @param l3 pointer to the layer 3 data
	 * @param l3_len length of the layer 3 data
	 * @param l3_return filled with inner l3 pointer
	 * @param l3_len_return filled with innter l3 length
	 * @param flags limit operation on ipv4 or ipv6 packets, possible values are IPOQUE_PACE_ONLY_IPV4 or IPOQUE_PACE_ONLY_IPV6; 0 means any
	 * @return 0 on success, 1 if no tunnel has been decapsulated, anything else otherwise
	 */
	u8 ipoque_pace_try_decapsulate(const u8 * l3, u16 l3_len, const u8 ** l3_return, u16 * l3_len_return, u32 flags);

	/**
	 * query if the last processed packet was skipped by the detection as part of a SOCKS proxy connection setup
	 *
	 * @param ipoque_struct the detection module
	 * @return 0 if the packet was processed by the detection, 1 if the packet was skipped
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u8 ipoque_pace_get_packet_skipped_as_proxy_setup(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * limit IP version handling to IPv4
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param flag limit operation to ipv4 packets if != 0, otherwise (==0) no limitation applies
	 */
	void ipoque_pace_limit_to_ipv4(struct ipoque_detection_module_struct *ipoque_struct, u8 flag);

/* OSDPI-START */
	/**
	 * returns the real protocol for the flow of the last packet given to the detection.
	 * if no real protocol could be found, the unknown protocol will be returned.
	 * 
	 * @param ipoque_struct the detection module, not NULL
	 * @return the protocol id of the last real protocol found in the protocol history of the flow
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u16 ipoque_pace_get_real_protocol_of_flow(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * returns true if the protocol history of the flow of the last packet given to the detection
	 * contains the given protocol.
	 * 
	 * @param ipoque_struct the detection module, not NULL
	 * @param protocol_id id of the protocol we search for in the history
	 * @return 1 if protocol has been found, 0 if the protocol was not detected or not found
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u8 ipoque_pace_flow_protocol_history_contains_protocol(struct ipoque_detection_module_struct *ipoque_struct,
														   u16 protocol_id);

	/**
	 * This function returns the maximum number of supported protocols
	 * including the unknown protocol and slots for custom defined
	 * protocols.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @return number of protocols
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u16 ipoque_pace_get_number_of_protocols(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * This function returns the number of protocols implemented by PACE
	 * including the unknown protocol.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @return number of implemented protocols
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u16 ipoque_pace_get_number_of_implemented_protocols(struct ipoque_detection_module_struct *ipoque_struct);

#ifdef IPOQUE_PACE_API_MK1

	/**
	 * This function returns the number of available slots for CDPs.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @return number of available CDPs
	 */
	u16 ipoque_pace_get_number_of_cdp_slots(struct ipoque_detection_module_struct *ipoque_struct);
#endif

	/**
	 * This function returns the number of supported subprotocols by the given protocol.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param protocol_id
	 * @return number of subprotocols, or 0 if protocol_id not found
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u16 ipoque_pace_get_number_of_subprotocols(struct ipoque_detection_module_struct *ipoque_struct, u16 protocol_id);

	/**
	 * This function returns the name of the given protocol.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param protocol_id id of the protocol
	 * @return protocol name when existing, otherwise NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const char *ipoque_pace_get_protocol_name(struct ipoque_detection_module_struct *ipoque_struct, u16 protocol_id);

	/**
	 * This function returns the name short of the given protocol.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param protocol_id id of the protocol
	 * @return protocol short name when existing, otherwise NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const char *ipoque_pace_get_protocol_short_name(struct ipoque_detection_module_struct *ipoque_struct,
													u16 protocol_id);

	/**
	 * This function returns the description of the given protocol.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param protocol_id id of the protocol
	 * @return protocol description when existing, otherwise NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const char *ipoque_pace_get_protocol_description(struct ipoque_detection_module_struct *ipoque_struct,
													 u16 protocol_id);

	/**
	 * This function returns the name of the given subprotocol.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param protocol_id id of the existing protocol
	 * @param subprotocol_id id of the subprotocol
	 * @return subprotocol name when existing, otherwise NULL
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	const char *ipoque_pace_get_subprotocol_name(struct ipoque_detection_module_struct *ipoque_struct, u16 protocol_id,
												 u16 subprotocol_id);

	/**
	 * This function returns the ID of the protocol described by the given name.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param protocol_name the name of the protocol, can be NULL but result will be 0
	 * @return protocol ID
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u16 ipoque_pace_get_protocol_id_for_name(struct ipoque_detection_module_struct *ipoque_struct,
											 const char *protocol_name);

/* OSDPI-END */

#ifdef IPOQUE_CUSTOM_DEFINED_PROTOCOLS_2_0
	enum ipoque_cdp_return {
		IPOQUE_CDP_EXCLUDE = 0,
		IPOQUE_CDP_MATCH = 1,
		IPOQUE_CDP_MATCH_BUT_NEED_NEXT_PACKET = 2,
		IPOQUE_CDP_NEED_NEXT_PACKET = 3
	};

	/**
	 * This is the prototype for protocol detection callbacks
	 *
	 * @param ipoque_struct the detection module
	 * @param userptr the user pointer set when the corresponding protocol has been registered
	 * @param flow_area the pointer to the dedicated flow area (the size is as requested at registration), might be NULL
	 * @param src_area the pointer to the dedicated subscriber area of the source of the packet (the size is as requested at registration), can be NULL
	 * @param dst_area the pointer to the dedicated subscriber area of the destination of the packet (the size is as requested at registration), can be NULL
	 * @return indicates if the protocol has matched, excluded or more packets are required
	 */
	typedef enum ipoque_cdp_return (*ipoque_cdp_detection_function_t) (struct ipoque_detection_module_struct *
																	   ipoque_struct, void *userptr, void *flow_area,
																	   void *src_area, void *dst_area);

	/**
	 * this function sets the number of CDPs available
	 * for registration.
	 *
	 * This function must be called AFTER the initialization of the
	 * detection module but BEFORE querying information about flow and
	 * subscriber sizes
	 * (ipoque_detection_get_sizeof_dynamic_ipoque_flow_struct...)
	 * since the value returned by this function depend on this
	 * setting.
	 *
	 * Also, this function can only be called once, it is not
	 * possible to change this value later on.
	 *
	 * @param ipoque_struct the detection module, can be NULL
	 * @param number_of_protocols the number of protocols, not 0
	 * @param ipoque_malloc a pointer to an allocator function, not NULL
	 * @param ipoque_free a pointer to a deallocator function, not NULL
	 * @param a user pointer for the memory function
	 * @return 0 for success, != 0 in case of errors
	 */
	u8 ipoque_pace_cdp_set_number_of_protocols(struct ipoque_detection_module_struct *ipoque_struct,
											   u32 number_of_protocols,
											   void *(*ipoque_malloc) (unsigned long size, void *userptr),
											   void (*ipoque_free) (void *ptr, void *userptr), void *userptr);

	/**
	 * This function returns the number of registered CDPs.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @return number of registered CDPs
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u32 ipoque_pace_cdp_get_number_of_protocols(struct ipoque_detection_module_struct * ipoque_struct);

	/**
	 * this function registers a CDP callback.
	 * 
	 * This function must be called AFTER the initialization of the
	 * detection module but BEFORE querying information about flow and
	 * subscriber sizes
	 * (ipoque_detection_get_sizeof_dynamic_ipoque_flow_struct...)
	 * since the value returned by this function depend on this
	 * setting.
	 *
	 * @param ipoque_struct the detection module, can be NULL but function just returns
	 * @param cdp_id the ID of the protocol, counting from 0, the function can only be called once for each cdp_id
	 * @param callback the detection callback function, can be NULL but function just returns
	 * @param callback_userptr a user pointer given to the callback function when called
	 * @param flow_area_size number of bytes reserved in the flow data structure
	 * @param subscriber_area_size number of bytes reserved in the subscriber data structure
	 * @param ipoque_malloc function pointer to memory allocator, not NULL
	 * @param ipoque_free function pointer to memory free function, not NULL
	 * @param mem_userptr user pointer given to memory function
	 * @return 0 for success, != 0 in case of errors
	 */
	u8 ipoque_pace_cdp_register_protocol(struct ipoque_detection_module_struct *ipoque_struct,
										 u32 cdp_id,
										 ipoque_cdp_detection_function_t callback,
										 void *callback_userptr,
										 u32 flow_area_size, u32 subscriber_area_size,
										 void *(*ipoque_malloc) (unsigned long size, void *mem_userptr),
										 void (*ipoque_free) (void *ptr, void *mem_userptr), void *mem_userptr);
#endif

	/**
	 * this function sets the protocol offset used when returning CDP
	 * protocol IDs.  The default value is 0 which means the CDP
	 * counting starts at LAST_IMPLEMENTED_PROTOCOL+1. By setting the
	 * offset it is possible to have constant protocol IDs even in
	 * case new native protocols have been added.
	 * 
	 * @param ipoque_struct the detection module, not NULL
	 * @param start_offset the start offset for counting
	 *        CDPs. Possible values are zero for start counting at
	 *        LAST_IMPLEMENTED_PROTOCOL+1 or any value >
	 *        LAST_IMPLEMENTED_PROTOCOL and value < 65535 - CDP.NUMBER_OF_PROTOCOLS.
	 * @return 0 for success, != 0 in case of errors
	 */
	u8 ipoque_pace_cdp_set_offset(struct ipoque_detection_module_struct *ipoque_struct, u32 start_offset);

#ifdef IPOQUE_CUSTOM_DEFINED_PROTOCOLS_2_0
	enum ipoque_l3_type {
		IPOQUE_L3_UNKNOWN,
		IPOQUE_L3_IPV4,
		IPOQUE_L3_IPV6
	};

	struct ipoque_cdp_l3_info {
		const void *l3_start;	/* the start of the layer 3 payload */
		u16 l3_length;			/* the length of the layer 3 payload (including all other layers) */
		enum ipoque_l3_type l3_type;	/* the type of the layer 3 header */

		/* this struct may grow in later versions but the previous fields will not change */
	};

	struct ipoque_cdp_l4_info {
		const void *l4_start;	/* the start of the layer 4 payload */
		u16 l4_length;			/* the length of the layer 4 payload (including all other layers) */
		u8 l4_type;				/* the type of the layer 4 header (the IP protocol type) */

		/* this struct may grow in later versions but the previous fields will not change */
	};

	struct ipoque_cdp_l7_info {
		const void *l7_start;	/* the start of the layer 7 payload */
		u16 l7_length;			/* the length of the layer 7 payload */

		/* this struct may grow in later versions but the previous fields will not change */
	};

	struct ipoque_cdp_generic_info {
		u32 protocol;			/* the current detected protocol ID */
		u16 flow_packet_counter[2];	/* the packet counters for both directions */
		u8 packet_direction;	/* the packet direction (0 or 1) */
		u8 initial_packet_direction;	/* the direction of the first packet of the flow (0 or 1) */

		/* this struct may grow in later versions but the previous fields will not change */
	};

	/**
	 * this function can be used in CDP to query the layer 3 information.
	 *
	 * @param ipoque_struct the detection module, can be NULL
	 * @return a pointer to a static area containing the layer 3 information
	 */
	const struct ipoque_cdp_l3_info *ipoque_pace_cdp_get_l3_info(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * this function can be used in CDP to query the layer 4 information.
	 *
	 * @param ipoque_struct the detection module, can be NULL
	 * @return a pointer to a static area containing the layer 4 information
	 */
	const struct ipoque_cdp_l4_info *ipoque_pace_cdp_get_l4_info(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * this function can be used in CDP to query the layer 7 information.
	 *
	 * @param ipoque_struct the detection module, can be NULL
	 * @return a pointer to a static area containing the layer 7 information
	 */
	const struct ipoque_cdp_l7_info *ipoque_pace_cdp_get_l7_info(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * this function can be used in CDP to query generic flow information.
	 *
	 * @param ipoque_struct the detection module, can be NULL
	 * @return a pointer to a static area containing the generic information
	 */
	const struct ipoque_cdp_generic_info *ipoque_pace_cdp_get_generic_info(struct ipoque_detection_module_struct
																		   *ipoque_struct);
#endif

	/**
	 * this function returns the default group of the given protocol.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param protocol_id the protocol ID
	 * @return the group ID of the given protocol
	 */
	u16 ipoque_pace_get_default_group(struct ipoque_detection_module_struct *ipoque_struct, u16 protocol_id);

	/**
	 * this function returns the group in respect to the given
	 * protocol and its subprotocol type. The group returned may or
	 * may not differ from the default group of the protocol ID.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param protocol_id the protocol ID
	 * @param subprotocol_id the sub-protocol ID of the protocol
	 * @return the group ID of the given protocol
	 */
	u16 ipoque_pace_get_current_group(struct ipoque_detection_module_struct *ipoque_struct,
									  u16 protocol_id, u16 subprotocol_id);

	/**
	 * this function returns the number of groups defined by PACE
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @return returns the number of groups
	 */
	u16 ipoque_pace_get_number_of_groups(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * this function returns the name of the given group
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param group_id the group ID
	 * @return a pointer to a statically allocated null-terminated string
	 */
	const char *ipoque_pace_get_group_name(struct ipoque_detection_module_struct *ipoque_struct, u16 group_id);

	/**
	 * this function returns the verbose description of the given group
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param group_id the group ID
	 * @return a pointer to a statically allocated null-terminated string
	 */
	const char *ipoque_pace_get_group_description(struct ipoque_detection_module_struct *ipoque_struct, u16 group_id);

	/**
	 * this function fills a given array with all protocol IDs found
	 * for a given group ID. It only considers the default group of a
	 * protocol.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param group_id the group ID
	 * @param list a pointer to a already allocated memory area, NULL returns 1
	 * @param list_len the number of entries available for writing in the list
	 *        the list should be large enough to store all protocols available in PACE
	 *        but it can be smaller.
	 * @param return_len the number of used entries will be written to this pointer, NULL returns 1
	 * @return 0 on success, != 0 on error
	 */
	u8 ipoque_pace_get_protocols_for_group(struct ipoque_detection_module_struct *ipoque_struct,
										   u16 group_id, u16 * list, u16 list_len, u16 * return_len);

	/**
	 * this function returns a pointer to a preallocated static list containing protocol groups
	 * for a given protocol which describes all features of the protocol besides its default group.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param protocol_id the protocol ID
	 * @param a pointer  to a variable to which the pointer to the internal list will be written to, NULL stays NULL
	 * @param return_len a pointer to a variable which will contains the length of the returned list, NULL stays NULL
	 */
	u8 ipoque_pace_get_descriptive_groups(struct ipoque_detection_module_struct *ipoque_struct,
										  u16 protocol_id, const u16 ** return_list, u16 * return_len);

	/**
	 * this function returns the application ID for the last packet
	 * processed by the given detection module
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @return application ID
	 */
	u32 ipoque_pace_get_application_id(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * this function returns the name of the given application ID
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param application_id application ID
	 * @return pointer to a statically allocated string
	 */
	const char *ipoque_pace_get_application_name(struct ipoque_detection_module_struct *ipoque_struct,
												 u32 application_id);

	enum ipoque_pace_application_version_type {
		IPOQUE_PACE_APPLICATION_VERSION_UNKNOWN = 0,
		IPOQUE_PACE_APPLICATION_VERSION_STRING,
	};

	struct ipoque_pace_application_version {
		enum ipoque_pace_application_version_type type;
		const u8 *version_string;
		u16 version_string_length;
	};

	/**
	 * this function returns the application version possibly found by PACE.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @return pointer to a statically allocated structure or NULL if no version is available
	 */
	const struct ipoque_pace_application_version *ipoque_pace_get_application_version(struct
																					  ipoque_detection_module_struct
																					  *ipoque_struct);

	/**
	 * this function returns the group of the given application ID
	 *
	 * @param ipoque_struct the detection module, not NULL
	 * @param application_id application ID
	 * @return the group ID
	 */
	u16 ipoque_pace_get_application_group(struct ipoque_detection_module_struct *ipoque_struct, u32 application_id);

	/**
	 * this function initializes the SSL session id tracker
	 * component. This allows to identify also SSL flows which do not
	 * have certificate information but re-uses a session ID for an
	 * already known protocol or application.
	 *
	 * The component can be initialized by either setting the amount
	 * of memory for the internal table or by setting the number of
	 * elements that should be stored.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 *
	 * @param memory the size of the internal memory buffer for
	 * session IDs, can be 0 (if 0, the number of elements or used to
	 * determine to memory size)
	 *
	 * @param number_of_elements the number of session IDs that should
	 * be stored. Can be 0. Will only be used if the memory argument
	 * is zero.
	 *
	 * @param key_reduce_factor the factor will be used to reduce the
	 * session ID and related key information to reduce memory usage
	 * while accepting a larger false positive ratio. Can 1, 2, or 4
	 * (1 means no reduction, use complete session ID)
	 *
	 * @param ipq_malloc Allocator function, including the allocation
	 * user-pointer
	 *
	 * @param ipq_free Freeing function with the allocation user-pointer
	 *
	 * @param allocation_userptr user pointer for the allocation and
	 * free function.
	 *
	 * @return 0 on success, != 0 on error
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u8 ipoque_pace_sit_init(struct ipoque_detection_module_struct *ipoque_struct,
							unsigned long memory,
							unsigned long number_of_elements,
							unsigned short key_reduce_factor,
							void *(*ipq_malloc) (unsigned long size, void *userptr),
							void (*ipq_free) (void *ptr, void *userptr),
							void *allocation_userptr);

	/**
	 * the statistic structure for the Session ID tracker
	 */
	struct ipoque_pace_sit_stats {
		/**
		 * number of session ID inserts
		 */
		u64 id_inserts;

		/**
		 * number of successful ID lookup
		 */
		u64 id_lookup_successful;

		/**
		 * number of failed ID lookups
		 */
		u64 id_lookup_failed;

		/**
		 * this is the maximum number of session IDs that can be stored
		 */
		unsigned long maximum_number_of_elements;

		/**
		 * this is the number of currently stored session IDs
		 */
		unsigned long currently_used_elements;

		/**
		 * this is the timestamp of the oldest entry in the session ID
		 * table. It gives a hint about which period of time is
		 * covered by the session ID tracker.
		 */
		IPOQUE_TIMESTAMP_COUNTER_SIZE ts_of_oldest_entry;
	};

	/**
	 * this function returns the current statistics for the SSL
	 * session id tracker component.
	 *
	 * @param ipoque_struct the detection module, not NULL
  	 *
	 * @return pointer to structure on success, NULL on error
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
 	const struct ipoque_pace_sit_stats *ipoque_pace_sit_get_statistics(struct ipoque_detection_module_struct *ipoque_struct);

#ifdef IPOQUE_DETECTION_SUPPORT_CLIENT_SERVER_INDICATION
	/* client server indication runtime option
	 * set this parameter to enable or disable to client/server indication
	 */

	enum ipoque_client_server_indication_mode {
		IPOQUE_CLIENT_SERVER_INDICATION_DISABLED = 0,
		IPOQUE_CLIENT_SERVER_INDICATION_ENABLED
	};

	/**
	 * This function enables or disables the client/server indication
	 * default is DISABLED
	 * @param ipoque_struct the detection module, not NULL
	 * @param param 1 ENABLES and 0 DISABLES the client/server indication, other values have no effect
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	void ipoque_pace_set_client_server_indication_mode(struct ipoque_detection_module_struct *ipoque_struct,
													   enum ipoque_client_server_indication_mode param);

	enum ipoque_client_server_indication_packet_type {
		IPOQUE_DIRECTION_UNKNOWN = 0,       /**< packet direction could not be detected */
		IPOQUE_DIRECTION_NOT_YET_DECIDED,   /**< packet direction is not yet decided */
		IPOQUE_CLIENT_TO_SERVER,            /**< packet goes from client to server */
		IPOQUE_SERVER_TO_CLIENT,            /**< packet goes from server to client */
		IPOQUE_CLIENT_TO_CLIENT,            /**< packet is between two clients */
		IPOQUE_SERVER_TO_SERVER             /**< packet is between two servers */
	};

	enum ipoque_client_server_indication_host_type {
		IPOQUE_HOST_TYPE_UNKNOWN = 0,       /**< it is not known whether host is client or server */
		IPOQUE_HOST_IS_SERVER,              /**< the host is mainly used as a server */
		IPOQUE_HOST_IS_CLIENT,              /**< the host is a client */
	};

	struct ipoque_pace_client_server_indication_host_status {
		enum ipoque_client_server_indication_host_type host_type;     /**< host type enum */
		int percentage_of_client_connections;                         /**< percentage of client connections, 0 means no client connection or value not known,
																		 anything between 1 and 100 gives the rate of client connections over server connections.
																		 The value will change over time. */
	};

	/**
	 * this function returns the direction information for the last
	 * packet given to the detection. For flows between a client and a
	 * server the direction will be corrected (if possible) according
	 * to the direction of the packet. That means that for a packet
	 * from the client to server the returned direction will be
	 * IPOQUE_CLIENT_TO_SERVER and for a packet in the same flow in
	 * the other direction the value will be
	 * IPOQUE_SERVER_TO_CLIENT. The argument
	 * "flow_direction_corrected" will indicate whether this
	 * correction has been made or not (in case of the internal fast
	 * path).
	 *
	 * @param ipoque_struct the detection module, not NULL
	 *
	 * @param flow_direction_corrected a pointer to a variable. The
	 * value written to it will be 1 if the correction has been made
	 * or 0 if the correction was not possible (due to missing
	 * internal information in case of the fast path)
	 *
	 * @return the packet direction enum
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	enum ipoque_client_server_indication_packet_type ipoque_pace_get_packet_client_server_indication(struct ipoque_detection_module_struct *ipoque_struct,
																									 u8 *flow_direction_corrected);

	/**
	 * this function returns information about both subscribers used for the last packet given to the detection.
	 * Both structures will be filled with internal information about both hosts.
	 *
	 * @param ipoque_struct the detection module, not NULL
	 *
	 * @param src_status pointer to a structure which will be filled
	 * with the information about the source host of the last packet.
	 *
	 * @param dst_status pointer to a structure which will be filled
	 * with the information about the destination host of the last
	 * packet.
	 *
	 * @return 0 if successful, != 0 in case of an error
	 */
	u8 ipoque_pace_get_host_client_server_indication(struct ipoque_detection_module_struct *ipoque_struct,
													 struct ipoque_pace_client_server_indication_host_status *src_status,
													 struct ipoque_pace_client_server_indication_host_status *dst_status);
#endif

	enum ipoque_fastpath_state {
		IPOQUE_FP_NO_PACKET_NEEDED,                               /**< no packet from this flow is needed anymore */
		IPOQUE_FP_NEXT_PACKET_NEEDED,                             /**< the next packet of this flow is needed */
		IPOQUE_FP_NEXT_PACKET_WITH_CONSTRAINT,                    /**< the next packet only with additional constraint (direction and/or time) */
	};

	enum ipoque_fastpath_direction_constraint {
		IPOQUE_FP_ANY_DIRECTION,                                  /**< no direction limit applies */
		IPOQUE_FP_NEXT_PAYLOAD_PACKET_SAME_DIRECTION,             /**< the next packet with payload for the current direction is needed */
		IPOQUE_FP_NEXT_PAYLOAD_PACKET_OTHER_DIRECTION,            /**< the next packet with payload for the other direction is needed */
	};

	struct ipoque_fastpath_information
	{
		enum ipoque_fastpath_state state;                         /**< the state of the fastpath stating whether additional packets are required */
		u8 skip_time_set;                                         /**< 1 if a time is set until all packets can be skipped, 0 if no time limit applies */
		u32 skip_until_time;                                      /**< time until all packets can be skipped for the state IPOQUE_FP_NEXT_PACKET_WITH_CONSTRAINT */
		enum ipoque_fastpath_direction_constraint direction;      /**< only packets with given direction */
	};

	/**
	 * this function returns information about whether packets of the same flow as the last packet are required by PACE to
	 * correctly identify traffic and manage protocol changes within flows.
	 * @param ipoque_struct the detection module, not NULL
	 *
	 * @param fp_information a pointer to a structure which will be filled with the available information.
	 * @return 0 if successful, != 0 in case of an error
	 */
	u8 ipoque_pace_get_fastpath_information(struct ipoque_detection_module_struct *ipoque_struct,
											struct ipoque_fastpath_information *fp_information);

	enum ipoque_flow_timeout_class {
		IPOQUE_MEDIUM_FLOW_TIMEOUT = 0,
		IPOQUE_SHORT_FLOW_TIMEOUT,
		IPOQUE_LARGE_FLOW_TIMEOUT
	};

	/**
	 * this function returns the current timeout class for the flow of
	 * the last packet given to the detection.  The actual time value
	 * for each class depends on the actual traffic, the PACE
	 * integration manual contains more information about the actual
	 * timeouts.
	 *
	 * @param ipoque_struct the detection module, not NULL.
	 *
	 * @return the timeout for the flow of the last packet given to
	 * PACE.
	 */
	enum ipoque_flow_timeout_class ipoque_pace_get_flow_timeout_class(struct ipoque_detection_module_struct *ipoque_struct);

	/**
	 * query if the flow of the last processed packet is running through a proxy server (socks or HTTP connect)
	 *
	 * @param ipoque_struct the detection module
	 * @return 1 if the flow is running over a proxy, 0 if no socks or HTTP connect proxy is involved
	 *
	 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
	 */
	u8 ipoque_pace_get_flow_is_proxy_connection(struct ipoque_detection_module_struct *ipoque_struct);

#ifdef IPOQUE_ENABLE_LICENSING

	enum ipoque_pace_licensing_loading_result {
		IPOQUE_LICENSE_LOAD_SUCCESS = 0,
		IPOQUE_LICENSE_UNSUPPORTED_VERSION,
		IPOQUE_LICENSE_UNSUPPORTED_FORMAT,
		IPOQUE_LICENSE_LOAD_FAILED
	};

	/**
	 * this function reads the license from a given file.
	 * It must be called after the library has been initialized but before the first packet has been processes
	 *
	 * @param ipoque_struct the detection module
	 * @param filename the filename of the license file
	 * @return enum indicates success or errors
	 */
	enum ipoque_pace_licensing_loading_result ipoque_pace_load_license(struct ipoque_detection_module_struct *ipoque_struct,
																	   const char *filename);
#endif

/* END PUBLIC FUNCTIONS, API DOCUMENTATION IN MANPAGES ONLY !! */
/* OSDPI-START */
#ifdef __cplusplus
}
#endif
#endif
/* OSDPI-END */
