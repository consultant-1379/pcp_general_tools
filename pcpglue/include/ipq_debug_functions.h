/* written by klaus degner, ipoque GmbH
 * klaus.degner@ipoque.com
 */

/* OSDPI-START */
#ifndef __IPOQUE_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE IPQ_API.H
#endif

#ifndef __IPQ_DEBUG_FUNCTIONS_H__
#define __IPQ_DEBUG_FUNCTIONS_H__

#ifdef __cplusplus
extern "C" {
#endif
/* OSDPI-END */

/*****************************************************************************************
* ALL FOLLOWING FUCTIONS ARE FOR DEBUGGING ONLY AND MIGHT BE REMOVED IN A FUTURE VERSION *
* SEE THE SRC CODE OF THESE FUNCTIONS FOR DETAILS                                        *
* IF YOU DO NOT HAVE SRC CODE ACCESS, DO NOT USE THEM UNLESS YOU REALLY KNOW WHY         *
*****************************************************************************************/

	void ipoque_detection_set_tcp_retransmission_window_size(struct
															 ipoque_detection_module_struct
															 *ipoque_struct, u32 tcp_max_retransmission_window_size);

	int ipoque_detection_set_bittorrent_parameters(struct
												   ipoque_detection_module_struct
												   *ipoque_struct,
												   const u8 detect_enycryption,
												   const u8
												   parallel_connections_needed,
												   const u32
												   parallel_gap_in_ticks,
												   const u32
												   id_detection_timeout_ticks,
												   const u8 use_only_safe_encrypted_patterns);


/* get functions, parameters as in the set function (only pointers) */
	void ipoque_detection_get_bittorrent_parameters(struct
													ipoque_detection_module_struct
													*ipoque_struct,
													u8 * detect_enycryption,
													u8 *
													parallel_connections_needed,
													u32 *
													parallel_gap_in_ticks,
													u32 *
													id_detection_timeout_ticks, u8 * use_only_safe_encrypted_patterns);

	int ipoque_detection_set_skype_parameters(struct
											  ipoque_detection_module_struct
											  *ipoque_struct,
											  const u8
											  parallel_connections_needed,
											  const u32 parallel_gap_in_ticks,
											  const u32
											  id_detection_timeout_ticks,
											  const u8
											  skype_safe_detection_mode, const u8 skype_use_default_ports_only);

/* get functions, parameters as in the set function (only pointers) */
	void ipoque_detection_get_skype_parameters(struct
											   ipoque_detection_module_struct
											   *ipoque_struct,
											   u8 *
											   parallel_connections_needed,
											   u32 * parallel_gap_in_ticks,
											   u32 *
											   id_detection_timeout_ticks,
											   u8 * skype_safe_detection_mode, u8 * skype_use_default_ports_only);

	int ipoque_detection_set_skype_voice_parameters(struct
													ipoque_detection_module_struct
													*ipoque_struct,
													const u8
													skype_min_packets_in_a_row_needed,
													const u16
													skype_max_voice_packet_size,
													const u32 skype_max_gap_between_voice_packets);

	void ipoque_detection_get_skype_voice_parameters(struct
													 ipoque_detection_module_struct
													 *ipoque_struct,
													 u8 *
													 skype_min_packets_in_a_row_needed,
													 u16 *
													 skype_max_voice_packet_size,
													 u32 * skype_max_gap_between_voice_packets);

	void ipoque_detection_get_ftp_parameters(struct
											 ipoque_detection_module_struct
											 *ipoque_struct, u32 * id_detection_timeout_ticks);

	int ipoque_detection_set_ftp_parameters(struct
											ipoque_detection_module_struct
											*ipoque_struct, const u32 id_detection_timeout_ticks);

	void ipoque_detection_get_rtsp_parameters(struct
											  ipoque_detection_module_struct
											  *ipoque_struct, u32 * id_detection_timeout_ticks);

	int ipoque_detection_set_rtsp_parameters(struct
											 ipoque_detection_module_struct
											 *ipoque_struct, const u32 id_detection_timeout_ticks);

	void ipoque_detection_get_tvants_parameters(struct
												ipoque_detection_module_struct
												*ipoque_struct, u32 * id_detection_timeout_ticks);

	int ipoque_detection_set_tvants_parameters(struct
											   ipoque_detection_module_struct
											   *ipoque_struct, const u32 id_detection_timeout_ticks);

	int ipoque_detection_set_ares_parameters(struct
											 ipoque_detection_module_struct
											 *ipoque_struct, const u8 needed_download_packets, const u32 max_gap);

	void ipoque_detection_get_ares_parameters(struct
											  ipoque_detection_module_struct
											  *ipoque_struct, u8 * needed_download_packets, u32 * max_gap);

	void ipoque_detection_get_orb_parameters(struct
											 ipoque_detection_module_struct
											 *ipoque_struct, u32 * orb_rstp_ts_timeout);

	int ipoque_detection_set_orb_parameters(struct
											ipoque_detection_module_struct
											*ipoque_struct, const u32 orb_rstp_ts_timeout);


	int ipoque_detection_set_edonkey_parameters(struct
												ipoque_detection_module_struct
												*ipoque_struct,
												const u8 detect_enycryption,
												const u8
												parallel_connections_needed,
												const u32
												parallel_gap_in_ticks,
												const u32
												id_detection_timeout_ticks,
												const u8
												edonkey_use_default_ports_only, const u8 edonkey_use_safe_mode);


/* get functions, parameters as in the set function (only pointers) */
	void ipoque_detection_get_edonkey_parameters(struct
												 ipoque_detection_module_struct
												 *ipoque_struct,
												 u8 * detect_enycryption,
												 u8 *
												 parallel_connections_needed,
												 u32 * parallel_gap_in_ticks,
												 u32 *
												 id_detection_timeout_ticks,
												 u8 * use_default_ports_only, u8 * use_safe_mode);

	int ipoque_detection_set_yahoo_parameters(struct
											  ipoque_detection_module_struct
											  *ipoque_struct, const u8 yahoo_detect_http_connections);

/* get functions, parameters as in the set function (only pointers) */
	void ipoque_detection_get_yahoo_parameters(struct
											   ipoque_detection_module_struct
											   *ipoque_struct, u8 * yahoo_detect_http_connections);

	int ipoque_detection_set_msn_parameters(struct
											ipoque_detection_module_struct
											*ipoque_struct,
											const u32
											msn_to_sip_connection_timeout, const u32 msn_to_rtp_connection_timeout);

/* get functions, parameters as in the set function (only pointers) */
	void ipoque_detection_get_msn_parameters(struct
											 ipoque_detection_module_struct
											 *ipoque_struct,
											 u32 * msn_to_sip_connection_timeout, u32 * msn_to_rtp_connection_timeout);

/* set ddl callback if you interested in more details about a ddl download */
	void ipoque_set_direct_download_link_callback(struct
												  ipoque_detection_module_struct
												  *ipoque_struct, u32(*direct_download_link_callback)
												   (const u8 * filename,
													u16 filenamelen,
													const u8 * hostname, u16 hostname_len, u16 packet_size), void
												   (*direct_download_link_counter_callback)
												   (u32 ddl_id, u16 packet_size));

/* set http callback if you interested in more details about a http download */
	void ipoque_set_http_callback(struct ipoque_detection_module_struct
								  *ipoque_struct,
								  u32(*http_callback) (const u8 * filename,
													   u16 filenamelen,
													   const u8 * hostname,
													   u16 hostname_len,
													   u16 packet_size),
								  void (*http_counter_callback) (const u8 *
																 content_type,
																 u16 content_type_len, u32 * http_id, u16 packet_size));

/* set usenet callback if you interested in more details about a usenet download */
	void ipoque_set_usenet_callback(struct ipoque_detection_module_struct
									*ipoque_struct, void (*usenet_article_counter_callback)
									 (u32 * http_id, u16 packet_size),
									u32(*new_usenet_article_callback) (const
																	   u8 *
																	   article_id,
																	   u16
																	   article_id_len,
																	   const
																	   u8 *
																	   subject,
																	   u16
																	   subjectlen,
																	   const
																	   u8 *
																	   payload_detail,
																	   u16
																	   payload_detail_len,
																	   u16
																	   packet_size),
									u32(*new_usenet_article_request_callback)
									 (const u8 * article_id, u16 article_idlen, u16 packet_size));

/* set mail_pop callback if you interested in more details about pop */
	void ipoque_set_mail_pop_callback(struct ipoque_detection_module_struct
									  *ipoque_struct,
									  u32(*mail_pop_callback) (u32 *
															   server_ip,
															   u16
															   packet_size),
									  void (*mail_pop_counter_callback) (u32 * pop_server_id, u16 packet_size));


	void ipoque_set_sip_call_callback(struct ipoque_detection_module_struct
									  *ipoque_struct,
									  u8(*sip_call_callback) (const struct
															  ipoque_detection_module_struct
															  * ipoque_struct,
															  const u8 *
															  sip_caller_id,
															  u16
															  sip_caller_id_len,
															  const u8 * sip_calling_id, u16 sip_calling_id_len));

/* same as sip callback */
	void ipoque_set_iax_call_callback(struct ipoque_detection_module_struct
									  *ipoque_struct,
									  u8(*iax_call_callback) (const struct
															  ipoque_detection_module_struct
															  * ipoque_struct,
															  const u8 *
															  iax_caller_id,
															  u16
															  iax_caller_id_len,
															  const u8 * iax_calling_id, u16 iax_calling_id_len));


/* set allowed bt address */
	void ipoque_set_allowed_bt_hash_address(struct
											ipoque_detection_module_struct
											*ipoque_struct, const u32 bt_address);

/* get allowed bt address */
	u32 ipoque_get_allowed_bt_hash_address(struct
										   ipoque_detection_module_struct
										   *ipoque_struct);


/* change current protocol identification */
	void ipoque_change_current_flow_mark(struct ipoque_detection_module_struct
										 *ipoque_struct, u32 protocol);

	u32 ipoque_debug_protocol_per_flow(void *flow);

	void ipoque_debug_state(void *flow, u32 * skype_stage, u32 * bittorrent_stage, u32 * edonkey_stage);

/* OSDPI-START */
	void ipoque_debug_get_last_log_function_line(struct
												 ipoque_detection_module_struct
												 *ipoque_struct, const char **file, const char **func, u32 * line);
/* OSDPI-END */

	/* used to classify unknown traffic without syn packets at the start better
	 * will return != IPOQUE_DEBUG_CONNECTION_STARTED_WITH_SYN_PACKET if this packet was tcp
	 * and belongs to an uninitalized tcp stream
	 * will return  IPOQUE_DEBUG_CONNECTION_STARTED_WITH_SYN_PACKET for all other protocols
	 */

#define IPOQUE_DEBUG_CONNECTION_STARTED_WITH_SYN_PACKET 0
#define IPOQUE_DEBUG_CONNECTION_STARTED_WITHOUT_SYN_PACKET 1
	int ipoque_packet_from_tcp_connection_without_syn_packet(struct
															 ipoque_detection_module_struct
															 *ipoque_struct);

#ifdef IPOQUE_USE_INTERNAL_FASTPATH
	u8 ipoque_fastpath_has_been_used(struct ipoque_detection_module_struct
									 *ipoque_struct);
#endif


#ifdef IPOQUE_PROTOCOL_TUNNELVOICE
		/**
         * This function returns statistic data about the tunnelvoice detection since the last call.
         * @param ipoque_struct the detection module
         * @param aktive_streams returns active voip calls since the last function call
         * @param new_streams returns new voip calls since the last function call
         * @param malloc_blocks returns allocated memory blocks currently used
         * @return <0 error (no output), 0 OK
         */
	int ipoque_detection_get_tunnelvoice_global_stat(struct ipoque_detection_module_struct *ipoque_struct,
													 u32 * aktive_streams, u32 * new_streams, u32 * malloc_blocks);
		/**
         * This function returns statistic data about the given flow. This function could be called
         * after every packet, but returns only every second values. If the call intervall is greater than 
         * one second the returned values are relative to the last call.
         * @param ipoque_struct the detection module
         * @param voip_stream_count returns active voip calls since the last function call
         * @param voip_ratio returns the actual bandwidth ratio between voip and other packets
         * @param voip_packet_ratio returns the actual packet ratio between voip and other packets
         * @param time the actual time (now)
         * @return <0 error (no output), 0 OK
         */
	int ipoque_detection_get_tunnelvoice_flow_stat_sec(struct ipoque_detection_module_struct *ipoque_struct,
													   u32 * voip_stream_count, u32 * voip_ratio,
													   u32 * voip_packet_ratio, u32 time);
		/**
         * This function returns statistic data about the given flow since the last call.
         * @param ipoque_struct the detection module
         * @param voip_stream_count returns active voip calls since the last function call
         * @param voip_ratio returns the actual bandwidth ratio between voip and other packets
         * @param voip_packet_ratio returns the actual packet ratio between voip and other packets
         * @return <0 error (no output), 0 OK
         */
	int ipoque_detection_get_tunnelvoice_flow_stat(struct ipoque_detection_module_struct *ipoque_struct,
												   u32 * voip_stream_count, u32 * voip_ratio, u32 * voip_packet_ratio);
		/**
         * This function MUST BE CALLED when a flow timeout occurs.
         * @param ipoque_struct the detection module
         * @param flow_struct the flow_struct
         * @param is_marked 0 this flow was not marked as TUNNELVOICE, 1 was marked as...
         * @param max_calls return maximum parallel active calls in flow lifetime
         * @param voip_ratio returns the bandwidth ratio between voip and other packets in flow lifetime
         * @param voip_packet_ratio returns the packet ratio between voip and other packets in flow lifetime
         */
		/**
         * This function MUST BE CALLED immediatly after detection init. This function need ipoque_struct, mem_size, 
         * malloc_func and free_func.
         * If one of the other paramertes is 0, default values will be used.
         * @param ipoque_struct the detection module
         * @param mem_size memory size for prealloc [bytes]
         * @param prot_bitmask protocols which should scanned for tunnelvoice [Default: 0]
         * @param malloc_func ptr to malloc func (malloc/kmalloc)
         * @param free_func ptr to free func (free/kfree)
         * @param calls_per_flow treshold for mark as tunnel: active voip calls [Default: 1]
         * @param percent_bandwidth treshold for mark as tunnel: bandwidth voip/bandwidth overall [0-100] [Default: 1]
         * @param percent_packets treshold for mark as tunnel: bandwidth voip/bandwidth overall [0-100] [Default: 1]
         * @param min_voip_size_tun min_packet_size <= voip frame size <= max_packet_size [byte] [Default: 75] (NON UDP/TCP packets)
         * @param max_voip_size_tun min_packet_size <= voip frame size <= max_packet_size [byte] [Default: 310] (NON UDP/TCP packets)
         * @param min_voip_size_l4 min_packet_size <= voip frame size <= max_packet_size [byte] [Default: 25] (TCP/UDP payload)
         * @param max_voip_size_l4 min_packet_size <= voip frame size <= max_packet_size [byte] [Default: 275] (TCP/UDP payload)
         * @param time_diff_min min- and max delay between packets of one call [ms] [Default: 16]
         * @param time_diff_max min- and max delay between packets of one call [ms] [Default: 250]
         * @param time_stream_min treshold for counting call as active call [ms] [Default: 10000]
         * @param max_calls_per_flow boundary for maximum list length inside tv-detection to avoid memory waste [Default: 200]
         * @param flags FLAG_TUNNELVOICE_SAME_FRAME_SIZE: issue that every packet of a voip call has same frame size\n
         *               FLAG_TUNNELVOICE_SET_DETECTED_PROTOCOL: mark flows as tunnelvoice if (calls_per_flow && 
         *               percent_bandwidth && percent_packets) true
         *               [Default: 0, no flags set]
         */
	int ipoque_detection_tunnelvoice_debug_init(struct ipoque_detection_module_struct *ipoque_struct, u64 mem_size,
												IPOQUE_PROTOCOL_BITMASK prot_bitmask,
												void *(*malloc_func) (unsigned long), void (*free_func) (void *),
												u8 calls_per_flow, u8 percent_bandwidth, u8 percent_packets,
												u16 min_voip_size_tun, u16 max_voip_size_tun, u16 min_voip_size_l4,
												u16 max_voip_size_l4, u16 time_diff_min, u16 time_diff_max,
												u16 time_stream_min, u16 max_calls_per_flow, u8 flags);
#endif

#ifdef IPOQUE_PROTOCOL_OPENVPN

#define OVPN_RET_TLS 1
#define OVPN_RET_RUNNING_TLS_CONTROL 2
#define OVPN_RET_RUNNING_TLS_DATA 3
#define OVPN_RET_PLAIN_PING 4
#define OVPN_RET_PLAIN_OCC 5
#define OVPN_RET_PLAIN_OCC_LZO 6
#define OVPN_RET_PLAIN_TUN 7
#define OVPN_RET_PLAIN_TUN_LZO 8
#define OVPN_RET_PLAIN_TAP 9
#define OVPN_RET_PLAIN_TAP_LZO 10
#define OVPN_RET_PLAIN_PACKET_ID 11
#define OVPN_RET_PLAIN_PACKET_ID_TUNTAP 12
#define OVPN_RET_PSK 13

	u8 ipoque_detection_ovpn_get_result(struct ipoque_detection_module_struct *ipoque_struct);

#endif

#ifdef IPOQUE_PROTOCOL_ULTRASURF

	typedef struct {
		u32 connection_timeout_ticks;
		u8 connection_threshold;
	} ipoque_ultrasurf_options_t;

	u8 ipoque_detection_set_ultrasurf_options(struct ipoque_detection_module_struct *ipoque_struct,
											  const ipoque_ultrasurf_options_t new_options);

#endif


/* OSDPI-START */
#ifdef __cplusplus
}
#endif
#endif
/* OSDPI-END */
