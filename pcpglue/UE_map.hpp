/*
 * UE_map.hpp
 *
 *  Created on: 16 Jan 2013
 *      Author: emilawl
 */

#ifndef UE_MAP_HPP_
#define UE_MAP_HPP_
#include <unordered_map>
#include <unordered_map>
#include <algorithm>
#include <list>

using std::unordered_map;
using std::hash;

struct hash_long_long {
	size_t operator()(const long long in)  const {
		long long ret = (in >> 32L) ^ hash<int>()(in & 0xFFFFFFFF);
		return (size_t) ret;
	}
};

/*
 * UEIP to PDPSession map and helper functions
 */
typedef unordered_map<unsigned long long, struct PDPSession*, hash_long_long> UE_maptype;

int Insert_UE_IP_IntoHash(UE_maptype&  UE_IP_map, unsigned long long UE_addr, PDPSession* s);
PDPSession* checkIfUEIsAlreadyPresentInHashMap(unsigned long long UE_addr);

/*
 * IMSI to PDPSession map and helper functions
 */
typedef unordered_map<unsigned long long, struct PDPSession*, hash_long_long> IMSI_maptype;

int insertIMSIIntoMap(IMSI_maptype& thisIMSIMap, unsigned long long imsi, PDPSession* session);
PDPSession* getPDPSessionByIMSI(unsigned long long imsi);


#endif /* UE_MAP_HPP_ */
