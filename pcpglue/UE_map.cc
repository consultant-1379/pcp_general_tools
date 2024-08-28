
#include "UE_map.hpp"
#include <unordered_map>
#include <iostream>
#include <algorithm>
#include <list>

using std::unordered_map;
using std::hash;
using std::cout;
using std::cin;
using std::endl;


UE_maptype ueMap;


int Insert_UE_IP_IntoHash(UE_maptype&  UE_IP_map, unsigned long long UE_addr, PDPSession* s){

	UE_IP_map[UE_addr] = s;

	return 0;

}

PDPSession* checkIfUEIsAlreadyPresentInHashMap(unsigned long long UE_addr){

	UE_maptype::iterator UE_it = ueMap.find(UE_addr);
	if(UE_it != ueMap.end()) {
		return UE_it->second;
		//cout << "found the ip again" << endl;
	} else {
		return NULL;
		//the IP is not yet in the map enter it
		//cout << "entering ip into the map" << endl;
		//Insert_UE_IP_IntoHash(ueMap, UE_addr, s);
	}

}

IMSI_maptype imsiMap;

int insertIMSIIntoMap(IMSI_maptype& thisIMSIMap, unsigned long long imsi, PDPSession* session) {
	thisIMSIMap[imsi] = session;
	return 0;
}

PDPSession * getPDPSessionByIMSI(unsigned long long imsi) {
	IMSI_maptype::iterator imsiIt = imsiMap.find(imsi);
	if(imsiIt != imsiMap.end()) {
		return imsiIt->second;
	} else {
		return NULL;
	}
}

