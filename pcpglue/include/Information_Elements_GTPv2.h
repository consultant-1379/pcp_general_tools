/*
 * Information_Elements_GTPv2.h
 *
 *  Created on: 26 Jul 2012
 *      Author: emilawl
 */

#ifndef INFORMATION_ELEMENTS_GTPV2_H_
#define INFORMATION_ELEMENTS_GTPV2_H_
#pragma pack(1) //vital to get bit fields to line up correctly

enum IETypes{
	ULIType = 86
};

struct INDICATION_IE{
	unsigned int type:8;
	unsigned short length:16;
	unsigned int instance:4;
	unsigned int spareField1:4;

	unsigned int SGWChangeIndication:1;
	unsigned int IdleModeSignallingReductionActivationIndication:1;
	unsigned int IdleModeSignallingReductionSupportedIndication:1;
	unsigned int OperationIndication:1;
	unsigned int DirectForwardingIndication:1;
	unsigned int HandoverIndication:1;
	unsigned int DirectTunnelFlag:1;
	unsigned int DualAddressBearerFlag:1;
	unsigned int MSValidated:1;
	unsigned int ScopeIndication:1;
	unsigned int ProtocolType:1;
	unsigned int PiggybackingSupported:1;
	unsigned int ChangeReportingSupportIndication:1;
	unsigned int ChangeFTEIDSupportIndication:1;
	unsigned int UnauthenticatedIMSI:1;
	unsigned int SubscribedQOSChangeIndication:1;
	unsigned int CSGChangeReportingSupportIndication:1;
	unsigned int ISRIsActivatedOnUE:1;
	unsigned int ManagementBasedMDTFlag:1;
	unsigned int StaticIPv4AddressFlag:1;
	unsigned int StaticIPv6AddressFlag:1;
	unsigned int SGWRestorationNeededIndication:1;
	unsigned int PropagateBBAIInformationChange:1;
	unsigned int RetriveLocationIndicationFlag:1;
	unsigned int CS_to_PS_SRVCC_Indication:1;
	unsigned int ChangeOfLocationIndication:1;
	unsigned int spareField2:1;
	//note additional fields may appear but need to be explicitly specified
};

struct BearerQualityOfService_IE{
	unsigned int type:8;
	unsigned short length:16;
	unsigned int instance:4;
	unsigned int spareField1:4;

	unsigned int PVI:1;
	unsigned int spareField2:1;
	unsigned int PL:4;
	unsigned int PCI:1;
	unsigned int spareField3:1;
	unsigned int LabelQCI:8;
	unsigned long MaxBitrateUpLink:40;
	unsigned long MaxBitrateDownLink:40;
	unsigned long GuaranteedBitRateUL:40;
	unsigned long GuaranteedBitRateDL:40;
	//note additional fields may appear but need to be explicitly specified
};

struct FlowQualityOfService_IE{
	unsigned int type:8;
	unsigned short length:16;
	unsigned int instance:4;
	unsigned int spareField1:4;

	unsigned int LabelQCI:8;
	unsigned long MaxBitrateUpLink:40;
	unsigned long MaxBitrateDownLink:40;
	unsigned long GuaranteedBitRateUL:40;
	unsigned long GuaranteedBitRateDL:40;
	//note additional fields may appear but need to be explicitly specified
};

struct UserLocationInformation{
	unsigned int type:8;
	unsigned short length:16;
	unsigned int instance:4;
	unsigned int spareField1:4;

	unsigned int CellGlobalIdentiferFlag:1;
	unsigned int ServiceAreaIdentiferFlag:1;
	unsigned int RoutingAreaIdentityFlag:1;
	unsigned int TrackingAreaIdentityFlag:1;
	unsigned int E_UTRANCellGlobalIdentifierFlag:1;
	unsigned int LocationAreaIdentifierFlag:1;
	unsigned int spareField2:2;
	//note the CGI,SAI,RAI,TAI,ECGI,LAI fields/IE may or may not be present thus they are declared in
	//their own structs seen below
};

struct CellGlobalIdentifer{
	unsigned int MCCDigit1:4;
	unsigned int MCCDigit2:4;
	unsigned int MCCDigit3:4;
	unsigned int MNCDigit3:4;
	unsigned int MNCDigit1:4;
	unsigned int MNCDigit2:4;
	unsigned short LocationAreaCode:16;
	unsigned short CellIdentity:16;
};

struct ServiceAreaIdentifer{
	unsigned int MCCDigit1:4;
	unsigned int MCCDigit2:4;
	unsigned int MCCDigit3:4;
	unsigned int MNCDigit3:4;
	unsigned int MNCDigit1:4;
	unsigned int MNCDigit2:4;
	unsigned short LocationAreaCode:16;
	unsigned short ServiceAreaCode:16;
};

struct RoutingAreaIdentity{
	unsigned int MCCDigit1:4;
	unsigned int MCCDigit2:4;
	unsigned int MCCDigit3:4;
	unsigned int MNCDigit3:4;
	unsigned int MNCDigit1:4;
	unsigned int MNCDigit2:4;
	unsigned short LocationAreaCode:16;
	unsigned short RoutingAreaCode:16;
};

struct TrackingAreaIdentity{
	unsigned int MCCDigit1:4;
	unsigned int MCCDigit2:4;
	unsigned int MCCDigit3:4;
	unsigned int MNCDigit3:4;
	unsigned int MNCDigit1:4;
	unsigned int MNCDigit2:4;
	unsigned short TrackingAreaCode:16;
};

struct E_UTRANCellGlobalIdentifier{
	unsigned int MCCDigit1:4;
	unsigned int MCCDigit2:4;
	unsigned int MCCDigit3:4;
	unsigned int MNCDigit3:4;
	unsigned int MNCDigit1:4;
	unsigned int MNCDigit2:4;
	unsigned short ECIFirstFourBits:4;
	unsigned short spare:4;
	unsigned int E_UTRANCellGlobalCode:24;
};

struct LocationAreaIdentifier{
	unsigned int MCCDigit1:4;
	unsigned int MCCDigit2:4;
	unsigned int MCCDigit3:4;
	unsigned int MNCDigit3:4;
	unsigned int MNCDigit1:4;
	unsigned int MNCDigit2:4;
	unsigned short LocationAreaCode:16;
};

struct PDU_Numbers_IE{
	unsigned int type:8;
	unsigned short length:16;
	unsigned int instance:4;
	unsigned int spareField1:4;

	unsigned int NSAPI:4;
	unsigned int spareField2:4;
	unsigned short DL_GTPUSequenceNumber:16;
	unsigned short UL_GTPUSequenceNumber:16;
	unsigned short sendN_PDUNumber:16;
	unsigned short receiveN_PDUNumber:16;

	//note additional fields may appear but need to be explicitly specified
};

struct ARP{
	unsigned int type:8;
	unsigned short length:16;
	unsigned int instance:4;
	unsigned int spareField1:4;

	unsigned int ARPData:8;
};

struct S1_U_Data_Forwarding{
	unsigned int type:8;
	unsigned short length:16;
	unsigned int instance:4;
	unsigned int spareField1:4;

	unsigned int EPS_Bearer_ID:4;
	unsigned int spareField2:4;
	unsigned int servingGWAddressLength:8;
	//followed be variable length serving GW Address of size 7 to servingGWAddressLength + 6, number of bits 32-128
	//ending with servingGWS1_U_TEID from servingGWAddressLength + 7, to servingGWAddressLength + 10, number of bits 32
};

struct fullyQuilifedTEID{
	unsigned int type:8;
	unsigned short length:16;
	unsigned int instance:4;
	unsigned int spareField1:4;

	unsigned int interfaceType:6;
	unsigned int V6:1;
	unsigned int V4:1;
	unsigned int TEID_GRE_Key:32;
	// will be present if v4 flag set IPv4_Address:32;
	// will be present if v6 flag set IPv6_Address:128;
};

#pragma pack()
#endif /* INFORMATION_ELEMENTS_GTPV2_H_ */
