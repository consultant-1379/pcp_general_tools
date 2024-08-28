/*
 * gtpv1_utils.cc


 *
 *  Created on: 12 Jul 2012
 *      Author: emilawl
 */
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include "include/ArgProcessor.h"
#include "include/gtpv1_utils.h"


using std::cerr;
using std::endl;
using std::ofstream;
using std::string;

extern int interval;
extern const char* instance_tag;
extern const char *base_dir;
bool verbose;
struct EArgs evaluatedArguments;

int processAndApplyArgs(vector<RequiredArgument>& theRequired, SuppliedArguments& theSupplied);

void outputErrorMessage(const string& first,const string& second){
	string message(first);
	message+= second;
	perror(message.c_str());
}
void setGTPCVersion(const string& theVersion){
	evaluatedArguments.GTPCVersion = theVersion;
}
void setGTPCOutput1(const string& theOutput){
	evaluatedArguments.GTPCOutput1 = theOutput;
}
void setGTPCOutput2(const string& theOutput){
	evaluatedArguments.GTPCOutput2 = theOutput;
}
void setGTPCLogOutput(const string& theOutput){
	evaluatedArguments.GTPCLogOutput = theOutput;
}
void setGTPCInput(const string& theInput){
	evaluatedArguments.GTPCInput = theInput;
}
void setGTPCInstanceTag(const string& theInstanceTag){ evaluatedArguments.GTPCInstance_tag = theInstanceTag;}

void setGTPFileInterval(const string& theInterval){
	int n = sscanf(theInterval.c_str(),"%i", &evaluatedArguments.GTP_file_interval);
	if (n != 1) throw string("File interval must be numeric: input was ") + theInterval;
}

void setGTPCVerbose(const string& on_off){
	verbose = on_off == "on";
}

void setHashSize(const string& theSize){
	int n = sscanf(theSize.c_str(),"%i", &evaluatedArguments.GTPC_HASHMAP_MAX_SIZE);
	if (n != 1) throw string("Hash size must be numeric: input was ") + theSize;
}
void setPropertyFileName(const string& value) { evaluatedArguments.propertyFileName = value; evaluatedArguments.usePropertyFile = true;}

void setType(const string& type){
	evaluatedArguments.type = type;
}

bool is_dir(const char* path){
	// Get the directory attributes
	struct stat stats;
	if (stat(path, &stats) != 0) {
		return false; // Not a directory
	}

	return (S_ISDIR(stats.st_mode)!=0);
}

bool is_dir(const string& path){
	// Get the directory attributes
	struct stat stats;
	if (stat(path.c_str(), &stats) != 0) {
		return false; // Not a directory
	}

	return (S_ISDIR(stats.st_mode)!=0);
}

int is_File(const char* path){

	struct stat stats;
		if (stat(path, &stats) != 0) {
			return 0; // Not a directory
		}

	return S_ISREG(stats.st_mode);
}

bool isNumber(const string& value) {  int i; return sscanf(value.c_str(), "%d", &i) == 1; }
bool isNumberGreaterThenOne(const string& value) {  int i; return (sscanf(value.c_str(), "%d", &i) == 1 && i>=1); }


int is_Pipe(const char* path){

	struct stat stats;
		if (stat(path, &stats) != 0) {
			return 0; // Not a directory
		}

	return S_ISFIFO(stats.st_mode);
}

bool isExistingFileOrPipe(const string& value) {
	FILE* file;
	file = fopen(value.c_str(), "r");
	if (file){
		fclose(file);
		return true;
	}
	if (is_Pipe(value.c_str())){
		return true;
	}

		return false;

}

extern ostream* v1_out;
extern ostream* v2_out;

int parseArgs(int argc, char ** argv, pcap_t** descrPtr){
//	if (argc != 7) {
//		cerr << "usage: " << argv[0] << " interval -i|-f interface|pcap_file output_path statistics_path tag\n";
//		cerr << "   interval:- The time in minutes between GTP-C outputs\n";
//		cerr << "   -i:- Capture from an interface\n";
//		cerr << "   -f:- Capture from a file\n";
//		cerr << "   interface:- The interface to capture from\n";
//		cerr << "   pcap_file:- A PCAP file to read packets from\n";
//		cerr << "   output_path:- The path to store output files\n";
//		cerr << "   statistics_path:- The path to store statistics files\n";
//		cerr << "   tag:- A tag to use on output and statistics files that identifies this GTP-C instance\n";
//		return 1;
//	}
//
	vector<RequiredArgument> requiredArgs;

	requiredArgs.push_back (RequiredArgument("-version", setGTPCVersion));
	requiredArgs.back().addValue("1");
	requiredArgs.back().addValue("2");
	requiredArgs.back().addValue("both", true); // Default value

	requiredArgs.push_back (RequiredArgument("-input", setGTPCInput));
	requiredArgs.back().addValue("live", true);

	requiredArgs.push_back (RequiredArgument("-output1", setGTPCOutput1, is_dir, "Must be a Directory."));
	requiredArgs.back().addValue("-", true);

	requiredArgs.push_back (RequiredArgument("-output2", setGTPCOutput2, is_dir, "Must be a Directory."));
	requiredArgs.back().addValue("-", true);

	requiredArgs.push_back (RequiredArgument("-log", setGTPCLogOutput, is_dir, "Must be a Directory."));
	requiredArgs.back().addValue("-", true);

	requiredArgs.push_back (RequiredArgument("-interval", setGTPFileInterval,isNumberGreaterThenOne, "Must be a number."));
	requiredArgs.back().addValue("1", true);

	requiredArgs.push_back (RequiredArgument("-instance_tag", setGTPCInstanceTag,isNumber, "Must be a number."));
	requiredArgs.back().addValue("0", true);

	requiredArgs.push_back (RequiredArgument("-v", setGTPCVerbose));
	requiredArgs.back().addValue("on");
	requiredArgs.back().addValue("off", true);

	requiredArgs.push_back (RequiredArgument("-live", setType));
	requiredArgs.back().addValue("true");
	requiredArgs.back().addValue("false", true);

	requiredArgs.push_back (RequiredArgument("-hash_size", setHashSize));
	requiredArgs.back().addValue("1000000", true);

	requiredArgs.push_back((RequiredArgument("-properties", setPropertyFileName, isExistingFileOrPipe, "Must be an existing file")));

	SuppliedArguments suppliedArguments;
	try {
		// First check if we have -properties <filename>, if so, then read properties from file
		suppliedArguments = SuppliedArguments(argc, argv);
		int valid = processAndApplyArgs(requiredArgs,suppliedArguments);
		if (valid==1){
				return 1;
			}
		if (evaluatedArguments.usePropertyFile){
			suppliedArguments =  SuppliedArguments(evaluatedArguments.propertyFileName);
		}
	}catch (const string& argumentError){
		cerr << argumentError << endl;
		cout << RequiredArgument::usage(requiredArgs) << endl;
		return 1;
	}
	//check all args are in place
	int valid = processAndApplyArgs(requiredArgs,suppliedArguments);
	if (valid==1){
		return 1;
	}

	cout << "Values: ";
	cout << "Version: " << evaluatedArguments.GTPCVersion << endl;
	cout << "Input: " << evaluatedArguments.GTPCInput << endl;
	cout << "Output1: " << evaluatedArguments.GTPCOutput1 << endl;
	cout << "Output2: " << evaluatedArguments.GTPCOutput2 << endl;
	cout << "LogOutput: " << evaluatedArguments.GTPCLogOutput << endl;
	cout << "Instance tag: " << evaluatedArguments.GTPCInstance_tag << endl;
	cout << "Type: " << evaluatedArguments.type << endl;
	cout << "Limiting HashMaps to a maximum size of: " << evaluatedArguments.GTPC_HASHMAP_MAX_SIZE << endl;
	if (evaluatedArguments.usePropertyFile) cout << "Properties file: " << evaluatedArguments.propertyFileName << endl;

	interval = evaluatedArguments.GTP_file_interval;
	if (interval < 1) {
		cerr << "invalid increment " << evaluatedArguments.GTP_file_interval << ", minimum increment is 1 minute\n";
		return 1;
	}
	else {
		// convert to seconds
		interval *= 60;
	}

	// Record the location for saving data files to
	base_dir = evaluatedArguments.GTPCOutput1.c_str();
	if (evaluatedArguments.GTPCOutput1.substr(0,1)=="-"){
		v1_out = &cout;
		v2_out = &cout;
	}else if (!is_dir(base_dir)) {
		cerr << "Data directory " << base_dir << " not found\n";
		return 1;
	}

	// The instance tag distinguishes data and statistics for this instance
	instance_tag = evaluatedArguments.GTPCInstance_tag.c_str();

	char errbuf[PCAP_ERRBUF_SIZE];
//	if (!strcmp(argv[2], "-i")) {
//		*descrPtr = pcap_open_live(argv[3],BUFSIZ,1,1000,errbuf);
//		printf("packet capture on interface %s\n", argv[3]);
//	}
//	else if (!strcmp(argv[2], "-f")) {
//		*descrPtr = pcap_open_offline(argv[3], errbuf);
//		printf("packet capture on file %s\n", argv[3]);
//	}
//	else {
//		cerr << "invalid argument " << argv[2] << endl;
//		return 1;
//	}

	if (strcmp(evaluatedArguments.type.c_str(),"true")==0) {
		*descrPtr = pcap_open_live(evaluatedArguments.GTPCInput.c_str(),BUFSIZ,1,1000,errbuf);
		printf("packet capture on interface %s\n", evaluatedArguments.GTPCInput.c_str());
	}
	else if (strcmp(evaluatedArguments.type.c_str(),"false")==0) {
		*descrPtr = pcap_open_offline(evaluatedArguments.GTPCInput.c_str(), errbuf);
		printf("packet capture on file %s\n", evaluatedArguments.GTPCInput.c_str());
	}
	else {
		outputErrorMessage("Unable to open: ", evaluatedArguments.GTPCInput );
		return 1;
	}
	if(*descrPtr == NULL) {
		printf("packet capture open failed: %s\n",errbuf);
		return 1;
	}

	return 0;
}

int processAndApplyArgs(vector<RequiredArgument>& theRequired, SuppliedArguments& theSupplied){
	ArgumentProcessor processor(theRequired, theSupplied);
		processor.applyDefaults();
		try {
			processor.processArguments();
		}
		catch (const string& message) {
			cerr << message << endl;
			cerr << RequiredArgument::usage(theRequired) << endl;
			return 1;
		}
	return 0;
}

bool checkDataMatches(const string& description, long long expectedValue, long long obtainedValue){
	bool match = true;
	if (expectedValue != obtainedValue){
		cerr << description << ", values do not match, expected: " << expectedValue << " got: " <<  obtainedValue << endl;
		match = !match;
	}
	return match;
}
bool checkDataGE(const string& description, long long expectedValue, long long obtainedValue){
	bool match = true;
	if (obtainedValue < expectedValue){
		cerr << description << ", value greater than required minimum, expected: " << expectedValue << " got: " <<  obtainedValue << endl;
		match = false;
	}
	return match;
}
bool GetPacketPointerAndLength(const u_char * packet, bool cooked, const struct my_ip** ipP, int *lengthP, struct pcap_pkthdr* pkthdr){
	if(cooked) {
		*ipP = (struct my_ip*)(packet + sizeof(LinuxCookedHeader));
		*lengthP = pkthdr->len - sizeof(LinuxCookedHeader);
	} else {

		struct ether_header* eptr = (struct ether_header *) packet;

		if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {

			*ipP = (struct my_ip*)(packet + sizeof(struct ether_header));
			*lengthP = pkthdr->len - sizeof(struct ether_header);

			if (*lengthP < sizeof(struct my_ip))
			{
				checkDataMatches("Length of my_ip, ip may be truncated, exiting ",sizeof(my_ip), *lengthP);
				exit(0);
			}
			return true;
		}
		if(ntohs (eptr->ether_type) == ETHERTYPE_VLAN) {

			*ipP = (struct my_ip*)(packet + sizeof(struct ether_header) + 4);
			*lengthP = pkthdr->len - sizeof(struct ether_header)+4;

			if (*lengthP < sizeof(struct my_ip))
			{
				checkDataMatches("Length of my_ip, ip may be truncated, exiting ",sizeof(my_ip), *lengthP);
				exit(0);
			}
			return true;
		}else{
			PacketCounter::getInstance()->incrementNonEthernetPackets();
			return false;
		}
	}
	//failed to match any condition leaving the length unset
	return false;
}

// esirich fixed indentation as part of DEFTFTS-1677
string PacketCounter::getDetails() const {
	char buffer[220];
	int bufferSize = sprintf(buffer," Total Packets: %ld , total OK packets: %ld, total error packets: %ld,"
			"\n total unexpected packets: %ld, total non Ethernet packets:, %ld, "
			"\n total version 1: %ld, total version 2: %ld",
			this->getTotalPackets(),
			this->getTotalOKPackets(),
			this->getTotalErrorPackets(),
			this->getTotalUnexpectedPackets(),
			this->getTotalNonEthernetPackets(),
			this->getTotalNumberOfVersionOnePackets(),
			this->getTotalNumberOfVersionTwoPackets()
	);
	if (bufferSize > sizeof(buffer)-1) cerr << "Packet details buffer over run by: " << bufferSize - sizeof(buffer) << endl;
	return buffer;
}

// esirich: DEFTFTS-1879 added EMPTY_INT_STRING outputs
ostream& operator<<(ostream& os, const printIFGE0& value){
	if(value.getValue() >= 0) {
		os << value.getValue();
	} else {
		os << EMPTY_INT_STRING;
	}
	os << value.getSeparator();
	return os;
}

ostream& operator<<(ostream& os, const printIFGT0& value){
	if(value.getValue() > 0) {
		os << value.getValue();
	} else {
		os << EMPTY_INT_STRING;
	}
	os << value.getSeparator();
	return os;
}

ostream& operator<<(ostream& os, const PacketCounter *pc){
	os << pc->getDetails() << endl;
	return os;
}

ostream& operator<< (ostream& os, const IPAddress& ipAddress){
	if (ipAddress.data.address >0){
		for ( int i = 3; i >= 0; --i){
			os << (int)ipAddress.data.bytes[i] << (i==0?"":".");
		}
	} else {
		os << EMPTY_INT_STRING;
	}
	return os;
}
