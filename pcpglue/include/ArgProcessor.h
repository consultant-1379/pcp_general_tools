/*
 * ArgProcessor.h
 *
 *  Created on: 26 Jul 2012
 *      Author: eroryma
 */

#ifndef ARGPROCESSOR_H_
#define ARGPROCESSOR_H_
#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <unordered_map>

using std::unordered_map;
using std::string;
using std::vector;
using std::cerr;
using std::cout;
using std::endl;

typedef void (*PFSTR)(const string& s);
typedef bool (*PFSTRBOOL)(const string& s);

class RequiredArgument{
public:
	friend class ArgumentProcessor;
	RequiredArgument(const string &theName, void(*theAction)(const string& theData) ,
			PFSTRBOOL theVerifier = 0, const string& theVerifierMessage = "")
		: name(theName), action(theAction), verifier(theVerifier), verifyMessage(theVerifierMessage){}
	void addValue(const string& theValue, bool isDefault = false){
		if (isDefault)
			defaultValue = theValue;
		values.push_back(theValue);
	}
	static string usage(const vector<RequiredArgument>& args);

	const string& getName() const { return name; }

	PFSTR getAction()const{ return action;}
	bool anyValueAccepted() const {
		return values.size() <= 1;
	}
	bool argumentValid(const string& suppliedValue) const {
		return anyValueAccepted() || ( find(values.begin(), values.end(), suppliedValue) != values.end()  );
	}
	bool argumentVerified(const string& suppliedValue){
		return verifier(suppliedValue);
	}
	string valuesAsString() const {
		string result;
		for (int i = 0; i < values.size(); i++){
			result += values[i];
			if ( i < values.size()-1 )
				result += ", ";
		}
		return result;
	}
private:
	string name;
	vector<string> values;
	string defaultValue, actualValue;
	//void (*action)(const string& data);
	PFSTR action;
	PFSTRBOOL verifier;
	string verifyMessage;
};

class SuppliedArguments{
public:
	SuppliedArguments(){}
	SuppliedArguments(int argc, char ** argv);
	SuppliedArguments(const string & filename);
	unordered_map<string,string> & getMap()  { return mapOfSuppliedArgs; }
private:
	unordered_map<string,string>mapOfSuppliedArgs; // maps arg names to values eg -file to /tmp/stuff.txt
};

class ArgumentProcessor{
public:
	ArgumentProcessor( vector<RequiredArgument>& theRequired, SuppliedArguments& theSupplied):
		requiredArguments(theRequired), suppliedArguments(theSupplied){}

	void applyDefaults();
	void processArguments();
private:
	vector<RequiredArgument>& requiredArguments;
	SuppliedArguments& suppliedArguments;
};



#endif /* ARGPROCESSOR_H_ */
