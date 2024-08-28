/*
 * ArgProcessor.c

 *
 *  Created on: 26 Jul 2012
 *      Author: eroryma
 */
#ifndef ArgProcessor_Included
#define ArgProcessor_Included
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <unordered_map>

using std::string;
#include "include/ArgProcessor.h"
#include "include/xmlParser.hpp"

string RequiredArgument::usage(const vector<RequiredArgument>& args) {
	string result = "Usage:";
	for ( int i = 0; i < args.size(); i++){
		result+= "\n" + args[i].name + ":\n\t";
		for ( int j = 0; j < args[i].values.size(); j++){
			result += args[i].values[j];
			if (args[i].values[j] == args[i].defaultValue) result += " (default) ";
			if (j < args[i].values.size()-1) result += "/";
		}
	}
	return result;
}

void ArgumentProcessor::applyDefaults(){
	for  (int i = 0; i < requiredArguments.size(); i++){
		RequiredArgument arg = requiredArguments[i];
		if (arg.defaultValue.length() > 0)
			arg.action(arg.defaultValue);
	}
}

void ArgumentProcessor::processArguments(){
	unordered_map<string,string>::const_iterator suppliedArgumentIterator;

	for (suppliedArgumentIterator = suppliedArguments.getMap().begin();suppliedArgumentIterator !=suppliedArguments.getMap().end();	suppliedArgumentIterator++)
	{
		vector<RequiredArgument>::const_iterator requiredArgumentIterator = requiredArguments.begin(), requiredArgumentEnd = requiredArguments.end();

		while (requiredArgumentIterator != requiredArgumentEnd){
			if (requiredArgumentIterator->getName() == suppliedArgumentIterator->first) break;
			requiredArgumentIterator++;
		}
		if ( requiredArgumentIterator == requiredArgumentEnd) {
			string errorMessage = "Unexpected argument: ";
			errorMessage += suppliedArgumentIterator->first + " " + suppliedArgumentIterator->second + "\n";
			errorMessage += RequiredArgument::usage(requiredArguments);
			throw(errorMessage);
		}
		else{
			// Now check that argument is valid
			// Argument is valid either if the argument accepts any value (list of values has only one item)
			// or if it one of the list of values.
			if (requiredArgumentIterator->argumentValid( suppliedArgumentIterator->second ))
				requiredArgumentIterator->getAction()(suppliedArgumentIterator->second);
			else
				throw string("Value ") + suppliedArgumentIterator->second + " for " + suppliedArgumentIterator->first + " is invalid. " +
				"Valid values are: " + requiredArgumentIterator->valuesAsString();

			if (requiredArgumentIterator->verifier){
				if ( ! requiredArgumentIterator->verifier(suppliedArgumentIterator->second)){
					throw string("Argument ") + suppliedArgumentIterator->first + " value " + suppliedArgumentIterator->second
							+ " is invalid: " + requiredArgumentIterator->verifyMessage + '\n';
				}
			}

		}
	}
}

SuppliedArguments::SuppliedArguments(const string & filename){
	std::ifstream inStream(filename, std::ifstream::in);

	if (inStream){

		typedef vector<Property> vectorType;
		typedef vectorType::value_type propertyType;

		vector<Property> properties = readProperties(inStream);
		inStream.close();
		BOOST_FOREACH(const propertyType& property, properties){
			string s=property.name,s1 = property.value;
			if (s.length() < 2){
				string errorMessage = "Invalid argument: ";
				errorMessage += s + " value " +s1 +"\n";
				throw(errorMessage);
			}
			mapOfSuppliedArgs[s] = s1;
		}
	}else{
		throw string("Failed to read from properties file");
	}
}

SuppliedArguments::SuppliedArguments(int argc, char ** argv){

	if (argc % 2 == 0){
		//Only valid option here is -h
		if ( strcmp(argv[1], "-h") == 0){
			mapOfSuppliedArgs["-h"] = "";
			return;
		}
		else{
			throw string("Invalid number of arguments, must be ' -name value ' pairs");
		}
	}

	for ( int i = 1; i < argc; i+=2){
		string s = argv[i], s1 = argv[i+1];
		if (s.length() < 2){
			cerr << "Invalid argument: " << s << " value " << s1 << endl;
			throw string("Invalid argument: ") + s;
		}
		mapOfSuppliedArgs[s] = s1;
	}
}

#endif


