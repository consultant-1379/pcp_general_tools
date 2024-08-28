/*
 * xmlParser.hpp
 *
 *  Created on: 16 Aug 2012
 *      Author: emilawl
 */

#ifndef XMLPARSER_HPP_
#define XMLPARSER_HPP_

#include <unistd.h>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/foreach.hpp>
using namespace std;
using namespace boost;

struct Property{
	string name;
	string value;
	bool active;
};
vector<Property> readProperties( std::istream & is )
{
    // populate tree structure pt
    using boost::property_tree::ptree;
    ptree propertyTree;
    read_xml(is, propertyTree);
    vector<Property> result;
    BOOST_FOREACH( ptree::value_type const& v, propertyTree.get_child("properties") ) {
        if( v.first == "property" ) {
            Property property;
            property.name = v.second.get<string>("name");
            property.value = v.second.get<string>("value");
            property.active = v.second.get<bool>("active");
            if (property.active == true){
            	result.push_back(property);
            }
        }
    }
    return result;
}



#endif /* XMLPARSER_HPP_ */
