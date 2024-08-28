/*
 * Give a magic string based on the epoch time 
 */

typedef unsigned char boolean;

class MagicStringTester {
private:
	long thisEpochHour;
	char * magic0;
	char * magic1;
public:
	MagicStringTester(long epochHour);
	MagicStringTester();
	~MagicStringTester();
	boolean testString(const char *magicString);
	char *magicString();
};
