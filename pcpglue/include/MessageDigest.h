
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#if !defined(MESSAGEDIGEST_H)
# define MESSAGEDIGEST_H

class MessageDigest
{
public:
	MessageDigest(const char *algorithm);
	MessageDigest(void);
	~MessageDigest(void);
	unsigned char *digest(void);
	unsigned char *digest(const char input);
/*	void update(char *input); */
	unsigned char *digest(const char *input, int offset, int len);
	MessageDigest getInstance(char *algorithm); 
	MessageDigest getInstance(char *algorithm, char *provider); 
	int  isEqual(const char *digesta, const char *digestb);
	void reset(void);
	char *toString(void);
	void update(const char input);
/*	void update(char *input); */
	void update(const char *input, size_t offset, size_t len);
private:
     unsigned char hash[SHA256_DIGEST_LENGTH];
     SHA256_CTX sha256;
};

#endif
/* ... MESSAGEDIGEST_H */
