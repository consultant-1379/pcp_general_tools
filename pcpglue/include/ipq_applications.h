/* written by Ralf Hoffmann, ipoque GmbH
 * ralf.hoffmann@ipoque.com
 */

#ifndef __IPOQUE_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE IPQ_API.H
#endif

#ifndef IPQ_APPLICATIONS_H
#define IPQ_APPLICATIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#define IPOQUE_APPLICATION_NOT_YET_DETECTED  	     0
#define IPOQUE_APPLICATION_NOT_DETECTED     	     1
#define IPOQUE_APPLICATION_FACEBOOK             	 2
#define IPOQUE_APPLICATION_MAGICJACK             	 3
#define IPOQUE_APPLICATION_ITUNES             	     4
#define IPOQUE_APPLICATION_MYSPACE               	 5
#define IPOQUE_APPLICATION_FACETIME             	 6
#define IPOQUE_APPLICATION_TRUPHONE             	 7
#define IPOQUE_APPLICATION_TWITTER                 	 8
#define IPOQUE_APPLICATION_WINDOWSMEDIA            	 9
#define IPOQUE_APPLICATION_XBOX                  	 10
#define IPOQUE_APPLICATION_REALMEDIA               	 11
#define IPOQUE_APPLICATION_GMAIL                 	 12
#define IPOQUE_APPLICATION_GOOBER                  	 13
#define IPOQUE_APPLICATION_BLACKBERRY             	 14
#define IPOQUE_APPLICATION_ICLOUD	             	 15
#define IPOQUE_APPLICATION_UBUNTUONE             	 16
#define IPOQUE_APPLICATION_DROPBOX	             	 17
#define IPOQUE_APPLICATION_GOOGLEDOCS             	 18
#define IPOQUE_APPLICATION_YUILOP             	     19
#define IPOQUE_APPLICATION_IMESSAGE             	 20
#define IPOQUE_APPLICATION_GOTOMYPC             	 21
#define IPOQUE_APPLICATION_GOTOMEETING             	 22
#define IPOQUE_APPLICATION_WINDOWS_AZURE             23
#define IPOQUE_APPLICATION_AMAZON_CLOUD              24
#define IPOQUE_APPLICATION_DAILYMOTION               25
#define IPOQUE_APPLICATION_DEEZER					 26
#define IPOQUE_APPLICATION_GROOVESHARK	             27
#define IPOQUE_APPLICATION_SUDAPHONE		         28
#define IPOQUE_APPLICATION_OFFICE365	             29
#define IPOQUE_APPLICATION_CNTV						 30
#define IPOQUE_APPLICATION_SINATV 		             31
#define IPOQUE_APPLICATION_YOUTUBE	             	 32
#define IPOQUE_APPLICATION_VOIP_SWITCH			   	 33
#define IPOQUE_APPLICATION_ZYNGA	             	 34
#define IPOQUE_APPLICATION_CRIMECITY	             35
#define IPOQUE_APPLICATION_MODERNWAR	             36
#define IPOQUE_APPLICATION_VIPPIE					 37
#define IPOQUE_APPLICATION_BOX						 38
#define IPOQUE_APPLICATION_SKYDRIVE					 39
#define IPOQUE_APPLICATION_ADOBE_CREATIVE_CLOUD		 40
#define IPOQUE_APPLICATION_LINKEDIN					 41

#define IPOQUE_NUMBER_OF_APPLICATIONS                42

#define IPOQUE_APPLICATION_SHORT_STRING \
	"not_yet_detected",					\
		"not_detected",					\
		"facebook",						\
		"magicjack",					\
		"itunes",						\
		"myspace",						\
		"facetime",						\
		"truphone",						\
		"twitter",						\
		"windowsmedia",					\
		"xbox",							\
		"realmedia",					\
		"gmail",						\
		"goober",						\
		"blackberry",					\
		"icloud",						\
		"ubuntuone",					\
		"dropbox",						\
		"googledocs",					\
		"yuilop",						\
		"imessage",						\
		"gotomypc",						\
		"gotomeeting",					\
		"windows_azure",				\
		"amazon_cloud",					\
		"dailymotion",					\
		"deezer",						\
		"grooveshark",					\
		"sudaphone",					\
		"office365",					\
		"cntv",							\
		"sinatv",						\
		"youtube",						\
		"voipswitchvoiptunnel",			\
		"zynga",						\
		"crimecity",					\
		"modernwar",					\
		"vippie",						\
		"box",							\
		"skydrive",						\
        "adobe_creative_cloud",         \
        "linkedin"

#ifdef __cplusplus
}
#endif

#endif /* IPQ_APPLICATIONS_H */
