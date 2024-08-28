
CC=g++
CXX=g++

CCFLAGS = -g -D_TRACE -DCCP -DASN1RT -DGNU -D_GNU_SOURCE -I. -Wall

CPPFLAGS = -o -g -std=c++0x -I ./include

OBJ = classify.o packetbuffer.o pcpglue.o mutex.o UE_map.o gtpv1.o gtp_ie.o GTPv1_packetFields.o gtpv1_utils.o gtpv2_main.o gtp_ie_gtpv2.o ArgProcessor.o 



HEADERS=classify.h packetbuffer.h UE_map.hpp mutex.hpp pcpglue.hpp
LIBS=-lpcap -lpthread -L./libs -lipoque_detection -I./include -lpcap -lcrypto -L./lib -lmagicstring


all: $(HEADERS) $(OBJ) gtpv1
      
.PHONY : all        
        
clean:
	\rm -f *.o gtpv1 pcpglue

gtpv1: $(objects) $(OBJ)
	$(CXX) $(CCFLAGS) -o gtpv1 $(OBJ) $(LIBS)
