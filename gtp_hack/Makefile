
HEADERS=events.h gtp_hack.h traffic.h config.h replayPcap.h
OBJECTS=events.o gtp_hack.o traffic.o config.o replayPcap.o

simulator: $(HEADERS) $(OBJECTS) simulator.c
	gcc -g -o simulator -lpcap -lpthread $(OBJECTS) simulator.c

empty: empty.c gtp_hack.o gtp_hack.h
	gcc -g -o empty -lpcap gtp_hack.o empty.c

brown: brown.c gtp_hack.o gtp_hack.h
	gcc -g -o brown -lpcap gtp_hack.o brown.c

events.o: events.h events.c
	gcc -g -c events.c

gtp_hack.o: gtp_hack.h gtp_hack.c
	gcc -g -c gtp_hack.c

traffic.o: traffic.h traffic.c
	gcc -g -c traffic.c

config.o: config.h config.c
	gcc -g -c config.c

replayPcap.o: replayPcap.h replayPcap.c
	gcc -g -c replayPcap.c
clean:
	rm -Rf *.o
