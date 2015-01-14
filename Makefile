
CFLAGS = -g -Wall
LDFLAGS = -lpcap -lpthread
CC = clang

proxy: main.o getPacket.o tap.o 
	$(CC) -o $@ $^ $(LDFLAGS) 

main.o : head.h

.PHONY : clean cleanobjs
clean:
	-rm -rf *.o proxy

cleanobjs:
	-rm -rf *.o

