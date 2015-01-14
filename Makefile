
CFLAGS = -g -Wall
LDFLAGS = -lpcap
CC = clang

testpcap: main.o tap.o
	$(CC) -o $@ $^ $(LDFLAGS) 

.PHONY : clean
clean:
	rm -rf *.o testpcap

