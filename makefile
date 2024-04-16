LDLIBS=-lpcap

all: spoof-arp

main.o: mac.h ip.h ethhdr.h arphdr.h iphdr.h main.cpp

iphdr.o : ip.h iphdr.h iphdr.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

spoof-arp: main.o arphdr.o ethhdr.o ip.o mac.o iphdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f spoof-arp *.o
