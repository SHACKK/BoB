LDLIBS=-lpcap

all: arp-spoof

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o my_class.o iphdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
