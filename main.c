#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char **argv){
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;

    struct bpf_program fp;

    pcap_t *pcd;  // packet capture descriptor

    dev = pcap_lookupdev(errbuf); // 디바이스 이름
    if (dev == NULL)    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV : %s\n", dev);

    pcd = pcap_open_live(dev, BUFSIZ,  1, -1, errbuf);
    if (pcd == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }

    // 패킷이 캡쳐되면 callback함수를 실행한다.
    pcap_loop(pcd, -1, callback, NULL);
}
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ip *iph; // IP 헤더 구조체
    struct tcphdr *tcph; // TCP 헤더 구조체
    struct ether_header *ep; // Ethernet 헤더 구조체
    unsigned short ether_type;
    int chcnt =0;
    int length=pkthdr->len;

    // 이더넷 헤더를 가져온다.
    ep = (struct ether_header *)packet;
    packet += sizeof(struct ether_header);
    // 네트워크 패킷은 big redian 이라서 little redian형식으로 바꿔준다.
    ether_type = ntohs(ep->ether_type);

    if (ether_type == ETHERTYPE_IP){
        iph = (struct ip *)packet;
        // TCP패킷인 경우.
        if (iph->ip_p == IPPROTO_TCP){
            tcph = (struct tcp *)(packet + iph->ip_hl * 4);
            // MAC 주소 출력.
            printf("Destination MAC : ");
            for (int i = 0; i <6; i++)
                printf("%02x ", ep->ether_dhost[i]);
            printf("\n");
            printf("Source MAC : ");
            for (int i = 0; i < 6; i++)
                printf("%02x ", ep->ether_dhost[i]);
            printf("\n");
            // IP 주소 출력
            printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
            printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));
            // Port 번호 출력
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n\n" , ntohs(tcph->dest));
        }
    }
}
