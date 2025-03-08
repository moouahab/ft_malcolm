#include "arp_spoofing.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>

bool parsing_ip(char *ip_arg, uint8_t *ip_field)
{
    if (inet_pton(AF_INET, ip_arg, ip_field) != 1) {
        fprintf(stderr, "ft_malcolm: unknown host or invalid IP address: (%s)\n", ip_arg);
        return false;
    }
    return true;
}

bool is_hex_digit(char c) {
    return ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'));
}

bool parsing_mac(char *mac_arg, uint8_t *mac_field)
{
    int i = 0, j = 0;
    char hex_byte[3] = {0};

    while (mac_arg[i] && j < 6) {
        if (!is_hex_digit(mac_arg[i]) || !is_hex_digit(mac_arg[i + 1])) {
            fprintf(stderr, "ft_malcolm: invalid MAC address format (%s)\n", mac_arg);
            return false;
        }
        hex_byte[0] = mac_arg[i];
        hex_byte[1] = mac_arg[i + 1];
        mac_field[j] = (uint8_t) strtol(hex_byte, NULL, 16);
        i += 2;
        j++;

        if (mac_arg[i] == ':' && j < 6)
            i++;
        else if (j < 6 && mac_arg[i] != ':') {
            fprintf(stderr, "ft_malcolm: invalid MAC separator (%s)\n", mac_arg);
            return false;
        }
    }

    if (j != 6 || mac_arg[i] != '\0') {
        fprintf(stderr, "ft_malcolm: invalid MAC address length (%s)\n", mac_arg);
        return false;
    }

    return true;
}


bool parsing_arg(int ac, char **av, t_arp_packet *arp_reponse)
{
    if (ac != 5) {
        fprintf(stderr, "Usage: %s <ip_source> <mac_source> <ip_cible> <mac_cible>\n", av[0]);
        return false;
    }
    /* Initialisation complète de la structure */
    memset(arp_reponse, 0, sizeof(t_arp_packet));
    arp_reponse->htype = htons(1);
    arp_reponse->ptype = htons(0x0800);
    arp_reponse->hlen = 6;
    arp_reponse->plen = 4;
    arp_reponse->opcode = htons(ARPOP_REPLY);

    if (!parsing_ip(av[1], arp_reponse->sender_ip) ||
        !parsing_mac(av[2], arp_reponse->sender_mac) ||
        !parsing_ip(av[3], arp_reponse->target_ip) ||
        !parsing_mac(av[4], arp_reponse->target_mac)) {
        return false;
    }
    return true;
}


