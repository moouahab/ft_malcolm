#ifndef ARP_SPOOFING_H
# define ARP_SPOOFING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>

/*
 * Structure d'un paquet ARP
 *
 * @brief Structure d'un paquet ARP
 * @param htype Type de matériel (Ethernet = 1)
 * @param ptype Type de protocole (IPv4 = 0x0800)
 * @param hlen Longueur adresse MAC (6)
 * @param plen Longueur adresse IP (4)
 * @param opcode Opération (1 = Request, 2 = Reply)
 * @param sender_mac Adresse MAC de l'expéditeur
 * @param sender_ip Adresse IP de l'expéditeur
 * @param target_mac Adresse MAC de la cible
 * @param target_ip Adresse IP de la cible
 * 
 * Structure d'un paquet ARP décrivant une demande ou une réponse ARP.
 * 
 * __attribute__((packed)) est utilisé pour aligner les champs sur des adresses mémoires alignées.
 */

typedef struct __attribute__((packed)) s_arp_packet {
    uint16_t    htype;
    uint16_t    ptype;
    uint8_t     hlen;
    uint8_t     plen;
    uint16_t    opcode;
    uint8_t     sender_mac[6];
    uint8_t     sender_ip[4];
    uint8_t     target_mac[6];
    uint8_t     target_ip[4];
} t_arp_packet;

/* Structure d'une trame Ethernet complète */
typedef struct s_ethernet_frame {
    uint8_t dest_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint16_t ethertype;
    t_arp_packet arp;
} t_ethernet_frame;

typedef enum e_interface_type {
    IFACE_UNKNOWN = 0,  // Pour tout ce qu'on ne sait pas classer
    IFACE_ETHERNET,     // Ethernet filaire
    IFACE_WIFI,         // Wi-Fi
    IFACE_LOOPBACK,     // Interface loopback (lo)
    IFACE_VIRTUAL,      // Interface virtuelle (VM, conteneurs, etc.)
    IFACE_TUN_TAP,      // Interface TUN/TAP (VPN, tunnels)
    IFACE_BRIDGE,       // Pont réseau (bridge)
    IFACE_VLAN,         // VLAN
    IFACE_CELLULAR      // 4G/5G, LTE, etc.
} t_interface_type;

# define ARPOP_REQUEST 1
# define ARPOP_REPLY 2
# define BUF_REQUEST 42

// Fonctions de traitement ARP
bool    get_arp_request(const t_arp_packet *arp_request, const char *source_ip);
int     ft_strcmp(const char *s1, const char *s2);
char	*ft_strtok(char *str, const char *delim);
bool    parsing_arg(int ac, char **av, t_arp_packet *arp_reponse);

// Fonctions de vérification et de conversion
int     ft_isalpha(int c);
int     ft_isdigit(int c);
int     ft_isalnum(int c);
char	*ft_strnchr(const char *s, int c, int n);
char	*ft_strchr(const char	*s, int c);
char	*ft_strncpy(char	*dest, const char	*src, size_t n);
void	*ft_memcpy(void	*dest, const void	*src, size_t n);
void    *ft_memset(void *s, int c, size_t n);
int     ft_memcmp(const void	*ptr1, const void	*ptr2, size_t num);

#endif
