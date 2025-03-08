#include "arp_spoofing.h"

int	ft_isalpha(int c)
{
	return ((c >= 65 && c <= 90) || (c >= 97 && c <= 122));
}

int	ft_isdigit(int c)
{
	return (c >= 48 && c <= 57);
}

void	*ft_memcpy(void	*dest, const void	*src, size_t n)
{
	char	*dst;
	char	*sc;

	dst = (char *)dest;
	sc = (char *)src;
	if (!dest && !src)
		return (NULL);
	while (n-- > 0)
		*dst++ = *sc++;
	return (dest);
}

char	*ft_strncpy(char	*dest, const char	*src, size_t n)
{
	size_t	i;

	i = 0;
	while (i < n && src[i] != '\0')
	{
		dest[i] = src[i];
		i++;
	}
	dest[i] = '\0';
	return (dest);
}

bool get_arp_request(const t_arp_packet *arp_pkt, const char *target_ip)
{
    char sender_ip[INET_ADDRSTRLEN], requested_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, arp_pkt->sender_ip, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_pkt->target_ip, requested_ip, INET_ADDRSTRLEN);

    if (ntohs(arp_pkt->opcode) == ARPOP_REQUEST) 
    {
        if (ft_strcmp(requested_ip, target_ip) == 0) 
        {
            printf("[INFO] Requête ARP détectée de %s (cherche %s)\n", sender_ip, requested_ip);
            return true;
        }
    }

    return false;
}
