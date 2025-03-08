#include <stddef.h>
#include <stdint.h>

/**
 * ft_memset - Remplit la zone mémoire pointée par s avec l'octet c, sur n octets.
 *
 * @s:  Pointeur vers la zone mémoire à remplir.
 * @c:  Valeur (sous forme d'entier) dont l'octet bas sera copié.
 * @n:  Nombre d'octets à écrire.
 *
 * Retourne: Le pointeur 's' (afin de suivre la convention standard memset).
 *
 * Remarques:
 *  - Cette version est optimisée pour des architectures 64 bits, en écrivant
 *    d'abord octet par octet jusqu'à aligner l'adresse sur 8 octets, puis
 *    en écrivant des blocs de 8 octets (64 bits) à la fois.
 *  - Les octets résiduels (si n n'est pas multiple de 8) sont écrits un par un
 *    à la fin de la fonction.
 */

void *ft_memset(void *s, int c, size_t n)
{
    unsigned char *dst = (unsigned char *)s;
    size_t i = 0;

    if (n < 8) {
        while (i < n)
            dst[i++] = (unsigned char)c;
        return s;
    }
    uint64_t pattern = (unsigned char)c;
    pattern |= pattern << 8;
    pattern |= pattern << 16;
    #if UINTPTR_MAX == 0xffffffffffffffff
        pattern |= pattern << 32;
    #endif
    while (((uintptr_t)(dst + i) & 7) != 0 && i < n)
        dst[i++] = (unsigned char)c;
    size_t remaining = n - i;
    size_t nb_blocks = remaining / 8;
    size_t tail = remaining % 8;
    uint64_t *ptr64 = (uint64_t *)(dst + i);
    for (size_t b = 0; b < nb_blocks; b++)
        ptr64[b] = pattern;
    i += nb_blocks * 8;
    while (tail--)
        dst[i + tail] = (unsigned char)c;
    return s;
}