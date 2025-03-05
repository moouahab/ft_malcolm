# FT MALCOLM

## Objectif de FT MALCOLM

- Attendre une **requête ARP** envoyée en **broadcast** par la cible.  
- Envoyer une **fausse réponse ARP** contenant une **adresse MAC falsifiée**.  
- Faire croire à la cible que l’**adresse IP source** appartient à une **autre adresse MAC**.  
- **Résultat** : la cible met à jour sa **table ARP** avec les fausses informations et commence à envoyer ses paquets à l’attaquant au lieu de l’appareil légitime.

---

## Introduction - ft_malcolm

Le projet **ft_malcolm** est un programme en **C** qui simule une **attaque de type Man-In-The-Middle (MITM)**.  
Cette attaque permet à un attaquant d’**intercepter** et éventuellement **modifier** les données échangées entre deux machines de manière **discrète**.

Ce programme exploite les **vulnérabilités du protocole ARP (Address Resolution Protocol)** pour intercepter les paquets échangés entre deux utilisateurs en se faisant passer pour une **machine légitime** du réseau.

L’objectif de ce programme est de **manipuler la table ARP de la cible** en lui envoyant des **réponses ARP falsifiées**, ce qui permet de **rediriger le trafic réseau** vers l’attaquant.

---

## Pourquoi le protocole ARP est-il vulnérable aux attaques comme l’ARP Spoofing ?

Le protocole **ARP** est vulnérable aux attaques de type **Spoofing** car :

1. Il **fait confiance aveuglément** aux réponses ARP reçues, sans aucune **vérification d’authenticité**.  
2. Il **ne possède aucun mécanisme d’authentification** des adresses IP et MAC.  
3. Une machine met à jour **automatiquement** sa table ARP dès qu’elle reçoit une **réponse ARP**, même si celle-ci est falsifiée.  
4. Un attaquant peut ainsi **usurper une adresse IP** et s’introduire dans le réseau en se faisant passer pour un appareil de confiance.

---

## Utilisation du programme

### Paramètres d'entrée

Le programme prend **quatre arguments** en entrée :

1. `ip_source` → L’adresse IP que l’on veut usurper.  
2. `mac_source` → L’adresse MAC qui sera associée à cette IP (spoofée).  
3. `ip_cible` → L’adresse IP de la cible (l’appareil que l’on veut tromper).  
4. `mac_cible` → L’adresse MAC de la cible.

### Exécution du programme

La commande suivante permet d’exécuter le programme :

```sh
./ft_malcolm <ip_source> <mac_source> <ip_cible> <mac_cible>
```

## Récupération et envoi des informations en C

Afin de récupérer et envoyer les paquets ARP en **C**, nous utiliserons les fonctions :

- `sendto()` : Permet d’envoyer un paquet sur le réseau.  
- `recvfrom()` : Permet de recevoir un paquet envoyé sur le réseau.  

Ces fonctions sont essentielles pour **capturer la requête ARP** de la cible, puis **envoyer une réponse falsifiée** afin de manipuler sa **table ARP**.

---

## Fonctionnement du programme

Un **paquet ARP** a une structure spécifique utilisée pour **résoudre** les adresses **IP** en adresses **MAC** dans le réseau local (LAN).

### Structure d'un paquet ARP

| Champ                 | Taille    | Description                                                                 |
|-----------------------|-----------|-----------------------------------------------------------------------------|
| **Hardware Type (HTYPE)** | 2 octets   | Indique le type de matériel (ex. Ethernet = 1).                              |
| **Protocol Type (PTYPE)** | 2 octets   | Indique le protocole de couche 3 utilisé (ex. IPv4 = 0x0800).                |
| **Hardware Size (HLEN)**  | 1 octet    | Taille de l’adresse matérielle (MAC) en octets (Ethernet = 6).               |
| **Protocol Size (PLEN)**  | 1 octet    | Taille de l’adresse du protocole (IPv4 = 4 octets).                          |
| **Operation (OPER)**      | 2 octets   | Type d'opération (1 = requête ARP, 2 = réponse ARP).                         |
| **Sender MAC Address**    | 6 octets   | Adresse MAC de l’expéditeur.                                                 |
| **Sender IP Address**     | 4 octets   | Adresse IP de l’expéditeur.                                                  |
| **Target MAC Address**    | 6 octets   | Adresse MAC du destinataire (inconnue pour une requête ARP).                 |
| **Target IP Address**     | 4 octets   | Adresse IP du destinataire.                                                  |

---

### Exemple de paquet ARP en hexadécimal

```txt
0001 0800 0604 0001 001A 2B3C 4D5E C0A8 0101 0000 0000 0000 C0A8 0102
```

#### Décryptage :

- `0001` → Type de matériel (Ethernet).  
- `0800` → Type de protocole (IPv4).  
- `06` → Taille d’une adresse MAC.  
- `04` → Taille d’une adresse IP.  
- `0001` → Type de message (1 = requête ARP).  
- `001A2B3C4D5E` → Adresse MAC source.  
- `C0A80101` → Adresse IP source (192.168.1.1).  
- `000000000000` → Adresse MAC cible (inconnue).  
- `C0A80102` → Adresse IP cible (192.168.1.2).

---

### Requête ARP

Lorsqu’un ordinateur veut connaître l’adresse MAC associée à une IP, il envoie un **message ARP** contenant l’IP cible avec une **adresse MAC cible vide** (`00:00:00:00:00:00`).

### Réponse ARP

L’appareil possédant cette **adresse IP** répond en envoyant un **paquet** contenant **son adresse MAC réelle**.

---

## Conclusion

Le projet **ft_malcolm** démontre de manière concrète comment fonctionne l’**ARP Spoofing** :  
en falsifiant des **paquets ARP**, on peut **usurper l’identité** d’une machine légitime et ainsi **intercepter** ou **rediriger** son trafic.  
Cette attaque, typique du **Man-In-The-Middle (MITM)**, illustre la **vulnérabilité fondamentale** du protocole ARP, qui ne repose sur **aucune authentification**.

Dans un contexte réel, pour protéger un réseau contre de telles attaques, on peut :

- Configurer des **tables ARP statiques**.  
- Utiliser des **protocoles sécurisés** (HTTPS, VPN, etc.).  
- Mettre en place des **systèmes de détection d’ARP Spoofing**.
