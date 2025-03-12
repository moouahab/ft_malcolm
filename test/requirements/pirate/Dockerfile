# Utilisation de Debian Slim pour minimiser la taille
FROM debian:bookworm-slim

# Mise à jour et installation des outils nécessaires
RUN apt update && apt install -y \
    gcc make iputils-ping net-tools \
    ettercap-text-only tcpdump \
    wireshark tshark \
    sudo curl vim \
    && rm -rf /var/lib/apt/lists/*

# Création d'un utilisateur non-root
RUN useradd -m -s /bin/bash pirate && echo "pirate:pirate" | chpasswd && adduser pirate sudo

# Définir le répertoire de travail
WORKDIR /home/pirate

# Copier les fichiers source dans le conteneur
COPY srcs /home/pirate/srcs
COPY Makefile /home/pirate/

# Compilation automatique de ft_malcolm
RUN make

# Définir le répertoire par défaut
WORKDIR /home/pirate

# Rendre l'entrée interactive
CMD ["/bin/bash"]
