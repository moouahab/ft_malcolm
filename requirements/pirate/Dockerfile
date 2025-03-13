# requirements/pirate/Dockerfile
FROM debian:bullseye

RUN apt-get update && apt-get install -y \
    build-essential \
    iproute2 iputils-ping net-tools \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ft_malcolm
COPY . /ft_malcolm

RUN make re 

CMD ["/bin/bash"]
