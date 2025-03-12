FROM debian:bookworm-slim

RUN apt update && apt install -y \
    iputils-ping net-tools arping\
    && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]
