FROM cowrie/cowrie:latest

# Enable JSON logging
COPY cowrie.cfg /cowrie/cowrie-git/etc/cowrie.cfg

# Resource limits are applied via Docker --memory and --cpus flags
ENV COWRIE_HOSTNAME=svr04
ENV COWRIE_LOG_PATH=/cowrie/cowrie-git/var/log/cowrie

EXPOSE 2222
