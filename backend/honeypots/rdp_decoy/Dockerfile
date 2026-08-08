FROM python:3.12-slim

WORKDIR /app
COPY server.py ./

ENV HONEYPOT_ID=rdp-decoy-01
ENV LOG_FILE=/var/log/honeypot/rdp-decoy.json
ENV PORT=3389

EXPOSE 3389

RUN useradd -r -s /bin/false honeypot && \
    mkdir -p /var/log/honeypot && \
    chown honeypot:honeypot /var/log/honeypot
USER honeypot

CMD ["python", "server.py"]
