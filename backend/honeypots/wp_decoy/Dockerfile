FROM python:3.12-slim

WORKDIR /app
COPY app.py requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

ENV HONEYPOT_ID=wp-decoy-01
ENV LOG_FILE=/var/log/honeypot/wp-decoy.json
ENV PORT=8080

EXPOSE 8080

# Run as non-root
RUN useradd -r -s /bin/false honeypot && \
    mkdir -p /var/log/honeypot && \
    chown honeypot:honeypot /var/log/honeypot
USER honeypot

CMD ["python", "app.py"]
