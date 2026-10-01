FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    bash \
    iputils-ping \
    netcat-openbsd \
    dnsutils \
    net-tools \
    iproute2 \
    curl \
    iperf3 \
    speedtest-cli \
    && rm -rf /var/lib/apt/lists/*

COPY . /app/

EXPOSE 8000

CMD ["python3", "server.py"]
