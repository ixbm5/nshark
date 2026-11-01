FROM python:3.12-slim

LABEL maintainer="NSHARK Project"
LABEL description="Fast PCAP Analysis, Hash Extraction & Threat Intel CLI"

WORKDIR /app

# Install libpcap for Scapy BPF filtering
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 -s /bin/sh nshark

COPY pyproject.toml README.md LICENSE config.yaml ./
COPY nshark/ nshark/

RUN pip install --no-cache-dir . && chown -R nshark:nshark /app

USER nshark
WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT ["nshark"]
CMD ["--help"]
