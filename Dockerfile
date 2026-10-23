FROM python:3.12-slim

LABEL maintainer="NSHARK Project"
LABEL description="PCAP Threat Hunter & SOC Analyst Toolkit"

WORKDIR /app

# Install system dependencies for scapy (libpcap)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap-dev \
        tshark \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY nshark/ nshark/
COPY config.yaml .

RUN pip install --no-cache-dir .

# Default data mount point
VOLUME ["/data"]

ENTRYPOINT ["nshark"]
CMD ["--help"]
