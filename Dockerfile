FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    nmap nikto sqlmap dirb exploitdb \
    gobuster ffuf nuclei whatweb \
    hydra john hashcat medusa cewl \
    whois dnsutils theharvester amass subfinder \
    metasploit-framework \
    responder bettercap aircrack-ng wifite \
    curl sshpass openssh-client netcat-traditional wget \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash arsenal && \
    mkdir -p /home/arsenal/.arsenal && \
    chown -R arsenal:arsenal /home/arsenal/.arsenal
WORKDIR /opt/arsenal
COPY . .

RUN python3 -m pip install --break-system-packages --ignore-installed -e .

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

USER arsenal
ENTRYPOINT ["python3", "-m", "arsenal", "--transport", "streamable-http"]
