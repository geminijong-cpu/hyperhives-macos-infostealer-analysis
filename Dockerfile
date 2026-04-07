FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Core RE tools and build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    curl \
    file \
    git \
    hexyl \
    less \
    libssl-dev \
    nasm \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    radare2 \
    unzip \
    vim \
    wget \
    xxd \
    zsh \
    && rm -rf /var/lib/apt/lists/*

# Python analysis environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir \
    capstone \
    keystone-engine \
    lief \
    pefile \
    yara-python \
    unicorn \
    r2pipe \
    ipython \
    rich \
    hexdump \
    pycryptodome \
    cryptography

# Install Ghidra (headless for scripted decompilation)
RUN mkdir -p /opt/ghidra && \
    wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip" \
    -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt/ghidra && \
    rm /tmp/ghidra.zip

# Ghidra needs Java
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

ENV GHIDRA_HOME="/opt/ghidra/ghidra_11.3.1_PUBLIC"
ENV PATH="${GHIDRA_HOME}/support:${PATH}"

# Install rustfilt for Rust symbol demangling
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install rustfilt && \
    cp /root/.cargo/bin/rustfilt /usr/local/bin/ && \
    rm -rf /root/.cargo/registry

# Working directory
WORKDIR /lab
RUN mkdir -p /lab/sample /lab/output /lab/scripts

COPY scripts/ /lab/scripts/
RUN chmod +x /lab/scripts/*.py 2>/dev/null || true

CMD ["/bin/bash"]
