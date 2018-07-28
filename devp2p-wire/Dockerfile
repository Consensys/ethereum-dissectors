# Based on Ubuntu - 17.10

# Ubuntu 17.10
FROM ubuntu:17.10

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

# Install essential tools
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev git tcpdump iptables netcat iputils-ping tar xz-utils unzip vim make gcc-multilib git curl software-properties-common build-essential golang && rm -rf /var/lib/apt/lists/*

# Install go-lang
ADD https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz /app/

RUN tar -xvf go1.10.3.linux-amd64.tar.gz && mv go /usr/local

ENV PATH="/usr/local/go/bin:${PATH}"

# Install geth
RUN git clone https://github.com/ethereum/go-ethereum && cd go-ethereum && make geth

### Done ###
