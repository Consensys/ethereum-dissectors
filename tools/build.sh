#! /bin/bash

HOST_IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | cut -d\  -f2)

docker build -t geth-patched --build-arg host_ip=$HOST_IP .
