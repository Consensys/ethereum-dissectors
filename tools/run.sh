#! /bin/bash

docker run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW geth-patched /app/go-ethereum/build/bin/geth 
