#! /bin/bash

docker run --rm -it -v myvolgeth:/app --cap-add=NET_ADMIN --cap-add=NET_RAW testgeth
