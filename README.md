# 🔍 Wireshark dissectors for Ethereum devp2p protocols

**Table of contents:**

   * [Introduction](#introduction)
   * [Roadmap](#roadmap)
   * [Team](#team)
   * [Get Involved](#get-involved)
   * [License](#license)

# Introduction

In the Protocol Engineering Groups and Systems team (PegaSys) at ConsenSys, we specialise in the low-level, deep aspects of the Ethereum technology. Some of the challenges we tackle are: scalability, secrecy, modularity, finality, permissioning, etc.

To perform our job we need tooling to x-ray into different parts of the system. One of those parts is the networking layer. No central authority exists in public chain Ethereum, hence all communication is peer-to-peer (P2P), which gives rise to both RPC-style and gossip-like communication patterns we need full insight of during development, research and testing. 

[devp2p](https://github.com/ethereum/devp2p) is the name of the networking subsystem of Ethereum, along with its collection of core protocols on top of which subprotocols like ETH, Whisper, Swarm, Light Ethereum, etc. are layered.

On the other hand, [Wireshark](https://www.wireshark.org/) is a popular tool for network packet analysis. Users can initiate network dumps and navigate through a wealth of packet data via its powerful GUI. The architecture of Wireshark is modular, and it revolves around the concept of _dissectors_: components capable of decoding a concrete protocol, which can be in use at any layer of the [OSI model](https://en.wikipedia.org/wiki/OSI_model).

Unfortunately no Wireshark dissectors exist yet for Ethereum devp2p protocols. This project changes that.

# Install

Run either install.bat (and re-build wireshark) or install.sh. If this doesn't work manually do the following steps and then rebuild wireshark:

make a Wireshark\plugins\epan\devp2p folder
copy the files packet-ethereum.c, CMakeLists.txt, Makefile.am, README, Custom.m4, Custom.make into that folder
copy the file CMakeListsCustom.txt to the wireshark root folder

# Roadmap

Specification: https://docs.google.com/document/d/1JKG6rZOq0F0GvPMWR3Gp-WyTQnHxGDx7PGpWCPiIADo

We aim to build a modular set of dissectors that cover the different layers of the devp2p stack:

* **Discovery v4 dissector (`devp2p.discovery`):** UDP-based protocol mirroring many aspects of Kademlia DHT. No encryption or authentication in place. Messages are serialized as RLP. We need to support all four packets: `PING`, `PONG`, `FIND_NODE`, `NODES`. See [the discovery v4 specification](https://github.com/ethereum/devp2p/blob/master/discv4.md) being formalized by the Ethereum Foundation (work in progress).
* **Wire protocol dissector (`devp2p.wire`):** TCP-based protocol for establishing a secure, multiplexed communication channel between peers, supportive of higher level protocols that are dynamically agreed upon during the protocol handshake. Previous to that, a cryptographic handshake takes place. The channel is encrypted and our dissector will need to gain access to the secrets to decrypt traffic. Messages can be compressed with [Snappy](https://github.com/google/snappy).
* **ETH v63 dissector (`devp2p.eth`):** Set of messages pertaining to the Ethereum protocol, with which peers exchange transactions, blocks, hashes, status information, etc.
* **Future:** Light Ethereum, Swarm, Whisper.

# Team

* Raúl Kripalani <raul.kripalani@consensys.net>
* Zhenyang Shi <zhenyang.shi@consensys.net>
* Scott Whittington <scott.whittington@consensys.net>

# Get Involved

Reach out to us on #team-pegasys-priv channel on the ConsenSys Slack!

# License

To be determined.
