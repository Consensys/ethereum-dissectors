# 🔍 Wireshark dissectors for Ethereum devp2p protocols

**Table of contents:**

   * [Introduction](#introduction)
   * [Install](#install)
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
Note: This dissector is developed under windows environment, the windows building procedures might take quite a long time for the first time, but only takes a few seconds to do future build and is proved to work. The mac building procedures should work, but is not tested **(As of 13/05/2018, there's a bug with brew that couldn't install wireshark with qt)**

### For Windows (For first time):
* Install C compiler "Microsoft Visual Studio 2015 Community Edition" [Download Link](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409).  **Make sure** when Install Select "Custom" install and just check "Common Tools for Visual C++ 2015"
* Install Qt [Download link](https://www.qt.io/download-open-source/) Select: **"msvc2015 64-bits"** for 64-bits build or "msvc2015 32-bits" for 32-bit build. **It is important to select the right version starts with msvc2015.**
* Install chocolatey <https://chocolatey.org/>
* Install Python: **choco install -y python3**
* Install Git: **choco install -y git**
* Install Cmake: **choco install -y cmake**
* Install Asciidoctor, Xsltproc, And DocBook: **choco install -y asciidoctorj xsltproc docbook-bundle**
* Create a folder **C:\Development\\**
* Use commond line to clone the wireshark repository in C:\Development **git clone https://code.wireshark.org/review/wireshark**
* Open a Visual Studio Command Prompt: **VS2015 x64 Native Tools Command Prompt** for a 64-bit version or VS2015 x86 Native Tools Command Prompt for a 32-bit version.
* In the Command Prompt: **set WIRESHARK\_BASE\_DIR=C:\Development** and set the Qt to the install path, _for example_ **set QT5\_BASE\_DIR=C:\Qt\5.9.1\msvc2015_64** _Also, Please set these in windows environment variable, otherwise you have to set them every time you open a new Visual Studio Command Prompt_
* Create a folder **C:\Development\wsbuild\\**
* Install this dissector: **Copy packet-ethereum.c to C:\Development\wireshark\epan\dissectors\\**
* Edit Cmake file **open C:\Development\wireshark\epan\dissectors\CMakeLists.txt** And add packet-ethereum.c to the DISSECTOR\_SRC at around line 620. So add **${CMAKE_CURRENT_SOURCE_DIR}/packet-ethereum.c** to around line 620
* In the Command Prompt: **cd C:\Development\wsbuild\\**
* In the Command Prompt: **cmake -G "Visual Studio 14 2015 Win64" ..\wireshark**
* In the Command Prompt: **msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln**
* Run wireshark in **C:\Development\wsbuild32\run\RelWithDebInfo\Wireshark.exe**

### For Windows (For future build)
* Open a Visual Studio Command Prompt: **VS2015 x64 Native Tools Command Prompt** and **cd C:\Development\wsbuild\\**
* _Make changes packet-ethereum.c in wireshark folder_
* In the Command Prompt: **msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln**
* _You can leave the Command Prompt open and build the dissector every time you make some changes to it_

### For Mac OS (Build as plugin)
##### Please note: build plugin when you have a wireshark installed in Application can cause some errors, please use a wireshark-dev version
* **brew install wireshark --with-headers --with-qt**
* **brew link wireshark** _(Use --overwrite flag if necessary)_
* **cd _${this Project path}_**
* **mkdir build**
* **cd build**
* **cmake ..**
* **make**
* **make install**

# Roadmap

#### Specification: 
<https://docs.google.com/document/d/1JKG6rZOq0F0GvPMWR3Gp-WyTQnHxGDx7PGpWCPiIADo>

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
