# 🔍 Wireshark dissectors for Ethereum devp2p protocols

This repo contains a set of network protocol dissectors for Ethereum that you can load into the widely popular Wireshark to begin inspecting Ethereum traffic.

Currently we support the UDP-based discovery protocol, but support for the RLPx Wire protocol and the ETH subprotocol are in the works.

<p align="center">
<img src="https://github.com/ConsenSys/devp2p-dissectors/raw/web/assets/ethereum-discovery-demo.gif" alt="Ethereum discovery dissector demo">
</p>

Here are the features currently supported by the Ethereum Discovery dissector (we're working on more):

* Heuristics to dynamically detect Ethereum discovery traffic, no matter the port it's running on.
* Decoding of `PING`, `PONG`, `FIND_NODE` and `NODES` packet, breaking the messages into its elements, with the appropriate datatypes.
* Linking of `PING` => `PONG` frames, as well as `FIND_NODE` => `NODES` interactions in protocol trees.
* Lots of supported filters! (documentation WIP)
* Service response time calculation for RPC interactions.
  * under: Statistics > Service Response Time > ETH discovery.
  * inline in protocol trees.
* Useful protocol statistics (e.g. message counts per type, nodes reported per response, etc.)

# Protocol version support

| Protocol	| Version	| Status         | Notes					|
| ------------- | ------------- | -------------- | -------------------------------------------- |
| discovery	| v4		| ✅		| 					       |
| discovery	| v5		| 🚧		 | v5 is work-in-progress in clients. Refer to issues and PRs labelled [discv5](https://github.com/ConsenSys/ethereum-dissectors/labels/discv5).					|
| wire		| v1		| 🚧		 | wip branch: [devp2p-wire](//github.com/ConsenSys/ethereum-dissectors/tree/devp2p-wire)						|

# Table of contents

   * [Build & run](#build--run)
   * [Team](#team)
   * [Why this project?](#why-this-project)
   * [License](#license)

# Build & run

**We're working to enable building the plugin separately from Wireshark. In the meantime, you will need to clone the Wireshark repo.**

1. Go to the [Wireshark repo](https://github.com/wireshark/wireshark) and clone it.
2. Set up your build environment. The steps vary depending on your OS.
  * For Windows, follow the [instructions here](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup.html).
  * For Unix and macOS systems, most tools are already installed, but you need to ensure you have `cmake` and `ninja`. On macOS, you can run `brew install cmake ninja` if you use Homebrew.
3. Run a plain Wireshark build to ensure all is OK. In macOS, it looks like this:

```
$ cd ${WIRESHARK_SRC}
$ # check out the latest 3.2 tag (could be higher)
$ git checkout wireshark-3.2.1
$ mkdir ../wireshark-ninja
$ cd ../wireshark-ninja
$ cmake -G Ninja ../wireshark
$ ninja
```

4. Clone this repo onto a separate directory.
5. Symlink the root of this repo under `${WIRESHARK_SRC}/plugins/epan/ethereum`, i.e. `ln -s ${THIS_REPO} ${WIRESHARK_SRC}/plugins/epan/ethereum`.
6. Modify the `${WIRESHARK_SRC}/CMakeLists.txt` file to add the `plugins/epan/ethereum` directory under the `PLUGIN_SRC_DIRS` variable, i.e.:
```
  ...
	set(PLUGIN_SRC_DIRS
		plugins/epan/ethercat
		plugins/epan/ethereum
		plugins/epan/gryphon
    ...
```
7. Delete all contents under `wireshark-ninja`, and run the full Wireshark build again repeating step 3.
8. If all went well, you should be able to run the resulting Wireshark executable inside the `wireshark-ninja/run` directory.
9. Happy dissecting!

# Team

Ordered alphabetically by surname.

* Raúl Kripalani (ConsenSys/Protocol Labs) -- project lead
* Guilherme Salgado (Py-EVM)
* Zhenyang Shi (University of Queensland)
* Scott Whittington (University of Queensland)

# Why this project?

In the Protocol Engineering Groups and Systems team (PegaSys) at ConsenSys, we specialise in the low-level, deep aspects of the Ethereum technology. Some of the challenges we tackle are: scalability, secrecy, modularity, finality, permissioning, etc.

To perform our job we need tooling to x-ray into different parts of the system. One of those parts is the networking layer. No central authority exists in public chain Ethereum, hence all communication is peer-to-peer (P2P), which gives rise to both RPC-style and gossip-like communication patterns we need full insight of during development, research and testing.

[devp2p](https://github.com/ethereum/devp2p) is the name of the networking subsystem of Ethereum, along with its collection of core protocols on top of which subprotocols like ETH, Whisper, Swarm, Light Ethereum, etc. are layered.

[Wireshark](https://www.wireshark.org/) is a popular tool for network packet analysis. Users can initiate network dumps and navigate through a wealth of packet data via its powerful GUI. The architecture of Wireshark is modular, and it revolves around the concept of _dissectors_: components capable of decoding a concrete protocol, which can be in use at any layer of the [OSI model](https://en.wikipedia.org/wiki/OSI_model).

Unfortunately no Wireshark dissectors exist yet for Ethereum devp2p protocols. This project changes that.

# About PegaSys

<a href="https://pegasys.tech/?utm_source=github&utm_medium=source&utm_campaign=ethereum-dissectors" rel="nofollow"><img src="https://github.com/ConsenSys/devp2p-dissectors/raw/web/assets/logo.png" alt="PegaSys logo" data-canonical-src="https://github.com/ConsenSys/devp2p-dissectors/raw/web/assets/logo.png" width=450></a>

PegaSys’ mission is to build blockchain solutions ready for production in business environments. We are committed to open source, and are creating a framework for collaborative innovation for the public-chain community and leading enterprises.

Our team is composed of engineers leading in the areas of big data processing, applied cryptography, open source computing, cloud services, and blockchain development.

[Learn more about PegaSys.](https://pegasys.tech/?utm_source=github&utm_medium=source&utm_campaign=ethereum-dissectors)

# License

This project is licensed under GPLv2.
