#!/usr/bin/env python
# -*- coding: utf-8 -*-

import itertools
import json
import subprocess
import unittest

class EthereumDiscoveryDissectorTest(unittest.TestCase):

    def setUp(self):
        output = subprocess.check_output(["../wireshark-ninja/run/tshark", "-r", "./test/test.pcapng", "-T", "json"])
        self.pcap_output = json.loads(output)

    def filter_by_type(self, packet_type):
        predicate = lambda frame: frame.get("_source", {}).get("layers", {}).get("ethereum.disc", {}).get("ethereum.disc.packet", "") == packet_type;
        extractor = lambda frame: frame["_source"]["layers"]["ethereum.disc"]
        return itertools.imap(extractor, itertools.ifilter(predicate, self.pcap_output))

    def test_ping(self):
        ping_cnt = 0
        for frame in self.filter_by_type("PING"):
            ping_cnt += 1
            try:
                frame["ethereum.disc.packet_tree"]["ethereum.disc.packet.ping.recipient.udp_port"]
                frame["ethereum.disc.packet_tree"]["ethereum.disc.packet.ping.sender.udp_port"]
                frame["ethereum.disc.packet_tree"]["ethereum.disc.packet.ping.expiration"]
                frame["ethereum.disc.packet_tree"]["ethereum.disc.packet.ping.version"]
                frame["ethereum.disc.packet_type"]
                frame["ethereum.disc.hash"]
            except:
                self.fail()
        self.assertEqual(ping_cnt, 967)

    def test_pong(self):
        pong_cnt = 0
        for frame in self.filter_by_type("PONG"):
            pong_cnt += 1
            try:
                frame["ethereum.disc.packet_tree"]["ethereum.disc.packet.pong.recipient.udp_port"]
                frame["ethereum.disc.packet_tree"]["ethereum.disc.packet.pong.expiration"]
                frame["ethereum.disc.packet_tree"]["ethereum.disc.packet.pong.ping_hash"]
                frame["ethereum.disc.packet_type"]
                frame["ethereum.disc.signature"]
                frame["ethereum.disc.hash"]
            except:
                self.fail()
        self.assertEqual(pong_cnt, 403)

    def test_find_node(self):
        find_node_cnt = 0
        for frame in self.filter_by_type("FIND_NODE"):
            find_node_cnt += 1
            try:
                frame["ethereum.disc.packet_tree"]["ethereum.disc.packet.find_node.expiration"]
                frame["ethereum.disc.packet_tree"]["ethereum.disc.packet.find_node.target"]
                frame["ethereum.disc.packet_type"]
                frame["ethereum.disc.signature"]
                frame["ethereum.disc.hash"]
            except:
                self.fail()
        self.assertEqual(find_node_cnt, 80)

    def test_nodes(self):
        nodes_cnt = 0
        for frame in self.filter_by_type("NODES"):
            nodes_cnt += 1
            try:
                frame["ethereum.disc.packet_tree"]["ethereum.disc.packet.nodes.expiration"]
                frame["ethereum.disc.packet_type"]
                frame["ethereum.disc.signature"]
                frame["ethereum.disc.hash"]
            except:
                self.fail()
        self.assertEqual(nodes_cnt, 144)

    def test_error(self):
        error = 0
        for i in self.pcap_output:
            try:
                frame = (i["_source"]["layers"]["ethereum.disc"])
            except:
                continue
            if (frame["ethereum.disc.packet"] != "PING" and
                        frame["ethereum.disc.packet"] != "PONG" and
                        frame["ethereum.disc.packet"] != "FIND_NODE" and
                        frame["ethereum.disc.packet"] != "NODES"):
                error += 1
        self.assertEqual(error, 0)

unittest.main()
