#!/usr/bin/env python

import subprocess
import json
import unittest


class EthereumDiscoveryTesting(unittest.TestCase):

    def setUp(self):
        output = subprocess.check_output(["../../wireshark-ninja/run/tshark", "-r", "./test.pcapng", "-T", "json"])
        self.pcap_output = json.loads(output)

    def test_ping(self):
        ping_cnt = 0

        for frame in self.pcap_output:
                
            try:
                temp = (frame["_source"]["layers"]["ethereum.disc"])
            except:
                continue
            if (temp["ethereum.disc.packet"] == "PING"):
                ping_cnt += 1
                try:
                    temp["ethereum.disc.packet_tree"]["ethereum.disc.packet.ping.recipient.udp_port"]
                    temp["ethereum.disc.packet_tree"]["ethereum.disc.packet.ping.sender.udp_port"]
                    temp["ethereum.disc.packet_tree"]["ethereum.disc.packet.ping.expiration"]
                    temp["ethereum.disc.packet_tree"]["ethereum.disc.packet.ping.version"]
                    temp["ethereum.disc.packet_type"]
                    temp["ethereum.disc.signature"]
                    temp["ethereum.disc.hash"]
                except:
                    self.fail()
        self.assertEqual(ping_cnt, 967)

    def test_pong(self):
        Pong = 0
        for i in self.js:
            try:
                temp = (i["_source"]["layers"]["ethereum.disc"])
            except:
                continue
            if (temp["ethereum.disc.packet"] == "PONG"):
                Pong += 1
                try:
                    temp["ethereum.disc.packet_tree"]["ethereum.disc.packet.pong.recipient.udp_port"]
                    temp["ethereum.disc.packet_tree"]["ethereum.disc.packet.pong.expiration"]
                    temp["ethereum.disc.packet_tree"]["ethereum.disc.packet.pong.ping_hash"]
                    temp["ethereum.disc.packet_type"]
                    temp["ethereum.disc.signature"]
                    temp["ethereum.disc.hash"]
                except:
                    self.fail()
        self.assertEqual(Pong, 403)

    def test_findNode(self):
        findNode = 0
        for i in self.js:
            try:
                temp = (i["_source"]["layers"]["ethereum.disc"])
            except:
                continue
            if (temp["ethereum.disc.packet"] == "FIND_NODE"):
                findNode += 1
                try:
                    temp["ethereum.disc.packet_tree"]["ethereum.disc.packet.find_node.expiration"]
                    temp["ethereum.disc.packet_tree"]["ethereum.disc.packet.find_node.target"]
                    temp["ethereum.disc.packet_type"]
                    temp["ethereum.disc.signature"]
                    temp["ethereum.disc.hash"]
                except:
                    self.fail()
        self.assertEqual(findNode, 80)

    def test_nodes(self):
        nodes = 0
        for i in self.js:
            try:
                temp = (i["_source"]["layers"]["ethereum.disc"])
            except:
                continue
            if (temp["ethereum.disc.packet"] == "NODES"):
                nodes += 1
                try:
                    temp["ethereum.disc.packet_tree"]["ethereum.disc.packet.nodes.expiration"]
                    temp["ethereum.disc.packet_type"]
                    temp["ethereum.disc.signature"]
                    temp["ethereum.disc.hash"]
                except:
                    self.fail()
        self.assertEqual(nodes, 144)

    def test_error(self):
        error = 0
        for i in self.js:
            try:
                temp = (i["_source"]["layers"]["ethereum.disc"])
            except:
                continue
            if (temp["ethereum.disc.packet"] != "PING" and
                        temp["ethereum.disc.packet"] != "PONG" and
                        temp["ethereum.disc.packet"] != "FIND_NODE" and
                        temp["ethereum.disc.packet"] != "NODES"):
                error += 1
        self.assertEqual(error, 0)


unittest.main()
