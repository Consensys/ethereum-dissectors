#include "config.h"

#include <epan/packet.h>

#define ETHEREUM_PORT 30303
#define MIN_ETHEREUM_LEN 98

/* Sub tree */
static int proto_ethdevp2p = -1;
static gint ett_ethdevp2p = -1;
static gint ett_ethdevp2p_packet = -1;
static gint ett_ethdevp2p_node = -1;

static const value_string packettypenames[] = {
    { 0x01, "Ping Packet" },
    { 0x02, "Pong Packet" },
    { 0x03, "FindNode Packet" },
    { 0x04, "Neighbors Packet" }
};

static int hf_ethdevp2p_hash = -1;
static int hf_ethdevp2p_signature = -1;
static int hf_ethdevp2p_packet = -1;
static int hf_ethdevp2p_packet_type = -1;
/* For Ping Message */
static int hf_ethdevp2p_ping_version = -1;
static int hf_ethdevp2p_ping_sender_ipv4 = -1;
static int hf_ethdevp2p_ping_sender_ipv6 = -1;
static int hf_ethdevp2p_ping_sender_udp_port = -1;
static int hf_ethdevp2p_ping_sender_tcp_port = -1;
static int hf_ethdevp2p_ping_recipient_ipv4 = -1;
static int hf_ethdevp2p_ping_recipient_ipv6 = -1;
static int hf_ethdevp2p_ping_recipient_udp_port = -1;
static int hf_ethdevp2p_ping_recipient_tcp_port = -1;
static int hf_ethdevp2p_ping_expiration = -1;
/* For Pong Message */
static int hf_ethdevp2p_pong_recipient_ipv4 = -1;
static int hf_ethdevp2p_pong_recipient_ipv6 = -1;
static int hf_ethdevp2p_pong_recipient_udp_port = -1;
static int hf_ethdevp2p_pong_recipient_tcp_port = -1;
static int hf_ethdevp2p_pong_ping_hash = -1;
static int hf_ethdevp2p_pong_expiration = -1;
/* For FindNode Message */
static int hf_ethdevp2p_findNode_target = -1;
static int hf_ethdevp2p_findNode_expiration = -1;
/* For Neighbors Message */
static int hf_ethdevp2p_neighbors_node = -1;
static int hf_ethdevp2p_neighbors_nodes_ipv4 = -1;
static int hf_ethdevp2p_neighbors_nodes_ipv6 = -1;
static int hf_ethdevp2p_neighbors_nodes_udp_port = -1;
static int hf_ethdevp2p_neighbors_nodes_tcp_port = -1;
static int hf_ethdevp2p_neighbors_nodes_id = -1;
static int hf_ethdevp2p_neighbors_expiration = -1;
/* Test only */
static int hf_ethdevp2p_data = -1;


static int ethereum_tap = -1;
struct EthereumTap {
    gint packet_type;
    gint priority;
};
static const guint8* st_str_packets = "Total Packets";
static const guint8* st_str_packet_types = "FOO Packet Types";
static int st_node_packets = -1;
static int st_node_packet_types = -1;


static int dissect_ethdevp2p(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
	gint offset = 0;
	guint test;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETHDEVP2PDISCO");
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, proto_ethdevp2p, tvb, 0, -1, ENC_NA);
	proto_tree *ethdevp2p_tree = proto_item_add_subtree(ti, ett_ethdevp2p);
	/* Add Header */
	proto_tree_add_item(ethdevp2p_tree, hf_ethdevp2p_hash, tvb, offset, 32, ENC_BIG_ENDIAN);
	offset += 32;
	proto_tree_add_item(ethdevp2p_tree, hf_ethdevp2p_signature, tvb, offset, 65, ENC_BIG_ENDIAN);
	offset += 65;

	/* Add Packet Sub Tree */
	proto_item *tiPacket = proto_tree_add_item(ethdevp2p_tree, hf_ethdevp2p_packet, tvb, offset, -1, ENC_NA);
	proto_tree *ethdevp2p_packet = proto_item_add_subtree(tiPacket, ett_ethdevp2p_packet);

	/* Packet Type */
	/* Get the Packet Type */
	guint value;
	value = tvb_get_guint8(tvb, offset);

	/* Add the Packet Type to the Sub Tree */
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_packet_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	if (value == 0x01) {
		/* This is a Ping Message */
		offset += 1;	//Skip Prefix
		//Getting Ping Version
		proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		offset += 1;	//Skip 0xcb
		test = tvb_get_guint8(tvb, offset); //Getting IP Prefix
		offset += 1;
		if (test == 0x84) {
			//It's IPv4
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		else if (test == 0x90) {
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_ipv6, tvb, offset, 16, ENC_BIG_ENDIAN);
			offset += 16;
		}
		test = tvb_get_guint8(tvb, offset); //Getting UDP Prefix
		offset += 1;
		if (test == 0x82) {
			//UDP exists
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		test = tvb_get_guint8(tvb, offset);	//Getting TCP Prefix
		offset += 1;
		if (test == 0x82) {
			//TCP exists
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		offset += 1;	//Skip 0xc9
		test = tvb_get_guint8(tvb, offset);	//Getting IP Prefix
		offset += 1;
		if (test == 0x84) {
			//It's IPv4
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_recipient_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		else if (test == 0x90) {
			//It's IPv6
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_recipient_ipv6, tvb, offset, 16, ENC_BIG_ENDIAN);
			offset += 16;
		}
		test = tvb_get_guint8(tvb, offset);	//Getting UDP Prefix
		offset += 1;
		if (test == 0x82) {
			//UDP exists
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_recipient_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		test = tvb_get_guint8(tvb, offset);	//Getting TCP Prefix
		offset += 1;
		if (test == 0x82) {
			//TCP exists
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_recipient_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		test = tvb_get_guint8(tvb, offset);	//Getting Expiration Prefix
		offset += 1;
		if (test == 0x84) {
			//Expiration exists
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_expiration, tvb, offset, 4, ENC_TIME_SECS | ENC_BIG_ENDIAN);
		}
	}
	else if (value == 0x02) {
		/* This is a Pong Message */
		offset += 2;	//Skip Prefix
		test = tvb_get_guint8(tvb, offset); //Getting the IP Prefix
		offset += 1;
		if (test == 0x84) {
			//It's IPv4
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		else if (test == 0x90) {
			//It's IPv6
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_ipv6, tvb, offset, 16, ENC_BIG_ENDIAN);
			offset += 16;
		}
		test = tvb_get_guint8(tvb, offset);	//Getting the UDP Prefix
		offset += 1;
		if (test == 0x82) {
			//UDP exists
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		test = tvb_get_guint8(tvb, offset);	//Getting the TCP Prefix
		offset += 1;
		if (test == 0x82) {
			//TCP exists
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		test = tvb_get_guint8(tvb, offset);	//Getting the Hash Prefix
		offset += 1;
		if (test == 0xa0) {
			//Hash exists
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_ping_hash, tvb, offset, 32, ENC_BIG_ENDIAN);
			offset += 32;
		}
		test = tvb_get_guint8(tvb, offset);	//Getting the Expiration Prefix
		offset += 1;
		if (test == 0x84) {
			//Expiration exists
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_expiration, tvb, offset, 4, ENC_TIME_SECS | ENC_BIG_ENDIAN);
		}
	}
	else if (value == 0x03) {
		offset += 3;	//Skip Prefix
		test = tvb_get_guint8(tvb, offset);	//Getting the Public key Prefix
		offset += 1;
		if (test == 0x40) {
			//Public key exists
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_findNode_target, tvb, offset, 64, ENC_BIG_ENDIAN);
			offset += 64;
		}
		test = tvb_get_guint8(tvb, offset);	//Getting the Expiration Prefix
		offset += 1;
		if (test == 0x84) {
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_findNode_expiration, tvb, offset, 4, ENC_TIME_SECS | ENC_BIG_ENDIAN);
		}
	}
	else if (value == 0x04) {
		//Skip Prefix
		test = tvb_get_guint8(tvb, offset);	//Get the length of the Overall List bytes length
		offset += 1;
		offset += (test - 0xf7);	//Skip the Overall List length byte(s)
		test = tvb_get_guint8(tvb, offset);	//Get the length of the Node List bytes length
		offset += 1;
		offset += (test - 0xf7);	//Skip the Node List length byte(s)
		proto_item *tiNode;
		proto_tree *ethdevp2p_node;
		// Loop continues if have 0xf8, which indicates a list
		while (tvb_get_guint8(tvb, offset) == 0xf8) {
			offset += 1;
			//This packet will not exceed 255 bytes
			test = tvb_get_guint8(tvb, offset);	//Get the packet length
			offset += 1;
			//Add a Node Sub Tree
			tiNode = proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_neighbors_node, tvb, offset, test, ENC_NA);
			ethdevp2p_node = proto_item_add_subtree(tiNode, ett_ethdevp2p_packet);

			test = tvb_get_guint8(tvb, offset);	//Get the IP Prefix
			offset += 1;
			if (test == 0x84) {
				//It's IPv4
				proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			else if (test == 0x90) {
				//It's IPv6
				proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_ipv6, tvb, offset, 16, ENC_BIG_ENDIAN);
				offset += 16;
			}
			test = tvb_get_guint8(tvb, offset);	//Get the UDP Prefix
			offset += 1;
			if (test == 0x82) {
				//UDP exists
				proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
			}
			test = tvb_get_guint8(tvb, offset);	//Get the TCP Prefix
			offset += 1;
			if (test == 0x82) {
				//TCP exists
				proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
			}
			offset += 1;	//Skip Prefix
			test = tvb_get_guint8(tvb, offset);	//Get the Public Key Prefix
			offset += 1;
			if (test == 0x40) {
				//Public key exists
				proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_id, tvb, offset, 64, ENC_BIG_ENDIAN);
				offset += 64;
			}
		}
		// Node List finished
		test = tvb_get_guint8(tvb, offset);	//Get Expiration Prefix
		offset += 1;
		if (test == 0x84) {
			proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_findNode_expiration, tvb, offset, 4, ENC_TIME_SECS | ENC_BIG_ENDIAN);
		}
	} 
	else {
		//Error occurs, it's not one of the basic 4 messages
		proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_data, tvb, offset, -1, ENC_BIG_ENDIAN);
	}
	return tvb_captured_length(tvb);
}

static gboolean dissect_ethdevp2p_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint type;
	// First, make sure we have enough data to do the check.
	if (tvb_captured_length(tvb) < MIN_ETHEREUM_LEN) {
		  return FALSE;
	}

	type = tvb_get_guint8(tvb, 97);
	
	if (type != 0x01 && type != 0x02 && type != 0x03 && type != 0x04) {
	  return FALSE;
	}
	
	dissect_ethdevp2p(tvb, pinfo, tree, data _U_);
	return TRUE;
}


// register all http trees
static void foo_stats_tree_init(stats_tree *st) {
	st_node_packets = stats_tree_create_node(st, st_str_packets, 0, TRUE);
	st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
}

static int foo_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt, const void* p) {
	struct FooTap *pi = (struct FooTap *)p;
	tick_stat_node(st, st_str_packets, 0, FALSE);
	stats_tree_tick_pivot(st, st_node_packet_types,
		val_to_str(pi->packet_type, msgtypevalues, "Unknown packet type (%d)"));
	return 1;
}

static void register_foo_stat_trees(void) {
    stats_tree_register_plugin("foo", "foo", "Foo/Packet Types", 0,
        foo_stats_tree_packet, foo_stats_tree_init, NULL);
}

WS_DLL_PUBLIC_DEF void plugin_register_tap_listener(void)
{
    register_foo_stat_trees();
}


void proto_register_ethdevp2p(void) {

    static hf_register_info hf[] = {
	{ &hf_ethdevp2p_hash,
	    {"Ethereum Devp2p Hash", "Ethdevp2p.hash",
	    FT_BYTES, BASE_NONE,
	    NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_signature,
	    {"Ethereum Devp2p Signature", "Ethdevp2p.signature",
	    FT_BYTES, BASE_NONE,
	    NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_packet,
		{ "Ethereum Devp2p Packet", "Ethdevp2p.packet",
		FT_NONE, BASE_NONE,
		NULL, 0X0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_packet_type,
	    {"Ethereum Devp2p Packet Type", "Ethdevp2p.packet-type",
	    FT_UINT8, BASE_DEC,
	    VALS(packettypenames), 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_version,
	    {"Ping Version", "Ping.version",
	    FT_UINT8, BASE_DEC,
	    NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_sender_ipv4,
	    {"Ping Sender IPv4", "Ping.sender-ipv4",
	    FT_IPv4, BASE_NONE,
	    NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_sender_ipv6,
		{ "Ping Sender IPv6", "Ping.sender-ipv6",
		FT_IPv6, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_sender_udp_port,
	    { "Ping Sender UDP Port", "Ping.sender-udp-port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_sender_tcp_port,
	    { "Ping Sender TCP Port", "Ping.sender-tcp-port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_recipient_ipv4,
	    { "Ping Recipient IPv4", "Ping.recipient-ipv4",
	    FT_IPv4, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_recipient_ipv6,
		{ "Ping Recipient IPv6", "Ping.recipient-ipv6",
		FT_IPv6, BASE_NONE,
		NULL, 0X0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_recipient_udp_port,
	    { "Ping Recipient UDP Port", "Ping.recipient-udp-port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_recipient_tcp_port,
		{ "Ping Recipient TCP Port", "Ping.recipient-tcp-port",
		FT_UINT32, BASE_DEC,
		NULL, 0X0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_expiration,
	    { "Ping Expiration", "Ping.expiration",
	    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_recipient_ipv4,
	    { "Pong Recipient IPv4", "Pong.recipient-ipv4",
	    FT_IPv4, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_recipient_ipv6,
		{ "Pong Recipient IPv6", "Pong.recipient-ipv6",
		FT_IPv6, BASE_NONE,
		NULL, 0X0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_recipient_udp_port,
	    { "Pong Recipient UDP Port", "Pong.recipient-udp-port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_recipient_tcp_port,
	    { "Pong Recipient TCP Port", "Pong.recipient-tcp-port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_ping_hash,
	    { "Pong Ping Hash", "Pong.ping-hash",
	    FT_BYTES, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_expiration,
	    { "Pong Expiration", "Pong.expiration",
	    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_findNode_target,
	    { "FindNode Target Public Key", "FindNode.target",
	    FT_BYTES, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_findNode_expiration,
	    { "FindNode Expiration", "FindNode.expiration",
	    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_data,
	    {"Ethereum Devp2p Data", "Ethdevp2p.data",
	    FT_BYTES, BASE_NONE,
	    NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_node,
		{ "Neighbors Node", "Neighbors.node",
		FT_NONE, BASE_NONE,
		NULL, 0X0,
		NULL, HFILL }
	},
    
	{ &hf_ethdevp2p_neighbors_nodes_ipv4,
	    { "Neighbors Nodes IPv4", "Neighbors.nodes-ipv4",
	    FT_IPv4, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_nodes_ipv6,
		{ "Neighbors Nodes IPv6", "Neighbors.nodes-ipv6",
		FT_IPv6, BASE_NONE,
		NULL, 0X0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_nodes_udp_port,
	    { "Neighbors Nodes UDP Port", "Neighbors.nodes-udp-port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_nodes_tcp_port,
	    { "Neighbors Nodes TCP Port", "Neighbors.nodes-tcp-port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_nodes_id,
	    { "Neighbors Nodes ID", "Neighbors.nodes-id",
	    FT_BYTES, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_expiration,
	    { "Neighbors Expiration", "Neighbors.expiration",
	    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	    NULL, 0X0,
	    NULL, HFILL }
	}
    };


    /* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_ethdevp2p,
	&ett_ethdevp2p_packet,
	&ett_ethdevp2p_node
    };

    proto_ethdevp2p = proto_register_protocol (
	    "Ethereum Devp2p Protocol",
	    "ETHDEVP2PDISCO",
	    "ethdevp2pdisco"
	);

	proto_register_field_array(proto_ethdevp2p, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	ethereum_tap = register_tap("ethdevp2p");    
}

void proto_reg_handoff_ethdevp2p(void) {
    static dissector_handle_t ethdevp2p_handle;
    ethdevp2p_handle = create_dissector_handle(dissect_ethdevp2p, proto_ethdevp2p);
	heur_dissector_add("udp", dissect_ethdevp2p_heur, "Ethdevp2p disco Over Udp", "Ethdevp2p_udp", proto_ethdevp2p, HEURISTIC_ENABLE);
    dissector_add_uint("udp.port", ETHEREUM_PORT, ethdevp2p_handle);
}