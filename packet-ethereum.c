#include "config.h"

#include <epan/packet.h>

#define ETHEREUM_PORT 30303
#define MIN_ETHEREUM_LEN 98

/* Sub tree */
static int proto_ethdevp2p = -1;
static gint ett_ethdevp2p = -1;
static int proto_ethdevp2p_packet = -1;
static gint ett_ethdevp2p_packet = -1;
static int proto_ethdevp2p_node = -1;
static gint ett_ethdevp2p_node = -1;

static const value_string packettypenames[] = {
    { 0x01, "Ping Packet" },
    { 0x02, "Pong Packet" },
    { 0x03, "FindNode Packet" },
    { 0x04, "Neighbors Packet" }
};

static int hf_ethdevp2p_hash = -1;
static int hf_ethdevp2p_signature = -1;
static int hf_ethdevp2p_packet_type = -1;
/* For Ping Message */
static int hf_ethdevp2p_ping_version = -1;
static int hf_ethdevp2p_ping_sender_ip = -1;
static int hf_ethdevp2p_ping_sender_udp_port = -1;
static int hf_ethdevp2p_ping_sender_tcp_port = -1;
static int hf_ethdevp2p_ping_recipient_ip = -1;
static int hf_ethdevp2p_ping_recipient_udp_port = -1;
static int hf_ethdevp2p_ping_expiration = -1;
/* For Pong Message */
static int hf_ethdevp2p_pong_recipient_ip = -1;
static int hf_ethdevp2p_pong_recipient_udp_port = -1;
static int hf_ethdevp2p_pong_recipient_tcp_port = -1;
static int hf_ethdevp2p_pong_ping_hash = -1;
static int hf_ethdevp2p_pong_expiration = -1;
/* For FindNode Message */
static int hf_ethdevp2p_findNode_target = -1;
static int hf_ethdevp2p_findNode_expiration = -1;
/* For Neighbors Message */
static int hf_ethdevp2p_neighbors_nodes_ip = -1;
static int hf_ethdevp2p_neighbors_nodes_udp_port = -1;
static int hf_ethdevp2p_neighbors_nodes_tcp_port = -1;
static int hf_ethdevp2p_neighbors_nodes_id = -1;
static int hf_ethdevp2p_neighbors_expiration = -1;
/* Test only */
static int hf_ethdevp2p_data = -1;

static heur_dissector_list_t heur_subdissector_list;

static int dissect_ethdevp2p(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    gint offset = 0;
    //gint nodeNumber = 0;
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
    proto_item *tiPacket = proto_tree_add_item(ethdevp2p_tree, proto_ethdevp2p_packet, tvb, offset, -1, ENC_NA);
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
	offset += 1;	//Skip 0xdc
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	offset += 2;	//Skip 0xcb84
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	offset += 1;	//Skip 0x82
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	offset += 1;	//Skip 0x82
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	offset += 2;	//Skip 0xc984
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_recipient_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	offset += 1;	//Skip 0x82
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_recipient_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	offset += 2;	//Skip 0x8084
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_expiration, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
    } else if (value == 0x02) {
	/* This is a Pong Message */
	offset += 3;	//Skip 0xf2cb84
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	offset += 1;	//Skip 0x82
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	offset += 1;	//Skip 0x82
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	offset += 1;	//Skip 0xa0
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_ping_hash, tvb, offset, 32, ENC_BIG_ENDIAN);
	offset += 32;
	offset += 1;	//Skip 0x84
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_expiration, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
    } else if (value == 0x03) {
	offset += 3;	//Skip 0xf847b8
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_findNode_target, tvb, offset, 65, ENC_BIG_ENDIAN);
	offset += 65;
	offset += 1;	//Skip 0x84
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_findNode_expiration, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
    } else if (value == 0x04) {
	offset += 6;	//Skip Header packets, NEED FURTHER INVESTIGATION
	// Note: 0xf84d 0x4d == 77, 0x4b == 75, the length of the node
	/* Add Node Sub Tree */
	proto_item *tiNode;
	proto_tree *ethdevp2p_node;
	guint location = offset;
	guint search;
	guint test;
	guint len = tvb_captured_length(tvb);
	location += 2;	//Skip the first 0xf84d
	while (location < len - 5) {
	    search = tvb_get_guint16(tvb, location, ENC_BIG_ENDIAN);
	    if (search == 0xf84d || search == 0xf84b) {
		tiNode = proto_tree_add_item(ethdevp2p_packet, proto_ethdevp2p_node, tvb, offset, location - offset, ENC_NA);
		ethdevp2p_node = proto_item_add_subtree(tiNode, ett_ethdevp2p_packet);
		// Add a Node Member
		offset += 2;	//Skip 0xf84d or 0xf84b
		offset += 1;	//Skip 0x84
		proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		test = tvb_get_guint8(tvb, offset);
		offset += 1;	//Skip 0x82 or 0x80
		if (test == 0x82) {
		    proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
		    offset += 2;
		}
		test = tvb_get_guint8(tvb, offset);
		offset += 1;	//Skip 0x82 or 0x80
		if (test == 0x82) {
		    proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
		    offset += 2;
		}
		offset += 1;	//Skip 0xb8
		proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_id, tvb, offset, location - offset, ENC_BIG_ENDIAN);
		offset = location;
		location += 2;
	    } else {
		location += 1;
	    }
	}
	tiNode = proto_tree_add_item(ethdevp2p_packet, proto_ethdevp2p_node, tvb, offset, location - offset, ENC_NA);
	ethdevp2p_node = proto_item_add_subtree(tiNode, ett_ethdevp2p_packet);// Add a Node Member
	offset += 2;	//Skip 0xf84d or 0xf84b
	offset += 1;	//Skip 0x84
	proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	test = tvb_get_guint8(tvb, offset);
	offset += 1;	//Skip 0x82 or 0x80
	if (test == 0x82) {
	    proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	    offset += 2;
	}
	test = tvb_get_guint8(tvb, offset);
	offset += 1;	//Skip 0x82 or 0x80
	if (test == 0x82) {
	    proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	    offset += 2;
	}
	offset += 1;	//Skip 0xb8
	proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_id, tvb, offset, location - offset, ENC_BIG_ENDIAN);
	offset = location;
	// Node List finished
	offset += 1;	//Skip 0x84
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_findNode_expiration, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
    } else {
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_data, tvb, offset, -1, ENC_BIG_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

static gboolean dissect_ethdevp2p_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint   len;
	guint	msn;
	len = tvb_captured_length(tvb);
	/* First, make sure we have enough data to do the check. */
	if (len < MIN_ETHEREUM_LEN) {
		  return FALSE;
	}

	msn = tvb_get_ntohs(tvb, 97);

	if (msn != 0x01 && msn != 0x02 && msn != 0x03 && msn != 0x04) {
	  return FALSE;
	}
	guint    offset = MIN_ETHEREUM_LEN;
	switch(msn){
		case 0x01:
		    offset += 25;
			if(len != offset) {
		        return FALSE;
			}
			break;
		case 0x02:
		    offset += 47;
			if(len != offset) {
		        return FALSE;
			}
			break;
		case 0x03:
		    offset += 69;
			if(len != offset) {
		        return FALSE;
			}
			break;
		case 0x04:
		    guint    nodeNumber = (tvb_captured_length(tvb) - 151) / 79;
			offset += 6;
			guint    len_per_node = 79;
			if(len != (nodeNumber * len_per_node + offset)) {
		        return FALSE;
			}
			break;
		default:
		    return FALSE;
	}
	dissect_ethdevp2p(tvb, pinfo, tree, data _U_);
	return TRUE;
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
	}
    };

    static hf_register_info packet[] = {
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

	{ &hf_ethdevp2p_ping_sender_ip,
	    {"Ping Sender IP", "Ping.sender-ip",
	    FT_IPv4, BASE_NONE,
	    NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_sender_udp_port,
	    { "ping Sender UDP Port", "Ping.sender-udp-port",
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

	{ &hf_ethdevp2p_ping_recipient_ip,
	    { "Ping Recipient IP", "Ping.recipient-ip",
	    FT_IPv4, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_recipient_udp_port,
	    { "Ping Recipient UDP Port", "Ping.recipient-udp-port",
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

	{ &hf_ethdevp2p_pong_recipient_ip,
	    { "Pong Recipient IP", "Pong.recipient-ip",
	    FT_IPv4, BASE_NONE,
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
	}
    };

    static hf_register_info node[] = {
	{ &hf_ethdevp2p_neighbors_nodes_ip,
	    { "Neighbors Nodes IP", "Neighbors.nodes-ip",
	    FT_IPv4, BASE_NONE,
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

    proto_ethdevp2p_packet = proto_register_protocol (
		    "Ethereum Devp2p Packet",
		    "ETHDEVP2PPACKET",
		    "ethdevp2ppacket"
		    );

    proto_ethdevp2p_node = proto_register_protocol (
		    "Neighbor Node",
		    "ETHDEVP2PPNODE",
		    "ethdevp2pnode"
		    );
    heur_subdissector_list = register_heur_dissector_list("ethereum", proto_ethdevp2p);
    proto_register_field_array(proto_ethdevp2p, hf, array_length(hf));
    proto_register_field_array(proto_ethdevp2p_packet, packet, array_length(packet));
    proto_register_field_array(proto_ethdevp2p_node, node, array_length(node));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_ethdevp2p(void) {
    static dissector_handle_t ethdevp2p_handle;
    ethdevp2p_handle = create_dissector_handle(dissect_ethdevp2p, proto_ethdevp2p);
    dissector_add_uint("udp.port", ETHEREUM_PORT, ethdevp2p_handle);
}
