#include "config.h"

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>
#include <epan/conversation.h>

#define MIN_ETHDEVP2PDISCO_LEN 98
#define MAX_ETHDEVP2PDISCO_LEN 1280

static dissector_handle_t ethdevp2pdisco_handle;

/* Sub tree */
static int proto_ethdevp2p = -1;
static gint ett_ethdevp2p = -1;
static gint ett_ethdevp2p_packet = -1;
static gint ett_ethdevp2p_node = -1;

static const value_string packettypenames[] = {
    { 0x01, "Ping" },
    { 0x02, "Pong" },
    { 0x03, "FindNode" },
    { 0x04, "Neighbors" },
	{ 0x00, NULL }
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
static int hf_ethdevp2p_neighbors_nodes_number = -1;

//For RLP decoding
struct UnitData {
	gint offset;
	gint length;
};

struct PacketContent {
	gint dataCount;
	struct UnitData *data_list;
};

//For Tap
static int ethdevp2p_tap = -1;

struct Ethdevp2pTap {
    gint packet_type;
};

//For conversation
struct Ethdevp2pConversation {
	gint packet_type;
};

static const guint8* st_str_packets = "Total Packets";
static const guint8* st_str_packet_types = "Ethdevp2p Packet Types";
static int st_node_packets = -1;
static int st_node_packet_types = -1;

static int rlp_decode(tvbuff_t *tvb, struct PacketContent *packet_content) {
	gint offset = 0;
	offset += 97;	//Skip Hash and Signature, checks packet data only
	gint length = tvb_captured_length(tvb);
	gint prefix;
	gint flag;	//Trigger to indicates if a new unit data is detected
	while (offset < length) {
		flag = 0;
		prefix = tvb_get_guint8(tvb, offset);
		if (prefix >= 0x00 && prefix <= 0x7f) {
			//data is prefix it self
			packet_content->data_list[packet_content->dataCount].offset = offset;
			packet_content->data_list[packet_content->dataCount].length = 1;
			offset += 1;	//Skip the packet
			flag = 1;
		}
		else if (prefix >= 0x80 && prefix <= 0xb7) {
			//A string less than 55 bytes long
			offset += 1;	//Skip the prefix
			packet_content->data_list[packet_content->dataCount].offset = offset;
			packet_content->data_list[packet_content->dataCount].length = prefix - 0x80;
			offset += prefix - 0x80;	//Skip the packet
			flag = 1;
		}
		else if (prefix >= 0xb8 && prefix <= 0xbf) {
			//A string more than 55 bytes long
			offset += 1;	//Skip the prefix
			switch (prefix - 0xb7) {
			case 1:
				packet_content->data_list[packet_content->dataCount].length = tvb_get_guint8(tvb, offset);
				offset += 1;
				break;
			case 2:
				packet_content->data_list[packet_content->dataCount].length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
				offset += 2;
				break;
			case 3:
				packet_content->data_list[packet_content->dataCount].length = tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN);
				offset += 3;
				break;
			case 4:
				packet_content->data_list[packet_content->dataCount].length = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
				offset += 4;
				break;
			case 5:
				packet_content->data_list[packet_content->dataCount].length = (guint32)tvb_get_guint40(tvb, offset, ENC_BIG_ENDIAN);
				offset += 5;
				break;
			case 6:
				packet_content->data_list[packet_content->dataCount].length = (guint32)tvb_get_guint48(tvb, offset, ENC_BIG_ENDIAN);
				offset += 6;
				break;
			case 7:
				packet_content->data_list[packet_content->dataCount].length = (guint32)tvb_get_guint56(tvb, offset, ENC_BIG_ENDIAN);
				offset += 7;
				break;
			case 8:
				packet_content->data_list[packet_content->dataCount].length = (guint32)tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
				offset += 8;
				break;
			}
			packet_content->data_list[packet_content->dataCount].offset = offset;
			offset += packet_content->data_list[packet_content->dataCount].length;	//Skip the packet
			flag = 1;
		}
		else if (prefix >= 0xc0 && prefix <= 0xf7) {
			//A list less than 55 bytes long
			offset += 1;	//Skip the prefix
		}
		else if (prefix >= 0xf8 && prefix <= 0xff) {
			//A list more than 55 bytes long
			offset += 1;	//Skip the prefix
			offset += prefix - 0xf7;	//Skip the length
		}
		else {
			//Not RLP encoded messsage
			return 1;
		}
		if (flag) {
			packet_content->dataCount++;
			packet_content->data_list = wmem_realloc(wmem_packet_scope(), packet_content->data_list,
				sizeof(struct UnitData) * (packet_content->dataCount + 1));
		}
	}
	return 0;
}

static int dissect_ethdevp2p(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_, struct PacketContent *packet_content) {
	//For conversation
	conversation_t *conversation;
	conversation = find_or_create_conversation(pinfo);
	struct Ethdevp2pConversation *ethdevp2pConversation;
	ethdevp2pConversation = wmem_alloc(wmem_packet_scope(), sizeof(struct Ethdevp2pConversation));
	conversation_set_dissector(conversation, ethdevp2pdisco_handle);
	conversation_add_proto_data(conversation, proto_ethdevp2p, ethdevp2pConversation);
	//For tap
	struct Ethdevp2pTap *ethdevp2pInfo;
	ethdevp2pInfo = wmem_alloc(wmem_packet_scope(), sizeof(struct Ethdevp2pTap));
	gint offset = 0;
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
	ethdevp2pInfo->packet_type = value;
	ethdevp2pConversation->packet_type = value;
	/* Add the Packet Type to the Sub Tree */
	proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_packet_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	gint currentData = 1;

	//This is a Ping message
	if (value == 0x01) {
		currentData = 1;
		//Get Ping version
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 1) {
				//It's Ping version
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_version, tvb,
					packet_content->data_list[currentData].offset, 1, ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		} 
		else {
			//Not valid packet
		}
		//Get sender IP address
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 4) {
				//It's IPv4
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_ipv4, tvb,
					packet_content->data_list[currentData].offset, 4, ENC_BIG_ENDIAN);
				currentData++;
			} 
			else if (packet_content->data_list[currentData].length == 16) {
				//It's IPv6
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_ipv6, tvb,
					packet_content->data_list[currentData].offset, 16, ENC_BIG_ENDIAN);
				currentData++;
			} 
			else {
				//Not valid packet
				return 1;
			}
		} 
		else {
			//Not valid packet
			return 1;
		}
		//Get sender UDP port
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 2) {
				//It's sender UDP port
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_udp_port, tvb,
					packet_content->data_list[currentData].offset, 2, ENC_BIG_ENDIAN);
				currentData++;
			} 
			else {
				//Not valid packet
				return 1;
			}
		} 
		else {
			//Not valid packet
			return 1;
		}
		//Get sender TCP port
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 0) {
				//Optional TCP port missed
				currentData++;
			} 
			else if (packet_content->data_list[currentData].length == 2) {
				//It's sender TCP port
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_sender_tcp_port, tvb,
					packet_content->data_list[currentData].offset, 2, ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		} 
		else {
			//Not valid packet
			return 1;
		}
		//Get recipient IP address
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 4) {
				//It's IPv4
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_recipient_ipv4, tvb,
					packet_content->data_list[currentData].offset, 4, ENC_BIG_ENDIAN);
				currentData++;
			}
			else if (packet_content->data_list[currentData].length == 16) {
				//It's IPv6
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_recipient_ipv6, tvb,
					packet_content->data_list[currentData].offset, 16, ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		} 
		else {
			//Not valid packet
			return 1;
		}
		//Get recipient UDP port
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 2) {
				//It's recipient UDP port
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_recipient_udp_port, tvb,
					packet_content->data_list[currentData].offset, 2, ENC_BIG_ENDIAN);
				currentData++;
			} 
			else {
				//Not valid packet
				return 1;
			}
		} 
		else {
			//Not valid packet
			return 1;
		}
		//Get recipient TCP port
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 0) {
				//Optional TCP port missed
				currentData++;
			} 
			else if (packet_content->data_list[currentData].length == 2) {
				//It's recipient TCP port
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_recipient_tcp_port, tvb,
					packet_content->data_list[currentData].offset, 2, ENC_BIG_ENDIAN);
				currentData++;
			} 
			else {
				//Not valid packet
				return 1;
			}
		} 
		else {
			//Not valid packet
			return 1;
		}
		//Get expiration
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 4) {
				//It's expiration
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_ping_expiration, tvb,
					packet_content->data_list[currentData].offset, 4, ENC_TIME_SECS | ENC_BIG_ENDIAN);
				currentData++;
			} 
			else {
				//Not valid packet
				return 1;
			}
		} 
		else {
			//Not valid packet
			return 1;
		}
	}
	//This is a Pong message	
	else if (value == 0x02) {
		//Get recipient IP address
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 4) {
				//It's IPv4
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_ipv4, tvb,
					packet_content->data_list[currentData].offset, 4, ENC_BIG_ENDIAN);
				currentData++;
			}
			else if (packet_content->data_list[currentData].length == 16) {
				//It's IPv6
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_ipv6, tvb,
					packet_content->data_list[currentData].offset, 16, ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		}
		else {
			//Not valid packet
			return 1;
		}
		//Get recipient UDP port
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 2) {
				//It's recipient UDP port
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_udp_port, tvb,
					packet_content->data_list[currentData].offset, 2, ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		}
		else {
			//Not valid packet
			return 1;
		}
		//Get recipient TCP port
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 0) {
				//Optional TCP port missed
				currentData++;
			}
			else if (packet_content->data_list[currentData].length == 2) {
				//It's recipient TCP port
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_recipient_tcp_port, tvb,
					packet_content->data_list[currentData].offset, 2, ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		}
		else {
			//Not valid packet
			return 1;
		}
		//Get hash
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 32) {
				//It's expiration
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_ping_hash, tvb,
					packet_content->data_list[currentData].offset, 32, ENC_TIME_SECS | ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		}
		else {
			//Not valid packet
			return 1;
		}
		//Get expiration
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 4) {
				//It's expiration
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_pong_expiration, tvb,
					packet_content->data_list[currentData].offset, 4, ENC_TIME_SECS | ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		}
		else {
			//Not valid packet
			return 1;
		}
	}
	//This is a FindNode message
	else if (value == 0x03) {
		//Get public key
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 64) {
				//It's Public key
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_findNode_target, tvb,
					packet_content->data_list[currentData].offset, 64, ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		}
		else {
			//Not valid packet
			return 1;
		}
		//Get expiration
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 4) {
				//It's expiration
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_findNode_expiration, tvb,
					packet_content->data_list[currentData].offset, 4, ENC_TIME_SECS | ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		}
		else {
			//Not valid packet
			return 1;
		}
	}
	//This is a Neighbour message
	else if (value == 0x04) {
		proto_item *tiNode;
		proto_tree *ethdevp2p_node;
		//Get a list of nodes
		//Variable to get node numbers
		gint nodeNumber = 0;
		for (currentData = 1; currentData < packet_content->dataCount - 1; currentData++) {
			//Add a Node Sub Tree
			//At least one node exists
			if (packet_content->dataCount > currentData + 4) {
				tiNode = proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_neighbors_node, tvb,
					packet_content->data_list[currentData].offset - 1,
					packet_content->data_list[currentData + 4].offset - packet_content->data_list[currentData].offset, ENC_NA);
				ethdevp2p_node = proto_item_add_subtree(tiNode, ett_ethdevp2p_packet);
				//Get neighbor node IP address
				if (packet_content->dataCount > currentData) {
					if (packet_content->data_list[currentData].length == 4) {
						//It's IPv4
						proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_ipv4, tvb,
							packet_content->data_list[currentData].offset, 4, ENC_BIG_ENDIAN);
						currentData++;
					}
					else if (packet_content->data_list[currentData].length == 16) {
						//It's IPv6
						proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_ipv6, tvb,
							packet_content->data_list[currentData].offset, 16, ENC_BIG_ENDIAN);
						currentData++;
					}
					else {
						//Not valid packet
						return 1;
					}
				}
				else {
					//Not valid packet
					return 1;
				}
				//Get neighbor node UDP port
				if (packet_content->dataCount > currentData) {
					if (packet_content->data_list[currentData].length == 2) {
						//It's node UDP port
						proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_udp_port, tvb,
							packet_content->data_list[currentData].offset, 2, ENC_BIG_ENDIAN);
						currentData++;
					}
					else {
						//Not valid packet
						return 1;
					}
				}
				else {
					//Not valid packet
					return 1;
				}
				//Get neighbor node TCP port
				if (packet_content->dataCount > currentData) {
					if (packet_content->data_list[currentData].length == 0) {
						//Optional TCP port missed
						currentData++;
					}
					else if (packet_content->data_list[currentData].length == 2) {
						//It's node TCP port
						proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_tcp_port, tvb,
							packet_content->data_list[currentData].offset, 2, ENC_BIG_ENDIAN);
						currentData++;
					}
					else {
						//Not valid packet
						return 1;
					}
				}
				else {
					//Not valid packet
					return 1;
				}
				//Get neighbor node Public key
				if (packet_content->dataCount > currentData) {
					if (packet_content->data_list[currentData].length == 64) {
						//It's public key
						proto_tree_add_item(ethdevp2p_node, hf_ethdevp2p_neighbors_nodes_id, tvb,
							packet_content->data_list[currentData].offset, 64, ENC_BIG_ENDIAN);
					}
					else {
						//Not valid packet
						return 1;
					}
				}
				else {
					//Not valid packet
					return 1;
				}
				nodeNumber++;
			}
			else {
				//Not valid packet
				return 1;
			}
		}
		//Add node number
		proto_tree_add_uint(ethdevp2p_packet, hf_ethdevp2p_neighbors_nodes_number, tvb,
			packet_content->data_list[0].offset + 1,
			packet_content->data_list[currentData].offset - packet_content->data_list[0].offset - 2,
			nodeNumber);
		//Get expiration
		if (packet_content->dataCount > currentData) {
			if (packet_content->data_list[currentData].length == 4) {
				//It's expiration
				proto_tree_add_item(ethdevp2p_packet, hf_ethdevp2p_neighbors_expiration, tvb,
					packet_content->data_list[currentData].offset, 4, ENC_TIME_SECS | ENC_BIG_ENDIAN);
				currentData++;
			}
			else {
				//Not valid packet
				return 1;
			}
		}
		else {
			//Not valid packet
			return 1;
		}
	}
	//This is not a valid message	
	else {
		//Not valid packet
		return 1;
	}
	tap_queue_packet(ethdevp2p_tap, pinfo, ethdevp2pInfo);
	wmem_free(wmem_packet_scope(), ethdevp2pInfo);
	wmem_free(wmem_packet_scope(), ethdevp2pConversation);
	return 0;
}

static gboolean dissect_ethdevp2p_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	// First, make sure we have enough data to do the check.
	if (tvb_captured_length(tvb) < MIN_ETHDEVP2PDISCO_LEN || tvb_captured_length(tvb) > MAX_ETHDEVP2PDISCO_LEN) {
		  return FALSE;
	}
	// Check if it is rlp encoded
	struct PacketContent *packet_content;
	packet_content = wmem_alloc(wmem_packet_scope(), sizeof(struct PacketContent));
	packet_content->dataCount = 0;
	packet_content->data_list = wmem_alloc(wmem_packet_scope(), sizeof(struct UnitData));
	if (rlp_decode(tvb, packet_content)) {
		wmem_free(wmem_packet_scope(), packet_content->data_list);
		wmem_free(wmem_packet_scope(), packet_content);
		return FALSE;
	}
	if (dissect_ethdevp2p(tvb, pinfo, tree, data _U_, packet_content) == 1) {
		//This is not a valid message
		wmem_free(wmem_packet_scope(), packet_content->data_list);
		wmem_free(wmem_packet_scope(), packet_content);
		return FALSE;
	}
	wmem_free(wmem_packet_scope(), packet_content->data_list);
	wmem_free(wmem_packet_scope(), packet_content);
	return TRUE;
}

// register all http trees

static void ethdevp2p_stats_tree_init(stats_tree *st) {
	st_node_packets = stats_tree_create_node(st, st_str_packets, 0, TRUE);
	st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
}

static int ethdevp2p_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt, const void* p) {
	struct Ethdevp2pTap *pi = (struct Ethdevp2pTap *)p;
	tick_stat_node(st, st_str_packets, 0, FALSE);
	stats_tree_tick_pivot(st, st_node_packet_types,
		val_to_str(pi->packet_type, packettypenames, "Unknown packet type (%d)"));
	return 1;
}

static void register_ethdevp2p_stat_trees(void) {
    stats_tree_register_plugin("ethdevp2p_tap", "ethdevp2pdisco", "Ethdevp2p/Packet Types", 0,
        ethdevp2p_stats_tree_packet, ethdevp2p_stats_tree_init, NULL);
}

void proto_register_ethdevp2p(void) {

    static hf_register_info hf[] = {
	{ &hf_ethdevp2p_hash,
	    {"Ethereum Devp2p Hash", "ethdevp2pdisco.hash",
	    FT_BYTES, BASE_NONE,
	    NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_signature,
	    {"Ethereum Devp2p Signature", "ethdevp2pdisco.signature",
	    FT_BYTES, BASE_NONE,
	    NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_packet,
		{ "Ethereum Devp2p Packet", "ethdevp2pdisco.packet",
		FT_NONE, BASE_NONE,
		NULL, 0X0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_packet_type,
	    {"Ethereum Devp2p Packet Type", "ethdevp2pdisco.packet_type",
	    FT_UINT8, BASE_DEC,
	    VALS(packettypenames), 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_version,
	    {"Ping Version", "ethdevp2pdisco.ping.version",
	    FT_UINT8, BASE_DEC,
	    NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_sender_ipv4,
	    {"Ping Sender IPv4", "ethdevp2pdisco.ping.sender_ipv4",
	    FT_IPv4, BASE_NONE,
	    NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_sender_ipv6,
		{ "Ping Sender IPv6", "ethdevp2pdisco.ping.sender_ipv6",
		FT_IPv6, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_sender_udp_port,
	    { "Ping Sender UDP Port", "ethdevp2pdisco.ping.sender_udp_port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_sender_tcp_port,
	    { "Ping Sender TCP Port", "ethdevp2pdisco.ping.sender_tcp_port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_recipient_ipv4,
	    { "Ping Recipient IPv4", "ethdevp2pdisco.ping.recipient_ipv4",
	    FT_IPv4, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_recipient_ipv6,
		{ "Ping Recipient IPv6", "ethdevp2pdisco.ping.recipient_ipv6",
		FT_IPv6, BASE_NONE,
		NULL, 0X0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_recipient_udp_port,
	    { "Ping Recipient UDP Port", "ethdevp2pdisco.ping.recipient_udp_port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_recipient_tcp_port,
		{ "Ping Recipient TCP Port", "ethdevp2pdisco.ping.recipient_tcp_port",
		FT_UINT32, BASE_DEC,
		NULL, 0X0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_ping_expiration,
	    { "Ping Expiration", "ethdevp2pdisco.ping.expiration",
	    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_recipient_ipv4,
	    { "Pong Recipient IPv4", "ethdevp2pdisco.pong.recipient_ipv4",
	    FT_IPv4, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_recipient_ipv6,
		{ "Pong Recipient IPv6", "ethdevp2pdisco.pong.recipient_ipv6",
		FT_IPv6, BASE_NONE,
		NULL, 0X0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_recipient_udp_port,
	    { "Pong Recipient UDP Port", "ethdevp2pdisco.pong.recipient_udp_port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_recipient_tcp_port,
	    { "Pong Recipient TCP Port", "ethdevp2pdisco.pong.recipient_tcp_port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_ping_hash,
	    { "Pong Ping Hash", "ethdevp2pdisco.pong.ping_hash",
	    FT_BYTES, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_pong_expiration,
	    { "Pong Expiration", "ethdevp2pdisco.pong.expiration",
	    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_findNode_target,
	    { "FindNode Target Public Key", "ethdevp2pdisco.findNode.target",
	    FT_BYTES, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_findNode_expiration,
	    { "FindNode Expiration", "ethdevp2pdisco.findNode.expiration",
	    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_node,
		{ "Neighbors Node", "ethdevp2pdisco.neighbors.node",
		FT_NONE, BASE_NONE,
		NULL, 0X0,
		NULL, HFILL }
	},
    
	{ &hf_ethdevp2p_neighbors_nodes_ipv4,
	    { "Neighbors Nodes IPv4", "ethdevp2pdisco.neighbors.node.ipv4",
	    FT_IPv4, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_nodes_ipv6,
		{ "Neighbors Nodes IPv6", "ethdevp2pdisco.neighbors.node.ipv6",
		FT_IPv6, BASE_NONE,
		NULL, 0X0,
		NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_nodes_udp_port,
	    { "Neighbors Nodes UDP Port", "ethdevp2pdisco.neighbors.node.udp_port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_nodes_tcp_port,
	    { "Neighbors Nodes TCP Port", "ethdevp2pdisco.neighbors.node.tcp_port",
	    FT_UINT32, BASE_DEC,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_nodes_id,
	    { "Neighbors Nodes ID", "ethdevp2pdisco.neighbors.node.id",
	    FT_BYTES, BASE_NONE,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_expiration,
	    { "Neighbors Expiration", "ethdevp2pdisco.neighbors.expiration",
	    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	    NULL, 0X0,
	    NULL, HFILL }
	},

	{ &hf_ethdevp2p_neighbors_nodes_number,
		{ "Neighbors Node number", "ethdevp2pdisco.neighbors.node_number",
		FT_UINT32, BASE_DEC,
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

	ethdevp2pdisco_handle = create_dissector_handle(dissect_ethdevp2p_heur, proto_ethdevp2p);
	proto_register_field_array(proto_ethdevp2p, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	ethdevp2p_tap = register_tap("ethdevp2p_tap");
	register_ethdevp2p_stat_trees();
}

void proto_reg_handoff_ethdevp2p(void) {
	heur_dissector_add("udp", dissect_ethdevp2p_heur, "Ethdevp2p disco Over Udp", "Ethdevp2p_udp", proto_ethdevp2p, HEURISTIC_ENABLE);
}