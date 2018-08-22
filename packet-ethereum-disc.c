/* packet-ethereum-disc.c
 * Routines for Ethereum devp2p discovery dissection.
 * Copyright 2018, ConsenSys AG.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998, Gerald Combs.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "packet-ethereum.h"

#include <epan/proto_data.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>
#include <epan/conversation.h>
#include <epan/srt_table.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/to_str.h>

#define MIN_ETHDEVP2PDISCO_LEN 98
#define MAX_ETHDEVP2PDISCO_LEN 1280

#define ETHEREUM_DISC_HASH_LEN 32
#define ETHEREUM_DISC_SIGNATURE_LEN 65
#define ETHEREUM_DISC_PACKET_TYPE_IDX 97
#define ETHEREUM_DISC_PACKET_DATA_START 98
// ETHEREUM_DISC_SIGNATURE_LEN + 22 (len('temporary discovery v5'))
#define ETHEREUM_DISCV5_PACKET_TYPE_IDX 87
#define ETHEREUM_DISCV5_PACKET_DATA_START 88

// Subtrees.
static int proto_ethereum = -1;
static gint ett_ethereum_disc_toplevel = -1;
static gint ett_ethereum_disc_packetdata = -1;
static gint ett_ethereum_disc_nodes = -1;

static dissector_handle_t ethereum_disc_dtor_handle;

static nstime_t unset_time;

// Ethereum discovery protocol packet types.
typedef enum packet_type {
  UNKNOWN = 0x00,   // initialization value
  PING = 0x01,
  PONG = 0x02,
  FIND_NODE = 0x03,
  NODES = 0x04,
  FIND_NODEHASH = 0x05,
  TOPIC_REGISTER = 0x06,
  TOPIC_QUERY = 0x07,
  TOPIC_NODES = 0x08,
} packet_type_e;

// Value strings: packet type <=> string representation.
static const value_string packet_type_names[] = {
    {UNKNOWN, "(Unknown)"},
    {PING, "PING"},
    {PONG, "PONG"},
    {FIND_NODE, "FIND_NODE"},
    {NODES, "NODES"},
    {FIND_NODEHASH, "FIND_NODEHASH"},
    {TOPIC_REGISTER, "TOPIC_REGISTER"},
    {TOPIC_QUERY, "TOPIC_QUERY"},
    {TOPIC_NODES, "TOPIC_NODES"}
};

// Message header/packet fields.
static int hf_ethereum_disc_msg_hash = -1;
static int hf_ethereum_disc_msg_sig = -1;
static int hf_ethereum_disc_packet = -1;
static int hf_ethereum_disc_packet_type = -1;
static int hf_ethereum_disc_seq = -1;
static int hf_ethereum_disc_seqtype = -1;
static int hf_ethereum_disc_req_ref = -1;
static int hf_ethereum_disc_res_ref = -1;
static int hf_ethereum_disc_rt = -1;

// PING packet.
static int hf_ethereum_disc_ping_version = -1;
static int hf_ethereum_disc_ping_sender_ipv4 = -1;
static int hf_ethereum_disc_ping_sender_ipv6 = -1;
static int hf_ethereum_disc_ping_sender_udp_port = -1;
static int hf_ethereum_disc_ping_sender_tcp_port = -1;
static int hf_ethereum_disc_ping_recipient_ipv4 = -1;
static int hf_ethereum_disc_ping_recipient_ipv6 = -1;
static int hf_ethereum_disc_ping_recipient_udp_port = -1;
static int hf_ethereum_disc_ping_recipient_tcp_port = -1;
static int hf_ethereum_disc_ping_expiration = -1;
static int hf_ethereum_disc_ping_topics = -1;

// PONG packet.
static int hf_ethereum_disc_pong_recipient_ipv4 = -1;
static int hf_ethereum_disc_pong_recipient_ipv6 = -1;
static int hf_ethereum_disc_pong_recipient_udp_port = -1;
static int hf_ethereum_disc_pong_recipient_tcp_port = -1;
static int hf_ethereum_disc_pong_ping_hash = -1;
static int hf_ethereum_disc_pong_expiration = -1;

// FIND_NODE packet.
static int hf_ethereum_disc_findnode_target = -1;
static int hf_ethereum_disc_findnode_expiration = -1;

// NODES packet.
static int hf_ethereum_disc_nodes_node = -1;
static int hf_ethereum_disc_nodes_nodes_ipv4 = -1;
static int hf_ethereum_disc_nodes_nodes_ipv6 = -1;
static int hf_ethereum_disc_nodes_nodes_udp_port = -1;
static int hf_ethereum_disc_nodes_nodes_tcp_port = -1;
static int hf_ethereum_disc_nodes_nodes_id = -1;
static int hf_ethereum_disc_nodes_expiration = -1;
static int hf_ethereum_disc_nodes_length = -1;

// TOPIC_NODES packet.
static int hf_ethereum_disc_topic_nodes_echo = -1;

// TOPIC_QUERY packet.
static int hf_ethereum_disc_topic_query_topic = -1;
static int hf_ethereum_disc_topic_query_expiration = -1;

// For tap.
static int ethereum_tap = -1;

static const gchar *st_str_packets = "Total packets";
static const gchar *st_str_packet_types = "Packet types";
static const gchar *st_str_packet_nodecount = "# of nodes returned in NODES";

// Statistics nodes.
static int st_node_packets = -1;
static int st_node_packet_types = -1;
static int st_node_packet_nodes_count = -1;

// The statistics struct handled by the Ethereum discovery tap.
// Exportable as other dissectors can consume from our tap.
typedef struct _ethereum_disc_stat {
  gboolean is_request;
  gboolean has_request;
  packet_type_e packet_type;
  guint node_count;
  nstime_t rq_time;
} ethereum_disc_stat_t;

// The struct where we store state concerning a conversation between two parties.
typedef struct _ethereum_disc_conv {
  guint32 total_count;
  guint32 ping_count;
  guint32 pong_count;
  guint32 findnode_count;
  guint32 topicquery_count;
  guint32 nodes_count;
  guint32 last_ping_frame;
  nstime_t last_ping_time;
  guint32 last_findnode_frame;
  nstime_t last_findnode_time;
  guint32 last_topicquery_frame;
  nstime_t last_topicquery_time;
  wmem_map_t *corr;
} ethereum_disc_conv_t;

// Enhanced packet data, attached to the pinfo for rendering in header fields.
typedef struct _ethereum_disc_enhanced_data {
  guint32 seq;
  guint seqtype;
  nstime_t rt;
  nstime_t rq_time;
} ethereum_disc_enhanced_data_t;

// Represents a peer endpoint parsed from the discovery packets.
typedef struct _endpoint {
  guint32 ipv4_addr;
  ws_in6_addr *ipv6_addr;
  guint16 udp_port;
  guint16 tcp_port;
} ethereum_disc_endpoint_t;

// A function that handles a packet.
typedef int(packet_processor)(tvbuff_t *,
                              proto_tree *,
                              packet_info *,
                              rlp_element_t *,
                              ethereum_disc_stat_t *,
                              ethereum_disc_conv_t *,
                              ethereum_disc_enhanced_data_t *);

/**
 * Decodes an endpoint from the provided RLP elements and adds protocol tree items into the specified fields.
 *
 * Fields are specified in this order:
 *  - IPv4 address, mutually exclusive group A.
 *  - IPv6 address, mutually exclusive group A.
 *  - UDP port.
 *  - TCP port (optional).
 *
 * @param packet_data The buffer.
 * @param disc_packet The tree onto which to add the tree items.
 * @param rlp The RLP element pointing to the list representing the endpoint.
 * @param fields The fields onto which to output the parsed data.
 * @return An endpoint struct.
 */
static ethereum_disc_endpoint_t decode_endpoint(tvbuff_t *packet_data,
                                                proto_tree *disc_packet,
                                                rlp_element_t *rlp,
                                                const int *fields[4]) {
  ethereum_disc_endpoint_t ret = { .ipv4_addr = 0, .ipv6_addr = NULL, .tcp_port = 0, .udp_port = 0 };

  // IP addr.
  rlp_next(packet_data, rlp->data_offset, rlp);
  if (rlp->byte_length == 4) {
    ret.ipv4_addr = tvb_get_ipv4(packet_data, rlp->data_offset);
    proto_tree_add_ipv4(disc_packet, *fields[0], packet_data, rlp->data_offset, rlp->byte_length, ret.ipv4_addr);
  } else {
    ws_in6_addr *addr = (ws_in6_addr *) wmem_alloc0(wmem_packet_scope(), sizeof(ws_in6_addr));
    tvb_get_ipv6(packet_data, rlp->data_offset, addr);
    ret.ipv6_addr = addr;
    proto_tree_add_ipv6(disc_packet, *fields[1], packet_data, rlp->data_offset, rlp->byte_length, ret.ipv6_addr);
  }

  // UDP port.
  rlp_next(packet_data, rlp->next_offset, rlp);
  ret.udp_port = tvb_get_guint16(packet_data, rlp->data_offset, ENC_BIG_ENDIAN);
  proto_tree_add_item(disc_packet, *fields[2], packet_data,
                      rlp->data_offset, rlp->byte_length, ENC_BIG_ENDIAN);

  // TCP port.
  rlp_next(packet_data, rlp->next_offset, rlp);
  if (rlp->byte_length > 0) {
    ret.tcp_port = tvb_get_guint16(packet_data, rlp->data_offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(disc_packet, *fields[3], packet_data,
                        rlp->data_offset, rlp->byte_length, ENC_BIG_ENDIAN);
  }
  return ret;
}

/**
 * Processes a PING packet.
 *
 * @param packet_tvb The buffer representing only the packet payload (excluding the message wrapper).
 * @param packet_tree The protocol tree representing the packet.
 * @param pinfo Packet
 * @param rlp The RLP element pointing to the list representing the packet.
 * @param st A ready-to-use statistics struct to populate.
 * @param conv A ready-to-use conversation struct (retrieved or initialized).
 * @param efdata A ready-to-use enhanced frame data struct.
 * @return TRUE if processing was successful; FALSE otherwise.
 */
static int process_ping_msg(tvbuff_t *packet_tvb,
                            proto_tree *packet_tree,
                            packet_info *pinfo,
                            rlp_element_t *rlp,
                            ethereum_disc_stat_t *st,
                            ethereum_disc_conv_t *conv,
                            ethereum_disc_enhanced_data_t *efdata) {
  proto_tree *parent;
  proto_item *ti;
  static const int *sender_endpoint_fields[] = {
      &hf_ethereum_disc_ping_sender_ipv4,
      &hf_ethereum_disc_ping_sender_ipv6,
      &hf_ethereum_disc_ping_sender_udp_port,
      &hf_ethereum_disc_ping_sender_tcp_port
  };
  static const int *recipient_endpoint_fields[] = {
      &hf_ethereum_disc_ping_recipient_ipv4,
      &hf_ethereum_disc_ping_recipient_ipv6,
      &hf_ethereum_disc_ping_recipient_udp_port,
      &hf_ethereum_disc_ping_recipient_tcp_port
  };

  // Version.
  rlp_next(packet_tvb, rlp->data_offset, rlp);
  proto_tree_add_item(packet_tree, hf_ethereum_disc_ping_version, packet_tvb,
                      rlp->data_offset, rlp->byte_length, ENC_BIG_ENDIAN);

  // Sender endpoint.
  rlp_next(packet_tvb, rlp->next_offset, rlp);
  decode_endpoint(packet_tvb, packet_tree, rlp, sender_endpoint_fields);

  // Recipient endpoint.
  rlp_next(packet_tvb, rlp->next_offset, rlp);
  decode_endpoint(packet_tvb, packet_tree, rlp, recipient_endpoint_fields);

  // Expiration.
  rlp_next(packet_tvb, rlp->next_offset, rlp);
  proto_tree_add_item(packet_tree, hf_ethereum_disc_ping_expiration, packet_tvb,
                      rlp->data_offset, rlp->byte_length, ENC_TIME_SECS | ENC_BIG_ENDIAN);

  if (!PINFO_FD_VISITED(pinfo)) {
    efdata->seqtype = ++conv->ping_count;
    conv->last_ping_frame = pinfo->num;
    conv->last_ping_time = pinfo->abs_ts;
  }

  // Update conversation.
  parent = proto_tree_get_parent_tree(packet_tree);
  ti = proto_tree_add_uint(parent, hf_ethereum_disc_seqtype, packet_tvb, 0, 0, efdata->seqtype);
  PROTO_ITEM_SET_GENERATED(ti);

  // Link to PONG message.
  guint32 pongref = GPOINTER_TO_UINT(wmem_map_lookup(conv->corr, GUINT_TO_POINTER(pinfo->num)));
  if (pongref) {
    ti = proto_tree_add_uint(parent, hf_ethereum_disc_res_ref, packet_tvb, 0, 0, pongref);
    PROTO_ITEM_SET_GENERATED(ti);
  }

  st->is_request = TRUE;
  return TRUE;
}

/**
 * Processes a PONG packet.
 *
 * @param packet_tvb The buffer representing only the packet payload (excluding the message wrapper).
 * @param packet_tree The protocol tree representing the packet.
 * @param pinfo Packet
 * @param rlp The RLP element pointing to the list representing the packet.
 * @param st A ready-to-use statistics struct to populate.
 * @param conv A ready-to-use conversation struct (retrieved or initialized).
 * @param efdata A ready-to-use enhanced frame data struct.
 * @return TRUE if processing was successful; FALSE otherwise.
 */
static int process_pong_msg(tvbuff_t *packet_tvb,
                            proto_tree *packet_tree,
                            packet_info *pinfo _U_,
                            rlp_element_t *rlp,
                            ethereum_disc_stat_t *st _U_,
                            ethereum_disc_conv_t *conv,
                            ethereum_disc_enhanced_data_t *efdata) {
  proto_tree *parent;
  proto_item *ti;
  static const int *recipient_endpoint_fields[] = {
      &hf_ethereum_disc_pong_recipient_ipv4,
      &hf_ethereum_disc_pong_recipient_ipv6,
      &hf_ethereum_disc_pong_recipient_udp_port,
      &hf_ethereum_disc_pong_recipient_tcp_port
  };

  // Recipient endpoint.
  rlp_next(packet_tvb, rlp->data_offset, rlp);
  decode_endpoint(packet_tvb, packet_tree, rlp, recipient_endpoint_fields);

  // Ping hash.
  rlp_next(packet_tvb, rlp->next_offset, rlp);
  proto_tree_add_item(packet_tree, hf_ethereum_disc_pong_ping_hash, packet_tvb,
                      rlp->data_offset, rlp->byte_length, ENC_BIG_ENDIAN);

  // Expiration.
  rlp_next(packet_tvb, rlp->next_offset, rlp);
  // FIXME: Disabled for now as Expiration on v5 pong is broken: https://github.com/ethereum/go-ethereum/issues/17468
  // proto_tree_add_item(packet_tree, hf_ethereum_disc_pong_expiration, packet_tvb,
  //                     rlp->data_offset, rlp->byte_length, ENC_TIME_SECS | ENC_BIG_ENDIAN);

  if (!PINFO_FD_VISITED(pinfo)) {
    efdata->seqtype = ++conv->pong_count;
    wmem_map_insert(conv->corr, GUINT_TO_POINTER(conv->last_ping_frame), GUINT_TO_POINTER(pinfo->num));
    wmem_map_insert(conv->corr, GUINT_TO_POINTER(pinfo->num), GUINT_TO_POINTER(conv->last_ping_frame));
    nstime_delta(&efdata->rt, &pinfo->fd->abs_ts, &conv->last_ping_time);
    efdata->rq_time = conv->last_ping_time;
  }

  // Sequence number of the message type.
  parent = proto_tree_get_parent_tree(packet_tree);
  ti = proto_tree_add_uint(parent, hf_ethereum_disc_seqtype, packet_tvb, 0, 0, efdata->seqtype);
  PROTO_ITEM_SET_GENERATED(ti);

  // Link the PING request.
  guint32 pingref = GPOINTER_TO_UINT(wmem_map_lookup(conv->corr, GUINT_TO_POINTER(pinfo->num)));
  if (pingref) {
    ti = proto_tree_add_uint(parent, hf_ethereum_disc_req_ref, packet_tvb, 0, 0, pingref);
    PROTO_ITEM_SET_GENERATED(ti);
    st->has_request = TRUE;
  }

  // Response time.
  if (!nstime_is_unset(&efdata->rt)) {
    ti = proto_tree_add_time(parent, hf_ethereum_disc_rt, packet_tvb, 0, 0, &efdata->rt);
    PROTO_ITEM_SET_GENERATED(ti);
  }

  st->is_request = FALSE;
  st->rq_time = efdata->rq_time;
  return TRUE;
}

static int process_pong_v5_msg(tvbuff_t *packet_tvb,
                               proto_tree *packet_tree,
                               packet_info *pinfo _U_,
                               rlp_element_t *rlp,
                               ethereum_disc_stat_t *st _U_,
                               ethereum_disc_conv_t *conv,
                               ethereum_disc_enhanced_data_t *efdata) {
    process_pong_msg(packet_tvb, packet_tree, pinfo, rlp, st, conv, efdata);
    // TODO: process v5 fields (TopicHash, TicketSerial and WaitPeriods)
    return TRUE;
}

/**
 * Processes a FIND_NODE packet.
 *
 * @param packet_tvb The buffer representing only the packet payload (excluding the message wrapper).
 * @param packet_tree The protocol tree representing the packet.
 * @param pinfo Packet
 * @param rlp The RLP element pointing to the list representing the packet.
 * @param st A ready-to-use statistics struct to populate.
 * @param conv A ready-to-use conversation struct (retrieved or initialized).
 * @param efdata A ready-to-use enhanced frame data struct.
 * @return TRUE if processing was successful; FALSE otherwise.
 */
static int process_findnode_msg(tvbuff_t *packet_tvb,
                                proto_tree *packet_tree,
                                packet_info *pinfo _U_,
                                rlp_element_t *rlp, ethereum_disc_stat_t *st _U_,
                                ethereum_disc_conv_t *conv,
                                ethereum_disc_enhanced_data_t *efdata _U_) {
  proto_tree *parent;
  proto_item *ti;

  // Target.
  rlp_next(packet_tvb, rlp->data_offset, rlp);
  proto_tree_add_item(packet_tree, hf_ethereum_disc_findnode_target, packet_tvb,
                      rlp->data_offset, rlp->byte_length, ENC_BIG_ENDIAN);

  // Expiration.
  rlp_next(packet_tvb, rlp->next_offset, rlp);
  proto_tree_add_item(packet_tree, hf_ethereum_disc_findnode_expiration, packet_tvb,
                      rlp->data_offset, rlp->byte_length, ENC_TIME_SECS | ENC_BIG_ENDIAN);

  // Update conversation and enhanced frame data.
  if (!PINFO_FD_VISITED(pinfo)) {
    efdata->seqtype = ++conv->findnode_count;
    conv->last_findnode_frame = pinfo->num;
    conv->last_findnode_time = pinfo->abs_ts;
  }

  // Sequence number of the message type.
  parent = proto_tree_get_parent_tree(packet_tree);
  ti = proto_tree_add_uint(parent, hf_ethereum_disc_seqtype, packet_tvb, 0, 0, efdata->seqtype);
  PROTO_ITEM_SET_GENERATED(ti);

  // Link the NODES response.
  parent = proto_tree_get_parent_tree(packet_tree);
  guint32 nodesref = GPOINTER_TO_UINT(wmem_map_lookup(conv->corr, GUINT_TO_POINTER(pinfo->num)));
  if (nodesref) {
    ti = proto_tree_add_uint(parent, hf_ethereum_disc_res_ref, packet_tvb, 0, 0, nodesref);
    PROTO_ITEM_SET_GENERATED(ti);
  }

  st->is_request = TRUE;
  return TRUE;
}

static void process_nodes_list(tvbuff_t *packet_tvb,
                               proto_tree *packet_tree,
                               packet_info *pinfo,
                               rlp_element_t *rlp,
                               ethereum_disc_stat_t *st,
                               ethereum_disc_conv_t *conv _U_,
                               ethereum_disc_enhanced_data_t *efdata _U_) {
  proto_item *ti;

  static const int *recipient_endpoint_fields[] = {
      &hf_ethereum_disc_nodes_nodes_ipv4,
      &hf_ethereum_disc_nodes_nodes_ipv6,
      &hf_ethereum_disc_nodes_nodes_udp_port,
      &hf_ethereum_disc_nodes_nodes_tcp_port
  };

  guint i = 0;
  proto_tree *node_tree;
  if (rlp->byte_length > 0) {
    // List is not empty, move into the first element.
    rlp_next(packet_tvb, rlp->data_offset, rlp);
  }
  while (rlp->type == LIST && rlp->byte_length > 0) {
    i++;
    ethereum_disc_endpoint_t ep;

    ti = proto_tree_add_string(packet_tree, hf_ethereum_disc_nodes_node, packet_tvb,
                               rlp->data_offset, rlp->byte_length, "enode://");

    node_tree = proto_item_add_subtree(ti, ett_ethereum_disc_nodes);
    ep = decode_endpoint(packet_tvb, node_tree, rlp, recipient_endpoint_fields);

    // Node ID.
    rlp_next(packet_tvb, rlp->next_offset, rlp);
    proto_tree_add_item(node_tree, hf_ethereum_disc_nodes_nodes_id, packet_tvb,
                        rlp->data_offset, rlp->byte_length, ENC_BIG_ENDIAN);

    proto_item_append_text(ti, "%s", tvb_bytes_to_str(wmem_packet_scope(), packet_tvb, rlp->data_offset, rlp->byte_length));
    proto_item_append_text(ti, "@");

    if (ep.ipv6_addr) {
      address addr = ADDRESS_INIT(AT_IPv6, 16, &ep.ipv6_addr->bytes);
      proto_item_append_text(ti, "%s", address_to_str(wmem_packet_scope(), &addr));
    } else {
      address addr = ADDRESS_INIT(AT_IPv4, 4, &ep.ipv4_addr);
      proto_item_append_text(ti, "%s", address_to_str(wmem_packet_scope(), &addr));
    }

    proto_item_append_text(ti, ":");

    if (ep.tcp_port) {
      proto_item_append_text(ti, "%d", ep.tcp_port);
    }

    if (ep.tcp_port != ep.udp_port) {
      proto_item_append_text(ti, "?discport=%d", ep.udp_port);
    }

    if (rlp->next_offset == 0) {
      break;
    }
    // Onto the next element.
    rlp_next(packet_tvb, rlp->next_offset, rlp);
  }

  // Enhance packet info with # of nodes.
  char more_info[64];
  g_snprintf(more_info, sizeof(more_info), " (%d nodes)", i);
  col_append_str(pinfo->cinfo, COL_INFO, more_info);

  // Update stats with node count.
  st->node_count = i;
}


/**
 * Processes a NODES packet.
 *
 * @param packet_tvb The buffer representing only the packet payload (excluding the message wrapper).
 * @param packet_tree The protocol tree representing the packet.
 * @param pinfo Packet
 * @param rlp The RLP element pointing to the list representing the packet.
 * @param st A ready-to-use statistics struct to populate.
 * @param conv A ready-to-use conversation struct (retrieved or initialized).
 * @param efdata A ready-to-use enhanced frame data struct.
 * @return TRUE if processing was successful; FALSE otherwise.
 */
static int process_nodes_msg(tvbuff_t *packet_tvb,
                             proto_tree *packet_tree,
                             packet_info *pinfo,
                             rlp_element_t *rlp,
                             ethereum_disc_stat_t *st,
                             ethereum_disc_conv_t *conv,
                             ethereum_disc_enhanced_data_t *efdata) {
  proto_tree *parent;
  proto_item *ti;

  // Node list.
  rlp_next(packet_tvb, rlp->data_offset, rlp);
  process_nodes_list(packet_tvb, packet_tree, pinfo, rlp, st, conv, efdata);

  // Expiration
  proto_tree_add_item(packet_tree, hf_ethereum_disc_nodes_expiration, packet_tvb,
                      rlp->data_offset, rlp->byte_length, ENC_TIME_SECS | ENC_BIG_ENDIAN);

  if (!PINFO_FD_VISITED(pinfo)) {
    efdata->seqtype = ++conv->nodes_count;
    wmem_map_insert(conv->corr, GUINT_TO_POINTER(conv->last_findnode_frame), GUINT_TO_POINTER(pinfo->num));
    wmem_map_insert(conv->corr, GUINT_TO_POINTER(pinfo->num), GUINT_TO_POINTER(conv->last_findnode_frame));
    nstime_delta(&efdata->rt, &pinfo->fd->abs_ts, &conv->last_findnode_time);
    efdata->rq_time = conv->last_findnode_time;
  }

  // Sequence number of the message type.
  parent = proto_tree_get_parent_tree(packet_tree);
  ti = proto_tree_add_uint(parent, hf_ethereum_disc_seqtype, packet_tvb, 0, 0, efdata->seqtype);
  PROTO_ITEM_SET_GENERATED(ti);

  // TODO: In v5, this may also be in response to a FIND_NODEHASH msg, so must attempt to
  // link to one of those is no FIND_NODE link is found.
  // Link the FIND_NODE request.
  guint32 findnodesref = GPOINTER_TO_UINT(wmem_map_lookup(conv->corr, GUINT_TO_POINTER(pinfo->num)));
  if (findnodesref) {
    ti = proto_tree_add_uint(parent, hf_ethereum_disc_req_ref, packet_tvb, 0, 0, findnodesref);
    PROTO_ITEM_SET_GENERATED(ti);
    st->has_request = TRUE;
  }

  // Response time.
  if (!nstime_is_unset(&efdata->rt)) {
    ti = proto_tree_add_time(parent, hf_ethereum_disc_rt, packet_tvb, 0, 0, &efdata->rt);
    PROTO_ITEM_SET_GENERATED(ti);
  }

  st->is_request = FALSE;
  st->rq_time = efdata->rq_time;
  return TRUE;
}

static int process_ping_v5_msg(tvbuff_t *packet_tvb,
                               proto_tree *packet_tree,
                               packet_info *pinfo,
                               rlp_element_t *rlp,
                               ethereum_disc_stat_t *st,
                               ethereum_disc_conv_t *conv,
                               ethereum_disc_enhanced_data_t *efdata) {
  process_ping_msg(packet_tvb, packet_tree, pinfo, rlp, st, conv, efdata);
  // TODO: Read topic list
  return TRUE;
}

static int process_topic_query_msg(tvbuff_t *packet_tvb,
                                   proto_tree *packet_tree,
                                   packet_info *pinfo _U_,
                                   rlp_element_t *rlp,
                                   ethereum_disc_stat_t *st _U_,
                                   ethereum_disc_conv_t *conv _U_,
                                   ethereum_disc_enhanced_data_t *efdata _U_) {
  proto_tree *parent;
  proto_item *ti;

  rlp_next(packet_tvb, rlp->data_offset, rlp);
  proto_tree_add_item(packet_tree, hf_ethereum_disc_topic_query_topic, packet_tvb,
                      rlp->data_offset, rlp->byte_length, ENC_ASCII);

  // Expiration (optional)
  rlp_next(packet_tvb, rlp->next_offset, rlp);
  if (rlp->byte_length > 0) {
    proto_tree_add_item(packet_tree, hf_ethereum_disc_topic_query_expiration, packet_tvb,
                        rlp->data_offset, rlp->byte_length, ENC_TIME_SECS | ENC_BIG_ENDIAN);
  }

  // Update conversation and enhanced frame data.
  if (!PINFO_FD_VISITED(pinfo)) {
    efdata->seqtype = ++conv->topicquery_count;
    conv->last_topicquery_frame = pinfo->num;
    conv->last_topicquery_time = pinfo->abs_ts;
  }

  // Sequence number of the message type.
  parent = proto_tree_get_parent_tree(packet_tree);
  ti = proto_tree_add_uint(parent, hf_ethereum_disc_seqtype, packet_tvb, 0, 0, efdata->seqtype);
  PROTO_ITEM_SET_GENERATED(ti);

  // Link the TOPIC_QUERY response.
  parent = proto_tree_get_parent_tree(packet_tree);
  guint32 queryref = GPOINTER_TO_UINT(wmem_map_lookup(conv->corr, GUINT_TO_POINTER(pinfo->num)));
  if (queryref) {
    ti = proto_tree_add_uint(parent, hf_ethereum_disc_res_ref, packet_tvb, 0, 0, queryref);
    PROTO_ITEM_SET_GENERATED(ti);
  }

  st->is_request = TRUE;
  return TRUE;
}

static int process_topic_nodes_msg(tvbuff_t *packet_tvb,
                                   proto_tree *packet_tree,
                                   packet_info *pinfo,
                                   rlp_element_t *rlp,
                                   ethereum_disc_stat_t *st,
                                   ethereum_disc_conv_t *conv,
                                   ethereum_disc_enhanced_data_t *efdata _U_) {
  proto_tree *parent;
  proto_item *ti;

  rlp_next(packet_tvb, rlp->data_offset, rlp);
  proto_tree_add_item(packet_tree, hf_ethereum_disc_topic_nodes_echo, packet_tvb,
                      rlp->data_offset, rlp->byte_length, ENC_BIG_ENDIAN);

  rlp_next(packet_tvb, rlp->next_offset, rlp);
  process_nodes_list(packet_tvb, packet_tree, pinfo, rlp, st, conv, efdata);

  if (!PINFO_FD_VISITED(pinfo)) {
    efdata->seqtype = ++conv->nodes_count;
    wmem_map_insert(conv->corr, GUINT_TO_POINTER(conv->last_topicquery_frame), GUINT_TO_POINTER(pinfo->num));
    wmem_map_insert(conv->corr, GUINT_TO_POINTER(pinfo->num), GUINT_TO_POINTER(conv->last_topicquery_frame));
    nstime_delta(&efdata->rt, &pinfo->fd->abs_ts, &conv->last_topicquery_time);
    efdata->rq_time = conv->last_topicquery_time;
  }

  // Sequence number of the message type.
  parent = proto_tree_get_parent_tree(packet_tree);
  ti = proto_tree_add_uint(parent, hf_ethereum_disc_seqtype, packet_tvb, 0, 0, efdata->seqtype);
  PROTO_ITEM_SET_GENERATED(ti);

  // Link the TOPIC_QUERY request.
  guint32 topicqueryref = GPOINTER_TO_UINT(wmem_map_lookup(conv->corr, GUINT_TO_POINTER(pinfo->num)));
  if (topicqueryref) {
    ti = proto_tree_add_uint(parent, hf_ethereum_disc_req_ref, packet_tvb, 0, 0, topicqueryref);
    PROTO_ITEM_SET_GENERATED(ti);
    st->has_request = TRUE;
  }

  // Response time.
  if (!nstime_is_unset(&efdata->rt)) {
    ti = proto_tree_add_time(parent, hf_ethereum_disc_rt, packet_tvb, 0, 0, &efdata->rt);
    PROTO_ITEM_SET_GENERATED(ti);
  }

  st->is_request = FALSE;
  st->rq_time = efdata->rq_time;
  return TRUE;
}

/**
 * Retrieves an existing conversation for this packet, or initialises a new one (and saves it).
 *
 * @param pinfo The packet.
 * @return A ready-to-use conversation struct.
 */
static ethereum_disc_conv_t *get_conversation(packet_info *pinfo) {
  conversation_t *conversation;
  ethereum_disc_conv_t *ret;

  conversation = find_or_create_conversation(pinfo);
  ret = (ethereum_disc_conv_t *) conversation_get_proto_data(conversation, proto_ethereum);

  if (!ret) {
    ret = wmem_new(wmem_file_scope(), ethereum_disc_conv_t);
    ret->total_count = 0;
    ret->ping_count = 0;
    ret->pong_count = 0;
    ret->findnode_count = 0;
    ret->topicquery_count = 0;
    ret->nodes_count = 0;
    ret->last_ping_frame = 0;
    ret->last_ping_time = unset_time;
    ret->last_findnode_frame = 0;
    ret->last_findnode_time = unset_time;
    ret->last_topicquery_frame = 0;
    ret->last_topicquery_time = unset_time;
    ret->corr = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    conversation_add_proto_data(conversation, proto_ethereum, ret);
  }
  return ret;
}

/**
 * Performs the dissection of a discovery packet.
 *
 * @param tvb The buffer containing the UDP datagram.
 * @param pinfo The packet info.
 * @param tree The protocol tree to populate.
 * @param data Extra data.
 * @return TRUE if successful, FALSE otherwise.
 */
static int dissect_ethereum(tvbuff_t *tvb,
                            packet_info *pinfo,
                            proto_tree *tree,
                            void *data _U_) {
  proto_tree *ethereum_tree, *packet_tree;
  proto_item *ti;
  tvbuff_t *packet_tvb;
  ethereum_disc_stat_t *st;
  ethereum_disc_conv_t *conv;
  ethereum_disc_enhanced_data_t *efdata;
  const gchar *packet_type_desc;
  rlp_element_t rlp;

  static packet_processor *processors[] = {
      [PING] = &process_ping_msg,
      [PONG] = &process_pong_msg,
      [FIND_NODE] = &process_findnode_msg,
      [NODES] = &process_nodes_msg
  };

  st = wmem_new(wmem_packet_scope(), ethereum_disc_stat_t);
  st->has_request = FALSE;
  st->is_request = FALSE;
  st->packet_type = UNKNOWN;
  st->rq_time = unset_time;
  st->node_count = 0;

  conv = get_conversation(pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ethereum");
  col_clear(pinfo->cinfo, COL_INFO);

  // Build the protocol tree.
  tree = proto_tree_add_item(tree, proto_ethereum, tvb, 0, -1, ENC_NA);
  ethereum_tree = proto_item_add_subtree(tree, ett_ethereum_disc_toplevel);

  // Message hash and signature.
  proto_tree_add_item(ethereum_tree, hf_ethereum_disc_msg_hash, tvb, 0, ETHEREUM_DISC_HASH_LEN, ENC_BIG_ENDIAN);
  proto_tree_add_item(ethereum_tree, hf_ethereum_disc_msg_sig, tvb, ETHEREUM_DISC_HASH_LEN,
                      ETHEREUM_DISC_SIGNATURE_LEN, ENC_BIG_ENDIAN);

  // Packet type.
  guint packet_type = tvb_get_guint8(tvb, ETHEREUM_DISC_PACKET_TYPE_IDX);
  proto_tree_add_item(ethereum_tree, hf_ethereum_disc_packet_type, tvb,
                      ETHEREUM_DISC_PACKET_TYPE_IDX, 1, ENC_BIG_ENDIAN);
  st->packet_type = (packet_type_e) packet_type;

  // Packet subtree, until the end.
  packet_type_desc = val_to_str(packet_type, packet_type_names, "(Unknown packet ID: %d)");
  ti = proto_tree_add_string(ethereum_tree, hf_ethereum_disc_packet, tvb,
                             ETHEREUM_DISC_PACKET_DATA_START, -1, packet_type_desc);
  packet_tree = proto_item_add_subtree(ti, ett_ethereum_disc_packetdata);

  packet_tvb = tvb_new_subset_remaining(tvb, ETHEREUM_DISC_PACKET_DATA_START);

  rlp_next(packet_tvb, 0, &rlp);
  // Assert we have a top level RLP list.
  if (rlp.type != LIST) {
    return FALSE;
  }

  col_append_str(pinfo->cinfo, COL_INFO, "Discovery v4 message: ");
  col_append_str(pinfo->cinfo, COL_INFO, packet_type_desc);

  // Sanity check.
  if (packet_type >= G_N_ELEMENTS(processors) || processors[packet_type] == NULL) {
    return FALSE;
  }

  // Create a new enhanced frame if it doesn't exist.
  efdata = (ethereum_disc_enhanced_data_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ethereum, 0);
  if (!efdata) {
    efdata = wmem_new(wmem_file_scope(), ethereum_disc_enhanced_data_t);
    efdata->seq = ++conv->total_count;
    efdata->seqtype = 0;
    efdata->rt = unset_time;
    efdata->rq_time = unset_time;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_ethereum, 0, efdata);
  }

  ti = proto_tree_add_uint(proto_tree_get_parent_tree(packet_tree), hf_ethereum_disc_seq,
                           packet_tvb, 0, 0, efdata->seq);
  PROTO_ITEM_SET_GENERATED(ti);

  processors[packet_type](packet_tvb, packet_tree, pinfo, &rlp, st, conv, efdata);
  tap_queue_packet(ethereum_tap, pinfo, st);
  return TRUE;
}

static int dissect_ethereum_discv5(tvbuff_t *tvb,
                                   packet_info *pinfo,
                                   proto_tree *tree,
                                   void *data _U_) {
  proto_tree *ethereum_tree, *packet_tree;
  proto_item *ti;
  tvbuff_t *packet_tvb;
  ethereum_disc_stat_t *st;
  ethereum_disc_conv_t *conv;
  ethereum_disc_enhanced_data_t *efdata;
  const gchar *packet_type_desc;
  rlp_element_t rlp;

  static packet_processor *processors[] = {
      [PING] = &process_ping_v5_msg,
      [PONG] = &process_pong_v5_msg,
      [FIND_NODE] = &process_findnode_msg,
      [NODES] = &process_nodes_msg,
      // TODO
      // [FIND_NODEHASH] = &process_find_nodehash_msg,
      // [TOPIC_REGISTER] = &process_topic_register_msg,
      [TOPIC_QUERY] = &process_topic_query_msg,
      [TOPIC_NODES] = &process_topic_nodes_msg,
  };

  st = wmem_new(wmem_packet_scope(), ethereum_disc_stat_t);
  st->has_request = FALSE;
  st->is_request = FALSE;
  st->packet_type = UNKNOWN;
  st->rq_time = unset_time;
  st->node_count = 0;

  conv = get_conversation(pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ethereum");
  col_clear(pinfo->cinfo, COL_INFO);

  // Build the protocol tree.
  tree = proto_tree_add_item(tree, proto_ethereum, tvb, 0, -1, ENC_NA);
  ethereum_tree = proto_item_add_subtree(tree, ett_ethereum_disc_toplevel);

  // Message hash and signature.
  // proto_tree_add_item(ethereum_tree, hf_ethereum_disc_msg_hash, tvb, 0, ETHEREUM_DISC_HASH_LEN, ENC_BIG_ENDIAN);
  proto_tree_add_item(ethereum_tree, hf_ethereum_disc_msg_sig, tvb, 0,
                      ETHEREUM_DISC_SIGNATURE_LEN, ENC_BIG_ENDIAN);

  // Packet type.
  guint packet_type = tvb_get_guint8(tvb, ETHEREUM_DISCV5_PACKET_TYPE_IDX);
  proto_tree_add_item(ethereum_tree, hf_ethereum_disc_packet_type, tvb,
                      ETHEREUM_DISCV5_PACKET_TYPE_IDX, 1, ENC_BIG_ENDIAN);
  st->packet_type = (packet_type_e) packet_type;

  // Packet subtree, until the end.
  packet_type_desc = val_to_str(packet_type, packet_type_names, "(Unknown packet ID: %d)");
  ti = proto_tree_add_string(ethereum_tree, hf_ethereum_disc_packet, tvb,
                             ETHEREUM_DISCV5_PACKET_DATA_START, -1, packet_type_desc);
  packet_tree = proto_item_add_subtree(ti, ett_ethereum_disc_packetdata);

  packet_tvb = tvb_new_subset_remaining(tvb, ETHEREUM_DISCV5_PACKET_DATA_START);

  rlp_next(packet_tvb, 0, &rlp);
  // Assert we have a top level RLP list.
  if (rlp.type != LIST) {
    return FALSE;
  }

  col_append_str(pinfo->cinfo, COL_INFO, "Discovery v5 message: ");
  col_append_str(pinfo->cinfo, COL_INFO, packet_type_desc);

  // Sanity check.
  if (packet_type >= G_N_ELEMENTS(processors) || processors[packet_type] == NULL) {
    return FALSE;
  }

  // Create a new enhanced frame if it doesn't exist.
  efdata = (ethereum_disc_enhanced_data_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ethereum, 0);
  if (!efdata) {
    efdata = wmem_new(wmem_file_scope(), ethereum_disc_enhanced_data_t);
    efdata->seq = ++conv->total_count;
    efdata->seqtype = 0;
    efdata->rt = unset_time;
    efdata->rq_time = unset_time;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_ethereum, 0, efdata);
  }

  ti = proto_tree_add_uint(proto_tree_get_parent_tree(packet_tree), hf_ethereum_disc_seq,
                           packet_tvb, 0, 0, efdata->seq);
  PROTO_ITEM_SET_GENERATED(ti);

  processors[packet_type](packet_tvb, packet_tree, pinfo, &rlp, st, conv, efdata);
  tap_queue_packet(ethereum_tap, pinfo, st);
  return TRUE;
}

/**
 * Evaluates heuristics on a frame and performs the dissection only if there's a high probability
 * that this is an Ethereum discovery message.
 *
 * @param tvb The buffer containing the UDP datagram.
 * @param pinfo The packet info.
 * @param tree The protocol tree to populate.
 * @param data Extra data.
 * @return TRUE if successful, FALSE otherwise.
 */
static gboolean dissect_ethereum_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  // Check length.
  if (tvb_captured_length(tvb) < MIN_ETHDEVP2PDISCO_LEN || tvb_captured_length(tvb) > MAX_ETHDEVP2PDISCO_LEN) {
    return FALSE;
  }

  // https://github.com/ethereum/go-ethereum/blob/c4712bf96bc1bae4a5ad4600e9719e4a74bde7d5/p2p/discv5/udp.go#L149
  static const gchar *discv5_id = "temporary discovery v5";
  gboolean is_discv5 = FALSE;
  const gchar *version_prefix = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, strlen(discv5_id), ENC_ASCII);
  if (strcmp(version_prefix, discv5_id) == 0) {
      is_discv5 = TRUE;
  } else {
      guint packet_type = tvb_get_guint8(tvb, ETHEREUM_DISC_PACKET_TYPE_IDX);
      if (packet_type > NODES) {
        return FALSE;
      }

      rlp_element_t rlp;
      // Check if the packet contains a top-level RLP list that spans the entire packet.
      // Next offset should be zero, to mark the end of the packet.
      if (!rlp_next(tvb, ETHEREUM_DISC_PACKET_DATA_START, &rlp) || rlp.type != LIST || rlp.next_offset > 0) {
        return FALSE;
      };
  }

  TRY {
        if (is_discv5 == TRUE) {
          dissect_ethereum_discv5(tvb, pinfo, tree, data);
        } else {
          dissect_ethereum(tvb, pinfo, tree, data);
        }
      }
      CATCH_NONFATAL_ERRORS {
        show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
      }
  ENDTRY;
  return TRUE;
}

/**
 * Initializes the statistics trees.
 *
 * @param st Statistics tree.
 */
static void ethereum_discovery_stats_tree_init(stats_tree *st) {
  st_node_packets = stats_tree_create_node(st, st_str_packets, 0, TRUE);
  st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
  st_node_packet_nodes_count = stats_tree_create_range_node(st, st_str_packet_nodecount, 0,
                                                            "0-5", "6-10", "11-", NULL);
}

/**
 * Callback called by Wireshark whenever a stat is published on the tap.
 *
 * @param st The statistics tree.
 * @param pinfo The packet info.
 * @param edt Data about the dissection.
 * @param p A pointer to the statistics struct.
 * @return TRUE if successful; FALSE otherwise.
 */
static int ethereum_discovery_stats_tree_packet(stats_tree *st,
                                                packet_info *pinfo _U_,
                                                epan_dissect_t *edt _U_,
                                                const void *p) {
  ethereum_disc_stat_t *stat = (ethereum_disc_stat_t *) p;
  tick_stat_node(st, st_str_packets, 0, FALSE);
  stats_tree_tick_pivot(st, st_node_packet_types,
                        val_to_str(stat->packet_type, packet_type_names, "Unknown packet type (%d)"));
  if (stat->packet_type == NODES) {
    stats_tree_tick_range(st, st_str_packet_nodecount, 0, stat->node_count);
  }
  return TRUE;
}

/**
 * Registers the statitics trees for the Ethereum discovery protocol.
 */
static void register_ethereum_stat_trees(void) {
  stats_tree_register_plugin("ethereum", "ETH", "Ethereum/Discovery protocol stats", 0,
                             ethereum_discovery_stats_tree_packet, ethereum_discovery_stats_tree_init, NULL);
}

/**
 * Initializes the Service Response Times table for the Ethereum discovery protocol.
 *
 * @param srt Data about the registration.
 * @param srt_array The array of SRT tables.
 * @param gui_callback GUI callback.
 * @param gui_data GUI data.
 */
static void ethereum_srt_table_init(struct register_srt *srt _U_, GArray *srt_array,
                                    srt_gui_init_cb gui_callback, void *gui_data) {
  srt_stat_table *eth_srt_table;
  eth_srt_table = init_srt_table("Ethereum discovery packets", NULL, srt_array, 2,
                                 NULL, NULL, gui_callback, gui_data, NULL);
  init_srt_table_row(eth_srt_table, 0, "PING->PONG response time");
  init_srt_table_row(eth_srt_table, 1, "FIND_NODE->NODES response time");
}

/**
 * Callback called by Wireshark whenever a stat is published on the tap, giving us a chance to
 * populate the SRT tables.
 *
 * @param pss Pointer to the SRT context.
 * @param pinfo The packet info.
 * @param edt Dissection data.
 * @param prv A pointer to the statistics struct.
 * @return TRUE if successful; FALSE otherwise.
 */
static int ethereum_srt_table_packet(void *pss,
                                     packet_info *pinfo,
                                     epan_dissect_t *edt _U_,
                                     const void *prv) {
  srt_stat_table *eth_srt_table;
  srt_data_t *data = (srt_data_t *) pss;
  const ethereum_disc_stat_t *stat = (const ethereum_disc_stat_t *) prv;
  if (!stat || stat->is_request || !(stat->has_request)) {
    return FALSE;
  }
  eth_srt_table = g_array_index(data->srt_array, srt_stat_table*, 0);
  add_srt_table_data(eth_srt_table, (stat->packet_type - 1) / 2, &stat->rq_time, pinfo);
  return TRUE;
}

/**
 * Registers the Service Response Times table for the Ethereum discovery protocol.
 */
static void register_ethereum_srt_table(void) {
  register_srt_table(proto_ethereum, "ethereum", 1, ethereum_srt_table_packet, ethereum_srt_table_init, NULL);
}

/**
 * Registers the protocol with Wireshark.
 */
void proto_register_ethereum(void) {
  static hf_register_info hf[] = {

      {&hf_ethereum_disc_msg_hash,
       {"Message hash", "ethereum.disc.hash", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

      {&hf_ethereum_disc_msg_sig,
       {"Message signature", "ethereum.disc.signature", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

      {&hf_ethereum_disc_packet_type,
       {"Packet type", "ethereum.disc.packet_type", FT_UINT8, BASE_DEC,
        VALS(packet_type_names), 0x0, NULL, HFILL}},

      {&hf_ethereum_disc_packet,
       {"Packet payload", "ethereum.disc.packet", FT_STRING, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_seq,
       {"Global sequence number of this packet in this conversation", "ethereum.disc.packet.seq", FT_UINT32,
        BASE_DEC,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_seqtype,
       {"Sequence number of this packet type in this conversation", "ethereum.disc.packet.seqtype", FT_UINT32,
        BASE_DEC,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_req_ref,
       {"This packet is in response to", "ethereum.disc.packet.reqref", FT_FRAMENUM, BASE_NONE,
        FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0X0,
        "This packet is in response to the indicated frame", HFILL}},

      {&hf_ethereum_disc_res_ref,
       {"This packet was responded in", "ethereum.disc.packet.resref", FT_FRAMENUM, BASE_NONE,
        FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0X0,
        "This packet was responded in the indicated frame", HFILL}},

      {&hf_ethereum_disc_rt,
       {"Response time", "ethereum.disc.packet.rt", FT_RELATIVE_TIME, BASE_NONE,
        NULL, 0X0, "Response time", HFILL}},

      {&hf_ethereum_disc_ping_version,
       {"(PING) Protocol version", "ethereum.disc.packet.ping.version", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},

      {&hf_ethereum_disc_ping_sender_ipv4,
       {"(PING) Sender address (IPv4)", "ethereum.disc.packet.ping.sender.ipv4", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

      {&hf_ethereum_disc_ping_sender_ipv6,
       {"(PING) Sender address (IPv6)", "ethereum.disc.packet.ping.sender.ipv6", FT_IPv6, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

      {&hf_ethereum_disc_ping_sender_udp_port,
       {"(PING) Sender UDP port", "ethereum.disc.packet.ping.sender.udp_port", FT_UINT16, BASE_PT_UDP,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_ping_sender_tcp_port,
       {"(PING) Sender TCP port", "ethereum.disc.packet.ping.sender.tcp_port", FT_UINT16, BASE_PT_TCP,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_ping_recipient_ipv4,
       {"(PING) Recipient address (IPv4)", "ethereum.disc.packet.ping.recipient.ipv4", FT_IPv4, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_ping_recipient_ipv6,
       {"(PING) Recipient address (IPv6)", "ethereum.disc.packet.ping.recipient.ipv6", FT_IPv6, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_ping_recipient_udp_port,
       {"(PING) Recipient UDP port", "ethereum.disc.packet.ping.recipient.udp_port", FT_UINT16, BASE_PT_UDP,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_ping_recipient_tcp_port,
       {"(PING) Recipient TCP port", "ethereum.disc.packet.ping.recipient.tcp_port", FT_UINT16, BASE_PT_TCP,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_ping_expiration,
       {"(PING) Expiration", "ethereum.disc.packet.ping.expiration", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_ping_topics,
       {"(PING) Topics", "ethereum.disc.packet.ping.topics", FT_STRING, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_pong_recipient_ipv4,
       {"(PONG) Recipient address (IPv4)", "ethereum.disc.packet.pong.recipient.ipv4", FT_IPv4, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_pong_recipient_ipv6,
       {"(PONG) Recipient address (IPv6)", "ethereum.disc.packet.pong.recipient.ipv6", FT_IPv6, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_pong_recipient_udp_port,
       {"(PONG) Recipient UDP port", "ethereum.disc.packet.pong.recipient.udp_port", FT_UINT16, BASE_PT_UDP,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_pong_recipient_tcp_port,
       {"(PONG) Recipient TCP port", "ethereum.disc.packet.pong.recipient.tcp_port", FT_UINT16, BASE_PT_TCP,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_pong_ping_hash,
       {"(PONG) PING hash", "ethereum.disc.packet.pong.ping_hash", FT_BYTES, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_pong_expiration,
       {"(PONG) Expiration", "ethereum.disc.packet.pong.expiration", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_findnode_target,
       {"(FIND_NODE) Target", "ethereum.disc.packet.find_node.target", FT_BYTES, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_findnode_expiration,
       {"(FIND_NODE) Expiration", "ethereum.disc.packet.find_node.expiration", FT_ABSOLUTE_TIME,
        ABSOLUTE_TIME_LOCAL,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_nodes_node,
       {"(NODES) Node", "ethereum.disc.packet.nodes.node", FT_STRING, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_nodes_nodes_ipv4,
       {"(NODES) Node address (IPv4)", "ethereum.disc.packet.nodes.node.ipv4", FT_IPv4, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_nodes_nodes_ipv6,
       {"(NODES) Node address (IPv6)", "ethereum.disc.packet.nodes.node.ipv6", FT_IPv6, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_nodes_nodes_udp_port,
       {"(NODES) Node UDP port", "ethereum.disc.packet.nodes.node.udp_port", FT_UINT16, BASE_PT_UDP,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_nodes_nodes_tcp_port,
       {"(NODES) Node TCP port", "ethereum.disc.packet.nodes.node.tcp_port", FT_UINT16, BASE_PT_TCP,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_nodes_nodes_id,
       {"(NODES) Node ID", "ethereum.disc.packet.nodes.node.id", FT_BYTES, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_nodes_expiration,
       {"(NODES) Expiration", "ethereum.disc.packet.nodes.expiration", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_nodes_length,
       {"(NODES) # of nodes returned", "ethereum.disc.packet.nodes.length", FT_UINT32, BASE_DEC,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_topic_query_topic,
       {"Topic", "ethereum.disc.packet.topic_query.topic", FT_STRING, BASE_NONE,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_topic_query_expiration,
       {"Expiration", "ethereum.disc.packet.topic_query.expiration", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0X0, NULL, HFILL}},

      {&hf_ethereum_disc_topic_nodes_echo,
       {"Echo", "ethereum.disc.packet.topic_nodes.echo", FT_BYTES, BASE_NONE,
        NULL, 0X0, NULL, HFILL}}
  };

  nstime_set_unset(&unset_time);

  // Setup protocol subtree array.
  static gint *ett[] = {
      &ett_ethereum_disc_toplevel,
      &ett_ethereum_disc_packetdata,
      &ett_ethereum_disc_nodes
  };

  proto_ethereum = proto_register_protocol("Ethereum discovery protocol", "ETH discovery", "ethereum.disc");

  // Register dissector.
  ethereum_disc_dtor_handle = create_dissector_handle(dissect_ethereum_heur, proto_ethereum);
  proto_register_field_array(proto_ethereum, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  // Register statistics-related features.
  ethereum_tap = register_tap("ethereum");
  register_ethereum_stat_trees();
  register_ethereum_srt_table();
}

/**
 * Registers the handoff to the Ethereum discovery protocol.
 */
void proto_reg_handoff_ethereum(void) {
  heur_dissector_add("udp", dissect_ethereum_heur, "Ethereum (devp2p) discovery", "ETH discovery",
                     proto_ethereum, HEURISTIC_ENABLE);
}
