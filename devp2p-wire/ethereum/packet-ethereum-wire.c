/* packet-ethereum-wire.c
* Routines for Ethereum devp2p wire dissection.
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

#include "config.h"
#include "aes256.h"

#include <epan/dissectors/packet-tcp.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>

#define	HEADER_LENGTH		32
#define MAC_LENGTH			16

#define HANDSHAKE			0x01
#define RLPX_PACKET			0x02

/* Subtrees. */
static int proto_devp2p_wire = -1;
static gint ett_devp2p_wire = -1;

/* For displaying secret comes out from ==patched== geth client. */
static int hf_devp2p_wire_secret_ip;
static int hf_devp2p_wire_secret_key;
static int hf_devp2p_wire_raw_message;

/* Information holds for each wire conversation. */
typedef struct _devp2p_conv_t {
	guint8 aes_key[32];			/* To hold the AES symmetric keys for this wire conversation. */
	guint current_offset;		/* To give each frame an initial AES counter value. */
	gboolean start;				/* To skip the encrypted handshake. */
} devp2p_conv_t;

/* Information holds for each frame in a wire conversation. */
typedef struct _devp2p_packet_info_t {
	gint type;					/* To store if the packet is encrypted handshake. */
	guint length;				/* The size of this frame */
	guint data_size;			/* The data size of the decrypted content. */
	unsigned char *data;		/* The decrypted content. */
	guint offset;				/* Initial AES counter value for this frame. */
	gboolean update;			/* Used as a trigger to update the AES counter in this conversation. */
} devp2p_packet_info_t;

/**
 * Set the aes256-ctr initial counter value to offset.
 *
 * @param ctr - The aes256-ctr decoder.
 * @param offset - The initial counter value.
 */
static void set_aes_ctr_value(rfc3686_blk *ctr, guint offset) {
	ctr->ctr[0] = offset / (256 * 256 * 256 * 16);
	offset = offset % (256 * 256 * 256 * 16);
	ctr->ctr[1] = offset / (256 * 256 * 16);
	offset = offset % (256 * 256 * 16);
	ctr->ctr[2] = offset / (256 * 16);
	offset = offset % (256 * 16);
	ctr->ctr[3] = offset / 16;
}

/**
* Decrypt the packet using aes256ctr mode at a given length.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param length - Only the given length of data in this packet will be decrypted.
* @param secret - The secret (aes-key, initial counter value) of this wire conversation.
* @param devp2p_packet_info - The frame data.
*/
static void decrypt_aes_256_ctr_data(tvbuff_t *tvb, guint length, devp2p_conv_t *secret, devp2p_packet_info_t *devp2p_packet_info) {
	/* Set up cipher. */
	rfc3686_blk ctr = {
		{ 0x00, 0x00, 0x00, 0x00 },
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0x00, 0x00, 0x00, 0x00 }
	};
	set_aes_ctr_value(&ctr, secret->current_offset);
	aes256_context ctx;
	aes256_init(&ctx, secret->aes_key);
	aes256_setCtrBlk(&ctx, &ctr);
	/* Decrypting. */
	unsigned char *buf;
	guint digest_length = secret->current_offset % 16;
	buf = (unsigned char *)wmem_alloc(wmem_file_scope(), (length + digest_length) * sizeof(unsigned char));
	for (guint i = 0; i < digest_length; i++) {
		buf[i] = 0;
	}
	for (guint offset = 0; offset < length; offset++) {
		buf[digest_length + offset] = tvb_get_guint8(tvb, offset);
	}
	aes256_encrypt_ctr(&ctx, buf, sizeof(unsigned char) * (length + digest_length));
	aes256_done(&ctx);
	/* Saving data to the frame. */
	devp2p_packet_info->data_size = length;
	devp2p_packet_info->data = wmem_alloc(wmem_file_scope(), length * sizeof(unsigned char));
	for (guint i = 0; i < length; i++) {
		devp2p_packet_info->data[i] = buf[i + digest_length];
	}
	wmem_free(wmem_file_scope(), buf);
}

/**
* Decrypt the frame length.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param secret - The secret (aes-key, initial counter value) of this wire conversation.
* @param devp2p_packet_info - The frame data.
*/
static guint decrypt_frame_length(tvbuff_t *tvb, devp2p_conv_t *secret) {
	devp2p_packet_info_t *temp;
	temp = wmem_new(wmem_file_scope(), devp2p_packet_info_t);
	decrypt_aes_256_ctr_data(tvb, HEADER_LENGTH - MAC_LENGTH, secret, temp);
	guint length;
	length = temp->data[0] * 256 * 256;
	length += temp->data[1] * 256;
	length += temp->data[2];
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, "16:data: %02x%02x%02x, first 2: %02x%02x", temp->data[0], temp->data[1], temp->data[2], tvb_get_guint8(tvb, 0), tvb_get_guint8(tvb, 1));
	if (length % 16) {
		length = (length / 16 + 1) * 16;
	}
	length += 48;
	wmem_free(wmem_file_scope(), temp);
	return length;
}

/**
* Attempt to get a conversation
*
* @param pinfo - The Packet.
* @return conversation if found, or NULL if not existed
*/
static conversation_t* attempt_to_get_conversation(packet_info *pinfo) {
	guint32 peer_ip = 0;
	peer_ip |= ((guint8 *)pinfo->src.data)[0] * 256 * 256 * 256;
	peer_ip |= ((guint8 *)pinfo->src.data)[1] * 256 * 256;
	peer_ip |= ((guint8 *)pinfo->src.data)[2] * 256;
	peer_ip |= ((guint8 *)pinfo->src.data)[3];
	return find_conversation(pinfo->num, &pinfo->dst, NULL, ENDPOINT_NONE, peer_ip, peer_ip, NO_ADDR_B | NO_PORT_B);
}

/**
* Dissect the packet comes out from ==patched== geth client.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param pinfo - The Packet.
* @param tree - The protocol tree representing the packet.
* @param data - Extra data.
*/
static int dissect_devp2p_wire_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
	/* Clear out stuff in the info column. */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Dissecting. */
	/* The patched geth client dumps a packet starts with two '?', a length of 38 and is to port 8888. */
	if (tvb_get_guint8(tvb, 0) == '?' && tvb_get_guint8(tvb, 1) == '?' &&
		tvb_captured_length(tvb) == 38 && pinfo->destport == 8888) {
		/* Set info column. */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETHDEVP2PWIRE SECRET");
		gint offset = 0;
		proto_item *ti = proto_tree_add_item(tree, proto_devp2p_wire, tvb, 0, -1, ENC_NA);
		proto_tree *key_tree = proto_item_add_subtree(ti, ett_devp2p_wire);
		offset += 2;
		proto_tree_add_item(key_tree, hf_devp2p_wire_secret_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		guint32 peer_ip;
		peer_ip = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(key_tree, hf_devp2p_wire_secret_key, tvb, offset, 32, ENC_BIG_ENDIAN);

		/* Create Conversation, send data towards actual devp2p-wire dissector */
		if (!PINFO_FD_VISITED(pinfo)) {
			conversation_t *conversation;
			conversation = find_conversation(pinfo->num, &pinfo->src, NULL, ENDPOINT_NONE, peer_ip, peer_ip, NO_ADDR_B | NO_PORT_B);
			if (conversation == NULL) {
				conversation = conversation_new(pinfo->num, &pinfo->src, NULL, ENDPOINT_NONE, peer_ip, peer_ip, NO_ADDR2 | NO_PORT2);
			}
			devp2p_conv_t *secret;
			secret = (devp2p_conv_t *)conversation_get_proto_data(conversation, proto_devp2p_wire);
			if (!secret) {
				/* Add data */
				secret = wmem_new(wmem_file_scope(), devp2p_conv_t);
				secret->current_offset = 0;
				for (int i = 0; i < 32; i++) {
					secret->aes_key[i] = tvb_get_guint8(tvb, offset++);
				}
				secret->start = TRUE;
				conversation_add_proto_data(conversation, proto_devp2p_wire, (void *)secret);
			}
		}
		return TRUE;
	}
	return FALSE;
}

/**
* Dissect the devp2p-wire frames.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param pinfo - The Packet.
* @param tree - The protocol tree representing the packet.
* @param data - Extra data.
*/
static int dissect_devp2p_wire_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
	/* Obtain conversation, secret and frame data. */
	conversation_t *conversation;
	conversation = attempt_to_get_conversation(pinfo);
	devp2p_conv_t *secret;
	secret = (devp2p_conv_t *)conversation_get_proto_data(conversation, proto_devp2p_wire);
	devp2p_packet_info_t *devp2p_packet_info;
	devp2p_packet_info = (devp2p_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num);

	if (devp2p_packet_info->update) {
		/* The current offset of this wire conversation needs to be updated. */
		secret->current_offset += devp2p_packet_info->length - 32;
		devp2p_packet_info->update = FALSE;
	}
	return tvb_captured_length(tvb);
}

/**
* Get the size of this frame.
*
* @param pinfo - The Packet.
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param offset - The offset.
* @param data - Extra data.
*/
static guint get_devp2p_wire_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
	/* Obtain conversation, secret and frame data. */
	conversation_t *conversation;
	conversation = attempt_to_get_conversation(pinfo);
	devp2p_conv_t *secret;
	secret = (devp2p_conv_t *)conversation_get_proto_data(conversation, proto_devp2p_wire);
	devp2p_packet_info_t *devp2p_packet_info;
	devp2p_packet_info = (devp2p_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num);
	
	if (devp2p_packet_info->length == 0) {
		/* The length of the frame is not calculated yet. */
		devp2p_packet_info->offset = secret->current_offset;
		devp2p_packet_info->length = decrypt_frame_length(tvb, secret);
		devp2p_packet_info->update = TRUE;
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, "Frame: %d, Offset: %d, Length: %d\n\n\n", pinfo->num, devp2p_packet_info->offset, devp2p_packet_info->length);
	}
	return devp2p_packet_info->length;
}

/**
* Dissect the devp2p-wire packets.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param pinfo - The Packet.
* @param tree - The protocol tree representing the packet.
* @param data - Extra data.
*/
static int dissect_devp2p_wire_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {

	devp2p_conv_t *secret;
	devp2p_packet_info_t *devp2p_packet_info;

	if (tvb_captured_length(tvb) > 0 && pinfo->src.type == AT_IPv4) {
		conversation_t *conversation;
		/* If this is a valid wire communication comes from the ==patched== geth client. */
		conversation = attempt_to_get_conversation(pinfo);
		if (conversation == NULL) {
			/* No conversation found. */
			return FALSE;
		}
		
		/* Conversation found, get secret. */
		secret = (devp2p_conv_t *)conversation_get_proto_data(conversation, proto_devp2p_wire);

		/* Attempt to get frame data. */
		devp2p_packet_info = (devp2p_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num);
		if (devp2p_packet_info == NULL) {
			/* No frame data found, create a new one. */
			devp2p_packet_info = wmem_new(wmem_file_scope(), devp2p_packet_info_t);
			if (secret->start) {
				/* If this is the first packet detected, it is handshake, mark the packet. */
				devp2p_packet_info->type = HANDSHAKE;
				secret->start = FALSE;
			}
			else {
				devp2p_packet_info->type = RLPX_PACKET;
			}
			devp2p_packet_info->length = 0;
			p_add_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num, devp2p_packet_info);
		}
		if (devp2p_packet_info->type == HANDSHAKE) {
			/* If the packet is Encrypted handshake, skip it */
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETHDEVP2WIRE Encrypted Handshake");
		}
		else {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETHDEVP2PWIRE");
			/* Conduct tcp reassembly, dissect frame once reassembled */
			tcp_dissect_pdus(tvb, pinfo, tree, TRUE, HEADER_LENGTH, get_devp2p_wire_pdu_length, dissect_devp2p_wire_pdu, data);
		}
		return TRUE;
	}
	return FALSE;
}

/**
* Registers the protocol with Wireshark.
*/
void proto_register_devp2p_wire(void) {

	static hf_register_info hf[] = {

		{ &hf_devp2p_wire_secret_ip,
		{ "Devp2p Wire Secret IP", "devp2pwire.secret.ip", FT_IPv4, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},

		{ &hf_devp2p_wire_secret_key,
		{ "Devp2p Wire Secret AES Key", "devp2pwire.secret.key", FT_BYTES, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},

		{ &hf_devp2p_wire_raw_message,
		{ "Devp2p Wire Secret Raw message", "devp2pwire.raw", FT_STRING, BASE_NONE,
		NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_devp2p_wire
	};

	proto_devp2p_wire = proto_register_protocol(
		"Devp2p Wire Protocol",
		"ETHDEVP2PWIRE",
		"ethdevp2pwire"
	);

	proto_register_field_array(proto_devp2p_wire, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/**
* Registers the handoff to the Ethereum devp2p wire protocol.
*/
void proto_reg_handoff_devp2p_wire(void) {
	heur_dissector_add("tcp", dissect_devp2p_wire_tcp, "devp2p wire over TCP",
		"devp2p_wire_tcp", proto_devp2p_wire, HEURISTIC_ENABLE);
	heur_dissector_add("udp", dissect_devp2p_wire_udp, "devp2p wire over UDP",
		"devp2p_wire_udp", proto_devp2p_wire, HEURISTIC_ENABLE);
}