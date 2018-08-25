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

#define	HEADER_LEN						32
#define HEADER_DATA_LEN					16
#define MAC_LEN							16
#define LENGTH_LEN						3

/* To indicate the type of this packet (Handshake or rlpx frame) */
typedef enum packet_type {
	HANDSHAKE = 0x01,
	RLPX_PACKET = 0x02
} packet_type_e;

/* To indicate the status of the pdu resembly */
typedef enum pdu_status {
	GET_LENGTH = 0x01,
	VERIFY_LENGTH = 0x02
} pdu_status_e;

/* Subtrees. */
static int proto_devp2p_wire = -1;
static gint ett_devp2p_wire = -1;

/* For displaying secret comes out from ==patched== geth client. */
static int hf_devp2p_wire_secret_ip;
static int hf_devp2p_wire_secret_key;
static int hf_devp2p_wire_raw_message;

/* Information holds for each wire conversation. */
typedef struct _devp2p_conv_t {
	guint8 aes_key[32];					/* To hold the AES symmetric keys for this wire conversation. */
	guint current_offset;				/* To give each pdu an initial AES counter value. */
	gboolean start;						/* To skip the encrypted handshake for incoming tcp traffic. */
	guint pdu_count;					/* To count the tcp pdu number. */
	pdu_status_e pdu_status;			/* To keep track of the pdu resembly status. */
} devp2p_conv_t;

/* Information holds for each resembled tcp pdu. */
typedef struct _devp2p_pdu_data_t {
	guint8 pdu_id[5];					/* To store the pdu_id, which is consist of first four bytes in the packet and an initial offset. */
	guint pdu_offset;					/* To store the initial AES counter value. */
	guint pdu_length;					/* To store the length of this pdu. */
	guint pdu_index;					/* To store the index of this pdu in this conversation. */
	guint data_size;					/* The data size of the decrypted content. */
	unsigned char *data;				/* The decrypted content. */
	struct _devp2p_pdu_data_t *next;	/* To store the memory address of the next pdu information (linked data structure). */
} devp2p_pdu_data_t;

/* Information holds for each packet in a wire conversation. */
typedef struct _devp2p_packet_info_t {
	packet_type_e packet_type;			/* To store if the packet is encrypted handshake. */
	gboolean update_secret;				/* To indicate if the dissector needs to update the secret. */
	guint pdu_size;						/* The size of the pdu list associated with this packet. */
	devp2p_pdu_data_t *head;			/* The head of the pdu list associated with this packet. */
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
* Decrypt the pdu length.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param secret - The secret (aes-key, initial counter value) of this wire conversation.
* @param start_position - The start position in this tvb.
* @return length - the decrypted pdu length.
*/
static guint decrypt_length(tvbuff_t *tvb, devp2p_conv_t *secret, guint start_position) {
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

	/* Decrypting the first three bytes. */
	unsigned char *buf;
	guint digest_length = secret->current_offset % 16;
	guint length = LENGTH_LEN;
	buf = (unsigned char *)wmem_alloc(wmem_file_scope(), (length + digest_length) * sizeof(unsigned char));
	for (guint i = 0; i < digest_length; i++) {
		buf[i] = 0;
	}
	for (guint i = 0; i < length; i++) {
		buf[digest_length + i] = tvb_get_guint8(tvb, i + start_position);
	}
	aes256_encrypt_ctr(&ctx, buf, sizeof(unsigned char) * (length + digest_length));
	aes256_done(&ctx);

	/* Calculate pdu length using the first three bytes */
	guint pdu_length;
	pdu_length = buf[0 + digest_length] * 256 * 256;
	pdu_length += buf[1 + digest_length] * 256;
	pdu_length += buf[2 + digest_length];
	if (pdu_length % 16) {
		pdu_length = (pdu_length / 16 + 1) * 16;
	}
	pdu_length += 48;
	wmem_free(wmem_file_scope(), buf);
	return pdu_length;
}

/**
* Decrypt the pdu data.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param secret - The secret (aes-key, initial counter value) of this wire conversation.
* @param devp2p_pdu - The undecrypted pdu data.
*/
static void decrypt_pdu_content(tvbuff_t *tvb, devp2p_conv_t *secret, devp2p_pdu_data_t *devp2p_pdu) {
	/* Set up cipher. */
	rfc3686_blk ctr = {
		{ 0x00, 0x00, 0x00, 0x00 },
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0x00, 0x00, 0x00, 0x00 }
	};
	set_aes_ctr_value(&ctr, devp2p_pdu->pdu_offset);
	aes256_context ctx;
	aes256_init(&ctx, secret->aes_key);
	aes256_setCtrBlk(&ctx, &ctr);

	/* Collect bytes that needs to be decrypted, not including MAC */
	unsigned char *buf;
	guint digest_length = secret->current_offset % 16;
	guint length = tvb_captured_length(tvb) - 2 * MAC_LEN;
	buf = (unsigned char *)wmem_alloc(wmem_file_scope(), (length + digest_length) * sizeof(unsigned char));
	for (guint i = 0; i < digest_length; i++) {
		buf[i] = 0;
	}
	/* Collect header data */
	for (guint i = 0; i < HEADER_DATA_LEN; i++) {
		buf[digest_length + i] = tvb_get_guint8(tvb, i);
	}
	/* Collect frame data */
	for (guint i = 0; i < length - HEADER_DATA_LEN ; i++) {
		buf[digest_length + i] = tvb_get_guint8(tvb, i + HEADER_LEN);
	}

	/* Perform aes256 decryption. */
	aes256_encrypt_ctr(&ctx, buf, sizeof(unsigned char) * (length + digest_length));
	aes256_done(&ctx);

	/* Saving data to the pdu */
	devp2p_pdu->data_size = length;
	devp2p_pdu->data = wmem_alloc(wmem_file_scope(), length * sizeof(unsigned char));
	for (guint i = 0; i < length; i++) {
		devp2p_pdu->data[i] = buf[i + digest_length];
	}
	wmem_free(wmem_file_scope(), buf);
}

/**
* Attempt to get a conversation based on the given packet info.
*
* @param pinfo - The packet info.
* @return a matching conversation if found or NULL otherwise.
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
* Search an existing matched pdu in the packet data associated with the given start position.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param devp2p_packet_info - The devp2p packet data.
* @return the pdu data if a match is found or NULL otherwise.
*/
static devp2p_pdu_data_t * try_find_pdu(tvbuff_t *tvb, devp2p_packet_info_t *devp2p_packet_info) {
	/* Set up the pdu id. */
	guint8 pdu_id[4];
	pdu_id[0] = tvb_get_guint8(tvb, 0);
	pdu_id[1] = tvb_get_guint8(tvb, 1);
	pdu_id[2] = tvb_get_guint8(tvb, 2);
	pdu_id[3] = tvb_get_guint8(tvb, 3);

	/* Search from the head of the pdu list. */
	devp2p_pdu_data_t *target = devp2p_packet_info->head;
	while (target != NULL) {
		if (target->pdu_id[0] == pdu_id[0] && target->pdu_id[1] == pdu_id[1] &&
			target->pdu_id[2] == pdu_id[2] && target->pdu_id[3] == pdu_id[3]) {
			/* Find a match, return the target */
			return target;
		}
		target = target->next;
	}
	/* Not found if reach here. */
	return NULL;
}

/**
* Test if given packet contains an exisitng matched pdu associated with the given start position.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param devp2p_packet_info - The devp2p packet data.
* @param start_position - The start position of this pdu in this packet.
* @param pdu_length - Reference to the length of the pdu (It will be set if an existing pdu has been found).
* @return TRUE if a match is found or FALSE otherwise.
*/
static gboolean is_in_pdu_list(tvbuff_t *tvb, devp2p_packet_info_t *devp2p_packet_info, guint start_position, guint *pdu_length) {
	/* Set up the pdu id. */
	guint8 pdu_id[5];
	pdu_id[0] = tvb_get_guint8(tvb, start_position);
	pdu_id[1] = tvb_get_guint8(tvb, start_position + 1);
	pdu_id[2] = tvb_get_guint8(tvb, start_position + 2);
	pdu_id[3] = tvb_get_guint8(tvb, start_position + 3);
	pdu_id[4] = start_position;

	/* Search from the head of the pdu list. */
	devp2p_pdu_data_t *target = devp2p_packet_info->head;
	while (target != NULL) {
		if (target->pdu_id[0] == pdu_id[0] && target->pdu_id[1] == pdu_id[1] &&
			target->pdu_id[2] == pdu_id[2] && target->pdu_id[3] == pdu_id[3] &&
			target->pdu_id[4] == pdu_id[4]) {
			/* Find a match, set the length */
			*pdu_length = target->pdu_length;
			return TRUE;
		}
		target = target->next;
	}
	/* Not found if reach here. */
	return FALSE;
}

/**
* Save the pdu associated with the given start position to the packet.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param devp2p_packet_info - The devp2p packet data.
* @param secret - The secret (aes-key, initial counter value) of this wire conversation.
* @param start_position - The start position of this pdu in this packet.
* @param pdu_length - The length of the pdu.
* @return TRUE if a match is found or FALSE otherwise.
*/
static void save_to_pdu_list(tvbuff_t *tvb, devp2p_packet_info_t *devp2p_packet_info, devp2p_conv_t *secret, guint start_position, guint pdu_length) {
	/* Set up the pdu id. */
	guint8 pdu_id[5];
	pdu_id[0] = tvb_get_guint8(tvb, start_position);
	pdu_id[1] = tvb_get_guint8(tvb, start_position + 1);
	pdu_id[2] = tvb_get_guint8(tvb, start_position + 2);
	pdu_id[3] = tvb_get_guint8(tvb, start_position + 3);
	pdu_id[4] = start_position;

	/* Create a new pdu data. */
	devp2p_pdu_data_t *new_pdu;
	new_pdu = wmem_new(wmem_file_scope(), devp2p_pdu_data_t);
	new_pdu->pdu_id[0] = pdu_id[0];
	new_pdu->pdu_id[1] = pdu_id[1];
	new_pdu->pdu_id[2] = pdu_id[2];
	new_pdu->pdu_id[3] = pdu_id[3];
	new_pdu->pdu_id[4] = pdu_id[4];
	new_pdu->pdu_offset = secret->current_offset;
	new_pdu->pdu_index = secret->pdu_count;
	new_pdu->pdu_length = pdu_length;
	new_pdu->data_size = 0;
	/* Insert the pdu data to the head of the pdu list. */
	new_pdu->next = devp2p_packet_info->head;

	/* Change the head of the pdu list to be this new pdu. */
	devp2p_packet_info->head = new_pdu;
	devp2p_packet_info->pdu_size++;
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
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ethereum secret");
		col_set_str(pinfo->cinfo, COL_INFO, "Secret from patched geth");

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
			/* Set up address for outgoing connection. */ 
			/* Incoming connection can be obtained by using pinfo. */
			address dst;
			dst.type = AT_IPv4, dst.len = 4;
			guint8 *temp_data;
			temp_data = (guint8 *)wmem_alloc(wmem_file_scope(), 4 * sizeof(guint8));
			temp_data[0] = (peer_ip >> 24) & 0x000000FF, temp_data[1] = (peer_ip >> 16) & 0x000000FF;
			temp_data[2] = (peer_ip >> 8) & 0x000000FF, temp_data[3] = (peer_ip) & 0x000000FF;
			dst.data = (const void *)temp_data, dst.priv = NULL;
			guint32 my_ip = 0;
			my_ip |= ((guint8 *)pinfo->src.data)[0] * 256 * 256 * 256;
			my_ip |= ((guint8 *)pinfo->src.data)[1] * 256 * 256;
			my_ip |= ((guint8 *)pinfo->src.data)[2] * 256;
			my_ip |= ((guint8 *)pinfo->src.data)[3];
			
			/* Create conversation for both incoming and outgoing connection. */
			conversation_t *conversation_in;
			conversation_t *conversation_out;
			conversation_in = find_conversation(pinfo->num, &pinfo->src, NULL, ENDPOINT_NONE, peer_ip, peer_ip, NO_ADDR_B | NO_PORT_B);
			conversation_out = find_conversation(pinfo->num, &dst, NULL, ENDPOINT_NONE, my_ip, my_ip, NO_ADDR_B | NO_PORT_B);
			
			/* Two conversations will be either both NULL or both existed. */
			if (conversation_in == NULL && conversation_out == NULL) {
				conversation_in = conversation_new(pinfo->num, &pinfo->src, NULL, ENDPOINT_NONE, peer_ip, peer_ip, NO_ADDR2 | NO_PORT2);
				conversation_out = conversation_new(pinfo->num, &dst, NULL, ENDPOINT_NONE, my_ip, my_ip, NO_ADDR_B | NO_PORT_B);
			}
			devp2p_conv_t *secret_in;
			devp2p_conv_t *secret_out;
			secret_in = (devp2p_conv_t *)conversation_get_proto_data(conversation_in, proto_devp2p_wire);
			secret_out = (devp2p_conv_t *)conversation_get_proto_data(conversation_out, proto_devp2p_wire);
			if (!secret_in && !secret_out) {
				/* Create new data. */
				secret_in = wmem_new(wmem_file_scope(), devp2p_conv_t);
				secret_out = wmem_new(wmem_file_scope(), devp2p_conv_t);
				
				/* Set up AES key and initialise data. */
				for (int i = 0; i < 32; i++) {
					secret_in->aes_key[i] = tvb_get_guint8(tvb, offset);
					secret_out->aes_key[i] = tvb_get_guint8(tvb, offset);
					offset++;
				}
				secret_in->current_offset = secret_out->current_offset = 0;
				secret_in->pdu_count = secret_out->pdu_count = 0;
				secret_in->pdu_status = secret_out->pdu_status = GET_LENGTH;

				/* For outgoing connection, we don't need to skip the first packet. */
				secret_in->start = TRUE, secret_out->start = FALSE;

				/* Add secret to the conversation. */
				conversation_add_proto_data(conversation_in, proto_devp2p_wire, (void *)secret_in);
				conversation_add_proto_data(conversation_out, proto_devp2p_wire, (void *)secret_out);
			}
			wmem_free(wmem_file_scope(), temp_data);
		}
		return TRUE;
	}
	return FALSE;
}

/**
* Dissect the devp2p-wire pdu.
*
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param pinfo - The Packet.
* @param tree - The protocol tree representing the packet.
* @param data - Extra data.
* @return captured length.
*/
static int dissect_devp2p_wire_pdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
	/* Obtain conversation, secret and pdu data. */
	conversation_t *conversation;
	conversation = attempt_to_get_conversation(pinfo);
	devp2p_conv_t *secret;
	secret = (devp2p_conv_t *)conversation_get_proto_data(conversation, proto_devp2p_wire);
	devp2p_packet_info_t *devp2p_packet_info;
	devp2p_packet_info = (devp2p_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num);
	
	if (devp2p_packet_info->update_secret) {
		/* The current offset of this wire conversation needs to be updated. */
		secret->current_offset += tvb_captured_length(tvb) - 32;

		/* Next state after dissecting must be to get length. */
		secret->pdu_status = GET_LENGTH;
		devp2p_packet_info->update_secret = FALSE;
	}

	/* Try to get pdu data */
	devp2p_pdu_data_t *devp2p_pdu;
	devp2p_pdu = try_find_pdu(tvb, devp2p_packet_info);
	if (devp2p_pdu->data_size == 0) {
		/* The pdu data hasn't been decrypted yet, perform decryption. */
		decrypt_pdu_content(tvb, secret, devp2p_pdu);
	}
	
	/* Dissecting */
	col_set_str(pinfo->cinfo, COL_INFO, "Ethereum rlpx frame");

	return tvb_captured_length(tvb);
}

/**
* Get the size of this pdu.
*
* @param pinfo - The Packet.
* @param tvb - The buffer representing only the packet payload (excluding the message wrapper).
* @param offset - The start position in this packet.
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
	
	guint start_position = (guint)offset;
	guint pdu_length;

	/* If a pdu associated with this packet exists */
	if (is_in_pdu_list(tvb, devp2p_packet_info, start_position, &pdu_length)) {
		/* There is an existing pdu associated with this packet and start position, */
		/* which means it is a packet revisiting action, return the length stored. */
		return pdu_length;
	}
	else {
		/* There is no match found, either we need to return a length or verify a length from previous packet. */
		/* Either way, we need to decrypt the length. */
		pdu_length = decrypt_length(tvb, secret, start_position);

		if (secret->pdu_status == VERIFY_LENGTH) {
			/* The pdu status at the moment is to verify. */
			/* It will enter dissecting routine, where secret gets updated. */
			devp2p_packet_info->update_secret = TRUE;
		}
		else {
			/* The pdu status at the moment is to get a length. */
			if (pdu_length + start_position <= tvb_captured_length(tvb)) {
				/* This packet still contains the next pdu. */
				/* It will skip the Verify and enter dissecting routine, update secret. */
				devp2p_packet_info->update_secret = TRUE;
			}
		}

		/* Save to the pdu list in this packet. */
		save_to_pdu_list(tvb, devp2p_packet_info, secret, start_position, pdu_length);

		/* Either way, set the next status to be Verify. */
		secret->pdu_status = VERIFY_LENGTH;
	}
	return pdu_length;
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

		/* Check if this is a valid wire communication comes from the ==patched== geth client. */
		conversation = attempt_to_get_conversation(pinfo);
		if (conversation == NULL) {
			/* No conversation found, this is not a valid devp2p wire packet. */
			return FALSE;
		}

		/* Conversation found, get secret. */
		secret = (devp2p_conv_t *)conversation_get_proto_data(conversation, proto_devp2p_wire);

		/* Attempt to get packet data. */
		devp2p_packet_info = (devp2p_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num);

		if (devp2p_packet_info == NULL) {
			/* No packet data found, create a new one. */
			devp2p_packet_info = wmem_new(wmem_file_scope(), devp2p_packet_info_t);
			if (secret->start) {
				/* If this is the first packet detected, it is handshake, mark the packet. */
				devp2p_packet_info->packet_type = HANDSHAKE;
				secret->start = FALSE;
			}
			else {
				devp2p_packet_info->packet_type = RLPX_PACKET;
			}
			/* Initialise packet data. */
			devp2p_packet_info->update_secret = FALSE;
			devp2p_packet_info->pdu_size = 0;
			devp2p_packet_info->head = NULL;
			p_add_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num, devp2p_packet_info);
		}
		if (devp2p_packet_info->packet_type == HANDSHAKE) {
			/* The packet is an Encrypted handshake, skip it. */
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ethereum");
			col_set_str(pinfo->cinfo, COL_INFO, "Ethereum encrypted handshake");
		}
		else {
			/* The packet is a RLPX Packet. */
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ethereum");
			/* Conduct tcp reassembly, dissect frame once reassembled. */
			tcp_dissect_pdus(tvb, pinfo, tree, TRUE, HEADER_LEN, get_devp2p_wire_pdu_length, dissect_devp2p_wire_pdu, data);
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
		NULL, 0x0, NULL, HFILL } },

		{ &hf_devp2p_wire_secret_key,
		{ "Devp2p Wire Secret AES Key", "devp2pwire.secret.key", FT_BYTES, BASE_NONE,
		NULL, 0x0, NULL, HFILL } },

		{ &hf_devp2p_wire_raw_message,
		{ "Devp2p Wire Secret Raw message", "devp2pwire.raw", FT_STRING, BASE_NONE,
		NULL, 0x0, NULL, HFILL } }
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