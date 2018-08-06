#include "config.h"

#include "aes256.h"

#include <epan/dissectors/packet-tcp.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>

#define HEADER_LENGTH	32
#define MAC_LENGTH		16

//#define NEW			0x00
#define START_HEADER	0x01
#define PROCESS_FRAME	0x02
#define END_MAC			0x03

#define WRONG			0x00
#define HEADER			0x01
#define FRAME			0x02
#define FRAMEMAC		0x03
#define MAC				0x04

typedef struct _big_number_t {
	guint most;
	guint middle;
	guint least;
} big_number_t;

typedef struct _devp2p_conv_t {
	guint8 aes_key[32];
	guint current_offset;
	guint state;	//To skip encrypt handshake
	guint32 frame_length;
} devp2p_conv_t;

typedef struct _devp2p_packet_info_t {
	gint type;
	guint data_size;
	unsigned char *data;
	guint offset;
} devp2p_packet_info_t;

static int proto_devp2p_wire = -1;
static int hf_devp2p_wire_secret_ip;
static int hf_devp2p_wire_secret_key;
static int hf_devp2p_wire_raw_message;

static gint ett_devp2p_wire = -1;

static int big_number_substration(big_number_t *big_number, guint length) {
	if (length <= big_number->least) {
		big_number->least -= length;
		return 1;
	}
	else {
		if (big_number->middle > 0) {
			big_number->least += (0xFF - length);
			big_number->middle -= 1;
			return 1;
		}
		else {
			if (big_number->most > 0) {
				big_number->least += (0xFF - length);
				big_number->middle = 0xFF - 1;
				big_number->most -= 1;
				return 1;
			}
			else {
				return 0;
			}
		}
	}
}

static int is_big_number_zero(big_number_t *big_number) {
	if (big_number->least == 0 && big_number->middle == 0 && big_number->most == 0) {
		return 1;
	}
	else {
		return 0;
	}
}

static void set_ctr(rfc3686_blk *ctr, guint offset) {
	ctr->ctr[0] = offset / (256 * 256 * 256 * 16);
	offset = offset % (256 * 256 * 256 * 16);
	ctr->ctr[1] = offset / (256 * 256 * 16);
	offset = offset % (256 * 256 * 16);
	ctr->ctr[2] = offset / (256 * 16);
	offset = offset % (256 * 16);
	ctr->ctr[3] = offset / 16;
}

static void decrypt_data(tvbuff_t *tvb, guint length, devp2p_conv_t *secret, devp2p_packet_info_t *devp2p_packet_info) {
	//Set up cipher
	rfc3686_blk ctr = {
		{ 0x00, 0x00, 0x00, 0x00 },
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0x00, 0x00, 0x00, 0x00 }
	};
	set_ctr(&ctr, secret->current_offset);
	aes256_context ctx;
	aes256_init(&ctx, secret->aes_key);
	aes256_setCtrBlk(&ctx, &ctr);
	//Decrypting
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
	//Saving data
	devp2p_packet_info->data_size = length;
	devp2p_packet_info->data = wmem_alloc(wmem_file_scope(), length * sizeof(unsigned char));
	for (guint i = 0; i < length; i++) {
		devp2p_packet_info->data[i] = buf[i + digest_length];
	}
	wmem_free(wmem_file_scope(), buf);
}

static int dissect_devp2p_wire_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	//Dissecting
	if (tvb_get_guint8(tvb, 0) == '?' && tvb_get_guint8(tvb, 1) == '?' &&
		tvb_captured_length(tvb) == 38 && pinfo->destport == 8888) {
		//For getting secret
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETHDEVP2PWIRE KEY");
		gint offset = 0;
		proto_item *ti = proto_tree_add_item(tree, proto_devp2p_wire, tvb, 0, -1, ENC_NA);
		proto_tree *key_tree = proto_item_add_subtree(ti, ett_devp2p_wire);
		offset += 2;
		proto_tree_add_item(key_tree, hf_devp2p_wire_secret_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		guint32 peer_ip;
		peer_ip = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(key_tree, hf_devp2p_wire_secret_key, tvb, offset, 32, ENC_BIG_ENDIAN);

		//Create Conversation
		if (!PINFO_FD_VISITED(pinfo)) {
			conversation_t *conversation;
			conversation = find_conversation(pinfo->num, &pinfo->src, NULL, ENDPOINT_NONE, peer_ip, peer_ip, NO_ADDR_B | NO_PORT_B);
			if (conversation == NULL) {
				//Create conversation
				conversation = conversation_new(pinfo->num, &pinfo->src, NULL, ENDPOINT_NONE, peer_ip, peer_ip, NO_ADDR2 | NO_PORT2);
			}
			devp2p_conv_t *secret;
			secret = (devp2p_conv_t *)conversation_get_proto_data(conversation, proto_devp2p_wire);
			if (!secret) {
				//Add data
				secret = wmem_new(wmem_file_scope(), devp2p_conv_t);
				secret->current_offset = 0;
				secret->state = START_HEADER;
				secret->frame_length = 0;
				for (int i = 0; i < 32; i++) {
					secret->aes_key[i] = tvb_get_guint8(tvb, offset++);
				}
				conversation_add_proto_data(conversation, proto_devp2p_wire, (void *)secret);
			}
		}
		return TRUE;
	}
	return FALSE;
}

static int dissect_devp2p_wire_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	devp2p_conv_t *secret;
	devp2p_packet_info_t *devp2p_packet_info;

	if (tvb_captured_length(tvb) > 0 && pinfo->src.type == AT_IPv4) {
		guint32 peer_ip = 0;
		peer_ip |= ((guint8 *)pinfo->src.data)[0] * 256 * 256 * 256;
		peer_ip |= ((guint8 *)pinfo->src.data)[1] * 256 * 256;
		peer_ip |= ((guint8 *)pinfo->src.data)[2] * 256;
		peer_ip |= ((guint8 *)pinfo->src.data)[3];
		conversation_t *conversation;
		conversation = find_conversation(pinfo->num, &pinfo->dst, NULL, ENDPOINT_NONE, peer_ip, peer_ip, NO_ADDR_B | NO_PORT_B);
		if (conversation == NULL) {
			return FALSE;
		}
		secret = (devp2p_conv_t *)conversation_get_proto_data(conversation, proto_devp2p_wire);
		if (!PINFO_FD_VISITED(pinfo)) {
			devp2p_packet_info = wmem_new(wmem_file_scope(), devp2p_packet_info_t);
			guint length;
			length = tvb_captured_length(tvb);
			//Decoding based on types
			switch (secret->state) {
				case START_HEADER:
					if (length == HEADER_LENGTH) {
						//Decrypt
						length -= MAC_LENGTH;
						devp2p_packet_info->type = HEADER;
						devp2p_packet_info->offset = secret->current_offset;
						decrypt_data(tvb, length, secret, devp2p_packet_info);
						//Set next state
						secret->current_offset += length;
						secret->state = PROCESS_FRAME;
						secret->frame_length = devp2p_packet_info->data[0] * 256 * 256;
						secret->frame_length += devp2p_packet_info->data[1] * 256;
						secret->frame_length += devp2p_packet_info->data[2];
						//For padding
						if (secret->frame_length % 16) {
							secret->frame_length = 16 * (secret->frame_length / 16 + 1);
						}
					}
					else {
						devp2p_packet_info->type = WRONG;
					}
					break;
				case PROCESS_FRAME:
					//Decrypt
					if (secret->frame_length == length - MAC_LENGTH) {
						//MAC inside
						length -= MAC_LENGTH;
						secret->state = START_HEADER;
						devp2p_packet_info->type = FRAMEMAC;
						devp2p_packet_info->offset = secret->current_offset;
					}
					else {
						secret->frame_length -= length;
						devp2p_packet_info->type = FRAME;
						devp2p_packet_info->offset = secret->current_offset;
					}
					decrypt_data(tvb, length, secret, devp2p_packet_info);
					//Set next state
					secret->current_offset += length;
					if (secret->frame_length == 0) {
						secret->state = END_MAC;
					}
					break;
				case END_MAC:
					devp2p_packet_info->type = MAC;
					devp2p_packet_info->offset = secret->current_offset;
					//Set next state
					secret->state = START_HEADER;
					break;
			}
			p_add_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num, devp2p_packet_info);
		}
		devp2p_packet_info = (devp2p_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num);
		if (devp2p_packet_info->type == WRONG) {
			return FALSE;
		}
		//Display
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETHDEVP2PWIRE");
		col_append_fstr(pinfo->cinfo, COL_INFO, "Type: %x, Length: %d, offset: %d|||", devp2p_packet_info->type, tvb_captured_length(tvb), devp2p_packet_info->offset);
		if (!(devp2p_packet_info->type == MAC)) {
			proto_tree *ethdevp2p_wire_tree;
			proto_item *ti;
			ethdevp2p_wire_tree = proto_item_add_subtree(tree, ett_devp2p_wire);
			ti = proto_tree_add_string(ethdevp2p_wire_tree, hf_devp2p_wire_raw_message, tvb, 0, -1, "Raw message: ");
			for (guint i = 0; i < devp2p_packet_info->data_size; i++) {
				col_append_fstr(pinfo->cinfo, COL_INFO, "%02x", devp2p_packet_info->data[i]);
				proto_item_append_text(ti, "%02x", devp2p_packet_info->data[i]);
			}
		}
		return TRUE;
	}
	return FALSE;
}

void proto_register_foo(void) {

	static hf_register_info hf[] = {
		{ &hf_devp2p_wire_secret_ip,
		{ "Devp2p Wire Secret IP", "devp2pwire.secret.ip",
		FT_IPv4, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
		},
		{ &hf_devp2p_wire_secret_key,
		{ "Devp2p Wire Secret AES Key", "devp2pwire.secret.key",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
		},
		{ &hf_devp2p_wire_raw_message,
		{ "Devp2p Wire Secret Raw message", "devp2pwire.raw",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
		}
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

void proto_reg_handoff_foo(void) {
	heur_dissector_add("tcp", dissect_devp2p_wire_tcp, "devp2p wire over TCP",
		"devp2p_wire_tcp", proto_devp2p_wire, HEURISTIC_ENABLE);
	heur_dissector_add("udp", dissect_devp2p_wire_udp, "devp2p wire over UDP",
		"devp2p_wire_udp", proto_devp2p_wire, HEURISTIC_ENABLE);
}