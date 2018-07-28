#include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>

typedef struct _devp2p_conv_t {
	guint8 aes_key[32];
	guint current_offset;
} devp2p_conv_t;

typedef struct _devp2p_offset_t {
	guint offset;
} devp2p_offset_t;

static int proto_devp2p_wire = -1;
static int hf_devp2p_wire_secret_ip;
static int hf_devp2p_wire_secret_key;

static gint ett_devp2p_wire = -1;

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
	devp2p_offset_t *devp2p_offset;

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
		else {
			secret = (devp2p_conv_t *)conversation_get_proto_data(conversation, proto_devp2p_wire);
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETHDEVP2PWIRE");
			if (!PINFO_FD_VISITED(pinfo)) {
				devp2p_offset = wmem_new(wmem_file_scope(), devp2p_offset_t);
				devp2p_offset->offset = secret->current_offset;
				p_add_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num, devp2p_offset);
				secret->current_offset += tvb_captured_length(tvb);
			}
			devp2p_offset = (devp2p_offset_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_devp2p_wire, pinfo->num);
			col_append_fstr(pinfo->cinfo, COL_INFO, "offset: %d", devp2p_offset->offset);
			return TRUE;
		}
	}
	return FALSE;
}

void proto_register_foo(void) {

	static hf_register_info hf[] = {
		{ &hf_devp2p_wire_secret_ip,
			{  "Devp2p Wire Secret IP", "devp2pwire.secret.ip",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_devp2p_wire_secret_key,
			{ "Devp2p Wire Secret AES Key", "devp2pwire.secret.key",
			FT_BYTES, BASE_NONE,
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