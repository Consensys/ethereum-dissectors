#include "config.h"

#include <epan/packet.h>

#define ETHEREUM_PORT 30303

static int proto_ethereum = -1;

static int dissect_ethereum(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETHEREUM");
    col_clear(pinfo->cinfo, COL_INFO);

    return tvb_captured_length(tvb);
}

void proto_register_ethereum(void) {
    proto_ethereum = proto_register_protocol (
		    "Ethereum Protocol",
		    "ETHEREUM",
		    "ethereum"
		    );
}

void proto_reg_handoff_ethereum(void) {
    static dissector_handle_t ethereum_handle;

    ethereum_handle = create_dissector_handle(dissect_ethereum, proto_ethereum);
    dissector_add_uint("udp.port", ETHEREUM_PORT, ethereum_handle);
}
