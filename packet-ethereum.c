#include "config.c"

#include <epan/packet.h>

#define ETH_PORT 30303

static int proto_eth = -1;

static int dissect_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETH");
    col_clear(pinfo->cinfo, COL_INFO);

    return tvb_captured_length(tvb);
}

void proto_register_eth(void) {
    proto_eth = proto_register_protocol (
		    "Ethereum Protocol",
		    "ETH",
		    "eth"
		    );
}

void proto_reg_handoff_eth(void) {
    static dissector_handle_t eth_handle;

    eth_handle = create_dissector_handle(dissect_eth, proto_eth);
    dissector_add_uint("udp.port", ETH_PORT, eth_handle);
}
