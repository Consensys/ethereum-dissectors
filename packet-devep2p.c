#include "config.h"

#include <stdio.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

void proto_register_devp2p(void);
void proto_reg_handoff_devp2p(void);

static dissector_handle_t devp2p_handle;

static int proto_devp2p = -1;

static gint ett_devp2p = -1;

static gint hf_devp2p_packet_len = -1;
static gint hf_devp2p_packet_data = -1;
static gint hf_devp2p_packet_terminator = -1;

#define PNAME  "devp2p wire Protocol"
#define PSNAME "devp2p"
#define PFNAME "devp2p"

#define TCP_PORT_DEVP2P    9418

/* desegmentation of devp2pover TCP */
static gboolean devp2p_desegment = TRUE;

static gboolean get_packet_length(tvbuff_t *tvb, int offset,
                                  guint16 *length)
{
  guint8 *lenstr;

  lenstr = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, ENC_ASCII);

  return (sscanf(lenstr, "%hx", length) == 1);
}

static guint
get_devp2p_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  guint16 plen;

  if (!get_packet_length(tvb, offset, &plen))
    return 0; /* No idea what this is */

  if (plen == 0) {
    /* Terminator packet */
    return 4;
  }

  return plen;
}

static int
dissect_devp2p_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree             *devp2p_tree;
  proto_item             *ti;
  int offset = 0;
  guint16 plen;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  col_set_str(pinfo->cinfo, COL_INFO, PNAME);

  ti = proto_tree_add_item(tree, proto_devp2p, tvb, offset, -1, ENC_NA);
  devp2p_tree = proto_item_add_subtree(ti, ett_devp2p);

  if (!get_packet_length(tvb, 0, &plen))
    return 0;

  if (plen == 0) {
    proto_tree_add_uint(git_tree, hf_git_packet_terminator, tvb, offset,
                        4, plen);
    return 4;
  }

  if (devp2p_tree)
  {
    proto_tree_add_uint(devp2p_tree, hf_devp2p_packet_len, tvb, offset,
                        4, plen);

    proto_tree_add_item(devp2p_tree, hf_devp2p_packet_data, tvb, offset+4,
                        plen-4, ENC_NA);
  }

  return tvb_captured_length(tvb);
}

static int
dissect_devp2p(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, devp2p_desegment, 4, get_devp2p_pdu_len,
                   dissect_devp2p_pdu, data);
  return tvb_captured_length(tvb);
}

void
proto_register_devp2p(void)
{
  static hf_register_info hf[] = {
    { &hf_git_packet_len,
      { "Packet length", "devp2p.length", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
    },
    { &hf_git_packet_data,
      { "Packet data", "devp2p.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
    },
    { &hf_git_packet_terminator,
      { "Terminator packet", "devp2p.terminator", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
    },
  };

  static gint *ett[] = {
    &ett_git,
  };

  module_t *devp2p_module;

  proto_devp2p = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_register_field_array(proto_devp2p, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  devp2p_handle = register_dissector(PFNAME, dissect_devp2p, proto_devp2p);

  devp2p_module = prefs_register_protocol(proto_devp2p, NULL);

  prefs_register_bool_preference(devp2p_module, "desegment",
                                 "Reassemble GIT messages spanning multiple TCP segments",
                                 "Whether the GIT dissector should reassemble messages spanning multiple TCP segments."
                                 " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                 &devp2p_desegment);
}

void
proto_reg_handoff_devp2p(void)
{
  dissector_add_uint_with_preference("tcp.port", TCP_PORT_DEVP2P, devp2p_handle);
}