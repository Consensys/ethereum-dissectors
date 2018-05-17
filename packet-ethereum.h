/* packet-ethereum.h
 * Common functions for Ethereum protocol dissections.
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

#ifndef __PACKET_ETHEREUM_H__
#define __PACKET_ETHEREUM_H__

#include <epan/packet.h>

typedef enum rlp_type {
  VALUE,
  LIST
} rlp_type;

typedef struct rlp_element {
  rlp_type type;
  guint byte_length;
  guint data_offset;
  guint next_offset;
} rlp_element_t;

int rlp_next(tvbuff_t *tvb, guint offset, rlp_element_t *rlp);

#endif //__PACKET_ETHEREUM_H__
