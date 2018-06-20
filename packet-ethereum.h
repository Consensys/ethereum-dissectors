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

// RLP element types.
typedef enum rlp_type {
  VALUE,
  LIST
} rlp_type_t;

// A struct that stores metadata about an RLP element
typedef struct rlp_element {
  rlp_type_t type;    // The element type
  guint byte_length;  // The length in bytes of the payload of this element.
  guint data_offset;  // The absolute offset in the buffer where the data actually starts within this element.
  guint next_offset;  // The absolute offset in the buffer of the next element, or 0 iff end of buffer.
} rlp_element_t;

/**
 * Introspects an RLP element starting at the position in the buffer designated by offset.
 * This function updates the incoming RLP element with the metadata concerning the introspected item.
 * It is recommended to pass in a variable assigned in the stack.
 *
 * @param tvb The buffer.
 * @param offset The offset of the element to analyze.
 * @param rlp The RLP element struct to update with the metadata.
 * @return TRUE if the RLP introspection succeeded; FALSE otherwise.
 */
int rlp_next(tvbuff_t *tvb, guint offset, rlp_element_t *rlp);

#endif //__PACKET_ETHEREUM_H__
