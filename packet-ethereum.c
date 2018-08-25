/* packet-ethereum.c
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

#include "config.h"

#include "packet-ethereum.h"

int rlp_next(tvbuff_t *tvb, guint offset, rlp_element_t *rlp) {
  guint8 prefix = tvb_get_guint8(tvb, offset);
  if (prefix <= 0x7f) {
    // The value is itself.
    rlp->type = VALUE;
    rlp->data_offset = offset;
    rlp->byte_length = 1;
  } else if (prefix >= 0x80 && prefix <= 0xb7) {
    // A value whose length is less or equal to 55 bytes.
    rlp->type = VALUE;
    rlp->data_offset = offset + 1;
    rlp->byte_length = prefix - (guint8) 0x80;
  } else if (prefix >= 0xb8 && prefix <= 0xbf) {
    // A value whose length is larger than 55 bytes (recursive length).
    rlp->type = VALUE;
    guint l = prefix - (guint8) 0xb7;
    if (l > 4) {
      // We do not support lengths longer than 32 bits (i.e. max supported length is 2**32, 4Gb).
      return FALSE;
    }
    rlp->data_offset = offset + 1 + l;
    rlp->byte_length = tvb_get_bits32(tvb, (offset + 1) * 8, l * 8, ENC_BIG_ENDIAN);
  } else if (prefix >= 0xc0 && prefix <= 0xf7) {
    // A list whose byte length is less than 55 bytes.
    rlp->type = LIST;
    rlp->data_offset = offset + 1;
    rlp->byte_length = prefix - (guint8) 0xc0;
  } else if (prefix >= 0xf8) {
    // A longer list.
    rlp->type = LIST;
    guint l = prefix - (guint8) 0xf7;
    if (l > 4) {
      // We do not support lengths longer than 32 bits (i.e. max supported length is 2**32, 4Gb).
      return FALSE;
    }
    rlp->data_offset = offset + 1 + l;
    rlp->byte_length = tvb_get_bits32(tvb, (offset + 1) * 8, l * 8, ENC_BIG_ENDIAN);
  }
  rlp->next_offset = tvb_captured_length_remaining(tvb, rlp->data_offset + rlp->byte_length) > 0 ?
                     rlp->data_offset + rlp->byte_length : 0;
  return TRUE;
}
