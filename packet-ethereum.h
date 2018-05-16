//
// Created by Raúl Kripalani on 14/05/2018.
//

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
