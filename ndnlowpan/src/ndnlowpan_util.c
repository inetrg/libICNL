/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include <string.h>

#include "ndnlowpan.h"

uint64_t icnl_ndn_tlv_read(const uint8_t *in, unsigned *pos_in)
{
    uint64_t val;
    uint8_t tmp = in[(*pos_in)++];

    if (tmp < 253) {
        val = (uint64_t) tmp;
    }
    else if (tmp == 253) {
        val  = ((uint64_t) (in[(*pos_in) + 0])) <<  8;
        val |= ((uint64_t) (in[(*pos_in) + 1])) <<  0;
        *pos_in += 2;
    }
    else if (in[*pos_in] == 254) {
        val  = ((uint64_t) (in[(*pos_in) + 0])) << 24;
        val |= ((uint64_t) (in[(*pos_in) + 1])) << 16;
        val |= ((uint64_t) (in[(*pos_in) + 2])) <<  8;
        val |= ((uint64_t) (in[(*pos_in) + 3])) <<  0;
        *pos_in += 4;
    }
    else if (in[*pos_in] == 255) {
        val  = ((uint64_t) (in[(*pos_in) + 0])) << 56;
        val |= ((uint64_t) (in[(*pos_in) + 1])) << 48;
        val |= ((uint64_t) (in[(*pos_in) + 2])) << 40;
        val |= ((uint64_t) (in[(*pos_in) + 3])) << 32;
        val |= ((uint64_t) (in[(*pos_in) + 4])) << 24;
        val |= ((uint64_t) (in[(*pos_in) + 5])) << 16;
        val |= ((uint64_t) (in[(*pos_in) + 6])) <<  8;
        val |= ((uint64_t) (in[(*pos_in) + 7])) <<  0;
        *pos_in += 8;
    }

    return val;
}

void icnl_ndn_tlv_write(uint64_t val, uint8_t *out, unsigned *pos_out)
{
    uint8_t tmp = val & 0xFF;

    if (val & 0x00000000FFFFFFFFULL) {
        out[(*pos_out)++] = 255;
        out[(*pos_out)++] = (uint8_t) ((val >> 56) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >> 48) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >> 40) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >> 32) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >> 24) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >> 16) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >>  8) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >>  0) & 0xFF);
    }
    else if (val & 0x0000FFFFFFFFFFFFULL) {
        out[(*pos_out)++] = 254;
        out[(*pos_out)++] = (uint8_t) ((val >> 24) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >> 16) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >>  8) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >>  0) & 0xFF);
    }
    else if (val & 0x00FFFFFFFFFFFFFFULL) {
        out[(*pos_out)++] = 253;
        out[(*pos_out)++] = (uint8_t) ((val >>  8) & 0xFF);
        out[(*pos_out)++] = (uint8_t) ((val >>  0) & 0xFF);
    }
    else {
        out[(*pos_out)++] = (uint8_t) ((val >>  0) & 0xFF);
    }
}
