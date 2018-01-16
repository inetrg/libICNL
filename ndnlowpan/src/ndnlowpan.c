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

size_t icnl_ndn_encode(uint8_t *out, uint8_t *in, size_t in_len)
{
    size_t pos = 0;

    if (in[0] == 0x05) {
        pos += icnl_ndn_encode_interest(out, in, in_len);
    }
    else if (in[0] == 0x06) {
        pos += icnl_ndn_encode_data(out, in, in_len);
    }

    return pos;
}

size_t icnl_ndn_encode_interest(uint8_t *out, uint8_t *in, size_t in_len)
{
    size_t pos = 0;

    pos += icnl_ndn_dispatch_add_interest(out + pos);

    memcpy(out + pos, in, in_len);
    pos += in_len;

    return pos;
}

size_t icnl_ndn_encode_data(uint8_t *out, uint8_t *in, size_t in_len)
{
    size_t pos = 0;

    pos += icnl_ndn_dispatch_add_data(out + pos);

    memcpy(out + pos, in, in_len);
    pos += in_len;

    return pos;
}
