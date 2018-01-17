/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "core.h"
#include "debug.h"

#ifdef MODULE_NDNLOWPAN
#include "ndnlowpan.h"
#endif

int icnl_encode(uint8_t *out, icnl_proto_t proto, uint8_t *in, unsigned in_len)
{
    unsigned pos = 0;

    /* page 2 */
    out[pos++] = ICNL_DISPATCH_PAGE;

    switch (proto) {
#ifdef MODULE_NDNLOWPAN
        case ICNL_PROTO_NDN:
            pos += icnl_ndn_encode(out + pos, in, in_len);
            break;
#endif
#ifdef MODULE_CCNLOWPAN
        case ICNL_PROTO_CCN:
            break;
#endif
        default:
            ICNL_DBG("could not identify ICN protocol\n");
            return -1;
    }
	return pos;
}

int icnl_decode(uint8_t *out, uint8_t *in, unsigned in_len)
{
    unsigned pos = 0;
    unsigned out_len = 0;

    if (in[pos++] != ICNL_DISPATCH_PAGE) {
        ICNL_DBG("unexpected dispatch page\n");
        return -1;
    }

    uint8_t dispatch = in[pos];

    if (0) {}
#ifdef MODULE_NDNLOWPAN
    else if (dispatch & 0x80) {
        out_len = icnl_ndn_decode(out, in + pos, in_len - pos);
    }
#endif
#ifdef MODULE_NDNLOWPAN
    else if (dispatch ^ 0x80) {
        ICNL_DBG("CCN is unsupported currently\n");
        return -1;
    }
#endif
    else {
        ICNL_DBG("unexpected dispatch type\n");
        return -1;
    }
	return out_len;
}
