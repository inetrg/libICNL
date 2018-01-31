/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "icnlowpan.h"
#include "debug.h"

#ifdef MODULE_NDNLOWPAN
#include "ndnlowpan.h"
#endif

icnl_tlv_off_t icnl_encode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos = 0;

    /* page 2 */
    out[pos++] = ICNL_DISPATCH_PAGE;

    if (0) {}
#ifdef MODULE_NDNLOWPAN
    else if ((proto == ICNL_PROTO_NDN) || (proto == ICNL_PROTO_NDN_HC)) {
        pos += icnl_ndn_encode(out + pos, proto, in, in_len);
    }
#endif
#ifdef MODULE_CCNLOWPAN
    else if ((proto == ICNL_PROTO_CCN) || (proto == ICNL_PROTO_CCN_HC)) {
        ICNL_DBG("CCN is unsupported currently\n");
        return 0;
    }
#endif
    else {
        ICNL_DBG("could not identify ICN protocol\n");
        return 0;
    }
	return pos;
}

icnl_tlv_off_t icnl_decode(uint8_t *out, const uint8_t *in, icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos = 0;
    icnl_tlv_off_t out_len = 0;

    if (in[pos++] != ICNL_DISPATCH_PAGE) {
        ICNL_DBG("unexpected dispatch page\n");
        return 0;
    }

    uint8_t *dispatch = (uint8_t *) (in + pos);

    if (0) {}
#ifdef MODULE_NDNLOWPAN
    else if ((*dispatch & 0x8F) == 0x80) {
        out_len = icnl_ndn_decode(out, ICNL_PROTO_NDN, in + pos, in_len - pos);
    }
    else if ((*dispatch & 0x88) == 0x88) {
        out_len = icnl_ndn_decode(out, ICNL_PROTO_NDN_HC, in + pos, in_len - pos);
    }
#endif
#ifdef MODULE_NDNLOWPAN
    else if (*dispatch ^ 0x80) {
        ICNL_DBG("CCN is unsupported currently\n");
        return 0;
    }
#endif
    else {
        ICNL_DBG("unexpected dispatch type\n");
        return 0;
    }
	return out_len;
}
