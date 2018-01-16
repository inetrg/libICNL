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

size_t icnl_encode(uint8_t *out, icnl_proto_t proto, uint8_t *in,
                   size_t in_len)
{
    size_t pos = 0;

    /* page 2 */
    pos += icnl_page_switch_add(out + pos, ICNL_DISPATCH_PAGE);

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
    }
	return pos;
}
