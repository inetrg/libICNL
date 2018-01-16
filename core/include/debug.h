/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file        debug.h
 * @brief       debug functions
 * @author      Cenk Gündoğan <cenk.guendogan@haw-hamburg.de>
 * @copyright   GNU Lesser General Public License v2.1
 * @ingroup     icnlowpan
 * @{
 */
#ifndef CORE_DEBUG_H
#define CORE_DEBUG_H

#include <stdio.h>

/**
 * Control debug printing
 */
#ifndef ICNL_DEBUG
#define ICNL_DEBUG (0)
#endif

/**
 * Print debug messages if COMPAS_DEBUG is not 0
 */
#define ICNL_DBG(...) do { if (ICNL_DEBUG) {printf("%s:%s - ", __FILE__, __func__);printf(__VA_ARGS__);}} while (0)

#endif /* CORE_DEBUG_H */
/** @} */
