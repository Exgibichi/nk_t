/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the GPL3 software license, see the accompanying   *
 * file COPYING or http://www.gnu.org/licenses/gpl.html.*
 **********************************************************************/

#ifndef _SECP256K1_FIELD_REPR_
#define _SECP256K1_FIELD_REPR_

#include <stdint.h>

typedef struct {
    /* X = sum(i=0..4, elem[i]*2^52) mod n */
    uint64_t n[5];
#ifdef VERIFY
    int magnitude;
    int normalized;
#endif
} secp256k1_fe_t;

#endif
