#ifndef _DP_VS_H
#define _DP_VS_H

#include <netinet/in.h>
#include "conf/route.h"
#include "conf/inetaddr.h"
#include "conf/laddr.h"
#include "conf/blklst.h"
#include "conf/conn.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"

enum{
    DPVS_SO_SET_FLUSH = 200,
    DPVS_SO_SET_ZERO,
    DPVS_SO_SET_ADD,
    DPVS_SO_SET_EDIT,
    DPVS_SO_SET_DEL,
    DPVS_SO_SET_ADDDEST,
    DPVS_SO_SET_EDITDEST,
    DPVS_SO_SET_DELDEST,
    DPVS_SO_SET_GRATARP,
};

enum{
    DPVS_SO_GET_VERSION = 200,
    DPVS_SO_GET_INFO,
    DPVS_SO_GET_SERVICES,
    DPVS_SO_GET_SERVICE,
    DPVS_SO_GET_DESTS,
};

#endif
