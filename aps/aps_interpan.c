
#include "zb_common.h"
#include "zb_nwk.h"
#include "zb_aps.h"
#include "zb_secur.h"
#include "aps_internal.h"
#include "zb_af_globals.h"
#include "zb_zdo.h"
#include <od.h>
/*! \addtogroup ZB_APS */
/*! @{ */

#include "zb_bank_7.h"
void zb_intrp_data_request(zb_uint8_t param) ZB_CALLBACK
{
    // G.2.3.3
    
    zb_buf_t *apsdu = (zb_buf_t *)ZB_BUF_FROM_REF(param);
    
    zb_intrp_data_req_params_t *intrp =
        ZB_GET_BUF_TAIL(apsdu, sizeof(zb_intrp_data_req_params_t));
    //G.3.2
    zb_uint8_t fc = 0x03; // 0x08 = Boradcast | 0x0C = group addr
    

    zb_nlde_data_req_t nldereq;
    //ZB_BZERO(nldereq, sizeof(zb_nlde_data_req_t));
    nldereq.addr_mode = ZB_APS_ADDR_MODE_64_ENDP_NOT_PRESENT;//0x4
    nldereq.security_enable = 0;
    //we need src: No, 16, 64 Bit
            //dst:  group, 16Bit, 64 bit
    //nldereq.radius = ?
    nldereq.nonmember_radius = 0;   /* if multicast, get it from APS IB */
    nldereq.discovery_route = 1;    /* always! see 2.2.4.1.1.3 */
    switch(intrp->src_addr_mode){
        case 0: //No addr
            nldereq.addr_mode |= 1; //should be 0 in the future
            break;
        case 2: //16-Bit short
            nldereq.addr_mode |= 2;
            break;
        case 3: //64-Bit extended
            //currently 0 as in no addr
            break;
        default:
            puts("Wrong aps src address mode");
            break;
    }
   // od_hex_dump(&nldereq.addr_mode, 2,2);
    switch(intrp->dst_addr_mode){
        case 1: //16-Bit short group
            nldereq.addr_mode |= 0x8;
            nldereq.dst_addr = intrp->dst_addr.addr_short;
            break;
        case 2: //16-Bit NWK (usually broadcast)
            fc |= 0x08;
            nldereq.addr_mode |= 0x10;
            break;
        case 3: //64-Bit extended addr
            //this should be 24 then, but due to compatibility is 0 for now
            ZB_IEEE_ADDR_COPY(&nldereq.dst_addr_long,&intrp->dst_addr.addr_long);
            break;
        default:
            printf("Wrong aps dst address mode:0x%x", intrp->dst_addr_mode);
            break;
    }
    // build aps frame
    zb_int8_t *ptr;
    ZB_BUF_ALLOC_LEFT(apsdu, 5, ptr);
    *ptr = fc; //FCF
    ptr++;
    ZB_MEMCPY(ptr, &intrp->clusterid, sizeof(zb_uint16_t));
    ptr += sizeof(zb_uint16_t);
    ZB_MEMCPY(ptr, &intrp->profileid, sizeof(zb_uint16_t));

    ZB_MEMCPY(
        ZB_GET_BUF_TAIL(apsdu, sizeof(zb_nlde_data_req_t)),
        &nldereq,
        sizeof(nldereq));

    ZB_SCHEDULE_CALLBACK(zb_nlde_data_request, ZB_REF_FROM_BUF(apsdu));

    

}