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
    zb_buf_t *du = (zb_buf_t *)ZB_BUF_FROM_REF(param);
    
    TRACE_MSG(TRACE_NWK1, "+intrpan_data_request %hd", (FMT__H, param));

    //reading params
    zb_intrp_data_req_params_t intrp;
    ZB_MEMCPY(&intrp, ZB_GET_BUF_TAIL(du, sizeof(zb_intrp_data_req_params_t)), sizeof(zb_intrp_data_req_params_t));

    // G.3.2
    zb_uint8_t fc = 0x03;

    // MAC header
    zb_mcps_data_req_params_t *mreq = ZB_GET_BUF_PARAM(du, zb_mcps_data_req_params_t);
    ZB_BZERO(mreq, sizeof(zb_mcps_data_req_params_t));
    //TODO find a way to insert destination pan through the layers
    mreq->dst_pan_id = 0xffff;// no other way to set it, than here
    mreq->tx_options = 0;// no ack //MAC_TX_OPTION_ACKNOWLEDGED_BIT;

    // MAC Addressing
    switch(intrp.dst_addr_mode){
        case 1:// 16Bit group addressing
            fc |= 0xc;
            mreq->dst_addr_mode = ZB_ADDR_16BIT_MULTICAST;
            ZB_MEMCPY(&mreq->dst_addr.addr_short, &intrp.dst_addr.addr_short, sizeof(zb_uint16_t));
            break;
        case 2: // 16Bit network addressing (0xffff)
            fc |= 0x08;
            mreq->dst_addr_mode = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
            mreq->dst_addr.addr_short = 0xffff;
            break;
        case 3: // 64Bit dev addressing (Table G-1)
            mreq->dst_addr_mode = ZB_ADDR_64BIT_DEV;
            ZB_IEEE_ADDR_COPY(&mreq->dst_addr.addr_long, &intrp.dst_addr.addr_long);
            break;
        default:
            printf("Wrong intrp dst address mode:0x%x", intrp.dst_addr_mode);
            break;
    }

    switch(intrp.src_addr_mode){
        case 0: //normally reserved, should be 0
            mreq->src_addr_mode = ZB_ADDR_NO_ADDR;
            break;
        case 2: // 16Bit short address
            mreq->src_addr_mode = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
            ZB_MEMCPY(&mreq->src_addr.addr_short, &ZB_PIB_SHORT_ADDRESS(), sizeof(zb_uint16_t));
            break;
        case 3: // this should actually be 0x03 (Table G-1)
            mreq->src_addr_mode = ZB_ADDR_64BIT_DEV;       
            ZB_IEEE_ADDR_COPY(mreq->src_addr.addr_long, ZB_PIB_EXTENDED_ADDRESS());
            break;
        default:
            printf("Wrong intrp src address mode:0x%x", intrp.src_addr_mode);
            break;
    } 

    // APS frame
    zb_int8_t *ptr;
    ZB_BUF_ALLOC_LEFT(du, 5, ptr);
    *ptr = fc; // 0x08 = Boradcast | 0x0C = group addr //FCF
    ptr++;
    ZB_MEMCPY(ptr, &intrp.clusterid, sizeof(zb_uint16_t));
    ptr += sizeof(zb_uint16_t);
    ZB_MEMCPY(ptr, &intrp.profileid, sizeof(zb_uint16_t));

    // NWK header
    zb_nwk_hdr_t *nwhdr;
    ZB_BUF_ALLOC_LEFT(du, ZB_NWK_INTERPAN_HDR_SIZE, nwhdr);
    nwhdr->frame_control[0] = 0x0b;
    nwhdr->frame_control[1] = 0x00;

    ZB_SCHEDULE_CALLBACK(zb_mcps_data_request, ZB_REF_FROM_BUF(du));

    TRACE_MSG(TRACE_NWK1, "-intrpan_data_request", (FMT__0));
}
