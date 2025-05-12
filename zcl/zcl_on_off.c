/**
 * PURPOSE: ZLL On, Off commands
 */
#include "zb_common.h"
#include "zb_zcl.h"
#include "zb_aps.h"
#include "zcl_internal.h"
#include "zb_secur_api.h"
#include "zcl_zll_internal.h"
#include "od.h"
#ifndef ZB_LIMITED_FEATURES
/*! \addtogroup ZB_ZCL */
/*! @{ */

void zb_zcl_send_on_off_toggle(zb_uint16_t addr, zb_uint8_t dst_ep, zb_uint8_t src_ep, zb_bool_t default_resp)
{
    zb_buf_t *buf = zb_get_out_buf();

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
        ZB_ZCL_FRAME_DIRECTION_TO_SRV, default_resp, ZB_ZCL_CMD_WRITE_ATTRIB);

    zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(dreq, sizeof(*dreq));
    dreq->dst_addr = addr;
    dreq->dst_endpoint = dst_ep;
    dreq->src_endpoint = src_ep;
    dreq->clusterid = ZB_ON_OFF_CLUSTER_ID;
    dreq->profileid = ZB_HA_PROFILE_ID;
    dreq->tx_options = ZB_APSDE_TX_OPT_SECURITY_ENABLED | ZB_APSDE_TX_OPT_USE_NWK_KEY;
    dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;

    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, ZB_REF_FROM_BUF(buf));
}

void zb_zcl_send_on_off_on(zb_uint16_t addr, zb_uint8_t dst_ep, zb_uint8_t src_ep, zb_bool_t default_resp)
{
    zb_buf_t *buf = zb_get_out_buf();

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
        ZB_ZCL_FRAME_DIRECTION_TO_SRV, default_resp, ZB_ZCL_CMD_READ_ATTRIB_RESP);

    zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(dreq, sizeof(*dreq));
    dreq->dst_addr = addr;
    dreq->dst_endpoint = dst_ep;
    dreq->src_endpoint = src_ep;
    dreq->clusterid = ZB_ON_OFF_CLUSTER_ID;
    dreq->profileid = ZB_HA_PROFILE_ID;
    dreq->tx_options = ZB_APSDE_TX_OPT_SECURITY_ENABLED | ZB_APSDE_TX_OPT_USE_NWK_KEY;
    dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;

    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, ZB_REF_FROM_BUF(buf));
}

void zb_zcl_send_on_off_off(zb_uint16_t addr, zb_uint8_t dst_ep, zb_uint8_t src_ep, zb_bool_t default_resp)
{
    zb_buf_t *buf = zb_get_out_buf();

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
        ZB_ZCL_FRAME_DIRECTION_TO_SRV, default_resp, ZB_ZCL_CMD_READ_ATTRIB);

    zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(dreq, sizeof(*dreq));
    dreq->dst_addr = addr;
    dreq->dst_endpoint = dst_ep;
    dreq->src_endpoint = src_ep;
    dreq->clusterid = ZB_ON_OFF_CLUSTER_ID;
    dreq->profileid = ZB_HA_PROFILE_ID;
    dreq->tx_options = ZB_APSDE_TX_OPT_SECURITY_ENABLED | ZB_APSDE_TX_OPT_USE_NWK_KEY;
    dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;

    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, ZB_REF_FROM_BUF(buf));
}
#endif /* LIMITED_FEATURES */
/*! @} */
