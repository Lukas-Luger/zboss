/**
 * PURPOSE: ZLL On, Off commands
 */
#include "zb_common.h"
#include "zb_zcl.h"
#include "zb_aps.h"
#include "zcl_internal.h"
#include "zb_secur_api.h"
#include "zb_zcl_on_off.h"
#include <zb_bufpool.h>
#include <zb_osif_unix.h>
#include <zb_scheduler.h>
#include <zb_types.h>
#ifndef ZB_LIMITED_FEATURES
/*! \addtogroup ZB_ZCL */
/*! @{ */

zb_zcl_global_attrs_t on_off_global_attrs;
/**
 * Server Side
 * 
 * TODO: proper use of attribute and better zcl callback scheme
 */
static zb_zcl_on_off_srv_attr_t *local_attrs;

void handle_off(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_free_buf(buf);
    local_attrs->on_time = 0x0000;
    local_attrs->on_off = ZB_FALSE;
    local_attrs->set_state(local_attrs->on_off);
}

void handle_on(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_free_buf(buf);
    if (local_attrs->on_time == 0x0000) {
        local_attrs->off_wait_time = 0x0000;
    }
    local_attrs->on_off = ZB_TRUE;
    local_attrs->set_state(local_attrs->on_off);
}

void handle_toggle(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_free_buf(buf);
    if (!local_attrs->on_off && local_attrs->on_time == 0x0000) {
        local_attrs->off_wait_time = 0x0000;
    }
    if (local_attrs->on_off) {
        local_attrs->on_time = 0x0000;
    }
    local_attrs->on_off = !local_attrs->on_off;
    local_attrs->set_state(local_attrs->on_off);
}

void handle_off_with_effect(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_on_off_off_with_effect_req_t *req; 
    req = (zb_zcl_on_off_off_with_effect_req_t *)ZB_BUF_BEGIN(buf);
    if (local_attrs->global_scene_ctrl) {
        // TODO: (in application) store seetings in globalSceneControl
        local_attrs->global_scene_ctrl = ZB_FALSE;
    }
    local_attrs->on_off = ZB_FALSE;
    local_attrs->on_time = 0x0000;
    // might be better in application?
    if (req->effect_id == 0) {
        switch (req->effect_variant) {
        case 1:
            // No fade
            break;
        case 2:
            // 50% dim down in 0.8 sec then fade to off in 12 sec
            break;
        case 0:
        default:
            // Fade to off in 0.8 sec
            break;
        }
    }
    if (req->effect_id == 1) {
        // 20% dim up in 0.5 sec then fade to off in 1 sec
    }
}

void handle_on_global_scene(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_free_buf(buf);
    if (local_attrs->global_scene_ctrl) {
        return;
    }
    // TODO: (in application) recall global scene, enter state
    local_attrs->on_off = ZB_TRUE; // might be wrong to assume the light will turn on?
    local_attrs->global_scene_ctrl = ZB_TRUE;
    if (local_attrs->on_time == 0x0000) {
        local_attrs->off_wait_time = 0x0000;
    }
}

void update_timed_off(zb_uint8_t param)
{
    ZVUNUSED(param);
    if (local_attrs->on_time == 0x0000 && local_attrs->off_wait_time == 0x0000) {
        return;
    }
    if (local_attrs->on_off) {
        if (local_attrs->on_time > 0x0000) {
            local_attrs->on_time--;
        }
        else {
            local_attrs->off_wait_time = 0x0000;
            local_attrs->on_off = ZB_FALSE;
        }

    }
    else {
        if (local_attrs->off_wait_time > 0x0000) {
            local_attrs->off_wait_time--;
        }
        else {
            return;
        }
    }
    ZB_SCHEDULE_ALARM(update_timed_off, 0, ZB_TIME_ONE_SECOND/10);
}

void handle_on_with_timed_off(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_on_off_on_with_timed_off_req_t *req;
    req = (zb_zcl_on_off_on_with_timed_off_req_t *)ZB_BUF_BEGIN(buf);
    /* accept only when on bitfield */
    if ((req->on_off_ctrl & 0x80) && !local_attrs->on_off) {
        return;
    }
    if (local_attrs->off_wait_time > 0 && !local_attrs->on_off) {
        local_attrs->off_wait_time = req->off_wait_time; // 3.8.2.3.6.4 "and minimum"??
    }
    else {
        local_attrs->on_time = req->on_time;  // 3.8.2.3.6.4 "and maximum"??
        local_attrs->off_wait_time = req->off_wait_time;
        local_attrs->on_off = ZB_TRUE;
    }
    if (local_attrs->on_time < 0xffff && local_attrs->off_wait_time < 0xffff) {
        ZB_SCHEDULE_ALARM(update_timed_off, 0, ZB_TIME_ONE_SECOND/10);
    }

}
void handle_on_off_srv(zb_uint16_t src_addr, zb_uint8_t src_ep,
                zb_uint16_t profile_id, zb_uint8_t param,
                zb_zcl_cluster_t *cluster)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_parsed_hdr_t *zcl_hdr = ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t);

    switch (zcl_hdr->cmd_id) {
    case ZB_ZCL_ON_OFF_OFF: /* 0 Off*/
        handle_off(param);
        break;
    case ZB_ZCL_ON_OFF_ON: /* 1 On */
        handle_on(param);
        break;
    case ZB_ZCL_ON_OFF_TOGGLE: /* 2 Toggle */
        handle_toggle(param);
        break;
    case ZB_ZCL_ON_OFF_OFF_WITH_EFFECT: /* 0x40 Off with effect */
        handle_off_with_effect(param);
        break;
    case ZB_ZCL_ON_OFF_ON_WITH_GLOB_SCENE: /* 0x41 On with recall global scene */
        handle_on_global_scene(param);
        break;
    case ZB_ZCL_ON_OFF_ON_WITH_TIMED_OFF: /* 0x42 On with timed off */
        handle_on_with_timed_off(param);
    default:
        break;
    }
}

void zb_zcl_on_off_srv_setup(zb_uint8_t ep, zb_zcl_on_off_srv_attr_t *attrs)
{
    local_attrs = attrs;
    zb_zcl_cluster_t *cluster = zb_zcl_register_cluster(ep, ZB_ON_OFF_CLUSTER_ID,
                                  ZB_ZCL_SERVER_ROLE, handle_on_off_srv, NULL);
    on_off_global_attrs.cluster_revision = ZB_ZCL_DEFAULT_CLUSTER_REVISION();
    on_off_global_attrs.reporting_status = ZB_ZCL_ATTR_REPORTING_COMPLETE;
    zb_zcl_add_attribute(cluster, 0xfffd, ZB_ZCL_ATTR_TYPE_U16, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(on_off_global_attrs.cluster_revision));
    zb_zcl_add_attribute(cluster, 0xfffe, ZB_ZCL_ATTR_TYPE_ENUM8, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(on_off_global_attrs.reporting_status));
    zb_zcl_add_attribute(cluster, 0x0000, ZB_ZCL_ATTR_TYPE_BOOL, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->on_off));
    zb_zcl_add_attribute(cluster, 0x4000, ZB_ZCL_ATTR_TYPE_BOOL, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->global_scene_ctrl));
    zb_zcl_add_attribute(cluster, 0x4001, ZB_ZCL_ATTR_TYPE_U16, ZB_ZCL_ATTR_ACCESS_READ_WRITE, &(attrs->on_time));
    zb_zcl_add_attribute(cluster, 0x4002, ZB_ZCL_ATTR_TYPE_U16, ZB_ZCL_ATTR_ACCESS_READ_WRITE, &(attrs->off_wait_time));
    zb_zcl_add_attribute(cluster, 0x4003, ZB_ZCL_ATTR_TYPE_ENUM8, ZB_ZCL_ATTR_ACCESS_READ_WRITE, &(attrs->startup_on_off));
}

/**
 * Client Side
 */
 void zb_zcl_on_off_send_off(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t dst_addr,
                            zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
        ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_ON_OFF_OFF);

    zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(dreq, sizeof(*dreq));
    dreq->dst_addr = dst_addr;
    dreq->dst_endpoint = dst_ep;
    dreq->src_endpoint = src_ep;
    dreq->clusterid = ZB_ON_OFF_CLUSTER_ID;
    dreq->profileid = profile_id;
    dreq->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;

    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, ZB_REF_FROM_BUF(buf));
}

void zb_zcl_on_off_send_on(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t dst_addr,
                            zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
        ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_ON_OFF_ON);

    zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(dreq, sizeof(*dreq));
    dreq->dst_addr = dst_addr;
    dreq->dst_endpoint = dst_ep;
    dreq->src_endpoint = src_ep;
    dreq->clusterid = ZB_ON_OFF_CLUSTER_ID;
    dreq->profileid = profile_id;
    dreq->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;

    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, ZB_REF_FROM_BUF(buf));
}

void zb_zcl_on_off_send_toggle(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t dst_addr,
                            zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
        ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_ON_OFF_TOGGLE);

    zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(dreq, sizeof(*dreq));
    dreq->dst_addr = dst_addr;
    dreq->dst_endpoint = dst_ep;
    dreq->src_endpoint = src_ep;
    dreq->clusterid = ZB_ON_OFF_CLUSTER_ID;
    dreq->profileid = profile_id;
    dreq->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;

    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, ZB_REF_FROM_BUF(buf));
}

void zb_zcl_on_off_send_off_with_effect(zb_uint8_t param, zb_uint16_t profile_id, zb_uint8_t effect_id,
                            zb_uint8_t effect_variant, zb_uint16_t dst_addr, zb_uint8_t dst_ep,
                            zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    zb_zcl_on_off_off_with_effect_req_t *req;

    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_on_off_off_with_effect_req_t), req);
    req->effect_id = effect_id;
    req->effect_variant = effect_variant;

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
        ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_ON_OFF_OFF_WITH_EFFECT);

    zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(dreq, sizeof(*dreq));
    dreq->dst_addr = dst_addr;
    dreq->dst_endpoint = dst_ep;
    dreq->src_endpoint = src_ep;
    dreq->clusterid = ZB_ON_OFF_CLUSTER_ID;
    dreq->profileid = profile_id;
    dreq->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;

    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, ZB_REF_FROM_BUF(buf));
}

void zb_zcl_on_off_send_on_with_glob_scene(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t dst_addr,
                            zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
        ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_ON_OFF_ON_WITH_GLOB_SCENE);

    zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(dreq, sizeof(*dreq));
    dreq->dst_addr = dst_addr;
    dreq->dst_endpoint = dst_ep;
    dreq->src_endpoint = src_ep;
    dreq->clusterid = ZB_ON_OFF_CLUSTER_ID;
    dreq->profileid = profile_id;
    dreq->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;

    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, ZB_REF_FROM_BUF(buf));
}

void zb_zcl_on_off_send_on_with_timed_off(zb_uint8_t param, zb_uint16_t profile_id, zb_bool_t only_when_on,
                            zb_uint16_t on_time, zb_uint16_t off_wait_time, zb_uint16_t dst_addr,
                            zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    zb_zcl_on_off_on_with_timed_off_req_t *req;

    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_on_off_on_with_timed_off_req_t), req);
    req->on_off_ctrl = (only_when_on) ? 0x80 : 0x00;
    req->on_time = on_time;
    req->off_wait_time = off_wait_time;
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
        ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_ON_OFF_ON_WITH_TIMED_OFF);

    zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(dreq, sizeof(*dreq));
    dreq->dst_addr = dst_addr;
    dreq->dst_endpoint = dst_ep;
    dreq->src_endpoint = src_ep;
    dreq->clusterid = ZB_ON_OFF_CLUSTER_ID;
    dreq->profileid = profile_id;
    dreq->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;

    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, ZB_REF_FROM_BUF(buf));
}
void zb_zcl_on_off_cli_setup(zb_uint8_t ep)
{
    (void)zb_zcl_register_cluster(ep, ZB_ON_OFF_CLUSTER_ID,
                                ZB_ZCL_CLIENT_ROLE, NULL, NULL);
}
#endif /* LIMITED_FEATURES */
/*! @} */
