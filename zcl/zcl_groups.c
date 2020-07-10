#include "zb_common.h"
#include "zb_aps.h"
#include "zb_zdo.h"
#include "zb_zcl_groups.h"

#include "log.h"

#include <stdbool.h>

#define ENABLE_DEBUG (0)
#include "debug.h"

#if ENABLE_DEBUG
#include "od.h"
#else
#define od_hex_dump(...)
#endif

extern uint16_t g_group_id;

static uint8_t zcl_seq = 0;

void group_add_confirmation(zb_uint8_t param)
{
    (void)param;
    zb_apsme_add_group_conf_t *conf = ZB_GET_BUF_PARAM(ZB_BUF_FROM_REF(param), zb_apsme_add_group_conf_t);
    printf("group add confirmation status: %i\n", conf->status);
}

void zb_zcl_handle_group_request(zb_uint8_t param)
{
    zb_buf_t *zbbuf = ZB_BUF_FROM_REF(param);
    zb_apsde_data_indication_t *ind = ZB_GET_BUF_PARAM(zbbuf,
                                                    zb_apsde_data_indication_t);

    DEBUG("zbbuf->buf:\n");
    od_hex_dump(zbbuf->buf, sizeof(zbbuf->buf), 16);
    DEBUG("ZB_BUF_BEGIN(zbbuf):\n");
    od_hex_dump(zbbuf->buf + zbbuf->u.hdr.data_offset, zbbuf->u.hdr.len, 16);

    /* pointer to beginning of aps header */
    uint8_t *aps = ZB_BUF_BEGIN(zbbuf);
    /* pointer to beginning of zcl header */
    uint8_t *zcl = aps + zb_aps_full_hdr_size(aps);
    /* zcl header type */
    zcl_hdr_t *zcl_hdr = (zcl_hdr_t *)zcl;

    if (zcl_hdr->fcf == 0x00) { /* profile-wide */
        LOG_DEBUG("unhandled profile-wide FCF 0x%x\n", zcl_hdr->fcf);
        zb_free_buf(zbbuf);
        return;
    }

    if (zcl_hdr->fcf != 0x01) { /* cluster-specific */
        LOG_WARNING("unhandled ZCL FCF 0x%x\n", zcl_hdr->fcf);
        zb_free_buf(zbbuf);
        return;
    }

    if (zcl_hdr->cmd == 0x2) { /* get group membership */

        LOG_INFO("get group membership\n");

        /* FIXME tradfri remotes can cause a bug if we reply to this, so don't */
        zb_free_buf(zbbuf);
        return;

        uint8_t *req = zcl + sizeof(zcl_hdr_t);
        zcl_get_group_membership_hdr_t *req_hdr =
                                    (zcl_get_group_membership_hdr_t *)req;

        bool group_match = false;
        if (req_hdr->group_count > 0) {
            uint16_t *first_group_id = (uint16_t *)
                                (req + sizeof(zcl_get_group_membership_hdr_t));

            for (int i = 0; i < req_hdr->group_count; i++) {
                LOG_INFO("get group 0x%04x\n", first_group_id[i]);
                if (g_group_id == first_group_id[i]) {
                    group_match = true;
                }
            }

            if(!group_match) {
                LOG_WARNING("not replying to group request\n");
                zb_free_buf(zbbuf);
                return;
            }
        }

        uint8_t group_count = 0;
        if (group_match) {
            group_count++;
        } else if (req_hdr->group_count == 0) {
            if (g_group_id != 0) {
                group_count++;
            }
        }

        zcl_get_group_membership_resp_t *resp;
        uint8_t resp_size = sizeof(zcl_get_group_membership_resp_t) +
                            sizeof(uint16_t) * group_count;
        ZB_BUF_INITIAL_ALLOC(zbbuf, resp_size, resp);
        ZB_BZERO(resp, sizeof(zcl_get_group_membership_resp_t));

        zcl_hdr_t *resp_zcl;
        ZB_BUF_ALLOC_LEFT(zbbuf, sizeof(*resp_zcl), resp_zcl);
        ZB_BZERO(resp_zcl, sizeof(*resp_zcl));
        resp_zcl->fcf = 0x19;
        resp_zcl->sequence_number = zcl_seq++;
        resp_zcl->cmd = 0x02; /* get group membership response */

        resp->group_count = group_count;
        resp->group_capacity = 255 - resp->group_count;

        if (resp->group_count > 0) {
            memcpy((uint8_t *)resp + sizeof(zcl_get_group_membership_resp_t), &g_group_id, 2);
            printf("respond group 0x%04x %u\n", g_group_id, sizeof(zcl_get_group_membership_resp_t));
        }

        uint16_t addr = ind->src_addr;

        uint8_t src_endpoint = ind->dst_endpoint;
        uint8_t dst_endpoint = ind->src_endpoint;
        uint16_t profileid = ind->profileid;
        uint16_t clusterid = ind->clusterid;

        DEBUG("ZB_BUF_BEGIN(zbbuf):\n");
        od_hex_dump(zbbuf->buf + zbbuf->u.hdr.data_offset, zbbuf->u.hdr.len, 16);

        zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(ZB_BUF_FROM_REF(param),
                                            sizeof(zb_apsde_data_req_t));
        ZB_BZERO(dreq, sizeof(*dreq));

        dreq->dst_addr = addr;
        dreq->dst_endpoint = dst_endpoint;
        dreq->src_endpoint = src_endpoint;
        dreq->clusterid = clusterid;
        dreq->profileid = profileid;

        if (!ZB_NWK_IS_ADDRESS_BROADCAST(addr)) {
            dreq->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
        }
        dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
        ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);

    } else if (zcl_hdr->cmd == 0x0) { /* add group */
        LOG_INFO("add group\n");

        zcl_add_group_hdr_t *req_hdr = (zcl_add_group_hdr_t *)(zcl +
                                                            sizeof(zcl_hdr_t));
        uint16_t group_id;
        memcpy(&group_id, &req_hdr->group_id, sizeof(uint16_t));

        uint16_t src_addr = ind->src_addr;
        uint8_t src_endpoint = ind->dst_endpoint;
        uint8_t dst_endpoint = ind->src_endpoint;
        uint16_t profileid = ind->profileid;
        uint16_t clusterid = ind->clusterid;

        /* save group_id to nvram */
        g_group_id = group_id;
        zb_save_formdesc_data();

        /* tell zdo to add group */
        zb_apsme_add_group_req_t *req;
        zb_buf_reuse(zbbuf);
        req = ZB_GET_BUF_PARAM(zbbuf, zb_apsme_add_group_req_t);
        req->group_address = group_id;
        req->endpoint = 1;
        zb_zdo_add_group_req(param, group_add_confirmation);

        /* send response */
        zcl_add_group_resp_t *resp;
        ZB_BUF_INITIAL_ALLOC(zbbuf, sizeof(zcl_add_group_resp_t), resp);
        ZB_BZERO(resp, sizeof(zcl_add_group_resp_t));

        zcl_hdr_t *resp_zcl;
        ZB_BUF_ALLOC_LEFT(zbbuf, sizeof(*resp_zcl), resp_zcl);
        ZB_BZERO(resp_zcl, sizeof(*resp_zcl));
        resp_zcl->fcf = 0x19;
        resp_zcl->sequence_number = zcl_seq++;
        resp_zcl->cmd = 0x0; /* add group response */

        resp->group_id = group_id;
        resp->status = 0; /* STATUS_OK */

        zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(ZB_BUF_FROM_REF(param),
                                                    sizeof(zb_apsde_data_req_t));
        ZB_BZERO(dreq, sizeof(*dreq));

        dreq->dst_addr = src_addr;
        dreq->dst_endpoint = dst_endpoint;
        dreq->src_endpoint = src_endpoint;
        dreq->clusterid = clusterid;
        dreq->profileid = profileid;

        if (!ZB_NWK_IS_ADDRESS_BROADCAST(src_addr)) {
            dreq->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
        }
        dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
        ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);

    } else if (zcl_hdr->cmd == 0x3) { /* remove group */
        LOG_INFO("remove group\n");

        zcl_remove_group_t *req_hdr = (zcl_remove_group_t *)(zcl +
        sizeof(zcl_hdr_t));
        uint16_t group_id;
        memcpy(&group_id, &req_hdr->group_id, sizeof(uint16_t));

        /* TODO zb_zdo_remove_group_req() doesn't exist */

        /* send response */

        zcl_remove_group_resp_t *resp;
        ZB_BUF_INITIAL_ALLOC(zbbuf, sizeof(zcl_remove_group_resp_t), resp);
        ZB_BZERO(resp, sizeof(zcl_remove_group_resp_t));

        zcl_hdr_t *resp_zcl;
        ZB_BUF_ALLOC_LEFT(zbbuf, sizeof(*resp_zcl), resp_zcl);
        ZB_BZERO(resp_zcl, sizeof(*resp_zcl));
        resp_zcl->fcf = 0x19;
        resp_zcl->sequence_number = zcl_seq++;
        resp_zcl->cmd = 0x3; /* remove group response */

        resp->group_id = group_id;

        if (group_id == g_group_id) {
            resp->status = 0x0; /* STATUS_OK */
            /* save a blank group_id to nvram */
            g_group_id = 0;
            zb_save_formdesc_data();
        } else {
            resp->status = 0x8b; /* NOT_FOUND */
        }

        uint16_t src_addr = ind->src_addr;
        uint8_t src_endpoint = ind->dst_endpoint;
        uint8_t dst_endpoint = ind->src_endpoint;
        uint16_t profileid = ind->profileid;
        uint16_t clusterid = ind->clusterid;

        zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(ZB_BUF_FROM_REF(param),
                                                    sizeof(zb_apsde_data_req_t));
        ZB_BZERO(dreq, sizeof(*dreq));

        dreq->dst_addr = src_addr;
        dreq->dst_endpoint = dst_endpoint;
        dreq->src_endpoint = src_endpoint;
        dreq->clusterid = clusterid;
        dreq->profileid = profileid;

        if (!ZB_NWK_IS_ADDRESS_BROADCAST(src_addr)) {
            dreq->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
        }
        dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
        ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);

    } else {
        LOG_WARNING("unhandled group request 0x%x\n", zcl_hdr->cmd);
        zb_free_buf(zbbuf);
        return;
    }
}
