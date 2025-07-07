
#include "zb_common.h"
#include "zb_zcl.h"
#include "zb_zcl_groups.h"
#include "zb_aps.h"
#include "zcl_internal.h"
#include "zcl_zll_internal.h"

void zb_zcl_cib_init();

void zb_zcl_init()
{
    TRACE_MSG(TRACE_ZCL1, "+zcl_init", (FMT__0));

    zb_zcl_cib_init();

    TRACE_MSG(TRACE_ZCL1, "-zcl_init", (FMT__0));
}

void zb_zcl_cib_init()
{
    TRACE_MSG(TRACE_ZCL1, ">>cib_init", (FMT__0));
    /* initialize params here using ZG->zcl */
    ZG->zcl.seq_number = 0;
    ZG->zcl.cluster_num = 0;
    ZB_BZERO(&ZG->zcl.cluster, ZB_ZCL_CLUSTER_NUM);

    zb_zcl_zll_target_setup();
    TRACE_MSG(TRACE - ZCL1, "<<cib_init", (FMT__0));
}

/*
    Alloc and fill full zcl hdr, return pointer to the allocated hdr
 */
zb_zcl_hdr_full_t *zcl_alloc_and_fill_full_hdr(zb_buf_t *buf,
                                               zb_zcl_frame_type_t type,
                                               zb_zcl_frame_direction_t direction,
                                               zb_bool_t default_resp,
                                               zb_uint8_t cmd,
                                               zb_uint16_t man_code)
{
    zb_zcl_hdr_full_t *zchdr;
    zb_ushort_t hdr_size = sizeof(zb_zcl_hdr_full_t);

    ZB_BUF_ALLOC_LEFT(buf, hdr_size, zchdr);

    zchdr->frame_control.frame_type = type;
    zchdr->frame_control.manufacturer = 0x1;
    zchdr->frame_control.direction = direction;
    zchdr->frame_control.disable_def_resp = default_resp;
    zchdr->frame_control.reserved = 0x0;
    zchdr->manufacturer_code = man_code;
    zchdr->seq_number = ZB_ZCL_GET_SEQ_NUM();
    zchdr->command_id = cmd;

    return zchdr;
}
/*
    Alloc and fill zcl hdr, return pointer to the allocated hdr
 */
zb_zcl_hdr_t *zcl_alloc_and_fill_hdr(zb_buf_t *buf,
                                     zb_zcl_frame_type_t type,
                                     zb_zcl_frame_direction_t direction,
                                     zb_bool_t default_resp,
                                     zb_uint8_t cmd)
{
    zb_zcl_hdr_t *zchdr;
    zb_ushort_t hdr_size = sizeof(zb_zcl_hdr_t);

    ZB_BUF_ALLOC_LEFT(buf, hdr_size, zchdr);

    zchdr->frame_control.frame_type = type & 0x3;
    zchdr->frame_control.manufacturer = 0x0;
    zchdr->frame_control.direction = direction & 0x1;
    zchdr->frame_control.disable_def_resp = default_resp & 0x1;
    zchdr->frame_control.reserved = 0x0;
    zchdr->seq_number = ZB_ZCL_GET_SEQ_NUM();
    zchdr->command_id = cmd;

    return zchdr;
}
void zb_zcl_send_default_resp(zb_uint8_t param, zb_zcl_parsed_hdr_t hdr, zb_zcl_status_t status)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_default_resp_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_default_resp_t), resp);
    resp->resp_cmd = hdr.cmd_id;
    resp->status = (zb_uint8_t) status;
    
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_COMMON,
                                1 - hdr.direction, ZB_TRUE, ZB_ZCL_DEFAULT_RESPONSE_CMD_ID);

    zb_apsde_data_req_t *req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    req->dst_addr = hdr.src_addr;
    req->profileid = hdr.profile_id;
    req->clusterid = hdr.cluster_id;
    req->dst_endpoint = hdr.src_endpoint;
    req->src_endpoint = hdr.dst_endpoint;
    req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void zb_zcl_handle(zb_uint8_t param, zb_zcl_cluster_t *cluster)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_parsed_hdr_t zcl_hdr;
    zb_zcl_status_t status = ZB_ZCL_STATUS_SUCCESS;
    zcl_parse_hdr(param, &zcl_hdr);
    if (!cluster ||
        (cluster->role == ZB_ZCL_SERVER_ROLE && zcl_hdr.direction != ZB_ZCL_FRAME_DIRECTION_TO_SRV) ||
        (cluster->role == ZB_ZCL_CLIENT_ROLE && zcl_hdr.direction != ZB_ZCL_FRAME_DIRECTION_TO_CLI))
    {
        zb_free_buf(buf);
        status = ZB_ZCL_STATUS_UNSUPPORTED_CLUSTER;
        goto done;
    }
    zb_ushort_t hdr_size = ZB_ZCL_FRAME_HDR_GET_SIZE(ZB_BUF_BEGIN(buf));
    ZB_BUF_CUT_LEFT2(buf, hdr_size);
    ZB_MEMCPY(ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t), &zcl_hdr, sizeof(zb_zcl_parsed_hdr_t));
    // here we have to decide if its a common command or should be handled by the cluster itself
    if (cluster->handle) {
        cluster->handle(zcl_hdr.src_addr, zcl_hdr.src_endpoint, zcl_hdr.profile_id, param, cluster);
    }
    if (cluster->action) {
        cluster->action(zcl_hdr.src_addr, zcl_hdr.src_endpoint, zcl_hdr.profile_id, param, cluster);
    }
done:
    if (!zcl_hdr.disable_default_resp) {
        zb_buf_t *sec_buf = zb_get_out_buf();
        zb_zcl_send_default_resp(ZB_REF_FROM_BUF(sec_buf), zcl_hdr, status);
    }
}

zb_zcl_cluster_t *zb_zcl_register_cluster(zb_uint8_t ep,
                                          zb_uint16_t cluster_id,
                                          zb_zcl_cluster_role_t role,
                                          void (*handle)(zb_uint16_t,
                                                         zb_uint8_t,
                                                         zb_uint16_t,
                                                         zb_uint8_t,
                                                         zb_zcl_cluster_t *),
                                          void (*action)(zb_uint16_t,
                                                         zb_uint8_t,
                                                         zb_uint16_t,
                                                         zb_uint8_t,
                                                         zb_zcl_cluster_t *))
{
    ZB_ASSERT(ZB_ZCL_CLUSTER_NUM > ZG->zcl.cluster_num);

    //zb_uint8_t attr_list_size = zb_zcl_get_attribute_size(attr_list);
    zb_zcl_cluster_t *cl = &ZG->zcl.cluster[ZG->zcl.cluster_num];
    cl->ep = ep;
    cl->cluster_id = cluster_id;
    cl->role = role;
    cl->handle = handle;
    cl->action = action;

    ZG->zcl.cluster_num++;
    /* TODO: add (simple) descriptor in APP!*/
    return cl;
}

zb_zcl_cluster_t *zb_zcl_find_cluster(zb_uint16_t cluster_id)
{
    zb_ushort_t i;
    zb_zcl_cluster_t *ret = NULL;
    for (i = 0; i < ZG->zcl.cluster_num; i++) {
        if (ZG->zcl.cluster[i].cluster_id == cluster_id) {
            ret = &ZG->zcl.cluster[i];
            break;
        }
    }
    return ret;
}

zb_zcl_attr_t *zb_zcl_find_attribute(zb_zcl_cluster_t *cluster,
                                     zb_uint16_t attribute_id)
{
    zb_zcl_attr_t *attr_desc = cluster->attr_list;
    zb_uint8_t i = 0;
    while (attr_desc != NULL) {
        if (attr_desc->id == attribute_id) {
            break;
        }
        i++;
        attr_desc++;
        if (i >= cluster->attr_count) {
            attr_desc = NULL;
            break;
        }
    }
    return attr_desc;
}

void zb_zcl_add_attribute(zb_zcl_cluster_t *cluster, zb_uint16_t attr_id,
                          zb_zcl_attr_type_t type, zb_zcl_attr_access_t access,
                          zb_voidp_t data_p)
{
    static zb_zcl_attr_t new_attr;
    new_attr.id = attr_id;
    new_attr.type = type;
    new_attr.access = access;
    new_attr.data_p = data_p;
    cluster->attr_list[cluster->attr_count] = new_attr;
    cluster->attr_count++;
}

void zcl_parse_hdr(zb_uint8_t param, zb_zcl_parsed_hdr_t *zcl_hdr)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_apsde_data_indication_t *ind = ZB_GET_BUF_PARAM(buf, zb_apsde_data_indication_t);
    if (ZB_APS_FC_GET_FRAME_TYPE(ind->fc) != ZB_APS_FRAME_INTERPAN) {
        zcl_hdr->src_addr = ind->src_addr;
        zcl_hdr->dst_addr = ind->dst_addr; // choose ind->group_addr
        zcl_hdr->src_endpoint = ind->src_endpoint;
        zcl_hdr->dst_endpoint = ind->dst_endpoint;
    }
    zcl_hdr->cluster_id = ind->clusterid;
    zcl_hdr->profile_id = ind->profileid;
    ZB_APS_HDR_CUT(buf);
    zb_uint8_t *ptr = ZB_BUF_BEGIN(buf);
    zb_zcl_frame_ctrl_t *fc = (zb_zcl_frame_ctrl_t *)ptr;
    zcl_hdr->cmd_id = ZB_ZCL_FRAME_HDR_GET_COMMAND_ID(ptr);
    zcl_hdr->direction = (zb_bool_t)fc->direction;
    zcl_hdr->disable_default_resp = (zb_bool_t)fc->disable_def_resp;
}
