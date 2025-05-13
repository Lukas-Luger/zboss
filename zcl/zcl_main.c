
#include "zb_common.h"
#include "zb_zcl.h"
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

    zb_zcl_zll_initiator_setup();
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

    zchdr->frame_control.frame_type = type;
    zchdr->frame_control.manufacturer = 0x0;
    zchdr->frame_control.direction = direction;
    zchdr->frame_control.disable_def_resp = default_resp;
    zchdr->frame_control.reserved = 0x0;
    zchdr->seq_number = ZB_ZCL_GET_SEQ_NUM();
    zchdr->command_id = cmd;

    return zchdr;
}

void zb_zcl_handle(zb_uint16_t src_addr, zb_uint8_t src_ep,
                   zb_uint16_t profile_id, zb_buf_t *buf,
                   zb_zcl_cluster_t *cluster)
{
    zb_uint8_t param = ZB_REF_FROM_BUF(buf);
    if (cluster->handle) {
        cluster->handle(src_addr, src_ep, profile_id, param, cluster);
    }
    if (cluster->action) {
        cluster->action(src_addr, src_ep, profile_id, param, cluster);
    }
}

zb_zcl_cluster_t *zb_zcl_register_cluster(zb_uint8_t ep,
                                          zb_uint16_t cluster_id,
                                          zb_zcl_attr_t *attr_list,
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
    //ZB_MEMCPY(cl->attr_list, attr_list, attr_list_size);
    cl->handle = handle;
    cl->action = action;

    ZG->zcl.cluster_num++;
    /* todo: add (simple) descriptor*/
    return cl;
}

zb_zcl_cluster_t *zb_zcl_find_cluster(zb_uint16_t cluster_id)
{
    zb_ushort_t i;
    zb_zcl_cluster_t *ret = NULL;
    for (i = 0; i < ZG->zcl.cluster_num; i++) {
        ret = &ZG->zcl.cluster[i];
        if (ret->cluster_id == cluster_id) {
            break;
        }
    }
    return ret;
}
