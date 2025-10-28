/***************************************************************************
 *                      ZBOSS ZigBee Pro 2007 stack                         *
 *                                                                          *
 *          Copyright (c) 2012 DSR Corporation Denver CO, USA.              *
 *                       http://www.dsr-wireless.com                        *
 *                                                                          *
 *                            All rights reserved.                          *
 *          Copyright (c) 2011 ClarIDy Solutions, Inc., Taipei, Taiwan.     *
 *                       http://www.claridy.com/                            *
 *                                                                          *
 *          Copyright (c) 2011 Uniband Electronic Corporation (UBEC),       *
 *                             Hsinchu, Taiwan.                             *
 *                       http://www.ubec.com.tw/                            *
 *                                                                          *
 *          Copyright (c) 2011 DSR Corporation Denver CO, USA.              *
 *                       http://www.dsr-wireless.com                        *
 *                                                                          *
 *                            All rights reserved.                          *
 *                                                                          *
 *                                                                          *
 * ZigBee Pro 2007 stack, also known as ZBOSS (R) ZB stack is available     *
 * under either the terms of the Commercial License or the GNU General      *
 * Public License version 2.0.  As a recipient of ZigBee Pro 2007 stack, you*
 * may choose which license to receive this code under (except as noted in  *
 * per-module LICENSE files).                                               *
 *                                                                          *
 * ZBOSS is a registered trademark of DSR Corporation AKA Data Storage      *
 * Research LLC.                                                            *
 *                                                                          *
 * GNU General Public License Usage                                         *
 * This file may be used under the terms of the GNU General Public License  *
 * version 2.0 as published by the Free Software Foundation and appearing   *
 * in the file LICENSE.GPL included in the packaging of this file.  Please  *
 * review the following information to ensure the GNU General Public        *
 * License version 2.0 requirements will be met:                            *
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html.                   *
 *                                                                          *
 * Commercial Usage                                                         *
 * Licensees holding valid ClarIDy/UBEC/DSR Commercial licenses may use     *
 * this file in accordance with the ClarIDy/UBEC/DSR Commercial License     *
 * Agreement provided with the Software or, alternatively, in accordance    *
 * with the terms contained in a written agreement between you and          *
 * ClarIDy/UBEC/DSR.                                                        *
 *                                                                          *
 ****************************************************************************
   PURPOSE: NVRAM functions for RIOT-OS
 */

#include <stdbool.h>

#include "zb_common.h"
#include "zb_mac_transport.h"
#include "zb_bufpool.h"
#include "zb_ringbuffer.h"
#include "zb_aps_globals.h"
#include "zb_osif.h"
#include "zb_debug.h"
#include "zb_g_context.h"
#include "zb_nwk_nib.h"
#include "zb_bank_common.h"
#include <zb_types.h>
#include "periph/pm.h"

#if defined ZB_USE_NVRAM

extern bool has_eeprom;

typedef struct __attribute__((packed)) {
    uint16_t        magic; /* always "ZB" 0x425a */
    uint8_t         designated_coordinator : 1;
    uint8_t         insecure_join : 1;
} zb_config_t;

zb_ret_t zb_save_nvram_config(void)
{
    if (!has_eeprom) {
        return RET_ERROR;
    }

    zb_config_t config;
    config.magic = 0x425a;
    config.designated_coordinator = ZB_AIB().aps_designated_coordinator;
    config.insecure_join = ZB_AIB().aps_insecure_join;

    zb_write_nvram(ZB_CONFIG_PAGE, &config, sizeof(config));

    return RET_OK;
}

zb_ret_t zb_config_from_nvram(void)
{
    if (!has_eeprom) {
        return RET_ERROR;
    }

    zb_config_t config;
    zb_read_nvram(ZB_CONFIG_PAGE, &config, sizeof(config));

    if (config.magic != 0x425a) {
        return RET_ERROR;
    }

    ZB_AIB().aps_designated_coordinator = config.designated_coordinator;
    ZB_AIB().aps_insecure_join = config.insecure_join;

//     ZB_UPDATE_LONGMAC();

    return RET_OK;
}

typedef struct __attribute__((packed)) {
    uint16_t            magic; /* always "ZB" 0x425a */
    uint8_t             profile_in_use;
    zb_ieee_addr_t      ext_parent_addr;
    uint32_t            channel_mask;
    uint8_t             current_channel;
    uint16_t            short_parent_addr;
    uint8_t             depth;
    uint16_t            pan_id;
    zb_ext_pan_id_t     aps_use_ext_pan_id;
    zb_ext_pan_id_t     ext_pan_id;
    uint16_t            short_addr;
    zb_ieee_addr_t      ext_addr;
    /* aps group table */
    zb_aps_group_table_ent_t groups[ZB_APS_GROUP_TABLE_SIZE];
    zb_uint8_t          n_groups;
    zb_bool_t           bdb_node_on_net;
    uint8_t             nwk_update_id;
    uint8_t             nwk_security_level;
    uint8_t             nwk_active_key_snum;
    uint8_t             nwk_dev_type;
    uint16_t            apl_group_begin;
    uint16_t            apl_group_end;
    uint16_t            apl_addr_begin;
    uint16_t            apl_addr_end;
    zb_ieee_addr_t      aps_tc_addr;
} zb_formdesc_data_t;

zb_ret_t zb_save_formdesc_data(void)
{
    if (!has_eeprom) {
        return RET_ERROR;
    }

    zb_formdesc_data_t data;
    data.magic = 0x425a;

    zb_uint8_t profile_in_use = 0;
    zb_uint16_t short_parent_addr;
    zb_ieee_addr_t ext_parent_addr;

    zb_address_short_by_ref(&short_parent_addr, ZG->nwk.handle.parent);
    zb_address_ieee_by_ref(ext_parent_addr, ZG->nwk.handle.parent);
#if defined ZB_NWK_DISTRIBUTED_ADDRESS_ASSIGN && defined ZB_ROUTER_ROLE
    data.depth = ZB_NIB_DEPTH();
#endif
    data.profile_in_use = profile_in_use;
    memcpy(&data.pan_id, &MAC_PIB().mac_pan_id, sizeof(data.pan_id));
    memcpy(&data.short_parent_addr, &short_parent_addr,
                                            sizeof(short_parent_addr));
    memcpy(&data.short_addr, &MAC_PIB().mac_short_address,
                                                sizeof(data.short_addr));
    memcpy(&data.channel_mask, &ZB_AIB().aps_channel_mask,
                                                sizeof(data.channel_mask));
    data.current_channel = MAC_CTX().current_channel;
    ZB_IEEE_ADDR_COPY(data.ext_parent_addr, ext_parent_addr);
    for (zb_ushort_t i = 0; i < ZB_APS_GROUP_TABLE_SIZE; i++) {
        data.groups[i].group_addr = ZG->aps.group.groups[i].group_addr;
        for (zb_ushort_t j = 0; j < ZB_APS_ENDPOINTS_IN_GROUP_TABLE; j++) {
            data.groups[i].endpoints[j] =  ZG->aps.group.groups[i].endpoints[j];
        }
        data.groups[i].n_endpoints = ZG->aps.group.groups[i].n_endpoints;
    }
    data.n_groups = (zb_uint8_t) ZG->aps.group.n_groups;
    ZB_IEEE_ADDR_COPY(data.aps_use_ext_pan_id, ZB_AIB().aps_use_extended_pan_id);
    ZB_IEEE_ADDR_COPY(data.ext_pan_id, ZB_NIB_EXT_PAN_ID());

    data.bdb_node_on_net = BDB_CTX().node_is_on_net;
    ZB_IEEE_ADDR_COPY(data.ext_addr, ZB_PIB_EXTENDED_ADDRESS());
    data.nwk_update_id = ZB_NIB_UPDATE_ID();
    data.nwk_security_level = (uint8_t) ZB_NIB_SECURITY_LEVEL();
    data.nwk_active_key_snum = ZG->nwk.nib.active_key_seq_number;
    data.nwk_dev_type = ZB_NIB_DEVICE_TYPE();
    ZB_IEEE_ADDR_COPY(data.aps_tc_addr, ZB_AIB().trust_center_address);
    data.apl_group_begin = APL_CTX().free_gr_id_range_begin;
    data.apl_group_end = APL_CTX().free_gr_id_range_end;
    data.apl_addr_begin = APL_CTX().free_addr_range_begin;
    data.apl_addr_end = APL_CTX().free_addr_range_end;
    zb_write_nvram(ZB_CONFIG_PAGE + sizeof(zb_config_t), &data, sizeof(data));

    return RET_OK;
}

zb_ret_t zb_read_formdesc_data(void)
{
    if (!has_eeprom) {
        return RET_ERROR;
    }

    zb_formdesc_data_t data;
    zb_read_nvram(ZB_CONFIG_PAGE + sizeof(zb_config_t), &data, sizeof(data));

    if (data.magic != 0x425a) {
        return RET_ERROR;
    }
#if defined ZB_NWK_DISTRIBUTED_ADDRESS_ASSIGN && defined ZB_ROUTER_ROLE
    ZB_NIB_DEPTH() = data.depth;
#endif
    memcpy(&MAC_PIB().mac_pan_id, &data.pan_id, sizeof(data.pan_id));
    memcpy(&ZB_AIB().aps_channel_mask, &data.channel_mask,
                                                    sizeof(data.channel_mask));
    ZB_TRANSCEIVER_SET_CHANNEL(data.current_channel);
    memcpy(&MAC_PIB().mac_short_address, &data.short_addr,
                                                    sizeof(data.short_addr));

    ZB_UPDATE_PAN_ID();
    ZB_UPDATE_SHORT_ADDR();
    ZB_IEEE_ADDR_COPY(ZB_AIB().aps_use_extended_pan_id, data.aps_use_ext_pan_id);
    ZB_IEEE_ADDR_COPY(ZB_PIB_BEACON_PAYLOAD().extended_panid, data.ext_pan_id);
    ZB_IEEE_ADDR_COPY(ZB_NIB_EXT_PAN_ID(), data.ext_pan_id);
    ZB_IEEE_ADDR_COPY(ZB_PIB_EXTENDED_ADDRESS(), data.ext_addr);
    ZB_UPDATE_LONGMAC();
    if (data.n_groups > ZB_APS_GROUP_TABLE_SIZE) {
        return RET_ERROR;
    }
    for (zb_ushort_t i = 0; i < ZB_APS_GROUP_TABLE_SIZE; i++) {
        ZG->aps.group.groups[i].group_addr = data.groups[i].group_addr;
        for (zb_ushort_t j = 0; j < ZB_APS_ENDPOINTS_IN_GROUP_TABLE; j++) {
            ZG->aps.group.groups[i].endpoints[j] = data.groups[i].endpoints[j];
        }
        ZG->aps.group.groups[i].n_endpoints = data.groups[i].n_endpoints;
    }
    ZG->aps.group.n_groups = (zb_ushort_t) data.n_groups;
    /* parent short & extended addr */
    zb_ret_t ret = zb_address_update(data.ext_parent_addr, data.short_parent_addr,
            ZB_FALSE, &ZG->nwk.handle.parent);
    if (ret != RET_OK) {
        return ret;
    }
    zb_neighbor_tbl_ent_t *nbt;
    ret = zb_nwk_neighbor_get(ZG->nwk.handle.parent, ZB_TRUE, &nbt);
    if (ret != RET_OK) {
        return ret;
    }
    nbt->relationship = ZB_NWK_RELATIONSHIP_PARENT;
    nbt->device_type = ZB_NWK_DEVICE_TYPE_COORDINATOR;
    nbt->rx_on_when_idle = ZB_TRUE;
    nbt->addr_ref = ZG->nwk.handle.parent;
    BDB_CTX().node_is_on_net = data.bdb_node_on_net;
    ZB_NIB_UPDATE_ID() = data.nwk_update_id;
    ZB_NIB_SECURITY_LEVEL() = data.nwk_security_level;
    ZG->nwk.nib.active_key_seq_number = data.nwk_active_key_snum;
    ZB_NIB_DEVICE_TYPE() = data.nwk_dev_type;
    ZB_IEEE_ADDR_COPY(ZB_AIB().trust_center_address, data.aps_tc_addr);
    APL_CTX().free_gr_id_range_begin = data.apl_group_begin;
    APL_CTX().free_gr_id_range_end = data.apl_group_end;
    APL_CTX().free_addr_range_begin = data.apl_addr_begin;
    APL_CTX().free_addr_range_end = data.apl_addr_end;
    char addr[24];
    LOG_DEBUG("restoring extended pan id %s\n", zb_pretty_long_address(
        addr, sizeof(addr), ZB_AIB().aps_use_extended_pan_id));

    LOG_DEBUG("restoring mac short address 0x%04x\n", MAC_PIB().mac_short_address);
    LOG_DEBUG("restoring mac pan id 0x%04x\n", MAC_PIB().mac_pan_id);
#if defined ZB_NWK_DISTRIBUTED_ADDRESS_ASSIGN && defined ZB_ROUTER_ROLE
    LOG_DEBUG("restoring device depth %u\n", ZB_NIB_DEPTH());
#endif
    LOG_DEBUG("restoring channel mask 0x%08lx\n", ZB_AIB().aps_channel_mask);

    return RET_OK;
}

#if defined ZB_SECURITY || defined DOXYGEN

typedef struct {
    uint16_t magic;  /* always "ZB" 0x425a */
    uint8_t key[ZB_CCM_KEY_SIZE];
    uint8_t key_seq_number;
} zb_secur_material_t;

zb_ret_t zb_write_security_key()
{
    if (!has_eeprom) {
        return RET_OK;
    }

    zb_secur_material_t keys[ZB_SECUR_N_SECUR_MATERIAL];

    for (int i = 0; i < ZB_SECUR_N_SECUR_MATERIAL; i++) {

        keys[i].magic = 0x425a;
        memcpy(keys[i].key, ZG->nwk.nib.secur_material_set[i].key,
                                                        sizeof(keys[i].key));
        keys[i].key_seq_number = ZG->nwk.nib.secur_material_set[i].key_seq_number;
    }

    zb_write_nvram(ZB_CONFIG_PAGE + sizeof(zb_config_t) +
                                    sizeof(zb_formdesc_data_t),
                                    &keys, sizeof(keys));
}

zb_ret_t zb_read_security_key()
{
    if (!has_eeprom) {
        return RET_OK;
    }
    zb_secur_material_t keys[ZB_SECUR_N_SECUR_MATERIAL];

    zb_read_nvram(ZB_CONFIG_PAGE + sizeof(zb_config_t) +
                                   sizeof(zb_formdesc_data_t),
                                   &keys, sizeof(keys));

    for (int i = 0; i < ZB_SECUR_N_SECUR_MATERIAL; i++) {

        if (keys[i].magic == 0x425a) {
            memcpy(ZG->nwk.nib.secur_material_set[i].key, keys[i].key,
                                                            sizeof(keys[i].key));
            ZG->nwk.nib.secur_material_set[i].key_seq_number = keys[i].key_seq_number;
        }
    }

    return RET_OK;
}

zb_ret_t zb_write_up_counter()
{
    if (!has_eeprom) {
        return RET_OK;
    }

    zb_uint32_t counter[2];
    
    counter[0] = 0x425a;
    /* ZB 3.0: 4.3.4.1 increment on reboot */
    counter[1] = ZG->nwk.nib.outgoing_frame_counter + 1024;

    zb_write_nvram(ZB_CONFIG_PAGE + sizeof(zb_config_t) +
                                    sizeof(zb_formdesc_data_t) +
                                    sizeof(zb_secur_material_t) * ZB_SECUR_N_SECUR_MATERIAL,
                                    &counter, sizeof(counter));

    return RET_OK;
}

zb_ret_t zb_read_up_counter()
{
    if (!has_eeprom) {
        return RET_OK;
    }

    zb_uint32_t counter[2];

    zb_read_nvram(ZB_CONFIG_PAGE + sizeof(zb_config_t) +
                                    sizeof(zb_formdesc_data_t) +
                                    sizeof(zb_secur_material_t) * ZB_SECUR_N_SECUR_MATERIAL,
                                    &counter, sizeof(counter));

    if (counter[0] != 0x425a) {
        return RET_OK;
    }

    ZG->nwk.nib.outgoing_frame_counter = counter[1];

    return RET_OK;
}

zb_ret_t zb_reset()
{
    zb_erase_nvram(0);
    zb_write_up_counter();
    pm_reboot();
    return RET_OK;
}
#endif

#endif
