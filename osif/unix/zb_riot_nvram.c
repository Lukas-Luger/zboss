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

#include "zb_bank_common.h"

#if defined ZB_USE_NVRAM

extern bool has_eeprom;
extern uint16_t g_group_id;

typedef struct __attribute__((packed)) {
    uint16_t        magic; /* always "ZB" 0x425a */
    uint8_t         designated_coordinator : 1;
    uint8_t         insecure_join : 1;
    zb_ieee_addr_t  extended_address;
} zb_config_t;

zb_ret_t zb_save_nvram_config(void)
{
    if (!has_eeprom) {
        return RET_OK;
    }

    zb_config_t config;
    config.magic = 0x425a;
    config.designated_coordinator = ZB_AIB().aps_designated_coordinator;
    config.insecure_join = ZB_AIB().aps_insecure_join;
    ZB_IEEE_ADDR_COPY(config.extended_address, MAC_PIB().mac_extended_address);

    zb_write_nvram(ZB_CONFIG_PAGE, &config, sizeof(config));

    return RET_OK;
}

zb_ret_t zb_config_from_nvram(void)
{
    if (!has_eeprom) {
        return RET_OK;
    }

    zb_config_t config;
    zb_read_nvram(ZB_CONFIG_PAGE, &config, sizeof(config));

    if (config.magic != 0x425a) {
        return RET_OK;
    }

    ZB_AIB().aps_designated_coordinator = config.designated_coordinator;
    ZB_AIB().aps_insecure_join = config.insecure_join;
//     ZB_IEEE_ADDR_COPY(MAC_PIB().mac_extended_address, config.extended_address);

//     ZB_UPDATE_LONGMAC();

    return RET_OK;
}

typedef struct __attribute__((packed)) {
    uint16_t            magic; /* always "ZB" 0x425a */
    uint8_t             profile_in_use;
    zb_ieee_addr_t      long_parent_addr;
    uint32_t            channel_mask;
    uint16_t            short_parent_addr;
    uint8_t             depth;
    uint16_t            pan_id;
    zb_ext_pan_id_t     ext_pan_id;
    uint16_t            short_addr;
    uint16_t            group_id;
} zb_formdesc_data_t;

zb_ret_t zb_save_formdesc_data(void)
{
    if (!has_eeprom) {
        return RET_OK;
    }

    zb_formdesc_data_t data;
    data.magic = 0x425a;

    zb_uint8_t profile_in_use = 0;
    zb_uint16_t short_parent_addr;
    zb_ieee_addr_t long_parent_addr;

    zb_address_short_by_ref(&short_parent_addr, ZG->nwk.handle.parent);
    zb_address_ieee_by_ref(long_parent_addr, ZG->nwk.handle.parent);

    data.depth = ZB_NIB_DEPTH();
    data.profile_in_use = profile_in_use;
    memcpy(&data.group_id, &g_group_id, sizeof(g_group_id));
    memcpy(&data.pan_id, &MAC_PIB().mac_pan_id, sizeof(data.pan_id));
    memcpy(&data.short_parent_addr, &short_parent_addr,
                                            sizeof(short_parent_addr));
    memcpy(&data.short_addr, &MAC_PIB().mac_short_address,
                                                sizeof(data.short_addr));
    memcpy(&data.channel_mask, &ZB_AIB().aps_channel_mask,
                                                sizeof(data.channel_mask));
    ZB_IEEE_ADDR_COPY(data.long_parent_addr, long_parent_addr);
    ZB_IEEE_ADDR_COPY(data.ext_pan_id, ZB_AIB().aps_use_extended_pan_id);

    zb_write_nvram(ZB_CONFIG_PAGE + sizeof(zb_config_t), &data, sizeof(data));

    return RET_OK;
}

zb_ret_t zb_read_formdesc_data(void)
{
    if (!has_eeprom) {
        return RET_OK;
    }

    zb_formdesc_data_t data;
    zb_read_nvram(ZB_CONFIG_PAGE + sizeof(zb_config_t), &data, sizeof(data));

    if (data.magic != 0x425a) {
        return RET_OK;
    }

    ZB_NIB_DEPTH() = data.depth;
    memcpy(&g_group_id, &data.group_id, sizeof(g_group_id));
    memcpy(&MAC_PIB().mac_pan_id, &data.pan_id, sizeof(data.pan_id));
    memcpy(&ZB_AIB().aps_channel_mask, &data.channel_mask,
                                                    sizeof(data.channel_mask));
    memcpy(&MAC_PIB().mac_short_address, &data.short_addr,
                                                    sizeof(data.short_addr));

    ZB_UPDATE_PAN_ID();
    ZB_UPDATE_SHORT_ADDR();
    ZB_IEEE_ADDR_COPY(ZB_AIB().aps_use_extended_pan_id, data.ext_pan_id);
    ZB_IEEE_ADDR_COPY(ZB_PIB_BEACON_PAYLOAD().extended_panid, data.ext_pan_id);

    /* parent short addr */
    /* parent long addr */

    char addr[24];
    printf("restoring extended pan id %s\n", zb_pretty_long_address(
        addr, sizeof(addr), ZB_AIB().aps_use_extended_pan_id));

    printf("restoring mac short address 0x%04x\n", MAC_PIB().mac_short_address);
    printf("restoring mac pan id 0x%04x\n", MAC_PIB().mac_pan_id);
    printf("restoring group id 0x%04x\n", g_group_id);

    printf("restoring device depth %u\n", ZB_NIB_DEPTH());
    printf("restoring channel mask 0x%08lx\n", ZB_AIB().aps_channel_mask);

    return RET_OK;
}

#if defined ZB_SECURITY || defined DOXYGEN

typedef struct {
    uint16_t magic;  /* always "ZB" 0x425a */
    uint8_t key[ZB_CCM_KEY_SIZE];
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

    for (int i = 0; i < ZB_SECUR_N_SECUR_MATERIAL; i++) {

        zb_secur_material_t key;
        zb_read_nvram(ZB_CONFIG_PAGE +
                        sizeof(zb_config_t) + sizeof(zb_formdesc_data_t),
                        &key, sizeof(key));
        if (key.magic == 0x425a) {
            memcpy(ZG->nwk.nib.secur_material_set[i].key, key.key,
                                                            sizeof(key.key));
        }
    }

    return RET_OK;
}

zb_ret_t zb_write_up_counter()
{
    if (!has_eeprom) {
        return RET_OK;
    }

//    zb_uint8_t buf[ZB_SCRATCHPAD_PAGE_SIZE];
//    zb_uint8_t i;
//
//    zb_read_nvram(ZB_VOLATILE_PAGE, buf, ZB_SCRATCHPAD_PAGE_SIZE);
//    if (buf[ZB_SCRATCHPAD_PAGE_SIZE-3]!=0xFF)
//       {
// //              zb_erase_nvram(1);
//              zb_write_nvram(ZB_VOLATILE_PAGE, (zb_uint8_t *) &ZG->nwk.nib.outgoing_frame_counter, sizeof(ZG->nwk.nib.outgoing_frame_counter));
//       }
//    else
//    {
//     for (i = ZB_SCRATCHPAD_PAGE_SIZE; i>=0; i--)
//     {
//         if (((buf[i]!=0xFF)&&(i<ZB_SCRATCHPAD_PAGE_SIZE))||(i == 0))
//         {
//           zb_write_nvram(ZB_VOLATILE_PAGE+i+1*(i&0x01), (zb_uint8_t *) &ZG->nwk.nib.outgoing_frame_counter, sizeof(ZG->nwk.nib.outgoing_frame_counter));
//           break;
//         }
//     }
//    }

    return RET_OK;
}

zb_ret_t zb_read_up_counter()
{
    if (!has_eeprom) {
        return RET_OK;
    }

//    zb_uint8_t i;
//    zb_uint8_t buf[ZB_SCRATCHPAD_PAGE_SIZE];
//    zb_read_nvram(ZB_VOLATILE_PAGE, buf, ZB_SCRATCHPAD_PAGE_SIZE);
//    for (i = ZB_SCRATCHPAD_PAGE_SIZE-1; i>=0; i--)
//    {
//       if ((buf[i]!=0xFF)&&(i>3)) /* i>3 just check if some garbage in nvram, because we always put an 4bytes value*/
//       {
//         ZG->nwk.nib.outgoing_frame_counter = *(zb_uint32_t*) (buf+i-3);
//         break;
//       }
//    }

    return RET_OK;
}
#endif

#endif
