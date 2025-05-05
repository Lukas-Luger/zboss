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
   PURPOSE: Zigbee application layer globals definition
 */

#ifndef ZB_APL_GLOBALS_H
#define ZB_APL_GLOBALS_H        1

/*! \addtogroup ZB_ZCL */
/*! @{ */

/**
 * aplcInterPANTransIdLifetime 8 sec
 */
#define INTRP_TRANS_ID_LIFETIME ZB_MILLISECONDS_TO_BEACON_INTERVAL(8000)

/**
 * aplcMinStartupDelayTime 2 sec
 */
#define MIN_STARTUP_DELAY_TIME  ZB_MILLISECONDS_TO_BEACON_INTERVAL(2000)

/**
 * aplcRxWindowDuration 5 sec
 */
#define RX_WINDOW_DURATION      ZB_MILLISECONDS_TO_BEACON_INTERVAL(5000)

/**
 * aplcScanTimeBaseDuration 0.25 sec
 */
#define SCAN_TIME_BASE_DURATION ZB_MILLISECONDS_TO_BEACON_INTERVAL(250)

/**
 * device information table (holds app info, so this should be the right place)
 */
#define ZB_APL_MAX_DEV_ENTRIES  10

typedef struct zb_apl_dev_info_ent_s {
    zb_ieee_addr_t long_addr;  /*!< IEEE address of each node */
    zb_uint8_t endpoint;       /*!< Endpoint choosen by application */
    zb_uint16_t profile_id;    /*!< corresponds to application profile ID */
    zb_uint16_t device_id;     /*!< corresponds to application device ID */
    zb_uint8_t version;        /*!< 4 Bit device version of subdevice */
    zb_uint8_t group_id_count; /*!< number of unique group identifiers */
    zb_uint8_t sort;           /*!< sort tag, indicating an order, 0 = unordered */
} zb_apl_dev_info_ent_t;
/**
   Global ZCL structure
 */
typedef struct zb_apl_globals_s {
    zb_uint16_t addr_in_use;
    zb_uint16_t free_addr_range_begin;                          /*!< APL addr range */
    zb_uint16_t free_addr_range_end;                            /*!< APL addr range */
    zb_uint16_t free_gr_id_range_begin;                         /*!< APL group id range */
    zb_uint16_t free_gr_id_range_end;                           /*!< APL group id range */
    zb_uint8_t dev_info_used;                                   /*!< Number of entries in table*/
    zb_apl_dev_info_ent_t dev_info_tbl[ZB_APL_MAX_DEV_ENTRIES]; /*!< device information table*/
} zb_apl_globals_t;

#define APL_CTX() ZG->apl

/*! @} */

#endif /* ZB_APL_GLOBALS_H */
