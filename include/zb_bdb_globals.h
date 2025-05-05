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

#ifndef ZB_BDB_GLOBALS_H
#define ZB_BDB_GLOBALS_H              1

/*! \addtogroup ZB_BDB */
/*! @{ */
/**
 * bdbcTLPrimaryChannelSet 
 */
#define BDB_TL_PRIMARY_CHANNEL_SET    (0)
/**
 * bdbcRxWindowDuration
 */
#define BDB_RX_WINDOW_DURATION        (0)
/**
 * bdbcTLMinStartupDelayTime
 */
#define BDB_TL_MIN_STARTUP_DELAY_TIME (0)
/* 
    bdbdCommissioningStatus
*/
typedef enum bdb_comm_status_e {
    NOT_PERMITTED,
    NOT_AA_CAPABLE,
    NO_NETWORK
} bdb_comm_status_t;
/*
   Global ZCL structure
 */
typedef struct zb_bdb_globals_s {
    bdb_comm_status_t comm_status;
    zb_bool_t node_is_on_net;
    zb_uint16_t scan_duration;
} zb_bdb_globals_t;

#define BDB_CTX() ZG->bdb

/*! @} */

#endif /* ZB_BDB_GLOBALS_H */
