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
   PURPOSE: Zigbee base device behaviour globals definition
 */

#include "zb_types.h"
#ifndef ZB_BDB_GLOBALS_H
#define ZB_BDB_GLOBALS_H              1

/*! \addtogroup ZB_BDB */
/*! @{ */
/**
 * bdbcMaxSameNetworkRetryAttempts
 */
#define BDB_MAX_SAME_NET_RETRIES       (10)
/**
 * bdbcMinCommissioningTime 180s
 */
#define BDB_MIN_COMM_TIME              (180 * ZB_TIME_ONE_SECOND)
/**
 * bdbcRecSameNetworkRetryAttempts (Recommended)
 */
#define BDB_REC_SAME_NET_RETRIES       (3)
/**
 * bdbcTCLinkKeyExchangeTimeout 5s
 */
#define BDB_TC_LINK_KEY_EX_TIMEOUT     (5 * ZB_TIME_ONE_SECOND)
/**
 * bdbcTLInterPANTransIdLifetime
 */
#define BDB_TL_INTRP_TRANS_ID_LIFETIME (8 * ZB_TIME_ONE_SECOND)
/**
 * bdbcTLMinStartupDelayTime
 */
#define BDB_TL_MIN_STARTUP_DELAY_TIME  (2 * ZB_TIME_ONE_SECOND)
/**
 * bdbcTLPrimaryChannelSet 
 */
#define BDB_TL_PRIMARY_CHANNEL_SET     (0x02108800)
/**
 * bdbcRxWindowDuration
 */
#define BDB_RX_WINDOW_DURATION         (5 * ZB_TIME_ONE_SECOND)
/**
 * bdbcTLScanTimeBaseDuration
 */
#define BDB_TL_SCAN_TIME_DURATION      (ZB_MILLISECONDS_TO_BEACON_INTERVAL(250))
/**
 * bdbcTLSecondaryChannelSet
 */
 #define BDB_TL_SECONDARY_CHANNEL_SET  (0x05ef7000)
/* 
    bdbdCommissioningStatus
*/
typedef enum bdb_comm_status_e {
    SUCCESS,
    IN_PROGRESS,
    NOT_AA_CAPABLE,
    NO_NETWORK,
    TARGET_FAILURE,
    FORMATION_FAILURE,
    NO_IDENTIFY_QUERY_RESPONSE,
    BINDING_TABLE_FULL,
    NO_SCAN_RESPONSE,
    NOT_PERMITTED,
    TCLK_EX_FAILURE
} bdb_comm_status_t;
/*
   Global ZCL structure
 */
typedef struct zb_bdb_globals_s {
    zb_uint16_t comm_group_id;              /*!< bdbCommissioningGroupID */
    zb_uint8_t comm_mode;                   /*!< bdbCommissioningMode */
    bdb_comm_status_t comm_status;          /*!< bdbCommissioningStatus */
    zb_ieee_addr_t joining_node;            /*!< bdbJoiningNodeEui64 */
    zb_uint8_t new_tc_key[ZB_CCM_KEY_SIZE]; /*!< bdbJoiningNodeNewTCLinkKey */
    zb_bool_t use_install_code;             /*!< bdbJoinUsesInstallCodeKey */
    zb_uint8_t comm_capability;             /*!< bdbNodeCommissioningCapability*/
    zb_bool_t node_is_on_net;               /*!< bdbNodeIsOnANetwork */
    zb_uint8_t node_join_linkkey_type;      /*!< bdbNodeJoinLinkKeyType */
    zb_uint32_t primary_channel_set;        /*!< bdbPrimaryChannelSet */
    zb_uint8_t scan_duration;               /*!< bdbScanDuration */
    zb_uint32_t secondary_channel_set;      /*!< bdbSecondaryChannelSet */
    zb_uint8_t tc_linkkey_ex_attempts;      /*!< bdbTCLinkKeyExchangeAttempts */
    zb_uint8_t tc_linkkey_ex_attempts_max;  /*!< bdbTCLinkKeyExchangeAttemptsMax */
    zb_uint8_t tc_linkkey_ex_method;        /*!< bdbTCLinkKeyExchangeMethod */
    zb_uint8_t tc_node_join_timeout;        /*!< bdbTrustCenterNodeJoinTimeout */
    zb_bool_t tc_require_key_ex;            /*!< bdbTrustCenterRequireKeyExchange */
} zb_bdb_globals_t;

#define BDB_CTX() ZG->bdb

/*! @} */

#endif /* ZB_BDB_GLOBALS_H */
