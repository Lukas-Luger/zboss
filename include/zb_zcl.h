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
   PURPOSE: Zigbee cluster library
 */

#ifndef ZB_ZCL_H
#define ZB_ZCL_H 1

/*! \addtogroup ZB_ZCL */
/*! @{ */

/**
 * General Cluster IDs ZCL 3.1.2 
 */
/* Basic */
#define ZB_BASIC_CLUSTER_ID             0x0000
/* Power Configuration */
#define ZB_PWR_CFG_CLUSTER_ID           0x0001
/* Device Temperature Configuration */
#define ZB_DEV_TMP_CLUSTER_ID           0x0002
/* Identify */
#define ZB_IDENTIFY_CLUSTER_ID          0x0003
/* Groups */
#define ZB_GROUPS_CLUSTER_ID            0x0004
/* Scenes */
#define ZB_SCENES_CLUSTER_ID            0x0005
/* On/Off */
#define ZB_ON_OFF_CLUSTER_ID            0x0006
/* On/Off Switch Configuration */
#define ZB_ON_OFF_SW_CFG_CLUSTER_ID     0x0007
/* Level Control for Lighting */
#define ZB_LVL_CTRL_LIGHT_CLUSTER_ID    0x0008
/* Pulse Width Modulation */
#define ZB_PWM_CLUSTER_ID               0x001c
/* Alarms */
#define ZB_ALARMS_CLUSTER_ID            0x0009
/* Time */
#define ZB_TIME_CLUSTER_ID              0x000a
/* RSSI Location */
#define ZB_RSSI_LOC_CLUSTER_ID          0x000b
/* Diagnostics */
#define ZB_DIAG_CLUSTER_ID              0x0b05
/* Poll Control */
#define ZB_POLL_CTRL_CLUSTER_ID         0x0020
/* Power Profile */
#define ZB_KEEP_ALIVE_CLUSTER_ID        0x0025
/* Analog Input */
#define ZB_ANALOG_INPUT_CLUSTER_ID      0x000c
/* Analog Output */
#define ZB_ANALOG_OUTPUT_CLUSTER_ID     0x000d
/* Analog Value */
#define ZB_ANALOG_VALUE_CLUSTER_ID      0x000e
/* Binary Input */
#define ZB_BINARY_INPUT_CLUSTER_ID      0x000f
/* Binary Output */
#define ZB_BINARY_OUTPUT_CLUSTER_ID     0x0010
/* Binary Value */
#define ZB_BINARY_VALUE_CLUSTER_ID      0x0011
/* Multistate Input */
#define ZB_MULTISTATE_INPUT_CLUSTER_ID  0x0012
/* Multistate Output */
#define ZB_MULTISTATE_OUTPUT_CLUSTER_ID 0x0013
/* Multistate Value */
#define ZB_MULTISTATE_VALUE_CLUSTER_ID  0x0014

/**
 * TODO: Cluster IDs ZCL [4-12].1.2
 */

/**
 * Commissioning Cluster IDs ZCL 13.1.2
 */
/* Commissioning */
#define ZB_COMM_CLUSTER_ID              0x0015
/* Touchlink Commissioning */
#define ZB_ZLL_CLUSTER_ID               0x1000

/**
 * TODO: Cluster IDs ZCL [14-15].1.2
 */

/**
 * Profile IDs
 * from https://www.rfwireless-world.com/terminology/zigbee-profile-device-id-list
 */
/* Industrial Plant Monitoring */
#define ZB_IND_PL_MON_PROFILE_ID    0x0101
/* Home automation*/
#define ZB_HA_PROFILE_ID            0x0104
/* Commercial Building Automation */
#define ZB_COMM_B_AUTOM_PROFILE_ID  0x0105
/* Personal Home and Hospital Care */
#define ZB_HOME_HOSP_PROFILE_ID     0x0108
/* Advanced Metering Initiative */
#define ZB_ADV_METERING_PROFILE_ID  0x0109
/* ZigBee Light Link */
#define ZB_ZLL_PROFILE_ID           0xc05e

/**
 * Device IDs for HA
 * from https://www.rfwireless-world.com/terminology/zigbee-profile-device-id-list
 */
/* ON/OFF Switch */
#define ZB_HA_ON_OFF_SW_DEV_ID      0x0000
/* Level Control Switch */
#define ZB_HA_LVL_CTRL_SW_DEV_ID    0x0001
/* ON/OFF Output */
#define ZB_HA_ON_OFF_OUTP_DEV_ID    0x0002
/* Level Controllable Output */
#define ZB_HA_LVL_CTRL_OUTP_DEV_ID  0x0003
/* Scene Selector */
#define ZB_HA_SCENE_SEL_DEV_ID      0x0004
/* Configuration Tool */
#define ZB_HA_CONF_TOOL_DEV_ID      0x0005
/* Remote control */
#define ZB_HA_REMOTE_CTRL_DEV_ID    0x0006
/* Combined Interface */
#define ZB_HA_COMB_IF_DEV_ID        0x0007
/* Range Extender */
#define ZB_HA_RANGE_EXT_DEV_ID      0x0008
/* Mains Power Outlet */
#define ZB_HA_MAINS_PWR_OUTL_DEV_ID 0x0009

/**
 * Device IDs from
 * ZigBee Lighting & Occupancy Spec. Table 1 
 */
/* ON/OFF Light */
#define ZB_HA_ON_OFF_LIGHT_DEV_ID   0x0100
/* Dimmable Light */
#define ZB_HA_DIMM_LIGHT_DEV_ID     0x0101
/* Color Dimmable Light */
#define ZB_HA_COL_DIMM_L_DEV_ID     0x0102
/* ON/OFF Light Switch */
#define ZB_HA_ON_OFF_L_SW_DEV_ID    0x0103
/* Dimmer Switch */
#define ZB_HA_DIMM_SW_DEV_ID        0x0104
/* Color Dimmer Switch */
#define ZB_HA_COL_DIMM_SW_DEV_ID    0x0105
/* Light Sensor */
#define ZB_HA_LIGHT_SENS_DEV_ID     0x0106
/* Occupancy Sensor */
#define ZB_HA_OCC_SENS_DEV_ID       0x0107
/* ON/OFF Ballast */
#define ZB_HA_ON_OFF_BALL_DEV_ID    0x0108
/* Dimmable Ballast */
#define ZB_HA_DIMM_BALL_DEV_ID      0x0109
/* On/off plug-in unit */
#define ZB_HA_ON_OFF_PLUG_DEV_ID    0x010a
/* Dimmable plug-in unit */
#define ZB_HA_DIMM_PLUG_DEV_ID      0x010b
/* Color temperature light */
#define ZB_HA_COL_TEMP_LIGHT_DEV_ID 0x010c
/* Extended color light */
#define ZB_HA_COLOR_LIGHT_DEV_ID    0x010d
/* Light level sensor */
#define ZB_HA_LVL_SENS_DEV_ID       0x010e
/* Color controller */
#define ZB_HA_COL_CTRL_DEV_ID       0x0800
/* Color scene controller */
#define ZB_HA_COL_SCENE_CTRL_DEV_ID 0x0810
/* Non-color controller */
#define ZB_HA_NON_COL_CTRL_DEV_ID   0x0820
/* Non-color scene controller */
#define ZB_HA_NON_COL_SC_CTR_DEV_ID 0x0830
/* Control bridge */
#define ZB_HA_CTRL_BR_DEV_ID        0x0840
/* On/off sensor */
#define ZB_HA_ON_OFF_SENS_DEV_ID    0x0850

/**
 * Device IDs for HA
 * from https://www.rfwireless-world.com/terminology/zigbee-profile-device-id-list
 */
/* Shade */
#define ZB_HA_SHADE_DEV_ID          0x0200
/* Shade Controller */
#define ZB_HA_SHADE_CTRL_DEV_ID     0x0201
/* Heating/Cooling Unit */
#define ZB_HA_HEAT_COOL_DEV_ID      0x0300
/* Thermostat */
#define ZB_HA_THERMO_DEV_ID         0x0301
/* Temperature Sensor */
#define ZB_HA_TEMP_SENS_DEV_ID      0x0302
/* Pump */
#define ZB_HA_PUMP_DEV_ID           0x0303
/* Pump Controller */
#define ZB_HA_PUMP_CTRL_DEV_ID      0x0304
/* Pressure Sensor */
#define ZB_HA_PRESSURE_SENS_DEV_ID  0x0305
/* Flow sensor */
#define ZB_HA_FLOW_SENS_DEV_ID      0x0306
/* IAS Control and Indicating Equipment */
#define ZB_HA_IAS_CTRL_IND_DEV_ID   0x0400
/* IAS Ancillary Control Equipment */
#define ZB_HA_IAS_ANC_CTRL_DEV_ID   0x0401
/* IAS Zone */
#define ZB_HA_IAS_ZONE_DEV_ID       0x0402
/* IAS Warning Device */
#define ZB_HA_IAS_WARN_DEV_ID       0x0403


/**
   Response for ZLL scan request
 */
typedef struct zb_zll_scan_resp_s {
    zb_uint32_t transaction_id;
    zb_uint8_t rssi_correction;
    zb_uint8_t zigbee_information;
    zb_uint8_t touchlink_information;
    zb_uint16_t key_bitmask;
    zb_uint32_t response_id;
    zb_ieee_addr_t extended_pan_id;
    zb_uint8_t network_update_id;
    zb_uint8_t logical_channel;
    zb_uint16_t pan_id;
    zb_uint16_t network_address;
    zb_uint8_t subdevices;
    zb_uint8_t total_group_identifiers;
    zb_uint8_t endpoint;
    zb_uint16_t profile_id;
    zb_uint16_t device_id;
    zb_uint8_t version;
    zb_uint8_t group_id_count;
} ZB_PACKED_STRUCT
zb_zll_scan_resp_t;

/**
 * Commissioning state
 */
typedef enum zb_zll_comm_state_e {
    ZB_ZLL_COMM_SCAN,
    ZB_ZLL_COMM_SCAN_DONE,
    ZB_ZLL_COMM_INIT_NET,
    ZB_ZLL_COMM_REJOIN,
    ZB_ZLL_COMM_FAIL,
    ZB_ZLL_COMM_SUCCESS,
} zb_zll_comm_state_t;

/**
 * Commissioning attributes
 */
typedef struct zb_zll_comm_attr_s {
    zb_uint8_t zigbee_info;
    zb_uint8_t touchlink_info;
    zb_uint32_t v_scan_channels; /*!< vScanChannels */
    zb_bool_t v_is_first_ch;     /*!< vIsFirstChannel */
    zb_bool_t v_do_prim_scan;    /*!< vDoPrimaryScan */
    zb_zll_comm_state_t state;
    zb_ieee_addr_t responder_addr;
    zb_uint16_t responder_addr_short;
    zb_zll_scan_resp_t scan_response;
    zb_uint8_t initiator_tl_info;
    zb_uint8_t initiator_zb_info;
    zb_uint8_t dev_info_start;
    zb_uint8_t prev_channel;
    zb_bool_t received_join_net;
    zb_buf_t *net_p_buf;
} zb_zll_comm_attr_t;

/**
   Used to define the end of the list
 */
#define ZB_ZCL_END_MARKER 0xffff

/**
   ZCL common command IDs.
 */
typedef enum zb_zcl_cmd_e {
    ZB_ZCL_CMD_READ_ATTRIB          = 0x00,     /*!< Read attributes command */
    ZB_ZCL_CMD_READ_ATTRIB_RESP     = 0x01,     /*!< Read attributes response command */
    ZB_ZCL_CMD_WRITE_ATTRIB         = 0x02,     /*!< Write attributes foundation command */
    ZB_ZCL_CMD_WRITE_ATTRIB_UNDIV   = 0x03,     /*!< Write attributes undivided command */
    ZB_ZCL_CMD_WRITE_ATTRIB_RESP    = 0x04,     /*!< Write attributes response command */
    ZB_ZCL_CMD_WRITE_ATTRIB_NO_RESP = 0x05,     /*!< Write attributes no response command */
    ZB_ZCL_CMD_CONFIG_REPORT        = 0x06,     /*!< Configure reporting command */
    ZB_ZCL_CMD_CONFIG_REPORT_RESP   = 0x07,     /*!< Configure reporting response command */
    ZB_ZCL_CMD_READ_REPORT_CFG      = 0x08,     /*!< Read reporting config command */
    ZB_ZCL_CMD_READ_REPORT_CFG_RESP = 0x09,     /*!< Read reporting config response command */
    ZB_ZCL_CMD_REPORT_ATTRIB        = 0x0a,     /*!< Report attribute command */
    ZB_ZCL_CMD_DEFAULT_RESP         = 0x0b,     /*!< Default response command */
    ZB_ZCL_CMD_DISC_ATTRIB          = 0x0c,     /*!< Discover attributes command */
    ZB_ZCL_CMD_DISC_ATTRIB_RESP     = 0x0d,     /*!< Discover attributes response command */
    ZB_ZCL_CMD_READ_ATTRIB_STRUCT   = 0x0e,     /*!< Read Attributes Structured command */
    ZB_ZCL_CMD_WRITE_ATTRIB_STRUCT  = 0x0f,     /*!< Write Attributes Structured command */
    ZB_ZCL_CMD_WRITE_ATTRIB_STRUCT_RESP = 0x10, /*!< Write Attributes Structured response command */
    ZB_ZCL_CMD_DISC_CMDS_REC        = 0x11,     /*!< Discover Commands Received command */
    ZB_ZCL_CMD_DISC_CMDS_REC_RESP   = 0x12,     /*!< Discover Commands Received Response command */
    ZB_ZCL_CMD_DISC_CMDS_GEN        = 0x13,     /*!< Discover Commands Generated command */
    ZB_ZCL_CMD_DISC_CMDS_GEN_RESP   = 0x14,     /*!< Discover Commands Generated Response command */
    ZB_ZCL_CMD_DISC_ATTRIB_EXT      = 0x15,     /*!< Discover Attributes Extended command */
    ZB_ZCL_CMD_DISC_ATTRIB_EXT_RESP = 0x16      /*!< Discover Attributes Extended Response command */
} zb_zcl_cmd_t;

/**
   ZCL attribute data type values
 */
typedef enum zb_zcl_attr_type_e {
    ZB_ZCL_ATTR_TYPE_NULL           = 0x00, /*!< Null data type */
    /* General data */
    ZB_ZCL_ATTR_TYPE_8BIT           = 0x08, /*!< data8 - 8-bit value data type */
    ZB_ZCL_ATTR_TYPE_16BIT          = 0x09, /*!< data16 - 16-bit value data type */
    ZB_ZCL_ATTR_TYPE_24BIT          = 0x0a, /*!< data24 - 24-bit value data type */
    ZB_ZCL_ATTR_TYPE_32BIT          = 0x0b, /*!< data32 - 32-bit value data type */
    ZB_ZCL_ATTR_TYPE_40BIT          = 0x0c, /*!< data40 - 40-bit value data type */
    ZB_ZCL_ATTR_TYPE_48BIT          = 0x0d, /*!< data48 - 48-bit value data type */
    ZB_ZCL_ATTR_TYPE_56BIT          = 0x0e, /*!< data56 - 56-bit value data type */
    ZB_ZCL_ATTR_TYPE_64BIT          = 0x0f, /*!< data64 - 64-bit value data type */
    /* Logical */
    ZB_ZCL_ATTR_TYPE_BOOL           = 0x10, /*!< bool -  Boolean data type */
    /* Bitmap */
    ZB_ZCL_ATTR_TYPE_8BITMAP        = 0x18, /*!< map8 - 8-bit bitmap data type */
    ZB_ZCL_ATTR_TYPE_16BITMAP       = 0x19, /*!< map16 - 16-bit bitmap data type */
    ZB_ZCL_ATTR_TYPE_24BITMAP       = 0x1a, /*!< map24 - 24-bit bitmap data type */
    ZB_ZCL_ATTR_TYPE_32BITMAP       = 0x1b, /*!< map32 - 32-bit bitmap data type */
    ZB_ZCL_ATTR_TYPE_40BITMAP       = 0x1c, /*!< map40 - 40-bit bitmap data type */
    ZB_ZCL_ATTR_TYPE_48BITMAP       = 0x1d, /*!< map48 - 48-bit bitmap data type */
    ZB_ZCL_ATTR_TYPE_56BITMAP       = 0x1e, /*!< map56 - 56-bit bitmap data type */
    ZB_ZCL_ATTR_TYPE_64BITMAP       = 0x1f, /*!< map64 - 64-bit bitmap data type */
    /* Unsigned integer */
    ZB_ZCL_ATTR_TYPE_U8             = 0x20, /*!< uint8 - Unsigned 8-bit integer data type */
    ZB_ZCL_ATTR_TYPE_U16            = 0x21, /*!< uint16 - Unsigned 16-bit integer data type */
    ZB_ZCL_ATTR_TYPE_U24            = 0x22, /*!< uint24 - Unsigned 14-bit integer data type */
    ZB_ZCL_ATTR_TYPE_U32            = 0x23, /*!< uint32 - Unsigned 32-bit integer data type */
    ZB_ZCL_ATTR_TYPE_U40            = 0x24, /*!< uint40 - Unsigned 40-bit integer data type */
    ZB_ZCL_ATTR_TYPE_U48            = 0x25, /*!< uint48 - Unsigned 48-bit integer data type */
    ZB_ZCL_ATTR_TYPE_U56            = 0x26, /*!< uint56 - Unsigned 56-bit integer data type */
    ZB_ZCL_ATTR_TYPE_U64            = 0x27, /*!< uint64 - Unsigned 64-bit integer data type */
    /* Signed Integer */
    ZB_ZCL_ATTR_TYPE_S8             = 0x28, /*!< uint8  - Signed 8-bit integer data type */
    ZB_ZCL_ATTR_TYPE_S16            = 0x29, /*!< uint16 - Signed 16-bit integer data type */
    ZB_ZCL_ATTR_TYPE_S24            = 0x2a, /*!< uint24 - Signed 14-bit integer data type */
    ZB_ZCL_ATTR_TYPE_S32            = 0x2b, /*!< uint32 - Signed 32-bit integer data type */
    ZB_ZCL_ATTR_TYPE_S40            = 0x2c, /*!< uint40 - Signed 40-bit integer data type */
    ZB_ZCL_ATTR_TYPE_S48            = 0x2d, /*!< uint48 - Signed 48-bit integer data type */
    ZB_ZCL_ATTR_TYPE_S56            = 0x2e, /*!< uint56 - Signed 56-bit integer data type */
    ZB_ZCL_ATTR_TYPE_S64            = 0x2f, /*!< uint64 - Signed 64-bit integer data type */
    /* Enumeration */
    ZB_ZCL_ATTR_TYPE_ENUM8          = 0x30, /*!< enum8 - 8-bit Enumeration data type */
    ZB_ZCL_ATTR_TYPE_ENUM16         = 0x31, /*!< enum16 - 16-bit Enumeration data type */
    /* Floating point */
    ZB_ZCL_ATTR_TYPE_FLOAT16        = 0x38, /*!< semi - 16-bit Semi-precision data type */
    ZB_ZCL_ATTR_TYPE_FLOAT32        = 0x39, /*!< single - 32-bit Single-precision data type */
    ZB_ZCL_ATTR_TYPE_FLOAT64        = 0x3a, /*!< double - 64-bit Double-precision data type */
    /* String */
    ZB_ZCL_ATTR_TYPE_BYTE_ARRAY     = 0x41, /*!< octstr - Byte array data type */
    ZB_ZCL_ATTR_TYPE_CHAR_STRING    = 0x42, /*!< string - Charactery string (array) data type */
    ZB_ZCL_ATTR_TYPE_LONG_ARRAY     = 0x43, /*!< octstr16 - Long byte array data type */
    ZB_ZCL_ATTR_TYPE_LONG_STRING    = 0x44, /*!< string16 - Long Charactery string (array) data type */
    /* Ordered Sequence */
    ZB_ZCL_ATTR_TYPE_ARRAY          = 0x48, /*!< array - Array data type */
    ZB_ZCL_ATTR_TYPE_STRUCT         = 0x4c, /*!< struct - Structure data type */
    /* Collection */
    ZB_ZCL_ATTR_TYPE_SET            = 0x50, /*!< set - Set data type */
    ZB_ZCL_ATTR_TYPE_BAG            = 0x51, /*!< bag - Bag data type */
    /* Time */
    ZB_ZCL_ATTR_TYPE_TOD            = 0xe0, /*!< ToD - Time of Day data type */
    ZB_ZCL_ATTR_TYPE_DATE           = 0xe1, /*!< date - Date data type */
    ZB_ZCL_ATTR_TYPE_UTC            = 0xe2, /*!< UTC - UTC Time data type */
    /* Identifier */
    ZB_ZCL_ATTR_TYPE_CLUSTER_ID     = 0xe8, /*!< clusterId - Cluster ID data type */
    ZB_ZCL_ATTR_TYPE_ATTR_ID        = 0xe9, /*!< attribId - Attribute ID data type */
    ZB_ZCL_ATTR_TYPE_BAC_OID        = 0xea, /*!< bacOID - BACnet OID data type */
    /* Miscellaneous */
    ZB_ZCL_ATTR_TYPE_IEEE_ADDR      = 0xf0, /*!< IEEE address (U64) type */
    ZB_ZCL_ATTR_TYPE_SEC_KEY        = 0xf1, /*!< key128 - 128-bit security key data type */
    ZB_ZCL_ATTR_TYPE_INVALID        = 0xff  /*!< Invalid data type */
} zb_zcl_attr_type_t;

/**
   ZCL attribute access values
 */
typedef enum zb_zcl_attr_access_e {
    ZB_ZCL_ATTR_ACCESS_READ_ONLY    = 0x00, /*!< Attribute is read only */
    ZB_ZCL_ATTR_ACCESS_READ_WRITE   = 0x01  /*!< Attribute is read/write */
} zb_zcl_attr_access_t;

/**
   ZCL status values.
 */
typedef enum zb_zcl_status_e {
    ZB_ZCL_STATUS_SUCCESS               = 0x00,     /*!< ZCL Success */
    ZB_ZCL_STATUS_FAIL                  = 0x01,     /*!< ZCL Fail */
    ZB_ZCL_STATUS_NOT_AUTHORIZED        = 0x7e,     /*!< Not authorized */
    ZB_ZCL_STATUS_RESERVED_FIELD_NZ     = 0x7f,     /*!< Reserved field non-zero */
    ZB_ZCL_STATUS_MALFORMED_CMD         = 0x80,     /*!< Malformed command */
    ZB_ZCL_STATUS_UNSUP_CLUST_CMD       = 0x81,     /*!< Unsupported cluster
                                                       command */
    ZB_ZCL_STATUS_UNSUP_GEN_CMD         = 0x82,     /*!< Unsupported general
                                                       command */
    ZB_ZCL_STATUS_UNSUP_MANUF_CLUST_CMD = 0x83,     /*!< Unsupported manuf-specific
                                                       clust command */
    ZB_ZCL_STATUS_UNSUP_MANUF_GEN_CMD   = 0x84,     /*!< Unsupported manuf-specific
                                                       general command */
    ZB_ZCL_STATUS_INVALID_FIELD         = 0x85,     /*!< Invalid field */
    ZB_ZCL_STATUS_UNSUP_ATTRIB          = 0x86,     /*!< Unsupported attribute */
    ZB_ZCL_STATUS_INVALID_VALUE         = 0x87,     /*!< Invalid value */
    ZB_ZCL_STATUS_READ_ONLY             = 0x88,     /*!< Read only */
    ZB_ZCL_STATUS_INSUFF_SPACE          = 0x89,     /*!< Insufficient space */
    ZB_ZCL_STATUS_DUPE_EXISTS           = 0x8a,     /*!< Duplicate exists */
    ZB_ZCL_STATUS_NOT_FOUND             = 0x8b,     /*!< Not found */
    ZB_ZCL_STATUS_UNREPORTABLE_ATTRIB   = 0x8c,     /*!< Unreportable attribute */
    ZB_ZCL_STATUS_INVALID_TYPE          = 0x8d,     /*!< Invalid type */
    ZB_ZCL_STATUS_INVALID_SELECTOR      = 0x8e,     /*!< Invalid attribute selector */
    ZB_ZCL_STATUS_WRITE_ONLY            = 0x8f,     /*!< Write only */
    ZB_ZCL_STATUS_INCON_STARTUP_STATE   = 0x90,     /*!< Inconsistent startup state */
    ZB_ZCL_STATUS_DEFINED_OUT_OF_BAND   = 0x91,     /*!< Write attribute present but defined out-of-band */
    ZB_ZCL_STATUS_INCONSISTENT          = 0x92,     /*!< Supplied values are inconsistent */
    ZB_ZCL_STATUS_ACTION_DENIED         = 0x93,     /*!< Credenntials are not sufficient */
    ZB_ZCL_STATUS_TIMEOUT               = 0x94,     /*!< exchange aborted due to excessive resp time */
    ZB_ZCL_STATUS_ABORT                 = 0x95,     /*!< Client or Server aborts upgrade process */
    ZB_ZCL_STATUS_INVALID_IMAGE         = 0x96,     /*!< Invalid OTA image*/
    ZB_ZCL_STATUS_WAIT_FOR_DATA         = 0x97,     /*!< Server has not have datablock yet */
    ZB_ZCL_STATUS_NO_IMAGE_AVAILABLE    = 0x98,     /*!< No image available for client */
    ZB_ZCL_STATUS_REQUIRE_MORE_IMAGE    = 0x99,     /*!< Client requires more image files */
    ZB_ZCL_STATUS_HW_FAIL               = 0xc0,     /*!< Hardware failure */
    ZB_ZCL_STATUS_SW_FAIL               = 0xc1,     /*!< Software failure */
    ZB_ZCL_STATUS_CALIB_ERR             = 0xc2,     /*!< Calibration error */
    ZB_ZCL_STATUS_UNSUPPORTED_CLUSTER   = 0xc3,     /*!< Cluster is not supported */
    ZB_ZCL_STATUS_DISC_COMPLETE         = 0x01,     /*!< Discovery complete */
    ZB_ZCL_STATUS_DISC_INCOMPLETE       = 0x00      /*!< Discovery incomplete */
} zb_zcl_status_t;


/**
   ZCL frame type
 */
typedef enum zb_zcl_frame_type_e {
    ZB_ZCL_FRAME_TYPE_COMMON            = 0x00, /*!< Command acts across the
                                                 * entire profile  */
    ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED = 0x01  /*!< Command is specific to a
                                                 * cluster */
} zb_zcl_frame_type_t;

/**
   ZCL frame direction
 */
typedef enum zb_zcl_frame_direction_e {
    ZB_ZCL_FRAME_DIRECTION_TO_SRV   = 0x00,
    ZB_ZCL_FRAME_DIRECTION_TO_CLI   = 0x01
} zb_zcl_frame_direction_t;

/**
  ZCL cluster role
 */
typedef enum zb_zcl_cluster_role_e {
    ZB_ZCL_SERVER_ROLE = 0x01,
    ZB_ZCL_CLIENT_ROLE = 0x02
} zb_zcl_cluster_role_t;
/**
   ZCL attribute structure
 */
typedef struct zb_zcl_attr_s {
    zb_uint16_t id;                 /*!< Attribute id */
    zb_zcl_attr_type_t type;        /*!< Attribute type @see zb_zcl_attr_type_t */
    zb_zcl_attr_access_t access;    /*!< Attribute access options @ see
                                     * zb_zcl_attr_access_t */
    zb_voidp_t data_p;              /*!< Pointer to data */
} zb_zcl_attr_t;

#define ZB_ZCL_SET_ATTRIBUTE(attr, id, type, access, _data_p) \
    {                                                          \
        attr->id = id;                                           \
        attr->type = type;                                       \
        attr->access = access;                                   \
        attr->data_p = _data_p;                                       \
    }

typedef enum zb_zcl_attr_reporting_status_e {
    ZB_ZCL_ATTR_REPORTING_PENDING       = 0x00,
    ZB_ZCL_ATTR_REPORTING_COMPLETE      = 0x01
} zb_zcl_attr_reporting_status_t;

typedef struct zb_zcl_global_attrs_s {
    zb_uint16_t cluster_revision;
    zb_zcl_attr_reporting_status_t reporting_status;
} zb_zcl_global_attrs_t;
/**
   ZCL cluster structure
 */
typedef struct zb_zcl_cluster_s zb_zcl_cluster_t;

struct zb_zcl_cluster_s {
    zb_uint8_t ep;              /*!< Endpoint that cluster belongs to */
    zb_uint16_t cluster_id;     /*!< Cluster ID */
    zb_zcl_cluster_role_t role; /*!< Cluster role (Server or Client)*/
    zb_zcl_attr_t attr_list[64];   /*!< Cluster attribute list */
    zb_uint8_t attr_count;
    zb_void_t (*handle)(zb_uint16_t, zb_uint8_t, zb_uint16_t, zb_uint8_t,
                        zb_zcl_cluster_t *) ZB_SDCC_REENTRANT;                                  /*!< Function to handle frames addressed to that cluster */
    zb_void_t (*action)(zb_uint16_t, zb_uint8_t, zb_uint16_t, zb_uint8_t,
                        zb_zcl_cluster_t *);                                                    /*!< Cluster action handler */
};

/**
   ZCL frame control field
 */
typedef struct zb_zcl_frame_ctrl_s {
    zb_bitfield_t frame_type : 2;       /*!< Frame type @see zb_zcl_frame_type_t */
    zb_bitfield_t manufacturer : 1;     /*!< Manufacturer specific frame */
    zb_bitfield_t direction : 1;        /*!< Direction */
    zb_bitfield_t disable_def_resp : 1; /*!< Disable default response */
    zb_bitfield_t reserved : 3;
} ZB_PACKED_STRUCT
zb_zcl_frame_ctrl_t;

/**
   ZCL frame header with manufacturer code
 */
typedef struct zb_zcl_hdr_full_s {
    zb_zcl_frame_ctrl_t frame_control; /*!< Frame control filed @see zb_zcl_frame_ctrl_t */
    zb_uint16_t manufacturer_code;  /*!< Manufacturer Code */
    zb_uint8_t seq_number;          /*!< Transaction Sequence Number */
    zb_uint8_t command_id;          /*!< Command Identifier Field */
} ZB_PACKED_STRUCT
zb_zcl_hdr_full_t;

/**
   ZCL frame header without manufacturer code
 */
typedef struct zb_zcl_hdr_s {
    zb_zcl_frame_ctrl_t frame_control; /*!< Frame control filed @see zb_zcl_frame_ctrl_t */
    zb_uint8_t seq_number;          /*!< Transaction Sequence Number */
    zb_uint8_t command_id;          /*!< Command Identifier Field */
} ZB_PACKED_STRUCT
zb_zcl_hdr_t;

/**
   Get ZCL frame type
 */
#define ZB_ZCL_FCTL_GET_TYPE(p) ((zb_zcl_frame_type_t)(((zb_zcl_frame_ctrl_t *)p) \
                                                       ->frame_type))

/**
   Get true if ZCL frame is manufacturer specific
 */
#define ZB_ZCL_FCTL_GET_MANUFACTURER(p) (((zb_zcl_frame_ctrl_t *)p)-> \
                                         manufacturer)

/**
   Get ZCL frame direction
 */
#define ZB_ZCL_FCTL_GET_DIRECTION(p) (((zb_zcl_frame_ctrl_t *)p)->direction)

/**
   Get ZCL frame response field
 */
#define ZB_ZCL_FCTL_GET_DISABLE_RESP(p) (((zb_zcl_frame_ctrl_t *)p)-> \
                                         disable_def_resp)

/**
   Caclulate ZCL frame header size
 */
#define ZB_ZCL_FRAME_HDR_GET_SIZE(p) (ZB_ZCL_FCTL_GET_MANUFACTURER(p) ? \
                                      sizeof(zb_zcl_hdr_full_t) : \
                                      sizeof(zb_zcl_hdr_t))

/**
   Get ZCL frame manufacturer code
 */
#define ZB_ZCL_FRAME_HDR_GET_MANUFACTURER_CODE(p) (*(zb_uint16_t *)((zb_uint8_t \
                                                                     *)p + \
                                                                    sizeof( \
                                                                        zb_zcl_frame_ctrl_t)))

/**
   Get ZCL frame sequence number
 */
#define ZB_ZCL_FRAME_HDR_GET_SEQ_NUM(p) (*((zb_uint8_t *)p             \
                                           + sizeof(zb_zcl_frame_ctrl_t) \
                                           + (ZB_ZCL_FCTL_GET_MANUFACTURER(p) ? \
                                              sizeof(zb_uint16_t) : 0)))

/**
   Get ZCL frame command identifier
 */
#define ZB_ZCL_FRAME_HDR_GET_COMMAND_ID(p) (*((zb_uint8_t *)p          \
                                              + sizeof(zb_zcl_frame_ctrl_t) \
                                              + (ZB_ZCL_FCTL_GET_MANUFACTURER(p) \
                                                 ? sizeof(zb_uint16_t) : 0) \
                                              + sizeof(zb_uint8_t)))
/**
   Return next sequence number for ZCL frame
 */
#define ZB_ZCL_GET_SEQ_NUM() (ZCL_CTX().seq_number++)

/**
 * Global default cluster revision
 */
#define ZB_ZCL_DEFAULT_CLUSTER_REVISION()         ((zb_uint16_t)1)

/**
 * Default max array length
 */
#define ZB_ZCL_ATTR_MAX_ARRAY_LENGTH        50
/**
   Initialize Zigbee cluster library
 */
void zb_zcl_init();

/**
   Register new cluster

   @param ep - Endpoint that cluster belogs to
   @param cluster_id - Cluster ID
   @param attr_list - Pointer to cluster attribute list @see zb_zcl_attr_t
   @param handle - Cluster handle function. All frames for this cluster will go
   here to get processed
   @param action - Cluster action handle.

   @return Pointer to cluster structure on success, NULL otherwise
 */
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
                                                         zb_zcl_cluster_t *));

/**
   Find cluster by cluster_id

   @param cluster_id - Cluster ID to be found

   @return Pointer to cluster structure if cluster found, NULL otherwise
 */
zb_zcl_cluster_t *zb_zcl_find_cluster(zb_uint16_t cluster_id);

/**
   Find attribute by attribute_id

   @param cluster - Cluster containing attributes
   @param attribute_id - Attribute ID to be found

   @return Pointer to attribute structure if attribute found, NULL otherwise
 */
zb_zcl_attr_t *zb_zcl_find_attribute(zb_zcl_cluster_t *cluster,
                                     zb_uint16_t attribute_id);

/**
   Calculate attribute size in butes

   @param attr - Attribute to calculate size

   @return Attribute size in bytes
 */
zb_uint8_t zb_zcl_get_attribute_size(zb_zcl_attr_t *attr);

/**
  Creates an attribute and adds it to a cluster

  @param cluster - Cluster to add Attributes to
  @param attr_id - Attribute ID
  @param type - Attribute type (see zb_zcl_attr_type_t)
  @param access - Access permissions (see zb_zcl_attr_access_t)
  @param data_p - pointer to data

  @return nothing
 */
void zb_zcl_add_attribute(zb_zcl_cluster_t *cluster, zb_uint16_t attr_id,
                          zb_zcl_attr_type_t type, zb_zcl_attr_access_t access,
                          zb_voidp_t data_p);
/**
   Main function to handle ZCL commands

   @param src_addr - Addrees of the device that send this frame
   @param src_ep - Endpoint of the source device
   @param profile_id - Profile ID
   @param buf - Incoming buffer with ZCL frame
   @param cluster - Pointer to the cluster that buffer belogs to

   @return nothing
 */
void zb_zcl_handle(zb_uint8_t param, zb_zcl_cluster_t *cluster);


/**
   Generate defaul response command

   @param buf - Buffer to generate the response
   @param status - Response status
   @param seq_number - Sequence number of the request
   @param command_id - Command ID

   @return nothing
 */
void zb_zcl_gen_default_resp(zb_buf_t *buf, zb_zcl_status_t status,
                             zb_uint8_t seq_number, zb_uint8_t command_id);

/**
 * Handle a group request received from a peer
 *
 * @param param - packet buffer to operate on
 *
 * @return nothing
 */
void zb_zcl_handle_group_request(zb_uint8_t param);


/**
   DeInitialize Zigbee cluster library
 */
void zb_zcl_deinit();

void zll_start_tl_scan();

void zll_nwk_rejoin();

void zll_nwk_rejoin_cb();

void zll_nwk_direct_join_cb();

void zll_nwk_leave_conf_cb();

void zll_nwk_start_router_conf_cb();

void zll_nwk_disc_conf_cb(zb_uint8_t param);

/*! @} */

#endif /* ZB_ZCL_H */
