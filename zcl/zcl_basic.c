#include "zb_common.h"
#include "zb_aps.h"
#include "zb_zdo.h"
#include "zb_zcl_basic.h"
#include "zcl_internal.h"
#include "log.h"

zb_zcl_global_attrs_t basic_global_attrs;
/**
 * Server Side
 */
void zb_zcl_basic_srv_set_defaults(zb_zcl_basic_srv_attr_t *attrs)
{
    attrs->zcl_version = 8;
    attrs->app_version = 0;
    attrs->stack_version = 0;
    attrs->hw_version = 0;
    attrs->manufacturer_name[0] = 0;
    attrs->manufacturer_name_len = 0;
    attrs->model_id[0] = 0;
    attrs->model_id_len = 0;
    attrs->date_code[0] = 0;
    attrs->date_code_len = 0;
    attrs->power_source = ZB_ZCL_BASIC_POWER_SRC_UNKNOWN;
    attrs->generic_device_class = 0xff;
    attrs->generic_device_type = 0xff;
    attrs->product_code_id = ZB_ZCL_BASIC_PRODUCT_CODE_MAN_DEFINED;
    attrs->product_code[0] = 0;
    attrs->product_code_len = 0;
    attrs->product_url[0] = 0;
    attrs->product_url_len = 0;
    attrs->man_version_details[0] = 0;
    attrs->man_version_details_len = 0;
    attrs->serial_number[0] = 0;
    attrs->serial_number_len = 0;
    attrs->product_label[0] = 0;
    attrs->product_label_len = 0;
    attrs->location_desc[0] = 0;
    attrs->location_desc_len = 0;
    attrs->phys_environment = ZB_ZCL_BASIC_PHYS_ENV_UNSPEC;
    attrs->device_enabled = ZB_ZCL_BASIC_DEV_ENABLED;
    attrs->alarm_mask = 0;
    attrs->disable_local_conf = 0;
    attrs->software_build_id[0];
    attrs->software_build_id_len = 0;
}

void zb_zcl_basic_srv_setup(zb_uint8_t ep, zb_zcl_basic_srv_attr_t *attrs)
{
    zb_zcl_cluster_t *cluster = zb_zcl_register_cluster(ep, ZB_BASIC_CLUSTER_ID,
                                  ZB_ZCL_SERVER_ROLE, NULL, NULL);
    basic_global_attrs.cluster_revision = ZB_ZCL_DEFAULT_CLUSTER_REVISION();
    basic_global_attrs.reporting_status = ZB_ZCL_ATTR_REPORTING_COMPLETE;
    zb_zcl_add_attribute(cluster, 0xfffd, ZB_ZCL_ATTR_TYPE_U16,         ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(basic_global_attrs.cluster_revision));
    zb_zcl_add_attribute(cluster, 0xfffe, ZB_ZCL_ATTR_TYPE_ENUM8,       ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(basic_global_attrs.reporting_status));
    zb_zcl_add_attribute(cluster, 0x0000, ZB_ZCL_ATTR_TYPE_U8,          ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->zcl_version));
    zb_zcl_add_attribute(cluster, 0x0001, ZB_ZCL_ATTR_TYPE_U8,          ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->app_version));
    zb_zcl_add_attribute(cluster, 0x0002, ZB_ZCL_ATTR_TYPE_U8,          ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->stack_version));
    zb_zcl_add_attribute(cluster, 0x0003, ZB_ZCL_ATTR_TYPE_U8,          ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->hw_version));
    
    zb_zcl_format_string(attrs->manufacturer_name, attrs->manufacturer_name_len);
    zb_zcl_add_attribute(cluster, 0x0004, ZB_ZCL_ATTR_TYPE_CHAR_STRING, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->manufacturer_name));

    zb_zcl_format_string(attrs->model_id, attrs->model_id_len);
    zb_zcl_add_attribute(cluster, 0x0005, ZB_ZCL_ATTR_TYPE_CHAR_STRING, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->model_id));
    
    zb_zcl_format_string(attrs->date_code, attrs->date_code_len);
    zb_zcl_add_attribute(cluster, 0x0006, ZB_ZCL_ATTR_TYPE_CHAR_STRING, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->date_code));
    zb_zcl_add_attribute(cluster, 0x0007, ZB_ZCL_ATTR_TYPE_ENUM8,       ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->power_source));
    zb_zcl_add_attribute(cluster, 0x0008, ZB_ZCL_ATTR_TYPE_ENUM8,       ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->generic_device_class));
    zb_zcl_add_attribute(cluster, 0x0009, ZB_ZCL_ATTR_TYPE_ENUM8,       ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->generic_device_type));
    
    zb_uint8_t tmp[ZB_ZCL_ATTR_MAX_ARRAY_LENGTH];
    tmp[0] = attrs->product_code_len;
    tmp[1] = attrs->product_code_id;
    ZB_MEMCPY(&tmp[2], attrs->product_code, attrs->product_code_len - 1);
    ZB_MEMCPY(attrs->product_code, tmp, attrs->product_code_len + 1);
    zb_zcl_add_attribute(cluster, 0x000a, ZB_ZCL_ATTR_TYPE_BYTE_ARRAY,  ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->product_code));

    zb_zcl_format_string(attrs->product_url, attrs->product_url_len);
    zb_zcl_add_attribute(cluster, 0x000b, ZB_ZCL_ATTR_TYPE_CHAR_STRING, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->product_url));
    
    zb_zcl_format_string(attrs->man_version_details, attrs->man_version_details_len);
    zb_zcl_add_attribute(cluster, 0x000c, ZB_ZCL_ATTR_TYPE_CHAR_STRING, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->man_version_details));
    
    zb_zcl_format_string(attrs->serial_number, attrs->serial_number_len);
    zb_zcl_add_attribute(cluster, 0x000d, ZB_ZCL_ATTR_TYPE_CHAR_STRING, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->serial_number));
    
    zb_zcl_format_string(attrs->product_label, attrs->product_label_len);
    zb_zcl_add_attribute(cluster, 0x000e, ZB_ZCL_ATTR_TYPE_CHAR_STRING, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->product_label));
    
    zb_zcl_format_string(attrs->location_desc, attrs->location_desc_len);
    zb_zcl_add_attribute(cluster, 0x0010, ZB_ZCL_ATTR_TYPE_CHAR_STRING, ZB_ZCL_ATTR_ACCESS_READ_WRITE, &(attrs->location_desc));
    
    zb_zcl_add_attribute(cluster, 0x0011, ZB_ZCL_ATTR_TYPE_ENUM8,       ZB_ZCL_ATTR_ACCESS_READ_WRITE, &(attrs->phys_environment));
    zb_zcl_add_attribute(cluster, 0x0012, ZB_ZCL_ATTR_TYPE_BOOL,        ZB_ZCL_ATTR_ACCESS_READ_WRITE, &(attrs->device_enabled));
    zb_zcl_add_attribute(cluster, 0x0013, ZB_ZCL_ATTR_TYPE_8BITMAP,     ZB_ZCL_ATTR_ACCESS_READ_WRITE, &(attrs->alarm_mask));
    zb_zcl_add_attribute(cluster, 0x0014, ZB_ZCL_ATTR_TYPE_8BITMAP,     ZB_ZCL_ATTR_ACCESS_READ_WRITE, &(attrs->disable_local_conf));

    zb_zcl_format_string(attrs->software_build_id, attrs->software_build_id_len);
    zb_zcl_add_attribute(cluster, 0x4000, ZB_ZCL_ATTR_TYPE_CHAR_STRING, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->software_build_id));
}
