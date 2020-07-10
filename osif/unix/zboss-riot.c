/* try to collect all the mess into this file to get the zboss stack
 * cleaned up and then clean this up later */

#include "od.h"
#include "log.h"
#include "luid.h"
#include "xtimer.h"
#include "memarray.h"
#include "net/netif.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netreg.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc.h"

#ifdef MODULE_PERIPH_FLASHPAGE
#include "periph/flashpage.h"
#include "riotboot/slot.h"
/* some mcus can only write to the "other half" from where the firmware is */
#define NV_FLASH_PAGE_0 (FLASHPAGE_NUMOF / 2 - 1)
#define NV_FLASH_PAGE_1 (FLASHPAGE_NUMOF - 1)
static uint16_t _flash_page;
#elif defined MODULE_AT24CXXX
#include "at24cxxx.h"
#include "at24cxxx_params.h"
at24cxxx_t at24cxxx_dev;
#endif
bool has_eeprom;

#include "zb_common.h"
#include "zb_aps.h"
#include "zb_zdo.h"
#include "zb_secur_api.h"
#include "zb_bufpool.h"

#include <stdarg.h>

#define ENABLE_DEBUG (0)
#include "debug.h"

// #if ENABLE_DEBUG
#include "od.h"
// #else
// #define od_hex_dump(...)
// #endif

#ifndef ZB_IS_COORDINATOR
#define ZB_IS_COORDINATOR (0)
#endif

kernel_pid_t _zb_iface_id;

#define QUEUE_SIZE (16)
static msg_t _zb_msg_queue[QUEUE_SIZE];

static pid_t _zb_pid;
static netdev_t *netdev;
static gnrc_netif_t *netif;
static netdev_driver_t *driver;
static uint8_t payload_buf[256];
static char _zigbee_thread_stack [THREAD_STACKSIZE_DEFAULT + 512];

static uint8_t _packet_buf[256];
static uint8_t _packet_buf_size;

uint8_t g_zc_addr[8] __attribute__ ((aligned(4)));
// zb_ieee_addr_t extended_pan_id;
uint16_t g_group_id;

/* tradfri remote network key */
// zb_uint8_t g_key[16] = { 0x8c, 0xb0, 0x6d, 0x62, 0x93, 0x7b, 0x10, 0x83, 0x76, 0x04, 0xa8, 0x64, 0xc2, 0x7c, 0x71, 0xdf};
zb_uint8_t g_key[16] =
{ 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
  0x14, 0x14, 0x14 };

__attribute__((weak)) void zb_identify(void)
{
    puts("override zb_identify()");
}

__attribute__((weak)) void zb_data_indication(zb_uint8_t param)
{
    (void) param;
    puts("override zb_data_indication()");
}

typedef struct {
    zb_callback_t func;
    xtimer_t timer;
    msg_t msg;
    uint8_t arg;
    uint16_t run_after;
} callback_msg_t;

#define CALLBACK_BUF_SIZE (16)
static memarray_t _callback_memarray;
static uint8_t _callback_memarray_buf[sizeof(callback_msg_t) *
                                      CALLBACK_BUF_SIZE];

void sleep_radio(uint8_t arg)
{
    bool sleep = arg;
    netopt_state_t state = NETOPT_STATE_IDLE;
    if (sleep) {
        state = NETOPT_STATE_SLEEP;
    }
    gnrc_netapi_set(_zb_iface_id, NETOPT_STATE, 0, &state, sizeof(netopt_state_t));
}

void extend_poll_timer(uint8_t arg)
{
    ZDO_CTX().conf_attr.nwk_indirect_poll_rate = ZB_TIME_ONE_SECOND * arg;
}

void zb_transceiver_set_pan_id(uint16_t pan_id)
{
    gnrc_netapi_set(_zb_iface_id, NETOPT_NID, 0, &pan_id, sizeof(uint16_t));
    LOG_INFO("NID set: 0x%x\n", pan_id);
}

void zb_uz2400_fifo_read(zb_uint8_t tx_fifo, zb_buf_t *buf, zb_uint8_t length)
{
    (void)tx_fifo;
    (void)length;

    // uint8_t packet[] = "\x00\x80\x63\xff\x01\x00\x00\xff\xcf\x00\x00\x00\x20\x84\x73\x65\x6e\x73\x6f\x72\x00\x00\xff\xff\xff\x00";
    // uint8_t packet[] = {0x03, 0x08, 0x06, 0xff, 0xff, 0xff, 0xff, 0x07};
    // int len = sizeof(packet) + 1;

    zb_buf_initial_alloc(buf, _packet_buf_size + 1);
//  LOG_DEBUG("zb_uz2400_fifo_read()\n");
//     printf("in: ");
//     od_hex_dump(_packet_buf, _packet_buf_size, 16);
    memcpy(ZB_BUF_BEGIN(buf) + 1, _packet_buf, _packet_buf_size);

    /* this tells the zigbee stack that the last ack had the data pending bit set
     * which is usually a lie since we didn't check */
//     ZG->mac.mac_ctx.mac_flags |= ZB_MAC_PEND_DATA_MASK; /* FIXME */
}



void zb_transceiver_update_long_addr(uint8_t *addr)
{
    char buf[24];

    zb_pretty_long_address(buf, sizeof(buf), addr);
    LOG_INFO("long hwaddr set: %s\n", buf);

    uint8_t address[8];
    address[0] = addr[7];
    address[1] = addr[6];
    address[2] = addr[5];
    address[3] = addr[4];
    address[4] = addr[3];
    address[5] = addr[2];
    address[6] = addr[1];
    address[7] = addr[0];

    gnrc_netapi_set(_zb_iface_id, NETOPT_ADDRESS_LONG, 0, &address, 8);
}

void zb_transceiver_update_short_addr(uint16_t addr)
{
    LOG_INFO("short hwaddr set: 0x%x\n", addr);
    /* gnrc_netapi_set() expects little endian */
    addr = byteorder_swaps(addr);
    gnrc_netapi_set(_zb_iface_id, NETOPT_ADDRESS, 0, &addr, 2);
}

void zb_set_pending_bit(int set)
{
    bool set_b = set;

    gnrc_netapi_set(_zb_iface_id, NETOPT_ACK_PENDING, 0, &set_b, sizeof(set_b));
}

#define ZB_BEACON_INTERVAL_USEC 15360
uint16_t zb_timer_get(void)
{
    return xtimer_now_usec() / ZB_BEACON_INTERVAL_USEC;
}

void zb_trace_msg_riot(zb_char_t *format, zb_int_t level, zb_char_t *file_name,
                       const zb_char_t *function, zb_int_t line_number,
                       zb_int_t args_size, ...)
{
    va_list arglist;

    va_start(arglist, args_size);
#ifdef MODULE_LOG_DMESG
    vlog_dmesg(level, file_name, function, line_number, format, arglist);
#else
    vprintf(format, arglist);
    puts("");
#endif
    va_end(arglist);
}

void group_add_conf1(zb_uint8_t param)
{
    (void)param;
    zb_apsme_add_group_conf_t *conf = ZB_GET_BUF_PARAM(ZB_BUF_FROM_REF(param), zb_apsme_add_group_conf_t);
    DEBUG("group add status: %i\n", conf->status);
}

void zb_zdo_startup_complete(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    TRACE_MSG(TRACE_APS2, ">>zb_zdo_startup_complete status %d",
              (FMT__D, (int)buf->u.hdr.status));
    if (buf->u.hdr.status == 0) {
        LOG_INFO("ZDO started ok\n");
        zb_af_set_data_indication(zb_data_indication);
        zb_data_indication(param);

        zb_apsme_add_group_req_t *req;
        zb_buf_reuse(buf);
        req = ZB_GET_BUF_PARAM(buf, zb_apsme_add_group_req_t);
        req->group_address = g_group_id;
        req->endpoint = 1;
        zb_zdo_add_group_req(param, group_add_conf1);

        zb_apsme_add_group_req_t *req2;
        zb_buf_t *buf2 = zb_get_out_buf();
        req2 = ZB_GET_BUF_PARAM(buf2, zb_apsme_add_group_req_t);
        req2->group_address = 0;
        req2->endpoint = 1;
        zb_zdo_add_group_req(ZB_REF_FROM_BUF(buf2), group_add_conf1);
    }
    else {
        zb_free_buf(buf);
        LOG_ERROR("ZDO start FAILED status %d\n", buf->u.hdr.status);
    }
}

#define ZB_MSG_SCHEDULE_ALARM (0x4)
#define ZB_MSG_SCHEDULE_CALLBACK (0x5)
#define ZB_MSG_CANCEL_ALARM (0x6)
#define ZB_MSG_FIRE_CALLBACK (0x7)

void zb_sched_loop_iteration(void)
{
    // thread_sleep();
}

zb_ret_t zb_schedule_alarm(zb_callback_t func, zb_uint8_t param,
                           zb_time_t run_after)
{
    //     LOG_DEBUG("0x%lx(%u) run_after %lu\n", (uint32_t)func, param, run_after);

    if (func == NULL) {
        return RET_OK;
    }

    msg_t msg;

    msg.content.ptr = func;
    msg.type = ZB_MSG_SCHEDULE_ALARM;
    msg_send(&msg, _zb_pid);

    msg.content.value = run_after;
    msg.type = param;
    msg_send(&msg, _zb_pid);

    return RET_OK;
}

static zb_ret_t _zb_schedule_alarm(zb_callback_t func, zb_uint8_t param,
                                   zb_time_t run_after)
{
    //     LOG_DEBUG("0x%lx(%u) run_after %lu\n", (uint32_t)func, param, run_after);

    callback_msg_t *callback = memarray_alloc(&_callback_memarray);

    callback->func = func;
    callback->arg = param;
    callback->run_after = run_after;

    callback->msg.content.ptr = callback;
    callback->msg.type = ZB_MSG_FIRE_CALLBACK;

    uint64_t run_after_usec = run_after * 15360;
    run_after_usec *= 30;
    xtimer_ticks64_t run_after_ticks = xtimer_ticks_from_usec64(run_after_usec);

    xtimer_set_msg64(&(callback->timer), run_after_ticks.ticks64,
                     &(callback->msg), _zb_pid);

    return RET_OK;
}

zb_ret_t zb_schedule_callback(zb_callback_t func, zb_uint8_t param)
{
    //     LOG_DEBUG("0x%lx(%u)\n", (uint32_t)func, param);

    return zb_schedule_alarm(func, param, 0);


    // msg_t msg;
    // msg.content.ptr = func;
    // msg.type = param;
    // msg_send(&msg, _zb_pid);
    // return RET_OK;
}

zb_ret_t zb_schedule_tx_cb(zb_callback_t func, zb_uint8_t param)
{
    //     LOG_DEBUG("0x%lx(%u)\n", (uint32_t)func, param);
    return zb_schedule_alarm(func, param, 1);
}

zb_ret_t zb_schedule_alarm_cancel(zb_callback_t func, zb_uint8_t param)
{
    //     LOG_DEBUG("0x%lx(%u)\n", (uint32_t)func, param);

    msg_t msg;

    msg.content.ptr = func;
    msg.type = ZB_MSG_CANCEL_ALARM;
    msg_send(&msg, _zb_pid);

    msg.type = param;
    msg_send(&msg, _zb_pid);

    return RET_OK;
}

static zb_ret_t _zb_schedule_alarm_cancel(zb_callback_t func, zb_uint8_t param)
{
    for (int i = 0; i < CALLBACK_BUF_SIZE; i++) {
        callback_msg_t *callback_msg = (void *)_callback_memarray_buf + i *
                                       sizeof(callback_msg_t);
        if (callback_msg->func == func) {
            DEBUG("removing one 0x%lx, %u, %u\n", (uint32_t)func, param, callback_msg->run_after);
            xtimer_remove(&callback_msg->timer);
            memset(callback_msg, 0, sizeof(callback_msg_t));
            memarray_free(&_callback_memarray, callback_msg);
        }

    }
    return RET_OK;
}

static void *_zb_thread(void *arg)
{
    (void)arg;
    msg_init_queue(_zb_msg_queue, QUEUE_SIZE);

    gnrc_netreg_entry_t entry;
    entry.target.pid = thread_getpid();
    entry.demux_ctx = GNRC_NETREG_DEMUX_CTX_ALL;
#if defined(MODULE_GNRC_NETAPI_MBOX) || defined(MODULE_GNRC_NETAPI_CALLBACKS)
    entry.type = GNRC_NETREG_TYPE_DEFAULT;
#endif
    gnrc_netreg_register(GNRC_NETTYPE_UNDEF, &entry);

    while (1) {
        /* sleep until a callback needs to run */
        msg_t msg;
        msg_receive(&msg);
//         DEBUG("msg type 0x%x from pid %u\n", msg.type, msg.sender_pid);

        if (msg.type == ZB_MSG_SCHEDULE_ALARM) {
            zb_callback_t func = msg.content.ptr;
            /* remaining paramaters are sent in a second msg */
            msg_receive(&msg);
            uint8_t arg = msg.type;
            uint16_t run_after = msg.content.value;
            _zb_schedule_alarm(func, arg, run_after);
            continue;
        }
        else if (msg.type == ZB_MSG_CANCEL_ALARM) {
            zb_callback_t func = msg.content.ptr;
            /* remaining paramaters are sent in a second msg */
            msg_receive(&msg);
            uint8_t arg = msg.type;
            _zb_schedule_alarm_cancel(func, arg);
            continue;
        }
        else if (msg.type == 0x8) {
            uint8_t arg = msg.type;
            zb_callback_t func = msg.content.ptr;
            // printf("_zb_thread(0x%lx, %u)\n", (uint32_t)func, arg);
            func(arg);
            zb_mac_main_loop();
            continue;
        }
        else if (msg.type == ZB_MSG_FIRE_CALLBACK) {
            callback_msg_t *callback = msg.content.ptr;

            assert((uint32_t)msg.content.ptr > 1);

            /* execute callback */
            //         LOG_DEBUG("firing callback 0x%lx(%u)\n", (uint32_t)callback->func, callback->arg);
            if ((uint32_t)callback->func > 0x10000000) {
                printf("wtf not calling 0x%lx(%u)\n", (uint32_t)callback->func,
                       callback->arg);
                printf("sender_pid %u\n", msg.sender_pid);
                assert(0);
                continue;
            }
            callback->func(callback->arg);

            /* clean up and continue sleeping */
            memarray_free(&_callback_memarray, callback);
            // printf("running zb_mac_main_loop()\n");
            // zb_handle_data_request_cmd();
            zb_mac_main_loop();
            continue;
        }
        else if (msg.type == GNRC_NETAPI_MSG_TYPE_RCV) {
            gnrc_pktsnip_t *pkt = msg.content.ptr;
            _packet_buf_size = pkt->size;
            memcpy(_packet_buf, pkt->data, _packet_buf_size);

            /* get lqi and rssi */
            gnrc_pktsnip_t *netif;
            netif = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_NETIF);
            gnrc_netif_hdr_t *netif_hdr = netif->data;
            _packet_buf[_packet_buf_size] = netif_hdr->lqi;
            _packet_buf[_packet_buf_size + 1] = netif_hdr->rssi;
            _packet_buf_size += 2;

            DEBUG("received packet len %u size %u snips %u\n",
                        gnrc_pkt_len(pkt), pkt->size, gnrc_pkt_count(pkt));
//             od_hex_dump(_packet_buf, _packet_buf_size, 16);

            gnrc_pktbuf_release(pkt);

            zb_buf_t *buf = zb_get_in_buf();
            zb_mac_recv_data(ZB_REF_FROM_BUF(buf));
//          LOG_INFO("finished receiving packet\n");
            continue;
        }
    }
    return NULL;
}

void zb_sched_init(void)
{
//  printf("sizeof(callback_msg_t) = %u\n", sizeof(callback_msg_t));
//  printf("sizeof(xtimer_t) = %u\n", sizeof(xtimer_t));
    memset(_callback_memarray_buf, 0x00, sizeof(_callback_memarray_buf));
    memarray_init(&_callback_memarray,
                  _callback_memarray_buf,
                  sizeof(callback_msg_t),
                  CALLBACK_BUF_SIZE
                  );

    _zb_pid = thread_create(_zigbee_thread_stack, sizeof(_zigbee_thread_stack),
                            5,
                            THREAD_CREATE_STACKTEST,
                            _zb_thread, NULL, "zigbee");
    LOG_INFO("started Zigbee stack with pid %i\n", _zb_pid);
}

int zb_input_packet(int argc, char **argv)
{
    if (argc != 2) {
        printf(
            "takes one argument - hex bytes representing a zigbee packet like 030806ffffffff07\n");
        return 1;
    }
    char *packet_str = argv[1];
    _packet_buf_size = strlen(packet_str) / 2;
//     printf("got %u bytes: <%s>\n", _packet_buf_size, packet_str);

    char byte_str[3];
    byte_str[2] = '\0';
    for (int i = 0; i < _packet_buf_size; ++i) {
        byte_str[0] = packet_str[i * 2];
        byte_str[1] = packet_str[i * 2 + 1];
        _packet_buf[i] = strtoul(byte_str, NULL, 16);
    }

    // zb_set_trans_int();
    // zb_mac_main_loop();


    zb_buf_t *buf = zb_get_in_buf();
    zb_mac_recv_data(ZB_REF_FROM_BUF(buf));

    return 0;
}

void send_packet(uint8_t *buf, uint32_t length)
{
//     LOG_DEBUG("sending packet with length %u\n", length);
//     printf("out: ");
//     od_hex_dump(buf, length, 16);

//     memcpy(payload_buf, buf, length);
//     iolist_t iolist = {
//         .iol_base = payload_buf,
//         .iol_len = length
//     };
//     driver->send(netdev, &iolist);

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, buf, length,
                                                        GNRC_NETTYPE_UNDEF);

//     gnrc_pktsnip_t netif_hdr = gnrc_netif_hdr_build(src, src_len, dst, dst_len);
//     netif_hdr.next = pkt;

//     if (!ZB_PIB_RX_ON_WHEN_IDLE()) {
        sleep_radio(false);
//     }

    gnrc_netapi_send(netif->pid, pkt);
//     gnrc_netapi_dispatch_send(GNRC_NETTYPE_NETIF, GNRC_NETREG_TYPE_DEFAULT,
//                                                                 netif_hdr);

    if (!ZB_PIB_RX_ON_WHEN_IDLE()) {
        ZB_SCHEDULE_ALARM(sleep_radio, true,
                                ZB_MILLISECONDS_TO_BEACON_INTERVAL(200));
        ZB_SCHEDULE_ALARM(extend_poll_timer, 180, ZB_TIME_ONE_SECOND * 15);
    }
}

int zb_inject_packet(int argc, char **argv)
{
    if (argc != 2) {
        printf(
            "takes one argument - hex bytes representing a zigbee packet like 030806ffffffff07\n");
        return 1;
    }

    char *packet_str = argv[1];
    unsigned packet_len = strlen(packet_str) / 2;
    uint8_t buf[packet_len];

    char byte_str[3];
    byte_str[2] = '\0';
    for (int i = 0; i < packet_len; ++i) {
        byte_str[0] = packet_str[i * 2];
        byte_str[1] = packet_str[i * 2 + 1];
        buf[i] = strtoul(byte_str, NULL, 16);
    }

    send_packet(buf, packet_len);
}

uint8_t pagebuf[FLASHPAGE_SIZE];

zb_uint8_t zb_write_nvram (zb_uint8_t pos, void *buf, zb_uint8_t len)
{
#ifdef MODULE_PERIPH_FLASHPAGE
    /* get the existing page data */
//     printf("read\n");
    flashpage_read(_flash_page, pagebuf);

    /* make the requested changes */
    memcpy(pagebuf + pos, buf, len);

    /* erase the flash page */
//     printf("erase\n");
    flashpage_write(_flash_page, NULL);

    /* write the new page data */
//     printf("write\n");
    if (flashpage_write_and_verify(_flash_page, pagebuf) != FLASHPAGE_OK) {
        LOG_ERROR("flashpage write failure\n");
        return 0;
    }

#elif defined MODULE_AT24CXXX
    if (at24cxxx_write(&at24cxxx_dev, pos, buf, len) != AT24CXXX_OK) {
        LOG_ERROR("eeprom write failure\n");
        return 0;
    }
#endif
    return len;
}

zb_uint8_t zb_read_nvram(zb_uint8_t pos, void *buf, zb_uint8_t len)
{
#ifdef MODULE_PERIPH_FLASHPAGE
    flashpage_read(_flash_page, pagebuf);
    memcpy(buf, pagebuf + pos, len);

#elif defined MODULE_AT24CXXX
    if (at24cxxx_read(&at24cxxx_dev, pos, buf, len) != AT24CXXX_OK) {
        LOG_ERROR("eeprom read failure\n");
        return 0;
    }
#endif
    return len;
}

zb_ieee_addr_t *shortaddr = &(g_zb.mac.pib.mac_short_address);

void zboss_init(void)
{
#ifdef MODULE_PERIPH_FLASHPAGE

    _flash_page = NV_FLASH_PAGE_1;
    has_eeprom = true;

#ifdef MODULE_RIOTBOOT
    if (riotboot_slot_current() == 0) {
        _flash_page = NV_FLASH_PAGE_1;
    }
    else if (riotboot_slot_current() == 1) {
        _flash_page = NV_FLASH_PAGE_0;
    }
    else {
        assert(0);
    }
#endif

LOG_INFO("using page %u of internal flash as nonvolatile storage\n",
           _flash_page);

#elif defined MODULE_AT24CXXX
    uint8_t c;
    if (at24cxxx_init(&at24cxxx_dev, &at24cxxx_params[0]) == AT24CXXX_OK &&
        at24cxxx_read(&at24cxxx_dev, 0, &c, 1) == AT24CXXX_OK
        ) {
        has_eeprom = true;
        LOG_ERROR("using external eeprom as nonvolatile storage\n");
    }
    else {
        LOG_ERROR("eeprom not detected\n");
    }
#else
    LOG_WARNING("compiled without eeprom/nvram support\n");
#endif

#if 0
    /* print eeprom contents to console */
    if (has_eeprom) {
        uint8_t buf[255];
        memset(buf, 0xff, sizeof(buf));
        zb_read_nvram(0, buf, sizeof(buf));
        od_hex_dump(buf, sizeof(buf), 16);
    }
#endif

    /* net netif to register */
    netif = gnrc_netif_iter(NULL); /* FIXME only works on first interface */

    /* register netif to receive our 802.15.4 packets */
    gnrc_netreg_entry_t netreg;
    netreg.demux_ctx = GNRC_NETREG_DEMUX_CTX_ALL;
#if defined(MODULE_GNRC_NETAPI_MBOX) || defined(MODULE_GNRC_NETAPI_CALLBACKS)
    netreg.type = GNRC_NETREG_TYPE_DEFAULT;
#endif
    netreg.target.pid = netif->pid;
    gnrc_netreg_register(GNRC_NETTYPE_NETIF, &netreg);

    netdev = netif->dev;
    driver = (netdev_driver_t *)netdev->driver;
    _zb_iface_id = netif->pid;

    uint16_t channel = 25;
    gnrc_netapi_set(_zb_iface_id, NETOPT_CHANNEL, 0, &channel,
                                                            sizeof(uint16_t));
    // int ret = gnrc_netif_set_from_netdev(netif, &opt);
    // printf("raw returned %i\n", ret);

    netopt_enable_t set = NETOPT_ENABLE;
    netopt_enable_t unset = NETOPT_DISABLE;
    gnrc_netapi_set(_zb_iface_id, NETOPT_CSMA, 0, &set,
                    sizeof(netopt_enable_t));
    gnrc_netapi_set(_zb_iface_id, NETOPT_RAWMODE, 0, &set,
                    sizeof(netopt_enable_t));
    gnrc_netapi_set(_zb_iface_id, NETOPT_ACK_REQ, 0, &set,
                    sizeof(netopt_enable_t));
    gnrc_netapi_set(_zb_iface_id, NETOPT_AUTOACK, 0, &set,
                    sizeof(netopt_enable_t));
//  gnrc_netapi_set(_zb_iface_id, NETOPT_PROMISCUOUSMODE, 0, &set, sizeof(netopt_enable_t));

    // uint8_t omg[] = {0x03, 0x08, 0x77, 0xff, 0xff, 0xff, 0xff, 0x07};
    // send_packet(omg, sizeof(omg));

    LOG_INFO("starting zigbee stack\n");

    /* copy long mac from radio to zigbee stack */
    uint8_t addr_long[8];
    gnrc_netapi_get(_zb_iface_id, NETOPT_ADDRESS_LONG, 0, addr_long, 8);
    for (int i = 0; i < 8; ++i) {
        g_zc_addr[i] = addr_long[7 - i];
    }
    // od_hex_dump(g_zc_addr, 8, 8);
    char buf[24];
    zb_pretty_long_address(buf, sizeof(buf), g_zc_addr);

    /* get addr_short from hardware */
    uint16_t addr_short;
    gnrc_netapi_get(_zb_iface_id, NETOPT_ADDRESS, 0, (uint8_t *)&addr_short, 2);
    LOG_INFO("got hw short address 0x%04x\n", addr_short);
    MAC_PIB().mac_short_address = addr_short;
    zb_transceiver_update_short_addr(addr_short);

    zb_init("omg", "3", "3");

    // ZG->nwk.nib.security_level = 0;

    ZB_IEEE_ADDR_COPY(ZB_PIB_EXTENDED_ADDRESS(), &g_zc_addr);

//     zb_secur_setup_preconfigured_key(g_key, 0);
//     zb_read_security_key();

//     zb_transceiver_update_short_addr(0x0043);
//     MAC_PIB().mac_pan_id = 0x359b;


//     extended_pan_id[7] = 0xfc;
//     extended_pan_id[6] = 0xc1;
//     extended_pan_id[5] = 0x1c;
//     extended_pan_id[4] = 0xe0;
//     extended_pan_id[3] = 0x61;
//     extended_pan_id[2] = 0xbe;
//     extended_pan_id[1] = 0x0f;
//     extended_pan_id[0] = 0xb9;
//     ZB_IEEE_ADDR_COPY(ZB_NIB_EXT_PAN_ID(), &extended_pan_id);

//     ZB_EXTPANID_COPY(ZB_PIB_BEACON_PAYLOAD().extended_panid, extended_pan_id);
//     ZB_EXTPANID_COPY(ZB_NIB_EXT_PAN_ID(), extended_pan_id);

//     if (ZB_IS_COORDINATOR || 1) {
//         /* let's always be coordinator */
//         ZB_AIB().aps_designated_coordinator = 1;
//         MAC_PIB().mac_pan_id = 0x1aaa;
//         MAC_PIB().mac_pan_id = 0x1417;
//      zb_transceiver_update_short_addr(0x0002);

//      zb_secur_setup_preconfigured_key(g_key, 0);
//     }

    uint8_t rand_seq;
    luid_get(&rand_seq, 1);
    ZB_NIB_SEQUENCE_NUMBER() = rand_seq;

#if defined BOARD_OPENLABS_KW41Z_MINI || 1
    ZG->nwk.handle.permit_join = 1;
    MAC_PIB().mac_association_permit = 1;
    ZB_AIB().aps_designated_coordinator = 1;
//     ZG->nwk.handle.router_started = 1;
#else
    ZB_AIB().aps_designated_coordinator = 0;
    ZB_PIB_RX_ON_WHEN_IDLE() = 0;
#endif

    ZG->aps.authenticated = 1;

    int res = zdo_dev_start();
    DEBUG("zdo_dev_start() returned %i\n", res);

    zdo_main_loop(); /* this does nothing and returns immediately */
}


int cmd_zconfig(int argc, char *argv[])
{
    char addr[IPV6_ADDR_MAX_STR_LEN];

    printf("joined: \t\t %i\n", ZG->nwk.handle.joined);
    printf("joined pro: \t\t %i\n", ZG->nwk.handle.joined_pro);
    printf("trust center: \t\t %i\n", ZG->nwk.handle.is_tc);
    printf("RX on while idle: \t %i\n", ZG->mac.pib.mac_rx_on_when_idle);
    printf("aps authenticated: \t %i\n", ZG->aps.authenticated);
    printf("designated coordinator:  %i\n", ZB_AIB().aps_designated_coordinator);
    printf("nwk state:\t\t %i\n", ZG->nwk.handle.state);
    printf("router: \t\t %i\n", ZG->nwk.handle.router_started);
    printf("device type: \t\t %i\n", ZG->nwk.nib.device_type);
    printf("permit joining: \t %i\n", ZG->nwk.handle.permit_join);

    printf("in buffers used: \t %i/%i\n", ZG->bpool.bufs_allocated[1],
                                            ZB_IOBUF_POOL_SIZE / 2);
    printf("out buffers used: \t %i/%i\n", ZG->bpool.bufs_allocated[0],
                                            ZB_IOBUF_POOL_SIZE / 2);

    printf("Group ID \t\t 0x%04x\n", g_group_id);

    uint8_t *network_key = ZG->nwk.nib.secur_material_set[0].key;

    printf("PAN ID \t\t\t 0x%04x\n", MAC_PIB().mac_pan_id);
    zb_pretty_long_address(addr, sizeof(addr),
                                            ZB_AIB().aps_use_extended_pan_id);
    printf("Extended Pan ID: \t %s\n", addr);

    printf("Short Address \t\t 0x%04x\n", ZG->mac.pib.mac_short_address);
    zb_pretty_long_address(addr, sizeof(addr),
                                            ZG->mac.pib.mac_extended_address);
    printf("Long Address: \t\t %s\n", addr);

    zb_ieee_addr_t long_parent_addr;
    zb_uint16_t short_parent_addr;
    zb_address_short_by_ref(&short_parent_addr, ZG->nwk.handle.parent);
    zb_address_ieee_by_ref(long_parent_addr, ZG->nwk.handle.parent);

    printf("Parent Short Address \t\t 0x%04x\n", short_parent_addr);
    zb_pretty_long_address(addr, sizeof(addr), long_parent_addr);
    printf("Parent Long Address: \t\t %s\n", addr);

    printf("Coordinator Short Address \t 0x%04x\n",
           ZG->mac.pib.mac_coord_short_address);
    zb_pretty_long_address(addr, sizeof(addr),
                        ZG->mac.pib.mac_coord_extended_address);
    printf("Coordinator Long Address: \t %s\n", addr);

    printf(
        "Network Key: \t\t\t %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
        network_key[0], network_key[1], network_key[2], network_key[3],
        network_key[4], network_key[5], network_key[6], network_key[7],
        network_key[8], network_key[9], network_key[10], network_key[11],
        network_key[12], network_key[13], network_key[14], network_key[15]
    );

#ifdef ZB_ROUTER_ROLE
    printf("nwk rebroadcast table:\n");
    printf(
        "\tseq_num\tused\tretries\tnext_retransmit\twait_conf\tneighbor\tsrc_addr\tdst_addr\n");
    zb_nwk_broadcast_retransmit_t *retransmit_entry = NULL;
    for (int i = 0; i < ZB_NWK_BRR_TABLE_SIZE; i++) {
        retransmit_entry = &ZG->nwk.handle.brrt[i];
        if (!retransmit_entry || !retransmit_entry->used) {
            continue;
        }
        printf("\t% 7i\t% 4i\t% 7i\t% 15i\t% 9i\t% 8i\t% 8x\t% 8x\n",
               retransmit_entry->seq_num,
               retransmit_entry->used, retransmit_entry->retries,
               retransmit_entry->next_retransmit * ZB_BEACON_INTERVAL_USEC / 1000,
               retransmit_entry->wait_conf, retransmit_entry->neighbor_table_iterator,
               retransmit_entry->src_addr, retransmit_entry->dst_addr
        );
    }
#endif


    printf("ext neighbors: %i/%i used\n", ZG->nwk.neighbor.ext_neighbor_used,
           ZG->nwk.neighbor.ext_neighbor_size );

    printf("\tlong_addr\t\text_panid\t\t\taddr\n");
    printf("\t\tpermit_join\tpotential_parent\tdevice_type\trouter\t\n");

    zb_ext_neighbor_tbl_ent_t *ext_neighbor = NULL;
    for (int i = 0; i < ZG->nwk.neighbor.ext_neighbor_used; i++) {
        ext_neighbor = &ZG->nwk.neighbor.ext_neighbor[i];

        char long_addr[24];
        zb_ieee_addr_t laddr;
        ZB_ADDRESS_DECOMPRESS(laddr, ext_neighbor->long_addr);
        zb_pretty_long_address(long_addr, sizeof(long_addr), laddr);

        char pan_id[24];
        zb_ieee_addr_t pan;
        zb_address_ieee_by_ref(pan, ext_neighbor->panid_ref);
        zb_pretty_long_address(pan_id, sizeof(pan_id), pan);

        printf("\t%s\t%s\t0x%04x\n",
               long_addr, pan_id, ext_neighbor->short_addr
        );
        printf("\t\t%i\t\t%i\t\t\t%i\t\t%i\n",
               ext_neighbor->permit_joining, ext_neighbor->potential_parent,
               ext_neighbor->device_type, ext_neighbor->router_capacity
        );
    }

    printf("neighbors: %i/%i used\n", ZG->nwk.neighbor.base_neighbor_used,
           ZG->nwk.neighbor.base_neighbor_size );
    printf("nwk neighbor table:\n");
    printf(
        "\tdevice_type\tdepth\trelationship\tlqi\tpermit_joining\trx_idle\ttx_failure\taddress\n");
    zb_neighbor_tbl_ent_t *neighbor = NULL;
    for (int i = 0; i < ZG->nwk.neighbor.base_neighbor_size; i++) {
        neighbor = &ZG->nwk.neighbor.base_neighbor[i];
        if (!neighbor || !neighbor->used) {
            continue;
        }

        char abuf[24];
        zb_ieee_addr_t addr;
        zb_address_ieee_by_ref(addr, neighbor->addr_ref);
        zb_pretty_long_address(abuf, sizeof(abuf), addr);
        printf("\t% 11i\t% 5i\t% 12i\t% 3i\t% 14i\t% 7i\t% 10i\t%s\n",
               neighbor->device_type, neighbor->depth, neighbor->relationship,
               neighbor->lqi, neighbor->permit_joining,
               neighbor->rx_on_when_idle, neighbor->transmit_failure,
               abuf
        );
    }


    return 0;
}
