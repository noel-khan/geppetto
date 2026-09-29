#include "pico/stdlib.h"
#include "hardware/clocks.h" 
#include "hardware/pio.h" 
#include "hardware/flash.h"  // Required for physical flash writes
#include "hardware/sync.h"   // Required to safely disable interrupts
#include "hardware/timer.h"  // add_repeating_time_us()
#include "tusb.h"
#include <string.h>          
#include "ws2812.pio.h"
#include "pico/rand.h"

// -------------------------------------------
//                CONSTANTS
// -------------------------------------------

#define SYNTHETIC_SENSOR    1
#define WS2812_PIN          16
#define TIMER_SENSOR_MS     1000    // 1ms = 1s
#define TIMER_BLINK_MS      1234    // time offset to avoid contention from multiple concurrent hw interrupts

// FLASH DRIVER DEFINITIONS (1MB Persistent Storage Boundary)
#define DISK_BLOCK_SIZE     512
#define DISK_BLOCK_NUM      2048                    // 1 Megabyte drive image size
#define FLASH_TARGET_OFFSET (1024 * 1024)           // Store 1MB inside your 2MB chip

// These EP address have to be unique
// CDC
#define EPNUM_CDC_NOTIF     0x81
#define EPNUM_CDC_OUT       0x02
#define EPNUM_CDC_IN        0x82
// MSC
#define EPNUM_MSC_OUT       0x03
#define EPNUM_MSC_IN        0x83

#define CONFIG_TOTAL_LEN    (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN + TUD_MSC_DESC_LEN)

// these are used in desc_configuration()
enum {
    ITF_NUM_CDC = 0,    // control/notification is ifc 0
    ITF_NUM_CDC_DATA,   // cdc data is ifc 1
    ITF_NUM_MSC,        // 
    ITF_NUM_TOTAL
};

// -------------------------------------------
//                  GLOBALS 
// avoid runtime memory allocations. Missing 
// deadlines may cause a device reset, which 
// will derail experiments
// -------------------------------------------

static uint8_t flash_sector_cache[4096];

// timers move work from main-loop so the host doesnt reset the device for being late
static struct repeating_timer timer_blink; 
static struct repeating_timer timer_sensor;

// faux devices
bool led_state = false;
// synthetic sensor
char sensor_buffer[14]; // A 32-bit integer needs up to 10 chars + 2 CRLF + 1 null terminator
int sensor_buffer_len;


// -------------------------------------------
//        HARDWARE CONFIGURATION
// -------------------------------------------
extern "C" void isr_usb_low_priority() {
    tud_int_handler(0); // prevents boot loop
}


tusb_desc_device_t const desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200, 
    .bDeviceClass       = TUSB_CLASS_MISC,
    .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol    = MISC_PROTOCOL_IAD, 
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = 0x2E8A, // Raspberry Pi Ltd.
    .idProduct          = 0x0022, // generic Composite peripheral
    .bcdDevice          = 0x0110, // TODO: increment version number with major/minor FW changes 
    .iManufacturer      = 0x01,   // constant
    .iProduct           = 0x02,   // constant
    .iSerialNumber      = 0x03,   // constant
    .bNumConfigurations = 0x01
};

// Pico-SDK uses MACROS to build config structures (vise TinyUSB's tusb_desc_configuration_t structure)
static uint8_t const desc_configuration[] = {
    // TUD_CONFIG_DESCRIPTOR: config#, ifc_count, string-index, total-len, attribute, power
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 
        //100 // default
        36
        // In mA and must be divisible by two. 
        // This is the minimum draw to ensure EP0 comms, per specification.
        // TODO: I measured the current draw of these CDC/MSC/LED boards to be 25mA.
        // COTS flash drives use 35mA. When doing large scale tests, I may want to use 
        // measured values to avoid over-estimating the utilization of bus-power.

    ),
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC, 4 /* string_desc_arr */, EPNUM_CDC_NOTIF, 8, EPNUM_CDC_OUT, EPNUM_CDC_IN, 64),
    TUD_MSC_DESCRIPTOR(ITF_NUM_MSC, 5 /* string_desc_arr */, EPNUM_MSC_OUT, EPNUM_MSC_IN, 64)
};

char const* string_desc_arr[] = {
    (const char[]) { 0x09, 0x04 }, // idx 0: LanguageID = English
    "DeMontfort",                  
    "Disembodiment",
    "P13167148-001",               // TODO: change for each board so I can use dmesg to track which boards drop out 
    "Observations CDC",            // idx 4: CDC
    "Properties MSC"               // idx 5: MSC
};

// -------------------------------------------
//            DESCRIPTOR CALLBACKS
// -------------------------------------------

uint8_t const * tud_descriptor_device_cb(void) { 
    return (uint8_t const *) &desc_device; 
}

uint8_t const * tud_descriptor_configuration_cb(uint8_t index) { 
    (void) index; return desc_configuration; 
}

static uint16_t _desc_str[32];
uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void) langid; uint8_t chr_count;
    if (index == 0) { memcpy(&_desc_str[0], string_desc_arr[0], 2); chr_count = 1; }
    else {
        if (index >= (sizeof(string_desc_arr) / sizeof(string_desc_arr[0]))) return NULL;
        const char* str = string_desc_arr[index]; chr_count = strlen(str);
        if (chr_count > 30) chr_count = 30; // truncate strings to 30 chars to avoid overflowing hw buffers
        for (uint8_t i = 0; i < chr_count; i++) _desc_str[1 + i] = str[i];
    }
    _desc_str[0] = (TUSB_DESC_STRING << 8) | (2 * chr_count + 2); return _desc_str;
}

// -------------------------------------------
//                    MSC
// -------------------------------------------

// Invoked when host checks drive properties
void tud_msc_inquiry_cb(uint8_t lun, uint8_t vendor_id[8], uint8_t product_id[16], uint8_t product_rev[4]) {
    (void) lun;
    const char vid[] = "Pico";
    const char pid[] = "Flash Drive";
    const char rev[] = "1.0";
    memcpy(vendor_id, vid, strlen(vid));
    memcpy(product_id, pid, strlen(pid));
    memcpy(product_rev, rev, strlen(rev));
}


// Invoked when host requests drive capacity
void tud_msc_capacity_cb(uint8_t lun, uint32_t* block_count, uint16_t* block_size) {
    (void) lun;
    *block_count = DISK_BLOCK_NUM;
    *block_size  = DISK_BLOCK_SIZE;
}


// Invoked when host checks if media ready
bool tud_msc_test_unit_ready_cb(uint8_t lun) {
    (void) lun;
    return true; 
}


// SCSI Read command hook pointing directly to Memory Mapped Flash (XIP Base)
int32_t tud_msc_read10_cb(uint8_t lun, uint32_t lba, uint32_t offset, void* buffer, uint32_t bufsize) {
    (void) lun; (void) offset;
    
    // Address assignment mapping directly out of target sector arrays
    uint8_t const* flash_target_contents = (const uint8_t*)(XIP_BASE + FLASH_TARGET_OFFSET + (lba * DISK_BLOCK_SIZE));
    memcpy(buffer, flash_target_contents, bufsize);
    
    return bufsize;
}


// SCSI Write command loop capturing blocks and program instructions directly to physical Flash
int32_t tud_msc_write10_cb(uint8_t lun, uint32_t lba, uint32_t offset, uint8_t* buffer, uint32_t bufsize) {
    (void) lun; (void) offset; // ignore

    uint32_t absolute_target_byte = FLASH_TARGET_OFFSET + (lba * DISK_BLOCK_SIZE);
    uint32_t sector_start_byte = absolute_target_byte & 0xFFFFF000;
    uint32_t byte_offset_inside_sector = absolute_target_byte % 4096;
    uint8_t const* current_flash_memory_ptr = (const uint8_t*)(XIP_BASE + sector_start_byte);
    
    memcpy(flash_sector_cache, current_flash_memory_ptr, 4096);
    memcpy(&flash_sector_cache[byte_offset_inside_sector], buffer, bufsize);
    
    uint32_t ints = save_and_disable_interrupts();
    
    flash_range_erase(sector_start_byte, 4096);
    flash_range_program(sector_start_byte, flash_sector_cache, 4096);    
    restore_interrupts(ints);
    return bufsize;
}


// Standard SCSI command validation block interface parameters
int32_t tud_msc_scsi_cb(uint8_t lun, uint8_t const scsi_cmd[16], void* buffer, uint16_t bufsize) {
    void* response = NULL;
    uint16_t resplen = 0;
    switch (scsi_cmd[0]) {
        default:
            tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x20, 0x00);
            return -1;
    }
    if (resplen > bufsize) resplen = bufsize;
    memcpy(buffer, response, resplen);
    return resplen;
}

// --------------------------------
// LED lights
// --------------------------------
static inline void put_pixel(uint32_t pixel_grb) {
    pio_sm_put_blocking(pio0, 0, pixel_grb << 8u);
}

static inline uint32_t urgb_u32(uint8_t r, uint8_t g, uint8_t b) {
    return ((uint32_t)(g) << 24) | ((uint32_t)(r) << 16) | ((uint32_t)(b) << 8);
}

// Hardware timer callback runs in ISR context
// NO TinyUSB calls in here!
bool blink_cb(struct repeating_timer *t) {
    led_state = !led_state;        
    if (led_state) {
        put_pixel(urgb_u32(5, 0, 0));  
    } else {
        put_pixel(urgb_u32(0, 0, 0));   
    }
    return true; // keep the timer active
}


// --------------------------------
// Pseudo sensor
// --------------------------------

bool sensor_cb(struct repeating_timer *t) {
    if (tud_mounted() && tud_cdc_connected()) {
#if SYNTHETIC_SENSOR
            sensor_buffer_len = snprintf(sensor_buffer, sizeof(sensor_buffer), "%u\r\n", get_rand_32()); // sprintf adds \0
#else
            sensor_buffer_len = 23;
#endif 

        if (tud_cdc_write_available() >= (uint32_t)sensor_buffer_len) {
#if SYNTHETIC_SENSOR
                tud_cdc_write_str(sensor_buffer);
#else
                tud_cdc_write_str("TinyUSB Stack: Active\r\n");
#endif
            tud_cdc_write_flush(); 
        }
    }
    return true; // keep the timer active
}



// --------------------------------
// Main Application Loop
// --------------------------------
int main() {
    set_sys_clock_khz(133000, true);
    tusb_init();

    PIO pio = pio0;
    int sm = 0;
    uint offset = pio_add_program(pio, &ws2812_program);
    ws2812_program_init(pio, sm, offset, WS2812_PIN, 800000, false);

    // theRP2040-Zero supports up to 4 hardware alarms/timers when NOT using an RTOS
    add_repeating_timer_us(TIMER_BLINK_MS*1000 /* MS to US*/, blink_cb, NULL, &timer_blink);
    add_repeating_timer_us(TIMER_SENSOR_MS*1000 /* MS to US*/, sensor_cb, NULL, &timer_sensor);

    // continuous TinyUSB event loop that serves as keep-alive signal to host.
    while (true) {
        tud_task(); // If this is delayed, the host may intermittently reset the device
    }
}
