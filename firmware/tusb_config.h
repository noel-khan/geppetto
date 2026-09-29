#ifndef _TUSB_CONFIG_H_
#define _TUSB_CONFIG_H_

// Set target microarchitecture
#define CFG_TUSB_MCU             OPT_MCU_RP2040

// --- FIX: Explicitly configure Root Hub Port 0 for the native RP2040 controller ---
#define CFG_TUSB_RHPORT0_MODE    (OPT_MODE_DEVICE | OPT_MODE_FULL_SPEED)

// Set standard TinyUSB operating system integration abstraction to Pico SDK
#define CFG_TUSB_OS              OPT_OS_PICO

// Enable device stack execution
#define CFG_TUD_ENABLED          1

// Enable Communication Device Class (CDC) for Virtual Serial Port
#define CFG_TUD_CDC              1
#define CFG_TUD_CDC_RX_BUFSIZE   64
#define CFG_TUD_CDC_TX_BUFSIZE   64

#define CFG_TUD_MSC              1
#define CFG_TUD_MSC_EP_BUFSIZE   512  // Standard sector block transmission chunk size

#endif
