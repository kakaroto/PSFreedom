/*
 * psfreedom_devices.h -- PS3 Jailbreak exploit Gadget Driver
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 * This code is based in part on:
 * PSGroove
 *
 */

#include "pl3/shellcode_egghunt.h"

#define MAGIC_NUMBER            0x50, 0x53, 0x46, 0x72, 0x65, 0x65, 0x64, 0x6d
#define RTOC_TABLE              0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xe7, 0x20

#ifdef USE_JIG
#include "pl3/default_payload_3_41.h"
#include "pl3/default_payload_3_40.h"
#include "pl3/default_payload_3_21.h"
#include "pl3/default_payload_3_30.h"
#include "pl3/default_payload_3_15.h"
#include "pl3/default_payload_3_10.h"
#include "pl3/default_payload_3_01.h"
#include "pl3/default_payload_2_85.h"
#include "pl3/default_payload_2_76.h"
#include "pl3/shellcode_panic.h"

/* Default firmware is the first entry in the list */
static const Firmware_t supported_firmwares[] = {
  {"3.41",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x3d, 0xee, 0x70},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xe7, 0x20},
   default_payload_3_41,
   sizeof(default_payload_3_41),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.40",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x3d, 0xee, 0x70},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xe7, 0x20},
   default_payload_3_40,
   sizeof(default_payload_3_40),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.30",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x3d, 0xde, 0x70},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xdb, 0xc0},
   default_payload_3_30,
   sizeof(default_payload_3_30),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.21",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x3d, 0xde, 0x30},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xda, 0x90},
   default_payload_3_21,
   sizeof(default_payload_3_21),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.15",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x3d, 0xde, 0x30},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xda, 0x10},
   default_payload_3_15,
   sizeof(default_payload_3_15),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.10",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x3d, 0xde, 0x30},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xda, 0x10},
   default_payload_3_10,
   sizeof(default_payload_3_10),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.01",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x3B, 0xFB, 0xC8},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x32, 0x06, 0x40},
   default_payload_3_01,
   sizeof(default_payload_3_01),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"2.85",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x3B, 0xBB, 0xC8},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x31, 0x3E, 0x70},
   shellcode_panic,
   sizeof(shellcode_panic),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"2.76",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x3B, 0x1B, 0xC8},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x31, 0x3E, 0x70},
   default_payload_2_76,
   sizeof(default_payload_2_76),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {NULL}
};

#define SHELLCODE_ADDR_BASE     0x80, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00
#define SHELLCODE_PAGE          0x80, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00
#define SHELLCODE_DESTINATION   SHELLCODE_ADDR_BASE
#define SHELLCODE_PTR           SHELLCODE_ADDR_BASE + 0x08
#define SHELLCODE_ADDRESS       SHELLCODE_ADDR_BASE + 0x18

#define PORT1_NUM_CONFIGS       4

#else /* USE_JIG */

#include "pl3/dump_lv2.h"
#include "pl3/shellcode_panic.h"

#define SHELLCODE_ADDR_BASE     0x80, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00
#define SHELLCODE_PAGE          SHELLCODE_ADDR_BASE
#define SHELLCODE_DESTINATION   SHELLCODE_ADDR_BASE + 0x20
#define SHELLCODE_PTR           SHELLCODE_ADDR_BASE + 0x28
#define SHELLCODE_ADDRESS       SHELLCODE_ADDR_BASE + 0x38

static const Firmware_t supported_firmwares[] = {
  {"x.yz",
   {SHELLCODE_ADDR_BASE},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x31, 0x3E, 0x70},
   shellcode_panic,
   sizeof(shellcode_panic),
   shellcode_panic,
   sizeof(shellcode_panic)
  },
  {"3.41",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x10, 0x00},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xe7, 0x20},
   dump_lv2,
   sizeof(dump_lv2),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.40",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xe7, 0x20},
   dump_lv2,
   sizeof(dump_lv2),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.30",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xdb, 0xc0},
   dump_lv2,
   sizeof(dump_lv2),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.21",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xda, 0x90},
   dump_lv2,
   sizeof(dump_lv2),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.15",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xda, 0x10},
   dump_lv2,
   sizeof(dump_lv2),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.10",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x33, 0xda, 0x10},
   dump_lv2,
   sizeof(dump_lv2),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"3.01",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x00},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x32, 0x06, 0x40},
   dump_lv2,
   sizeof(dump_lv2),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {"2.76",
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x3B, 0x1B, 0xC8},
   {0x80, 0x00, 0x00, 0x00, 0x00, 0x31, 0x3E, 0x70},
   dump_lv2,
   sizeof(dump_lv2),
   shellcode_egghunt,
   sizeof(shellcode_egghunt)
  },
  {NULL}
};

#define PORT1_NUM_CONFIGS       100

#endif /* USE_JIG */

/* Hub endpoint Descriptor */
static struct usb_endpoint_descriptor jig_out_endpoint_desc = {
  .bLength =            USB_DT_ENDPOINT_SIZE,
  .bDescriptorType =    USB_DT_ENDPOINT,
  .bEndpointAddress =   USB_DIR_OUT | 0x02,
  .bmAttributes =       USB_ENDPOINT_XFER_BULK,
  .wMaxPacketSize =     __constant_cpu_to_le16(8),
  .bInterval =          0x00,
};

/* Hub endpoint Descriptor */
static struct usb_endpoint_descriptor jig_in_endpoint_desc = {
  .bLength =            USB_DT_ENDPOINT_SIZE,
  .bDescriptorType =    USB_DT_ENDPOINT,
  .bEndpointAddress =   USB_DIR_IN | 0x01,
  .bmAttributes =       USB_ENDPOINT_XFER_BULK,
  .wMaxPacketSize =     __constant_cpu_to_le16(8),
  .bInterval =          0x00,
};

static u8 jig_response[64] = {
  0x4a, 0x49, 0x47, 0x20, 0x52, 0x45, 0x53, 0x50,
  0x4f, 0x4e, 0x53, 0x45, 0x20, 0x42, 0x55, 0x46,
  0x46, 0x45, 0x52, 0x20, 0x20, 0x20, 0x20, 0x20
};

static u8 port1_device_desc[] = {
  0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08,
  0xAA, 0xAA, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00,
  0x00, PORT1_NUM_CONFIGS,
};

static u8 port1_short_config_desc[] = {
  0x09, 0x02, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x80,
};

static u8 port1_config_desc_prefix[] = {
  0x09, 0x02, 0x12, 0x00, 0x01, 0x00, 0x00, 0x80, 0xfa,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  MAGIC_NUMBER,
#ifndef USE_JIG
  SHELLCODE_PTR,
  SHELLCODE_ADDRESS,
  RTOC_TABLE
#endif
};

static u8 port2_device_desc[] = {
  0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08,
  0xAA, 0xAA, 0xBB, 0xBB, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x01,
};

static u8 port2_config_desc[] = {
  // config
  0x09, 0x02, 0x16, 0x00, 0x01, 0x01, 0x00, 0x80, 0x01,
  // interface
  0x09, 0x04, 0x00, 0x00, 0x00, 0xFE, 0x01, 0x02, 0x00,
  // extra
  0x04, 0x21, 0xb4, 0x2f,
};

static u8 port3_device_desc[] = {
  0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08,
  0xAA, 0xAA, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x02,
};


const u8 port0_device_desc[] = {
  0x50, 0x53, 0x46, 0x72, 0x65, 0x65, 0x64, 0x6f,
  0x6d, 0x20, 0x62, 0x79, 0x20, 0x4b, 0x61, 0x4b,
  0x61, 0x52, 0x6f, 0x54, 0x6f, 0x0a, 0x52, 0x65,
  0x6c, 0x65, 0x61, 0x73, 0x65, 0x64, 0x20, 0x75,
  0x6e, 0x64, 0x65, 0x72, 0x20, 0x47, 0x50, 0x4c,
  0x20, 0x76, 0x33, 0x0a, 0x00, 0x00, 0x00, 0x00,
};

static u8 port3_config_desc[] = {
  0x09, 0x02, 0x4d, 0x0a, 0x01, 0x01, 0x00, 0x80, 0x01,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x00, 0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00, 0x09, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00, 0x09, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x02, 0x00, 0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x00, 0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00, 0x09, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x02, 0x00, 0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02,
};

static u8 port4_device_desc[] = {
  0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08,
  0xAA, 0xAA, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x03,
};

static u8 port4_config_desc_1[] = {
  // config
  0x09, 0x02, 0x12, 0x00, 0x01, 0x01, 0x00, 0x80,
  0x01,
  // interface
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02,
  0x00,
};

static u8 port4_short_config_desc_2[] = {
  // config
  0x09, 0x02, 0x12, 0x00, 0x01, 0x01, 0x00, 0x80,
};

static u8 port4_config_desc_2[] = {
  // config
  0x09, 0x02, 0x00, 0x00, 0x01, 0x01, 0x00, 0x80, 0x01,
  // interface
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
};

static u8 port4_config_desc_3[] = {
  0x09, 0x02, 0x30, 0x00, 0x01, 0x01, 0x00, 0x80, 0x01,
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
  0x3e, 0x21, 0x00, 0x00, 0x00, 0x00,
  MAGIC_NUMBER, /* magic number to look for in the start of the page */
  SHELLCODE_PAGE, /* Initial data search ptr */
  SHELLCODE_DESTINATION, /* destination ptr for heap structure (jig response) */
};

static u8 port5_device_desc[] = {
  0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08,
  0x4c, 0x05, 0xeb, 0x02, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x01,
};

static u8 port5_config_desc[] = {
  // config
  0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0x01,
  // interface
  0x09, 0x04, 0x01, 0x00, 0x02, 0xff, 0x00, 0x00, 0x00,
  // endpoint
  0x07, 0x05, 0x02, 0x02, 0x08, 0x00, 0x00,
  // endpoint
  0x07, 0x05, 0x81, 0x02, 0x08, 0x00, 0x00,
};

static u8 port6_device_desc[] = {
  0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08,
  0xAA, 0xAA, 0x13, 0x37, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x01,
};

static u8 port6_config_desc[] = {
  // config
  0x09, 0x02, 0x12, 0x00, 0x01, 0x01, 0x00, 0x80, 0x01,
  // interface
  0x09, 0x04, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x02, 0x00,
};
