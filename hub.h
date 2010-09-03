/*
 * hub.h -- USB HUB definitions.
 *
 * Copyright (C) Youness Alaoui
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 2, as published by the Free Software Foundation.
 *
 * This file holds USB constants and structures defined
 * by the USB Device Class Definition for HUB Devices.
 * Comments below reference relevant sections of that document:
 *
 */

#ifndef __LINUX_USB_HUB_H
#define __LINUX_USB_HUB_H

#include <linux/types.h>

#define USB_DT_CS_HUB 0x29

/* 11.23.2.1  Class-Specific AC Interface Descriptor */
struct usb_hub_header_descriptor {
	__u8  bLength;			/* 8+n */
	__u8  bDescriptorType;		/* USB_DT_CS_HUB */
	__u8  bNbrPorts;		/* n */
	__le16 wHubCharacteristics;	/* hub characteristics */
	__u8  bPwrOn2PwrGood;		/* ? */
	__u8  bHubContrCurrent;		/* ? */
	__u8  DeviceRemovable;		/* [n/8] */
	__u8  PortPwrCtrlMask;		/* [n/8] */
} __attribute__ ((packed));

#define USB_DT_HUB_HEADER_SIZE(n)	(sizeof(struct usb_hub_header_descriptor))


#define PORT_STAT_CONNECTION	0x0001
#define PORT_STAT_ENABLE	0x0002
#define PORT_STAT_RESET		0x0010
#define PORT_STAT_POWER		0x0100
#define PORT_STAT_LOW_SPEED	0x0200
#define PORT_STAT_HIGH_SPEED	0x0400

#define PORT_STAT_C_CONNECTION	0x0001
#define PORT_STAT_C_RESET	0x0010


struct hub_port {
  u16 status;
  u16 change;
};

#endif /* __LINUX_USB_HUB_H */
