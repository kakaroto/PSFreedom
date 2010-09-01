/*
 * <linux/usb/audio.h> -- USB Audio definitions.
 *
 * Copyright (C) 2006 Thumtronics Pty Ltd.
 * Developed for Thumtronics by Grey Innovation
 * Ben Williamson <ben.williamson@greyinnovation.com>
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 2, as published by the Free Software Foundation.
 *
 * This file holds USB constants and structures defined
 * by the USB Device Class Definition for Audio Devices.
 * Comments below reference relevant sections of that document:
 *
 * http://www.usb.org/developers/devclass_docs/audio10.pdf
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

#endif /* __LINUX_USB_HUB_H */
