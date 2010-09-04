/*
 * psfreedom_address.c -- PS3 Jailbreak exploit Gadget Driver
 *
 * Copyright (C) Youness Alaoui
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 * This code is based in part on:
 *
 * MUSB controller driver, Copyright 2005 Mentor Graphics Corporation
 * MUSB controller driver, Copyright (C) 2005-2006 by Texas Instruments
 * MUSB controller driver, Copyright (C) 2006-2007 Nokia Corporation
 *
 */

#ifdef ENABLE_MUSB_CONTROLLER

/* Kernel 2.6.21 (N800/N900) needs this to compile */
#define MUSB_DEBUG 0

#include "../drivers/usb/musb/musb_core.h"
#include "../drivers/usb/musb/musb_gadget.h"

/**
 * psfreedom_is_high_speed:
 *
 * Determine whether this controller supports high speed or not
 * Returns: 1 if supports high speed, 0 otherwise
 */
static int psfreedom_is_high_speed (void)
{
  return 1;
}

/**
 * psfreedom_is_low_speed:
 *
 * Determine whether this controller supports low speed or not
 * Returns: 1 if supports low speed, 0 otherwise
 */
static int psfreedom_is_low_speed (void)
{
  return 0;
}

/**
 * psfreedom_get_endpoint_name:
 * desc: The endpoint description
 *
 * A function to help find the name of the endpoint that we're looking for.
 * This should take into consideration the endpoint address and the direction.
 * Make sure each endpoint requested (1 IN, 2 IN and 2 OUT) has a different
 * endpoint name to avoid a single endpoint being used for different devices.
 *
 * Returs: the name of the endpoint
 */
static char *psfreedom_get_endpoint_name (struct usb_endpoint_descriptor *desc)
{
  u8 address = desc->bEndpointAddress;
  u8 epnum = address & 0x0f;

  if (epnum == 1 && (address & USB_DIR_IN) == USB_DIR_IN)
    return "ep1in";
  else if (epnum == 2 && (address & USB_DIR_IN) == USB_DIR_IN)
    return "ep2in";
  else if (epnum == 2 && (address & USB_DIR_IN) == 0)
    return "ep2out";
  else
    return NULL;
}

/**
 * psfreedom_get_address:
 * @g: The usb_gadget
 *
 * Fetch the address of the usb controller
 * Returns: the address set on the controller
 */
static u8 psfreedom_get_address (struct usb_gadget *g)
{
  struct musb *musb = gadget_to_musb (g);
  u8 address = 0;

  if (musb)
    address = musb_readb(musb->mregs, MUSB_FADDR);

  return address;
}

/**
 * psfreedom_set_address:
 * @g: The usb_gadget
 * @address: The address to set
 *
 * Change the address of the usb controller
 */
static void psfreedom_set_address (struct usb_gadget *g, u8 address)
{
  struct musb *musb = gadget_to_musb (g);

  if (musb) {
    musb->address = address;
    musb_writeb(musb->mregs, MUSB_FADDR, address);
  }
}

#endif /* ENABLE_MUSB_CONTROLLER */
