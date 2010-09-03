/*
 * psfreedom_address.c -- PS3 Jailbreak exploit Gadget Driver
 *
 * Copyright (C) Youness Alaoui
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 2, as published by the Free Software Foundation.
 *
 * This code is based in part on:
 *
 * MUSB controller driver, Copyright 2005 Mentor Graphics Corporation
 * MUSB controller driver, Copyright (C) 2005-2006 by Texas Instruments
 * MUSB controller driver, Copyright (C) 2006-2007 Nokia Corporation
 *
 */

#ifdef ENABLE_MUSB_CONTROLLER

#include "../drivers/usb/musb/musb_core.h"
#include "../drivers/usb/musb/musb_gadget.h"

/**
 * psfreedom_is_high_speed:
 *
 * Determine whether this controller supports high speed or not
 * Returns: 1 if supports high speed, 0 otherwise
 */
int psfreedom_is_high_speed () {
  return 1;
}

/**
 * psfreedom_is_low_speed:
 *
 * Determine whether this controller supports low speed or not
 * Returns: 1 if supports low speed, 0 otherwise
 */
int psfreedom_is_low_speed () {
  return 0;
}

/**
 * psfreedom_get_endpoint_name:
 * epnum: The endpoint index number
 * in: set to 1 if it's for an IN endpoint
 *
 * A function to help find the name of the endpoint that we're looking for
 * Retursn: the name of the endpoint
 */
char *psfreedom_get_endpoint_name (int epnum, int in)
{
  if (epnum == 1 && in)
    return "ep1in";
  else if (epnum == 2 && in)
    return "ep2in";
  else if (epnum == 2 && !in)
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
u8 psfreedom_get_address (struct usb_gadget *g)
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
void psfreedom_set_address (struct usb_gadget *g, u8 address)
{
  struct musb *musb = gadget_to_musb (g);

  if (musb) {
    musb->address = address;
    musb_writeb(musb->mregs, MUSB_FADDR, address);
  }
}

#endif /* ENABLE_MUSB_CONTROLLER */
