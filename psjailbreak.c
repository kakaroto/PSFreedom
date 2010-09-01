/*
 * psjailbreak.c -- PS3 Jailbreak exploit Gadget Driver
 *
 * Copyright (C) Youness Alaoui
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 2, as published by the Free Software Foundation.
 *
 * This code is based in part on:
 *
 * USB MIDI Gadget Driver, Copyright (C) 2006 Thumtronics Pty Ltd.
 * Gadget Zero driver, Copyright (C) 2003-2004 David Brownell.
 * USB Audio driver, Copyright (C) 2002 by Takashi Iwai.
 * USB MIDI driver, Copyright (C) 2002-2005 Clemens Ladisch.
 *
 */

#define DEBUG
#define VERBOSE_DEBUG

#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/device.h>

#include <sound/core.h>
#include <sound/initval.h>
#include <sound/rawmidi.h>

#include <linux/usb/ch9.h>
#include <linux/usb/gadget.h>

#include "../kernel-2.6.28/drivers/usb/gadget/epautoconf.c"
#include "../kernel-2.6.28/drivers/usb/gadget/config.c"


/*-------------------------------------------------------------------------*/


MODULE_AUTHOR("Youness Alaoui");
MODULE_LICENSE("GPL v2");

#define DRIVER_VERSION "29 August 2010"

static const char shortname[] = "ps3jailbreak";
static const char longname[] = "PS3 Jailbreak exploit";

/* big enough to hold our biggest descriptor */
#define USB_BUFSIZ 4000

enum PsjailbState {INIT_HUB, CONNECT_DEVICE_1};
#define STATUS_STR(s) (s==INIT_HUB?"INIT_HUB": \
      s==CONNECT_DEVICE_1?"CONNECT_DEVICE_1": \
      "UNKNOWN_STATE")


#include "hub.h"

struct psjailb_device {
  spinlock_t		lock;
  struct usb_gadget	*gadget;
  struct usb_request	*req;		/* for control responses */
  u8			config;
  struct usb_ep		*in_ep;
  enum PsjailbState	status;
  struct hub_port	hub_ports[6];
};


#define DBG(d, fmt, args...)                    \
  dev_dbg(&(d)->gadget->dev , fmt , ## args)
#define VDBG(d, fmt, args...)                   \
  dev_vdbg(&(d)->gadget->dev , fmt , ## args)
#define ERROR(d, fmt, args...)                  \
  dev_err(&(d)->gadget->dev , fmt , ## args)
#define INFO(d, fmt, args...)                   \
  dev_info(&(d)->gadget->dev , fmt , ## args)


static struct usb_request *alloc_ep_req(struct usb_ep *ep, unsigned length);
static void free_ep_req(struct usb_ep *ep, struct usb_request *req);


#include "hub.c"

static struct usb_request *alloc_ep_req(struct usb_ep *ep, unsigned length)
{
  struct usb_request	*req;

  req = usb_ep_alloc_request(ep, GFP_ATOMIC);
  if (req) {
    req->length = length;
    req->buf = kmalloc(length, GFP_ATOMIC);
    if (!req->buf) {
      usb_ep_free_request(ep, req);
      req = NULL;
    }
  }
  return req;
}

static void free_ep_req(struct usb_ep *ep, struct usb_request *req)
{
  kfree(req->buf);
  usb_ep_free_request(ep, req);
}

static void psjailb_disconnect (struct usb_gadget *gadget)
{
  struct psjailb_device *dev = get_gadget_data (gadget);
  unsigned long flags;

  spin_lock_irqsave (&dev->lock, flags);
  hub_disconnect (gadget);
  /* TODO: disconnect others? */
  spin_unlock_irqrestore (&dev->lock, flags);
}

static void psjailb_setup_complete(struct usb_ep *ep, struct usb_request *req)
{
  if (req->status || req->actual != req->length) {
    struct psjailb_device * dev = (struct psjailb_device *) ep->driver_data;
    DBG(dev, "%s setup complete --> %d, %d/%d\n",
        STATUS_STR (dev->status), req->status, req->actual, req->length);
  }
}

/*
 * The setup() callback implements all the ep0 functionality that's
 * not handled lower down, in hardware or the hardware driver (like
 * device and endpoint feature flags, and their status).  It's all
 * housekeeping for the gadget function we're implementing.  Most of
 * the work is in config-specific setup.
 */
static int psjailb_setup(struct usb_gadget *gadget,
    const struct usb_ctrlrequest *ctrl)
{
  struct psjailb_device *dev = get_gadget_data(gadget);
  struct usb_request *req = dev->req;
  int value = -EOPNOTSUPP;
  u16 w_index = le16_to_cpu(ctrl->wIndex);
  u16 w_value = le16_to_cpu(ctrl->wValue);
  u16 w_length = le16_to_cpu(ctrl->wLength);

  DBG (dev, "Setup called %d (%d) -- %d -- %d. Myaddr :%d\n", ctrl->bRequest,
      ctrl->bRequestType, w_value, w_index, usb_gadget_get_address ());

  req->zero = 0;

  if (dev->status == INIT_HUB) {
    value = hub_setup (gadget, ctrl, (ctrl->bRequestType << 8) | ctrl->bRequest,
        w_index, w_value, w_length);
  }

  DBG (dev, "setup finished with value %d (w_length=%d)\n", value, w_length);

  /* respond with data transfer before status phase? */
  if (value >= 0) {
    req->length = value;
    req->zero = value < w_length;
    value = usb_ep_queue(gadget->ep0, req, GFP_ATOMIC);
    if (value < 0) {
      DBG(dev, "ep_queue --> %d\n", value);
      req->status = 0;
      psjailb_setup_complete(gadget->ep0, req);
    }
  }

  /* device either stalls (value < 0) or reports success */
  return value;
}

static void /* __init_or_exit */ psjailb_unbind(struct usb_gadget *gadget)
{
  struct psjailb_device *dev = get_gadget_data(gadget);

  DBG(dev, "unbind\n");

  /* we've already been disconnected ... no i/o is active */
  if (dev) {
    if (dev->req) {
      dev->req->length = USB_BUFSIZ;
      free_ep_req(gadget->ep0, dev->req);
    }
    kfree(dev);
    set_gadget_data(gadget, NULL);
  }
}



static int __init psjailb_bind(struct usb_gadget *gadget)
{
  struct psjailb_device *dev;
  int err = 0;

  dev = kzalloc(sizeof(*dev), GFP_KERNEL);
  if (!dev) {
    return -ENOMEM;
  }

  spin_lock_init(&dev->lock);
  usb_gadget_set_selfpowered (gadget);
  dev->gadget = gadget;
  set_gadget_data(gadget, dev);

  /* preallocate control response and buffer */
  dev->req = alloc_ep_req(gadget->ep0, USB_BUFSIZ);
  if (!dev->req) {
    err = -ENOMEM;
    goto fail;
  }

  dev->req->complete = psjailb_setup_complete;
  gadget->ep0->driver_data = dev;

  INFO(dev, "%s, version: " DRIVER_VERSION "\n", longname);

  err = hub_bind (gadget, dev);

  if (err < 0)
    goto fail;

  VDBG(dev, "psjailb_bind finished ok\n");
  return 0;

 fail:
  psjailb_unbind(gadget);
  return err;
}


static void psjailb_suspend(struct usb_gadget *gadget)
{
  struct psjailb_device *dev = get_gadget_data(gadget);

  if (gadget->speed == USB_SPEED_UNKNOWN) {
    return;
  }

  DBG(dev, "suspend\n");
}

static void psjailb_resume(struct usb_gadget *gadget)
{
  struct psjailb_device *dev = get_gadget_data(gadget);

  DBG(dev, "resume\n");
}


static struct usb_gadget_driver psjailb_driver = {
  .speed	= USB_SPEED_HIGH,
  .function	= (char *)longname,

  .bind		= psjailb_bind,
  .unbind	= psjailb_unbind,

  .setup	= psjailb_setup,
  .disconnect	= psjailb_disconnect,

  .suspend	= psjailb_suspend,
  .resume	= psjailb_resume,

  .driver	= {
    .name		= (char *)shortname,
    .owner		= THIS_MODULE,
  },
};

static int __init psjailb_init(void)
{
  int ret = 0;

  printk(KERN_INFO "init\n");
  ret = usb_gadget_register_driver(&psjailb_driver);

  printk(KERN_INFO "register driver returned %d\n", ret);

  return ret;
}
module_init(psjailb_init);

static void __exit psjailb_cleanup(void)
{
  usb_gadget_unregister_driver(&psjailb_driver);
}
module_exit(psjailb_cleanup);

