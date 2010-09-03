/*
 * psfreedom.c -- PS3 Jailbreak exploit Gadget Driver
 *
 * Copyright (C) Youness Alaoui
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 2, as published by the Free Software Foundation.
 *
 * This code is based in part on:
 *
 * PSGroove
 * USB MIDI Gadget Driver, Copyright (C) 2006 Thumtronics Pty Ltd.
 * Gadget Zero driver, Copyright (C) 2003-2004 David Brownell.
 * USB Audio driver, Copyright (C) 2002 by Takashi Iwai.
 * USB MIDI driver, Copyright (C) 2002-2005 Clemens Ladisch.
 *
 */

#define DEBUG
//#define VERBOSE_DEBUG

#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/device.h>

#include <sound/core.h>
#include <sound/initval.h>
#include <sound/rawmidi.h>

#include <linux/usb/ch9.h>
#include <linux/usb/gadget.h>

#include "../drivers/usb/gadget/epautoconf.c"
#include "../drivers/usb/gadget/config.c"
#include "../drivers/usb/musb/musb_core.h"
#include "../drivers/usb/musb/musb_gadget.h"

/*-------------------------------------------------------------------------*/


MODULE_AUTHOR("Youness Alaoui");
MODULE_LICENSE("GPL v2");

#define DRIVER_VERSION "29 August 2010"

static const char shortname[] = "PSFreedom";
static const char longname[] = "PS3 Jailbreak exploit";

/* big enough to hold our biggest descriptor */
#define USB_BUFSIZ 4000

enum PsfreedomState {
  INIT,
  HUB_READY,
  DEVICE1_WAIT_READY,
  DEVICE1_READY,
  DEVICE1_WAIT_DISCONNECT,
  DEVICE1_DISCONNECTED,
  DEVICE2_WAIT_READY,
  DEVICE2_READY,
  DEVICE2_WAIT_DISCONNECT,
  DEVICE2_DISCONNECTED,
  DEVICE3_WAIT_READY,
  DEVICE3_READY,
  DEVICE3_WAIT_DISCONNECT,
  DEVICE3_DISCONNECTED,
  DEVICE4_WAIT_READY,
  DEVICE4_READY,
  DEVICE4_WAIT_DISCONNECT,
  DEVICE4_DISCONNECTED,
  DEVICE5_WAIT_READY,
  DEVICE5_CHALLENGED,
  DEVICE5_READY,
  DEVICE5_WAIT_DISCONNECT,
  DEVICE5_DISCONNECTED,
  DEVICE6_WAIT_READY,
  DEVICE6_READY,
  DONE,
};

#define STATUS_STR(s) (                                         \
      s==INIT?"INIT":                                           \
      s==HUB_READY?"HUB_READY":                                 \
      s==DEVICE1_WAIT_READY?"DEVICE1_WAIT_READY":               \
      s==DEVICE1_READY?"DEVICE1_READY":                         \
      s==DEVICE1_WAIT_DISCONNECT?"DEVICE1_WAIT_DISCONNECT":     \
      s==DEVICE1_DISCONNECTED?"DEVICE1_DISCONNECTED":           \
      s==DEVICE2_WAIT_READY?"DEVICE2_WAIT_READY":               \
      s==DEVICE2_READY?"DEVICE2_READY":                         \
      s==DEVICE2_WAIT_DISCONNECT?"DEVICE2_WAIT_DISCONNECT":     \
      s==DEVICE2_DISCONNECTED?"DEVICE2_DISCONNECTED":           \
      s==DEVICE3_WAIT_READY?"DEVICE3_WAIT_READY":               \
      s==DEVICE3_READY?"DEVICE3_READY":                         \
      s==DEVICE3_WAIT_DISCONNECT?"DEVICE3_WAIT_DISCONNECT":     \
      s==DEVICE3_DISCONNECTED?"DEVICE3_DISCONNECTED":           \
      s==DEVICE4_WAIT_READY?"DEVICE4_WAIT_READY":               \
      s==DEVICE4_READY?"DEVICE4_READY":                         \
      s==DEVICE4_WAIT_DISCONNECT?"DEVICE4_WAIT_DISCONNECT":     \
      s==DEVICE4_DISCONNECTED?"DEVICE4_DISCONNECTED":           \
      s==DEVICE5_WAIT_READY?"DEVICE5_WAIT_READY":               \
      s==DEVICE5_CHALLENGED?"DEVICE5_CHALLENGED":               \
      s==DEVICE5_READY?"DEVICE5_READY":                         \
      s==DEVICE5_WAIT_DISCONNECT?"DEVICE5_WAIT_DISCONNECT":     \
      s==DEVICE5_DISCONNECTED?"DEVICE5_DISCONNECTED":           \
      s==DEVICE6_WAIT_READY?"DEVICE6_WAIT_READY":               \
      s==DEVICE6_READY?"DEVICE6_READY":                         \
      s==DONE?"DONE":                                           \
      "UNKNOWN_STATE")

#define REQUEST_STR(r) (                        \
      r==0x8006?"GET_DESCRIPTOR":               \
      r==0xa006?"GET_HUB_DESCRIPTOR":           \
      r==0x0009?"SET_CONFIGURATION":            \
      r==0x2303?"SET_PORT_FEATURE":             \
      r==0xa300?"GET_PORT_STATUS":              \
      r==0x2301?"CLEAR_PORT_FEATURE":           \
      r==0x000B?"SET_INTERFACE":                \
      r==0x21AA?"FREEDOM":                   \
      "UNKNOWN")

#include "hub.h"

struct psfreedom_device {
  spinlock_t		lock;
  struct usb_gadget	*gadget;
  struct usb_request	*req;		/* for control responses */
  struct usb_ep		*hub_ep;
  struct usb_ep		*in_ep;
  struct usb_ep		*out_ep;
  enum PsfreedomState	status;
  int			challenge_len;
  int			response_len;
  struct hub_port	hub_ports[6];
  unsigned int		current_port;
  u8			port_address[7];
};

#ifdef DBG
#  undef DBG
#endif
#ifdef VDBG
#  undef VDBG
#endif
#ifdef INFO
#  undef INFO
#endif
#ifdef ERROR
#  undef ERROR
#endif



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

static int timer_added = 0;
static struct timer_list psfreedom_state_machine_timer;
#define SET_TIMER(ms) DBG (dev, "Setting timer to %dms\n", ms); \
  mod_timer (&psfreedom_state_machine_timer, jiffies + msecs_to_jiffies(ms))

static int switch_to_port_delayed = -1;


u8 musb_get_address (struct usb_gadget *g)
{
  struct musb *musb = gadget_to_musb (g);
  u8 address = 0;

  if (musb)
    address = musb_readb(musb->mregs, MUSB_FADDR);

  return address;
}

void musb_set_address (struct usb_gadget *g, u8 address)
{
  struct musb *musb = gadget_to_musb (g);

  if (musb) {
    musb->address = address;
    musb_writeb(musb->mregs, MUSB_FADDR, address);
  }
}

#include "hub.c"
#include "psfreedom_devices.c"


static void psfreedom_state_machine_timeout(unsigned long data)
{
  struct usb_gadget *gadget = (struct usb_gadget *)data;
  struct psfreedom_device *dev = get_gadget_data (gadget);
  unsigned long flags;

  spin_lock_irqsave (&dev->lock, flags);
  DBG (dev, "Timer fired, status is %s\n", STATUS_STR (dev->status));

  //SET_TIMER (1000);
  if (switch_to_port_delayed >= 0)
    switch_to_port (dev, switch_to_port_delayed);
  switch_to_port_delayed = -1;

  switch (dev->status) {
    case HUB_READY:
      dev->status = DEVICE1_WAIT_READY;
      hub_connect_port (dev, 1);
      break;
    case DEVICE1_READY:
      dev->status = DEVICE2_WAIT_READY;
      hub_connect_port (dev, 2);
      break;
    case DEVICE2_READY:
      dev->status = DEVICE3_WAIT_READY;
      hub_connect_port (dev, 3);
      break;
    case DEVICE3_READY:
      dev->status = DEVICE2_WAIT_DISCONNECT;
      hub_disconnect_port (dev, 2);
      break;
    case DEVICE2_DISCONNECTED:
      dev->status = DEVICE4_WAIT_READY;
      hub_connect_port (dev, 4);
      break;
    case DEVICE4_READY:
      dev->status = DEVICE5_WAIT_READY;
      hub_connect_port (dev, 5);
      break;
    case DEVICE5_CHALLENGED:
      jig_response_send (dev, NULL);
      break;
    case DEVICE5_READY:
      dev->status = DEVICE3_WAIT_DISCONNECT;
      hub_disconnect_port (dev, 3);
      break;
    case DEVICE3_DISCONNECTED:
      dev->status = DEVICE5_WAIT_DISCONNECT;
      hub_disconnect_port (dev, 5);
      break;
    case DEVICE5_DISCONNECTED:
      dev->status = DEVICE4_WAIT_DISCONNECT;
      hub_disconnect_port (dev, 4);
      break;
    case DEVICE4_DISCONNECTED:
      dev->status = DEVICE1_WAIT_DISCONNECT;
      hub_disconnect_port (dev, 1);
      break;
    case DEVICE1_DISCONNECTED:
      dev->status = DEVICE6_WAIT_READY;
      hub_connect_port (dev, 6);
      break;
    case DEVICE6_READY:
      dev->status = DONE;
      INFO (dev, "YAHOO, worked!");
      del_timer (&psfreedom_state_machine_timer);
      timer_added = 0;
      break;
    default:
      break;
  }
  spin_unlock_irqrestore (&dev->lock, flags);

}

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

static void psfreedom_disconnect (struct usb_gadget *gadget)
{
  struct psfreedom_device *dev = get_gadget_data (gadget);
  unsigned long flags;
  int i;

  spin_lock_irqsave (&dev->lock, flags);
  DBG (dev, "Got disconnected\n");
  dev->challenge_len = 0;
  dev->response_len = 0;
  dev->current_port = 0;
  for (i = 0; i < 6; i++)
    dev->hub_ports[i].status = dev->hub_ports[i].change = 0;
  for (i = 0; i < 7; i++)
    dev->port_address[i] = 0;
  hub_disconnect (gadget);
  devices_disconnect (gadget);
  del_timer (&psfreedom_state_machine_timer);
  timer_added = 0;
  dev->status = INIT;
  spin_unlock_irqrestore (&dev->lock, flags);
}

static void psfreedom_setup_complete(struct usb_ep *ep, struct usb_request *req)
{
  struct psfreedom_device *dev = ep->driver_data;
  unsigned long flags;

  spin_lock_irqsave (&dev->lock, flags);
  if (req->status || req->actual != req->length) {
    struct psfreedom_device * dev = (struct psfreedom_device *) ep->driver_data;
    DBG(dev, "%s setup complete FAIL --> %d, %d/%d\n",
        STATUS_STR (dev->status), req->status, req->actual, req->length);
  } else {
    VDBG(dev, "%s setup complete SUCCESS --> %d, %d/%d\n",
        STATUS_STR (dev->status), req->status, req->actual, req->length);
  }
  spin_unlock_irqrestore (&dev->lock, flags);
}

/*
 * The setup() callback implements all the ep0 functionality that's
 * not handled lower down, in hardware or the hardware driver (like
 * device and endpoint feature flags, and their status).  It's all
 * housekeeping for the gadget function we're implementing.  Most of
 * the work is in config-specific setup.
 */
static int psfreedom_setup(struct usb_gadget *gadget,
    const struct usb_ctrlrequest *ctrl)
{
  struct psfreedom_device *dev = get_gadget_data(gadget);
  struct usb_request *req = dev->req;
  int value = -EOPNOTSUPP;
  u16 w_index = le16_to_cpu(ctrl->wIndex);
  u16 w_value = le16_to_cpu(ctrl->wValue);
  u16 w_length = le16_to_cpu(ctrl->wLength);
  u8 address = musb_get_address (dev->gadget);
  unsigned long flags;
  u16 request = (ctrl->bRequestType << 8) | ctrl->bRequest;

  spin_lock_irqsave (&dev->lock, flags);
  VDBG (dev, "Setup called %d (%d) -- %d -- %d. Myaddr :%d\n", ctrl->bRequest,
      ctrl->bRequestType, w_value, w_index, address);

  req->zero = 0;

  if (timer_added == 0)
    add_timer (&psfreedom_state_machine_timer);
  timer_added = 1;

  if (address)
    dev->port_address[dev->current_port] = address;

  if (dev->current_port == 0)
    value = hub_setup (gadget, ctrl, request, w_index, w_value, w_length);
  else
    value = devices_setup (gadget, ctrl, request, w_index, w_value, w_length);

  VDBG (dev, "setup finished with value %d (w_length=%d)\n", value, w_length);
  DBG (dev, "%s Setup called %s (%d - %d) -> %d\n", STATUS_STR (dev->status),
      REQUEST_STR (request), w_value, w_index, value);

  /* respond with data transfer before status phase? */
  if (value >= 0) {
    req->length = value;
    req->zero = value < w_length;
    value = usb_ep_queue(gadget->ep0, req, GFP_ATOMIC);
    if (value < 0) {
      DBG(dev, "ep_queue --> %d\n", value);
      req->status = 0;
      spin_unlock_irqrestore (&dev->lock, flags);
      psfreedom_setup_complete(gadget->ep0, req);
      return value;
    }
  }

  spin_unlock_irqrestore (&dev->lock, flags);
  /* device either stalls (value < 0) or reports success */
  return value;
}

static void /* __init_or_exit */ psfreedom_unbind(struct usb_gadget *gadget)
{
  struct psfreedom_device *dev = get_gadget_data(gadget);

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



static int __init psfreedom_bind(struct usb_gadget *gadget)
{
  struct psfreedom_device *dev;
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

  dev->current_port = 0;
  dev->req->complete = psfreedom_setup_complete;
  gadget->ep0->driver_data = dev;

  INFO(dev, "%s, version: " DRIVER_VERSION "\n", longname);

  usb_ep_autoconfig_reset(gadget);

  err = hub_bind (gadget, dev);
  if (err < 0)
    goto fail;

  err = devices_bind (gadget, dev);
  if (err < 0)
    goto fail;

  DBG(dev, "psfreedom_bind finished ok. Maxpacket: %d\n", gadget->ep0->maxpacket);

  setup_timer(&psfreedom_state_machine_timer, psfreedom_state_machine_timeout,
      (unsigned long) gadget);

  psfreedom_disconnect (gadget);

  return 0;

 fail:
  psfreedom_unbind(gadget);
  return err;
}


static void psfreedom_suspend(struct usb_gadget *gadget)
{
  struct psfreedom_device *dev = get_gadget_data(gadget);

  if (gadget->speed == USB_SPEED_UNKNOWN) {
    return;
  }

  DBG(dev, "suspend\n");
}

static void psfreedom_resume(struct usb_gadget *gadget)
{
  struct psfreedom_device *dev = get_gadget_data(gadget);

  DBG(dev, "resume\n");
}


static struct usb_gadget_driver psfreedom_driver = {
  .speed	= USB_SPEED_HIGH,
  .function	= (char *)longname,

  .bind		= psfreedom_bind,
  .unbind	= psfreedom_unbind,

  .setup	= psfreedom_setup,
  .disconnect	= psfreedom_disconnect,

  .suspend	= psfreedom_suspend,
  .resume	= psfreedom_resume,

  .driver	= {
    .name		= (char *)shortname,
    .owner		= THIS_MODULE,
  },
};

static int __init psfreedom_init(void)
{
  int ret = 0;

  printk(KERN_INFO "init\n");
  ret = usb_gadget_register_driver(&psfreedom_driver);

  printk(KERN_INFO "register driver returned %d\n", ret);

  return ret;
}
module_init(psfreedom_init);

static void __exit psfreedom_cleanup(void)
{
  usb_gadget_unregister_driver(&psfreedom_driver);
}
module_exit(psfreedom_cleanup);

