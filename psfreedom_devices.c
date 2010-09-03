/*
 * psfreedom_devices.c -- PS3 Jailbreak exploit Gadget Driver
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

#include "psfreedom_devices.h"

static void jig_response_send (struct psfreedom_device *dev, struct usb_request *req);

static void jig_response_complete(struct usb_ep *ep, struct usb_request *req)
{
  struct psfreedom_device *dev = ep->driver_data;
  int status = req->status;
  unsigned long flags;

  spin_lock_irqsave (&dev->lock, flags);
  DBG (dev, "Jig response sent (status %d). Sent data so far : %d + %d\n", status,
      dev->response_len, req->length);

  switch (status) {
    case 0:				/* normal completion */
      if (ep == dev->in_ep) {
        /* our transmit completed.
           see if there's more to go.
           hub_transmit eats req, don't queue it again. */
        dev->response_len += req->length;
        if (dev->response_len < 64) {
          jig_response_send (dev, req);
        } else {
          dev->status = DEVICE5_READY;
          SET_TIMER (150);
        }
        spin_unlock_irqrestore (&dev->lock, flags);
        return;
      }
      break;

      /* this endpoint is normally active while we're configured */
    case -ECONNABORTED:		/* hardware forced ep reset */
    case -ESHUTDOWN:		/* disconnect from host */
      VDBG(dev, "%s gone (%d), %d/%d\n", ep->name, status,
          req->actual, req->length);
    case -ECONNRESET:		/* request dequeued */
      hub_interrupt_queued = 0;
      spin_unlock_irqrestore (&dev->lock, flags);
      return;

    case -EOVERFLOW:		/* buffer overrun on read means that
                                 * we didn't provide a big enough
                                 * buffer.
                                 */
    default:
      DBG(dev, "%s complete --> %d, %d/%d\n", ep->name,
          status, req->actual, req->length);
      break;
    case -EREMOTEIO:		/* short read */
      break;
  }

  status = usb_ep_queue(ep, req, GFP_ATOMIC);
  if (status) {
    ERROR(dev, "kill %s:  resubmit %d bytes --> %d\n",
        ep->name, req->length, status);
    usb_ep_set_halt(ep);
    /* FIXME recover later ... somehow */
  }
  spin_unlock_irqrestore (&dev->lock, flags);
}

static void jig_response_send (struct psfreedom_device *dev, struct usb_request *req)
{
  struct usb_ep *ep = dev->in_ep;

  if (!ep)
    return;

  if (!req)
    req = alloc_ep_req(ep, 8);

  if (!req) {
    ERROR(dev, "hub_interrupt_transmit: alloc_ep_request failed\n");
    return;
  }

  req->complete = jig_response_complete;

  memcpy (req->buf, jig_response + dev->response_len, 8);
  req->length = 8;
  DBG (dev, "transmitting response. Sent so far %d\n", dev->response_len);
  DBG (dev, "Sending %X %X %X %X %X %X %X %X\n",
      ((char *)req->buf)[0], ((char *)req->buf)[1],
      ((char *)req->buf)[2], ((char *)req->buf)[3],
      ((char *)req->buf)[4], ((char *)req->buf)[5],
      ((char *)req->buf)[6], ((char *)req->buf)[7]);

  usb_ep_queue(ep, req, GFP_ATOMIC);
}


static void jig_interrupt_complete(struct usb_ep *ep, struct usb_request *req)
{
  struct psfreedom_device *dev = ep->driver_data;
  int status = req->status;
  unsigned long flags;

  spin_lock_irqsave (&dev->lock, flags);
  DBG (dev, "******Out interrupt complete (status %d) : length %d, actual %d\n",
      status, req->length, req->actual);

  switch (status) {
    case 0:				/* normal completion */
      if (ep == dev->out_ep) {
        /* our transmit completed */
        /* TODO handle data */
        dev->challenge_len += req->actual;
        DBG (dev, "******Challenge length : %d\n", dev->challenge_len);
        if (dev->challenge_len >= 64) {
          dev->status = DEVICE5_CHALLENGED;
          SET_TIMER (450);
        }
      }
      break;

      /* this endpoint is normally active while we're configured */
    case -ECONNABORTED:		/* hardware forced ep reset */
    case -ECONNRESET:		/* request dequeued */
    case -ESHUTDOWN:		/* disconnect from host */
      VDBG(dev, "%s gone (%d), %d/%d\n", ep->name, status,
          req->actual, req->length);
      spin_unlock_irqrestore (&dev->lock, flags);
      return;

    case -EOVERFLOW:		/* buffer overrun on read means that
                                 * we didn't provide a big enough
                                 * buffer.
                                 */
    default:
      DBG(dev, "%s complete --> %d, %d/%d\n", ep->name,
          status, req->actual, req->length);
      break;
    case -EREMOTEIO:		/* short read */
      break;
  }

  status = usb_ep_queue(ep, req, GFP_ATOMIC);
  if (status) {
    ERROR(dev, "kill %s:  resubmit %d bytes --> %d\n",
        ep->name, req->length, status);
    usb_ep_set_halt(ep);
    /* FIXME recover later ... somehow */
  }
  spin_unlock_irqrestore (&dev->lock, flags);
}

static void jig_interrupt_start (struct psfreedom_device *dev)
{
  struct usb_ep *ep = dev->out_ep;
  struct usb_request *req = NULL;

  if (!ep)
    return;

  req = alloc_ep_req(ep, USB_BUFSIZ);

  if (!req) {
    ERROR(dev, "out_interrupt_transmit: alloc_ep_request failed\n");
    return;
  }

  req->complete = jig_interrupt_complete;
  req->length = 8;

  usb_ep_queue(ep, req, GFP_ATOMIC);
}



static int set_jig_config(struct psfreedom_device *dev)
{
  int err = 0;

  err = usb_ep_enable(dev->out_ep, &jig_out_endpoint_desc);
  if (err) {
    ERROR(dev, "can't start %s: %d\n", dev->out_ep->name, err);
    goto fail;
  }
  dev->out_ep->driver_data = dev;

  DBG (dev, "Enabled BULK OUT endpoint %d\n", jig_out_endpoint_desc.bEndpointAddress);

  err = usb_ep_enable(dev->in_ep, &jig_in_endpoint_desc);
  if (err) {
    ERROR(dev, "can't start %s: %d\n", dev->in_ep->name, err);
    goto fail;
  }
  dev->in_ep->driver_data = dev;

  DBG (dev, "Enabled BULK IN endpoint %d\n", jig_in_endpoint_desc.bEndpointAddress);

  jig_interrupt_start (dev);
fail:
  /* caller is responsible for cleanup on error */
  return err;
}

static void
jig_reset_config(struct psfreedom_device *dev)
{
  DBG(dev, "JIG reset config\n");
  usb_ep_disable(dev->out_ep);
  usb_ep_disable(dev->in_ep);
}

/* change our operational config.  this code must agree with the code
 * that returns config descriptors, and altsetting code.
 *
 * it's also responsible for power management interactions. some
 * configurations might not work with our current power sources.
 *
 * note that some device controller hardware will constrain what this
 * code can do, perhaps by disallowing more than one configuration or
 * by limiting configuration choices (like the pxa2xx).
 */
static int
jig_set_config(struct psfreedom_device *dev, unsigned number)
{
  int result = 0;
  struct usb_gadget *gadget = dev->gadget;

  jig_reset_config(dev);
  result = set_jig_config(dev);

  if (!result && !dev->in_ep) {
    result = -ENODEV;
  }
  if (result) {
    jig_reset_config(dev);
  } else {
    char *speed;

    switch (gadget->speed) {
      case USB_SPEED_LOW:	speed = "low"; break;
      case USB_SPEED_FULL:	speed = "full"; break;
      case USB_SPEED_HIGH:	speed = "high"; break;
      default:		speed = "?"; break;
    }

    INFO(dev, "%s speed\n", speed);
  }
  return result;
}

/*
 * The setup() callback implements all the ep0 functionality that's
 * not handled lower down, in hardware or the hardware driver (like
 * device and endpoint feature flags, and their status).  It's all
 * housekeeping for the gadget function we're implementing.  Most of
 * the work is in config-specific setup.
 */
static int devices_setup(struct usb_gadget *gadget,
    const struct usb_ctrlrequest *ctrl, u16 request,
    u16 w_index, u16 w_value, u16 w_length)
{
  struct psfreedom_device *dev = get_gadget_data(gadget);
  struct usb_request *req = dev->req;
  int value = -EOPNOTSUPP;

  /* usually this stores reply data in the pre-allocated ep0 buffer,
   * but config change events will reconfigure hardware.
   */
  switch (ctrl->bRequest) {
    case USB_REQ_GET_DESCRIPTOR:
      if ((ctrl->bRequestType & USB_DIR_IN) == 0) {
        goto unknown;
      }
      switch (w_value >> 8) {
        case USB_DT_DEVICE:
          switch (dev->current_port) {
            case 1:
              value = min(w_length, (u16) sizeof(port1_device_desc));
              memcpy(req->buf, port1_device_desc, value);
              break;
            case 2:
              value = min(w_length, (u16) sizeof(port2_device_desc));
              memcpy(req->buf, port2_device_desc, value);
              break;
            case 3:
              value = min(w_length, (u16) sizeof(port3_device_desc));
              memcpy(req->buf, port3_device_desc, value);
              break;
            case 4:
              value = min(w_length, (u16) sizeof(port4_device_desc));
              memcpy(req->buf, port4_device_desc, value);
              break;
            case 5:
              value = min(w_length, (u16) sizeof(port5_device_desc));
              memcpy(req->buf, port5_device_desc, value);
              break;
            case 6:
              value = min(w_length, (u16) sizeof(port6_device_desc));
              memcpy(req->buf, port6_device_desc, value);
              break;
            default:
              value = -EINVAL;
              break;
          }
          break;
        case USB_DT_CONFIG:
          value = 0;
          switch (dev->current_port) {
            case 1:
              if ((w_value & 0xff) < 4) {
                if (w_length == 8) {
                  value = sizeof(port1_short_config_desc);
                  memcpy(req->buf, port1_short_config_desc, value);
                } else {
                  value = sizeof(port1_config_desc);
                  memcpy(req->buf, port1_config_desc, value);
                }
                if ((w_value & 0xff) == 3 && w_length > 8) {
                  dev->status = DEVICE1_READY;
                  SET_TIMER (100);
                }
              }
              break;
            case 2:
              value = sizeof(port2_config_desc);
              memcpy(req->buf, port2_config_desc, value);
              if (w_length > 8) {
                dev->status = DEVICE2_READY;
                SET_TIMER (150);
              }
              break;
            case 3:
              value = sizeof(port3_config_desc);
              memcpy(req->buf, port3_config_desc, value);
              if ((w_value & 0xff) == 1 && w_length > 8) {
                dev->status = DEVICE3_READY;
                SET_TIMER (80);
              }
              break;
            case 4:
              if ((w_value & 0xff) == 0) {
                value = sizeof(port4_config_desc_1);
                memcpy(req->buf, port4_config_desc_1, value);
              } else if ((w_value & 0xff) == 1) {
                if (w_length == 8) {
                  value = sizeof(port4_short_config_desc_2);
                  memcpy(req->buf, port4_short_config_desc_2, value);
                } else {
                  value = sizeof(port4_config_desc_2);
                  memcpy(req->buf, port4_config_desc_2, value);
                }
              } else if ((w_value & 0xff) == 2) {
                value = sizeof(port4_config_desc_3);
                memcpy(req->buf, port4_config_desc_3, value);
                if (w_length > 8) {
                  dev->status = DEVICE4_READY;
                  SET_TIMER (180);
                }
              }
              break;
            case 5:
              value = sizeof(port5_config_desc);
              memcpy(req->buf, port5_config_desc, value);
              break;
            case 6:
              value = sizeof(port6_config_desc);
              memcpy(req->buf, port6_config_desc, value);
              break;
            default:
              value = -EINVAL;
              break;
          }
          if (value >= 0)
            value = min(w_length, (u16)value);
          break;
        case USB_DT_STRING:
          value = 0;
          break;
      }
      break;
    case USB_REQ_SET_CONFIGURATION:
      if (dev->current_port == 5) {
        DBG (dev, "********* SET CONFIGURATION ON JIG***********************\n");
        jig_set_config(dev, 0);
      }
    case USB_REQ_GET_CONFIGURATION:
    case USB_REQ_GET_STATUS:
    case USB_REQ_SET_INTERFACE:
      if (dev->current_port == 5)
        DBG (dev, "********* SET INTERFACE ON JIG***********************\n");
      value = 0;
      break;
    case USB_REQ_GET_INTERFACE:
      if (ctrl->bRequestType != (USB_DIR_IN|USB_RECIP_INTERFACE)) {
        goto unknown;
      }
      *(u8 *)req->buf = 0;
      value = min(w_length, (u16)1);
      break;

    case 0xAA:
      INFO (dev, "JAILBROKEN!!! DONE!!!!!!!!!\n");
      dev->status = DEVICE6_READY;
      SET_TIMER (0);
      value = 0;
      break;
    default:
    unknown:
      DBG(dev, "unknown control req%02x.%02x v%04x i%04x l%d\n",
          ctrl->bRequestType, ctrl->bRequest,
          w_value, w_index, w_length);
  }

  /* device either stalls (value < 0) or reports success */
  return value;
}

static void devices_disconnect (struct usb_gadget *gadget)
{
  struct psfreedom_device *dev = get_gadget_data (gadget);

  jig_reset_config (dev);
}



static int __init devices_bind(struct usb_gadget *gadget, struct psfreedom_device *dev)
{
  struct usb_ep *out_ep;
  struct usb_ep *in_ep;

  gadget_for_each_ep (out_ep, gadget) {
    if (0 == strcmp (out_ep->name, psfreedom_get_endpoint_name (2, 0)))
      break;
  }
  if (!out_ep) {
    pr_err("%s: can't find %s on %s\n", psfreedom_get_endpoint_name (2, 0),
        shortname, gadget->name);
    return -ENODEV;
  }
  out_ep->driver_data = out_ep;	/* claim */

  gadget_for_each_ep (in_ep, gadget) {
    if (0 == strcmp (in_ep->name, psfreedom_get_endpoint_name (1, 1)))
      break;
  }
  if (!in_ep) {
    pr_err("%s: can't find %s on %s\n", psfreedom_get_endpoint_name (1, 1),
        shortname, gadget->name);
    return -ENODEV;
  }
  in_ep->driver_data = in_ep;	/* claim */

  /* ok, we made sense of the hardware ... */
  dev->in_ep = in_ep;
  dev->out_ep = out_ep;


  INFO(dev, "using %s, EP IN %s (0x%X)\n", gadget->name, in_ep->name,
      jig_in_endpoint_desc.bEndpointAddress);
  INFO(dev, "using %s, EP OUT %s (0x%X)\n", gadget->name, out_ep->name,
      jig_out_endpoint_desc.bEndpointAddress);

  /* the max packet size of all the devices must be the same as the ep0 max
     packet size, otherwise it won't work */
  ((struct usb_device_descriptor *)port1_device_desc)->bMaxPacketSize0 = \
      ((struct usb_device_descriptor *)port2_device_desc)->bMaxPacketSize0 = \
      ((struct usb_device_descriptor *)port3_device_desc)->bMaxPacketSize0 = \
      ((struct usb_device_descriptor *)port4_device_desc)->bMaxPacketSize0 = \
      ((struct usb_device_descriptor *)port5_device_desc)->bMaxPacketSize0 = \
      ((struct usb_device_descriptor *)port6_device_desc)->bMaxPacketSize0 = \
      gadget->ep0->maxpacket;
  VDBG(dev, "devices_bind finished ok\n");

  return 0;
}

