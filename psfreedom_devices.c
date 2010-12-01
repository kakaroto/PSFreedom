/*
 * psfreedom_devices.c -- PS3 Jailbreak exploit Gadget Driver
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
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
#include "sha1.c"
#include <linux/random.h>

/* stage1 AsbestOS request */
#define ASBESTOS_PRINT_DBG_MSG          1
#define ASBESTOS_GET_STAGE2_SIZE        2
#define ASBESTOS_READ_STAGE2_BLOCK      3

static void jig_response_send (struct psfreedom_device *dev,
    struct usb_request *req);

static void jig_response_complete(struct usb_ep *ep, struct usb_request *req)
{
  struct psfreedom_device *dev = ep->driver_data;
  int status = req->status;
  unsigned long flags;

  spin_lock_irqsave (&dev->lock, flags);
  DBG (dev, "Jig response sent (status %d). Sent data so far : %d + %d\n",
      status, dev->response_len, req->length);

  switch (status) {
    case 0:                             /* normal completion */
      if (ep == dev->in_ep) {
        /* our transmit completed.
           see if there's more to go.
           jig_response_send eats req, don't queue it again. */
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
    case -ECONNABORTED:         /* hardware forced ep reset */
    case -ESHUTDOWN:            /* disconnect from host */
      VDBG(dev, "%s gone (%d), %d/%d\n", ep->name, status,
          req->actual, req->length);
    case -ECONNRESET:           /* request dequeued */
      spin_unlock_irqrestore (&dev->lock, flags);
      return;

    case -EOVERFLOW:            /* buffer overrun on read means that
                                 * we didn't provide a big enough
                                 * buffer.
                                 */
    default:
      DBG(dev, "%s complete --> %d, %d/%d\n", ep->name,
          status, req->actual, req->length);
      break;
    case -EREMOTEIO:            /* short read */
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

/* Send the challenge response */
static void jig_response_send (struct psfreedom_device *dev,
    struct usb_request *req)
{
  struct usb_ep *ep = dev->in_ep;

  if (!ep)
    return;

  if (!req)
    req = alloc_ep_req(ep, 8);

  if (!req) {
    ERROR(dev, "jig_response_send: alloc_ep_request failed\n");
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

#define JIG_DATA_HEADER_LEN 7

/* Generate the JIG challenge response */
static void jig_generate_response(struct psfreedom_device *dev)
{
  uint16_t dongle_id;
  uint8_t dongle_key[SHA1_MAC_LEN];
  int i;

 restart:
  dongle_id = (uint16_t) random32 ();
  for (i = 0; usb_dongle_revoke_list[i] != 0xFFFF; i++) {
    if (dongle_id == usb_dongle_revoke_list[i])
      goto restart;
  }

  jig_response[0] = 0x00;
  jig_response[1] = 0x00;
  jig_response[2] = 0xFF;
  jig_response[3] = 0x00;
  jig_response[4] = 0x2E;
  jig_response[5] = 0x02;
  jig_response[6] = 0x02;
  jig_response[7] = (dongle_id >> 8) & 0xFF;
  jig_response[8] = dongle_id & 0xFF;


  hmac_sha1 (usb_dongle_master_key, SHA1_MAC_LEN,
      (uint8_t *)&dongle_id, sizeof(uint16_t), dongle_key);
  hmac_sha1 (dongle_key, SHA1_MAC_LEN,
      jig_challenge + JIG_DATA_HEADER_LEN, SHA1_MAC_LEN,
      jig_response + JIG_DATA_HEADER_LEN + sizeof(dongle_id));
}

/* Received challenge data */
static void jig_interrupt_complete(struct usb_ep *ep, struct usb_request *req)
{
  struct psfreedom_device *dev = ep->driver_data;
  int status = req->status;
  unsigned long flags;

  spin_lock_irqsave (&dev->lock, flags);
  DBG (dev, "******Out interrupt complete (status %d) : length %d, actual %d\n",
      status, req->length, req->actual);

  switch (status) {
    case 0:                             /* normal completion */
      if (ep == dev->out_ep) {
        /* our transmit completed */
        memcpy (jig_challenge + dev->challenge_len, req->buf, 8);
        DBG (dev, "Received %X %X %X %X %X %X %X %X\n",
            ((char *)req->buf)[0], ((char *)req->buf)[1],
            ((char *)req->buf)[2], ((char *)req->buf)[3],
            ((char *)req->buf)[4], ((char *)req->buf)[5],
            ((char *)req->buf)[6], ((char *)req->buf)[7]);

        dev->challenge_len += req->actual;
        DBG (dev, "******Challenge length : %d\n", dev->challenge_len);
        if (dev->challenge_len >= 64) {
          if (dev->jig)
            jig_generate_response (dev);
          dev->status = DEVICE5_CHALLENGED;
          SET_TIMER (450);
        }
      }
      break;

      /* this endpoint is normally active while we're configured */
    case -ECONNABORTED:         /* hardware forced ep reset */
    case -ECONNRESET:           /* request dequeued */
    case -ESHUTDOWN:            /* disconnect from host */
      VDBG(dev, "%s gone (%d), %d/%d\n", ep->name, status,
          req->actual, req->length);
      spin_unlock_irqrestore (&dev->lock, flags);
      return;

    case -EOVERFLOW:            /* buffer overrun on read means that
                                 * we didn't provide a big enough
                                 * buffer.
                                 */
    default:
      DBG(dev, "%s complete --> %d, %d/%d\n", ep->name,
          status, req->actual, req->length);
      break;
    case -EREMOTEIO:            /* short read */
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

/* queue a request for receiving the challenge on endpoint 2 */
static void jig_interrupt_start (struct psfreedom_device *dev)
{
  struct usb_ep *ep = dev->out_ep;
  struct usb_request *req = NULL;

  if (!ep)
    return;

  req = alloc_ep_req(ep, 8);

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

  INFO (dev, "Enabled BULK OUT endpoint\n");

  err = usb_ep_enable(dev->in_ep, &jig_in_endpoint_desc);
  if (err) {
    ERROR(dev, "can't start %s: %d\n", dev->in_ep->name, err);
    goto fail;
  }
  dev->in_ep->driver_data = dev;

  INFO (dev, "Enabled BULK IN endpoint\n");

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
      case USB_SPEED_LOW:       speed = "low"; break;
      case USB_SPEED_FULL:      speed = "full"; break;
      case USB_SPEED_HIGH:      speed = "high"; break;
      default:          speed = "?"; break;
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
              if ((w_value & 0xff) < PORT1_NUM_CONFIGS) {
                if (w_length == 8) {
                  value = sizeof(port1_short_config_desc);
                  memcpy(req->buf, port1_short_config_desc, value);
                } else {
                  value = dev->port1_config_desc_size;
                  memcpy(req->buf, dev->port1_config_desc, value);
                }
                if ((w_value & 0xff) == (PORT1_NUM_CONFIGS-1) && w_length > 8) {
                  dev->status = DEVICE1_READY;
                  SET_TIMER (100);
                  dev->switch_to_port_delayed = 0;
                }
              }
              break;
            case 2:
              value = sizeof(port2_config_desc);
              memcpy(req->buf, port2_config_desc, value);
              if (w_length > 8) {
                dev->status = DEVICE2_READY;
                SET_TIMER (150);
                dev->switch_to_port_delayed = 0;
              }
              break;
            case 3:
              value = sizeof(port3_config_desc);
              memcpy(req->buf, port3_config_desc, value);
              if ((w_value & 0xff) == 1 && w_length > 8) {
                dev->status = DEVICE3_READY;
                SET_TIMER (80);
                dev->switch_to_port_delayed = 0;
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
                  dev->switch_to_port_delayed = 0;
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
        DBG (dev, "SET CONFIGURATION ON JIG\n");
        jig_set_config(dev, 0);
      }
      value = 0;
      break;
    case USB_REQ_GET_CONFIGURATION:
    case USB_REQ_GET_STATUS:
    case USB_REQ_SET_INTERFACE:
      if (dev->current_port == 5)
        DBG (dev, "SET INTERFACE ON JIG\n");
      value = 0;
      break;
    case USB_REQ_GET_INTERFACE:
      if (ctrl->bRequestType != (USB_DIR_IN|USB_RECIP_INTERFACE)) {
        goto unknown;
      }
      *(u8 *)req->buf = 0;
      value = min(w_length, (u16)1);
      break;
    case ASBESTOS_PRINT_DBG_MSG:
      DBG(dev, "ASBESTOS [LV2]: Printing debug message (ignore)\n");
      /* HACK ALERT: Asbestos sends data to print in ep0, but there is no
       * way to read data from ep0. The ep0 gadget is meant to be used to
       * only receive setup packets of 8 bytes and the controller takes care
       * of that. The gadget->ep0 is only for sending data out, so we can't
       * queue a request in order to receive the message to print.
       * Because of that, we will stall to tell the host we won't read its
       * data, and we ignore the message to print.
       */
      value = -EOPNOTSUPP;
      break;
    case ASBESTOS_GET_STAGE2_SIZE:
      if (ctrl->bRequestType == 0xc0) {
        u32 reply = htonl(dev->stage2_payload_size);

        DBG(dev, "ASBESTOS: stage2 size requested, stage2 size : 0x%x\n",
            dev->stage2_payload_size);
        value = sizeof(u32);
        memcpy(req->buf, &reply, value);
      }
      break;
    case ASBESTOS_READ_STAGE2_BLOCK:
      if (ctrl->bRequestType == 0xc0) {
        int offset = w_index<<12;
        int available = dev->stage2_payload_size - offset;
        int length = w_length;

        if (!dev->stage2_payload) {
          DBG(dev, "ASBESTOS: couldn't find stage2 payload\n");
          break;
        }

        DBG(dev, "ASBESTOS: read_stage2_block(offset=0x%x, len=0x%x)\n",
            offset, length);

        if (available < 0)
          available = 0;

        if (length > available) {
          DBG(dev, "ASBESTOS: warning: length exceeded, want 0x%x avail 0x%x\n",
              length, available);
          length = available;
        }
        if (length == available) {
          INFO(dev, "ASBESTOS stage2 Loaded\n");
          dev->status = DONE;
          SET_TIMER (0);
        }

        value = length;
        memcpy(req->buf, dev->stage2_payload + offset, value);
      }
      break;
    default:
    unknown:
      DBG(dev, "unknown control req %02x.%02x v%04x i%04x l%d\n",
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



static int __init devices_bind(struct usb_gadget *gadget,
    struct psfreedom_device *dev)
{
  struct usb_ep *out_ep;
  struct usb_ep *in_ep;

  gadget_for_each_ep (out_ep, gadget) {
    if (0 == strcmp (out_ep->name,
            psfreedom_get_endpoint_name (&jig_out_endpoint_desc)))
      break;
  }
  if (!out_ep) {
    ERROR (dev, "%s: can't find %s on %s\n",
        psfreedom_get_endpoint_name (&jig_out_endpoint_desc),
        shortname, gadget->name);
    return -ENODEV;
  }
  out_ep->driver_data = out_ep; /* claim */

  gadget_for_each_ep (in_ep, gadget) {
    if (0 == strcmp (in_ep->name,
            psfreedom_get_endpoint_name (&jig_in_endpoint_desc)))
      break;
  }
  if (!in_ep) {
    ERROR (dev, "%s: can't find %s on %s\n",
        psfreedom_get_endpoint_name (&jig_in_endpoint_desc),
        shortname, gadget->name);
    return -ENODEV;
  }
  in_ep->driver_data = in_ep;   /* claim */

  /* ok, we made sense of the hardware ... */
  dev->in_ep = in_ep;
  dev->out_ep = out_ep;

  /* If the machine specific code changed our descriptors,
     change the ones we'll send too */
  memcpy (port5_config_desc + USB_DT_CONFIG_SIZE + USB_DT_INTERFACE_SIZE,
      &jig_out_endpoint_desc,
      USB_DT_ENDPOINT_SIZE);
  memcpy (port5_config_desc + USB_DT_CONFIG_SIZE + \
      USB_DT_INTERFACE_SIZE + USB_DT_ENDPOINT_SIZE,
      &jig_in_endpoint_desc,
      USB_DT_ENDPOINT_SIZE);


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

