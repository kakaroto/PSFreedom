/*
 * hub.c -- PS3 Jailbreak exploit Gadget Driver
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

#include "hub.h"

static ushort idVendor;
module_param(idVendor, ushort, S_IRUGO);
MODULE_PARM_DESC(idVendor, "USB Vendor ID");

static ushort idProduct;
module_param(idProduct, ushort, S_IRUGO);
MODULE_PARM_DESC(idProduct, "USB Product ID");

#define HUB_BUFSIZ 256


static int hub_interrupt_queued = 0;
static void hub_interrupt_transmit(struct psjailb_device *dev);

/* Taking first HUB vendor/product ids from http://www.linux-usb.org/usb.ids
 *
 * DO NOT REUSE THESE IDs with a protocol-incompatible driver!!  Ever!!
 * Instead:  allocate your own, using normal USB-IF procedures.
 */
#define DRIVER_VENDOR_NUM	0x03eb		/* Atmel Corp */
#define DRIVER_PRODUCT_NUM	0x0902		/* 4-Port Hub */


/*
 * DESCRIPTORS ...
 */


/* B.1  Device Descriptor */
static struct usb_device_descriptor hub_device_desc = {
  .bLength =		USB_DT_DEVICE_SIZE,
  .bDescriptorType =	USB_DT_DEVICE,
  .bcdUSB =		cpu_to_le16(0x0110),
  .bDeviceClass =	USB_CLASS_HUB,
  .idVendor =		cpu_to_le16(DRIVER_VENDOR_NUM),
  .idProduct =		cpu_to_le16(DRIVER_PRODUCT_NUM),
  .bcdDevice =		cpu_to_le16(0x0123),
  .iManufacturer =	0,
  .iProduct =		0,
  .bNumConfigurations =	1,
};

/* Hub Configuration Descriptor */
static struct usb_config_descriptor hub_config_desc = {
  .bLength =		USB_DT_CONFIG_SIZE,
  .bDescriptorType =	USB_DT_CONFIG,
  .wTotalLength =         USB_DT_CONFIG_SIZE + USB_DT_INTERFACE_SIZE,
  .bNumInterfaces =	1,
  .bConfigurationValue =  1,
  .iConfiguration =	0,
  .bmAttributes =	USB_CONFIG_ATT_WAKEUP | USB_CONFIG_ATT_SELFPOWER,
  .bMaxPower =		50,
};

/* Hub Interface Descriptor */
static const struct usb_interface_descriptor hub_interface_desc = {
  .bLength =		USB_DT_INTERFACE_SIZE,
  .bDescriptorType =	USB_DT_INTERFACE,
  .bInterfaceNumber =	0,
  .bNumEndpoints =	1,
  .bInterfaceClass =	USB_CLASS_HUB,
  .bInterfaceSubClass =	0,
  .bInterfaceProtocol = 0,
  .iInterface =		0,
};

/* Hub endpoint Descriptor */
static struct usb_endpoint_descriptor hub_endpoint_desc = {
  .bLength =		USB_DT_ENDPOINT_SIZE,
  .bDescriptorType =	USB_DT_ENDPOINT,
  .bEndpointAddress =	USB_DIR_IN,
  .bmAttributes =	USB_ENDPOINT_XFER_INT,
  .wMaxPacketSize =	__constant_cpu_to_le16(1),
  .bInterval =		255,	// frames -> 32 ms
};

/* Hub class specific Descriptor */
static const struct usb_hub_header_descriptor hub_header_desc = {
  .bLength =		USB_DT_HUB_HEADER_SIZE (6),
  .bDescriptorType =	USB_DT_CS_HUB,
  .bNbrPorts = 6,
  .wHubCharacteristics = __constant_cpu_to_le16 (9),
  .bPwrOn2PwrGood = 25,
  .bHubContrCurrent = 100,
  .DeviceRemovable = 0x00,
  .PortPwrCtrlMask = 0xFF,
};

static const struct usb_descriptor_header *hub_function [] = {
	(struct usb_descriptor_header *)&hub_interface_desc,
	(struct usb_descriptor_header *)&hub_endpoint_desc,
	NULL,
};


static int hub_config_buf(struct usb_gadget *gadget,
		u8 *buf, u8 type, unsigned index)
{
	int len;

	/* only one configuration */
	if (index != 0) {
		return -EINVAL;
	}
	len = usb_gadget_config_buf(&hub_config_desc,
			buf, USB_BUFSIZ, hub_function);
	if (len < 0) {
		return len;
	}
	((struct usb_config_descriptor *)buf)->bDescriptorType = type;
	return len;
}

static void hub_interrupt_complete(struct usb_ep *ep, struct usb_request *req)
{
  struct psjailb_device *dev = ep->driver_data;
  int status = req->status;

  DBG (dev, "Hub complete (status %d)\n", status);

  switch (status) {
    case 0:				/* normal completion */
      if (ep == dev->in_ep) {
        /* our transmit completed.
           see if there's more to go.
           hub_transmit eats req, don't queue it again. */
        hub_interrupt_transmit(dev);
        return;
      }
      break;

      /* this endpoint is normally active while we're configured */
    case -ECONNABORTED:		/* hardware forced ep reset */
    case -ECONNRESET:		/* request dequeued */
    case -ESHUTDOWN:		/* disconnect from host */
      VDBG(dev, "%s gone (%d), %d/%d\n", ep->name, status,
          req->actual, req->length);
      hub_interrupt_queued = 0;
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

  hub_interrupt_queued = 1;
  status = usb_ep_queue(ep, req, GFP_ATOMIC);
  if (status) {
    ERROR(dev, "kill %s:  resubmit %d bytes --> %d\n",
        ep->name, req->length, status);
    usb_ep_set_halt(ep);
    hub_interrupt_queued = 0;
    /* FIXME recover later ... somehow */
  }
}

static void hub_interrupt_transmit (struct psjailb_device *dev)
{
  struct usb_ep *ep = dev->in_ep;
  static struct usb_request *req = NULL;
  u8 data = 0;
  int i;

  if (!ep)
    return;

  if (!req)
    req = alloc_ep_req(ep, HUB_BUFSIZ);

  if (!req) {
    ERROR(dev, "hub_interrupt_transmit: alloc_ep_request failed\n");
    return;
  }
  if (hub_interrupt_queued) {
    ERROR(dev, "hub_interrupt_transmit: Already queued a request\n");
    return;
  }

  req->complete = hub_interrupt_complete;
  req->length = 0;

  for (i = 0; i < 6; i++) {
    if (dev->hub_ports[i].connect_changed ||
        dev->hub_ports[i].enable_changed ||
        dev->hub_ports[i].suspend_changed ||
        dev->hub_ports[i].reset_changed)
      data |= 1 << (i+1);
  }

  if (data != 0) {
    memcpy (req->buf, &data, sizeof(data));
    req->length = sizeof(data);
  }

  if (req->length > 0) {
    int err = 0;
    DBG (dev, "transmitting interrupt byte %d\n", data);
    hub_interrupt_queued = 1;
    err = usb_ep_queue(ep, req, GFP_ATOMIC);
  } else {
    DBG (dev, "Nothing to report, freeing request, NAK-ing interrupt");
    hub_interrupt_queued = 0;
  }

}

static void hub_port_changed (struct psjailb_device *dev)
{
  hub_interrupt_transmit (dev);
}


static int set_hub_config(struct psjailb_device *dev)
{
  int err = 0;

  hub_interrupt_queued = 0;
  err = usb_ep_enable(dev->in_ep, &hub_endpoint_desc);
  if (err) {
    ERROR(dev, "can't start %s: %d\n", dev->in_ep->name, err);
    goto fail;
  }
  dev->in_ep->driver_data = dev;

  hub_interrupt_transmit (dev);
fail:
  /* caller is responsible for cleanup on error */
  return err;
}

static void
hub_reset_config(struct psjailb_device *dev)
{

  if (dev->config == 0) {
    return;
  }

  DBG(dev, "reset config\n");
  usb_ep_disable(dev->in_ep);
  hub_interrupt_queued = 0;

  dev->config = 0;
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
hub_set_config(struct psjailb_device *dev, unsigned number)
{
  int result = 0;
  struct usb_gadget *gadget = dev->gadget;

  hub_reset_config(dev);

  switch (number) {
    case 1:
      result = set_hub_config(dev);
      break;
    default:
      result = -EINVAL;
    case 0:
      return result;
  }

  if (!result && !dev->in_ep) {
    result = -ENODEV;
  }
  if (result) {
    hub_reset_config(dev);
  } else {
    char *speed;

    switch (gadget->speed) {
      case USB_SPEED_LOW:	speed = "low"; break;
      case USB_SPEED_FULL:	speed = "full"; break;
      case USB_SPEED_HIGH:	speed = "high"; break;
      default:		speed = "?"; break;
    }

    dev->config = number;
    INFO(dev, "%s speed\n", speed);
  }
  return result;
}

static void hub_disconnect (struct usb_gadget *gadget)
{
  struct psjailb_device *dev = get_gadget_data (gadget);

  hub_reset_config (dev);
}


/*
 * The setup() callback implements all the ep0 functionality that's
 * not handled lower down, in hardware or the hardware driver (like
 * device and endpoint feature flags, and their status).  It's all
 * housekeeping for the gadget function we're implementing.  Most of
 * the work is in config-specific setup.
 */
static int hub_setup(struct usb_gadget *gadget,
    const struct usb_ctrlrequest *ctrl, u16 request,
    u16 w_index, u16 w_value, u16 w_length)
{
  struct psjailb_device *dev = get_gadget_data(gadget);
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
      if ((ctrl->bRequestType & USB_TYPE_CLASS) == USB_TYPE_CLASS) {
        /* GET_HUB_DESCRIPTOR Class specific request */
        value = min(w_length, (u16) sizeof(hub_header_desc));
        memcpy(req->buf, &hub_header_desc, value);
        if (value >= 0)
          value = min(w_length, (u16)value);
      } else {
        switch (w_value >> 8) {
          case USB_DT_DEVICE:
            value = min(w_length, (u16) sizeof(hub_device_desc));
            memcpy(req->buf, &hub_device_desc, value);
            break;
          case USB_DT_CONFIG:
            value = 0;
            value = hub_config_buf(gadget, req->buf, w_value >> 8, w_value & 0xff);
            if (value >= 0)
              value = min(w_length, (u16)value);
            break;
          case USB_DT_STRING:
            value = 0;
            break;
        }
      }
      break;

      /* currently two configs, two speeds */
    case USB_REQ_SET_CONFIGURATION:
      if (ctrl->bRequestType != 0) {
        goto unknown;
      }
      if (gadget->a_hnp_support) {
        DBG(dev, "HNP available\n");
      } else if (gadget->a_alt_hnp_support) {
        DBG(dev, "HNP needs a different root port\n");
      } else {
        VDBG(dev, "HNP inactive\n");
      }
      spin_lock(&dev->lock);
      value = hub_set_config(dev, w_value);
      spin_unlock(&dev->lock);
      break;
    case USB_REQ_GET_CONFIGURATION:
      if (ctrl->bRequestType != USB_DIR_IN) {
        goto unknown;
      }
      *(u8 *)req->buf = dev->config;
      value = min(w_length, (u16)1);
      break;

    case USB_REQ_SET_INTERFACE:
      if (ctrl->bRequestType != USB_RECIP_INTERFACE) {
        goto unknown;
      }
      spin_lock(&dev->lock);
      if (dev->config && w_index < 1
          && w_value == 0)
      {
        u8 config = dev->config;

        /* resets interface configuration, forgets about
         * previous transaction state (queued bufs, etc)
         * and re-inits endpoint state (toggle etc)
         * no response queued, just zero status == success.
         * if we had more than one interface we couldn't
         * use this "reset the config" shortcut.
         */
        hub_reset_config(dev);
        hub_set_config(dev, config);
        value = 0;
      }
      spin_unlock(&dev->lock);
      break;
    case USB_REQ_GET_INTERFACE:
      if (ctrl->bRequestType != (USB_DIR_IN|USB_RECIP_INTERFACE)) {
        goto unknown;
      }
      if (!dev->config) {
        break;
      }
      if (w_index >= 1) {
        value = -EDOM;
        break;
      }
      *(u8 *)req->buf = 0;
      value = min(w_length, (u16)1);
      break;

    case USB_REQ_SET_FEATURE:
      if ((ctrl->bRequestType & USB_TYPE_CLASS) == USB_TYPE_CLASS) {
        switch (ctrl->bRequestType & USB_RECIP_MASK) {
          case USB_RECIP_DEVICE:
            switch (w_value) {
              case 0: /* C_HUB_LOCAL_POWER */
              case 1: /* C_HUB_OVER_CURRENT */
                DBG (dev, "SetHubFeature called\n");
                value = 0;
                break;
              default:
                value = -EINVAL;
                break;
            }
            break;
          case USB_RECIP_OTHER:
            if (w_index == 0 || w_index > 6) {
              DBG (dev, "SetPortFeature: invalid port index %d\n", w_index);
              value = -EINVAL;
              break;
            }
            switch (w_value) {
              case 0: /* PORT_CONNECTION */
                DBG (dev, "SetPortFeature PORT_CONNECTION called\n");
                value = -EINVAL;
                break;
              case 1: /* PORT_ENABLE */
                DBG (dev, "SetPortFeature PORT_ENABLE called\n");
                if (dev->hub_ports[w_index-1].enable == 0) {
                  dev->hub_ports[w_index-1].enable_changed = 1;
                  hub_port_changed (dev);
                }
                dev->hub_ports[w_index-1].enable = 1;
                value = 0;
                break;
              case 2: /* PORT_SUSPEND */
                DBG (dev, "SetPortFeature PORT_SUSPEND called\n");
                if (dev->hub_ports[w_index-1].suspend == 0) {
                  dev->hub_ports[w_index-1].suspend_changed = 1;
                  hub_port_changed (dev);
                }
                dev->hub_ports[w_index-1].suspend = 1;
                value = 0;
                break;
              case 3: /* PORT_OVER_CURRENT */
                DBG (dev, "SetPortFeature PORT_OVER_CURRENT called\n");
                value = -EINVAL;
                break;
              case 4: /* PORT_RESET */
                DBG (dev, "SetPortFeature PORT_RESET called\n");
                if (dev->hub_ports[w_index-1].reset == 0) {
                  dev->hub_ports[w_index-1].reset_changed = 1;
                  hub_port_changed (dev);
                }
                dev->hub_ports[w_index-1].enable = 1; /* FIXME: is it ?*/
                value = 0;
                break;
              case 8: /* PORT_POWER */
                DBG (dev, "SetPortFeature PORT_POWER called\n");
                dev->hub_ports[w_index-1].power = 1;
                value = 0;
                break;
              case 9: /* PORT_LOW_SPEED */
                DBG (dev, "SetPortFeature PORT_LOW_SPEED called\n");
                dev->hub_ports[w_index-1].low_speed = 1;
                dev->hub_ports[w_index-1].high_speed = 0;
                value = 0;
                break;
              case 16: /* C_PORT_CONNECTION */
              case 17: /* C_PORT_ENABLE */
              case 18: /* C_PORT_SUSPEND */
              case 19: /* C_PORT_OVER_CURRENT */
              case 20: /* C_PORT_RESET */
              case 21: /* PORT_TEST */
              case 22: /* PORT_INDICATOR */
                DBG (dev, "SetPortFeature called\n");
                value = 0;
                break;
              default:
                value = -EINVAL;
                break;
            }
            break;
        }
      }
      break;
    case USB_REQ_CLEAR_FEATURE:
      if ((ctrl->bRequestType & USB_TYPE_CLASS) == USB_TYPE_CLASS) {
        switch (ctrl->bRequestType & USB_RECIP_MASK) {
          case USB_RECIP_DEVICE:
            switch (w_value) {
              case 0: /* C_HUB_LOCAL_POWER */
              case 1: /* C_HUB_OVER_CURRENT */
                DBG (dev, "ClearHubFeature called\n");
                value = 0;
                break;
              default:
                value = -EINVAL;
                break;
            }
            break;
          case USB_RECIP_OTHER:
            if (w_index == 0 || w_index > 6) {
              DBG (dev, "ClearPortFeature: invalid port index %d\n", w_index);
              value = -EINVAL;
              break;
            }
            switch (w_value) {
              case 0: /* PORT_CONNECTION */
                DBG (dev, "ClearPortFeature PORT_CONNECTION called\n");
                value = -EINVAL;
                break;
              case 1: /* PORT_ENABLE */
                DBG (dev, "ClearPortFeature PORT_ENABLE called\n");
                if (dev->hub_ports[w_index-1].enable == 1) {
                  dev->hub_ports[w_index-1].enable_changed = 1;
                  hub_port_changed (dev);
                }
                dev->hub_ports[w_index-1].enable = 0;
                value = 0;
                break;
              case 2: /* PORT_SUSPEND */
                DBG (dev, "ClearPortFeature PORT_SUSPEND called\n");
                if (dev->hub_ports[w_index-1].suspend == 1) {
                  dev->hub_ports[w_index-1].suspend_changed = 1;
                  hub_port_changed (dev);
                }
                dev->hub_ports[w_index-1].suspend = 0;
                value = 0;
                break;
              case 3: /* PORT_OVER_CURRENT */
                DBG (dev, "ClearPortFeature PORT_OVER_CURRENT called\n");
                value = -EINVAL;
                break;
              case 4: /* PORT_RESET */
                DBG (dev, "ClearPortFeature PORT_RESET called\n");
                if (dev->hub_ports[w_index-1].reset == 1) {
                  dev->hub_ports[w_index-1].reset_changed = 1;
                  hub_port_changed (dev);
                }
                value = 0;
                break;
              case 8: /* PORT_POWER */
                DBG (dev, "ClearPortFeature PORT_POWER called\n");
                dev->hub_ports[w_index-1].power = 0;
                value = 0;
                break;
              case 9: /* PORT_LOW_SPEED */
                DBG (dev, "ClearPortFeature PORT_LOW_SPEED called\n");
                dev->hub_ports[w_index-1].low_speed = 0;
                dev->hub_ports[w_index-1].high_speed = 1;
                value = 0;
                break;
              case 16: /* C_PORT_CONNECTION */
              case 17: /* C_PORT_ENABLE */
              case 18: /* C_PORT_SUSPEND */
              case 19: /* C_PORT_OVER_CURRENT */
              case 20: /* C_PORT_RESET */
              case 21: /* PORT_TEST */
              case 22: /* PORT_INDICATOR */
                DBG (dev, "ClearPortFeature called\n");
                value = 0;
                break;
              default:
                value = -EINVAL;
                break;
            }
            break;
        }
      }
      break;
    case USB_REQ_GET_STATUS:
      if ((ctrl->bRequestType & USB_TYPE_CLASS) == USB_TYPE_CLASS) {
        u16 status = 0;
        u16 change = 0;

        value = 2 * sizeof (u16);
        switch (ctrl->bRequestType & USB_RECIP_MASK) {
          case USB_RECIP_DEVICE: /* GET_HUB_STATUS */
            status = 0;
            change = 0;
            break;
          case USB_RECIP_OTHER: /* GET_PORT_STATUS */
            if (w_index == 0 || w_index > 6) {
              DBG (dev, "GetPortstatus : invalid port index %d\n", w_index);
              value = -EINVAL;
              break;
            }
            if (dev->hub_ports[w_index -1].connect)
              status |= 0x0001;
            if (dev->hub_ports[w_index -1].enable)
              status |= 0x0002;
            if (dev->hub_ports[w_index -1].suspend)
              status |= 0x0004;
            if (dev->hub_ports[w_index -1].reset)
              status |= 0x0010;
            if (dev->hub_ports[w_index -1].power)
              status |= 0x0100;
            if (dev->hub_ports[w_index -1].low_speed)
              status |= 0x0200;
            if (dev->hub_ports[w_index -1].high_speed)
              status |= 0x0400;

            if (dev->hub_ports[w_index -1].connect_changed)
              change |= 0x0001;
            if (dev->hub_ports[w_index -1].enable_changed)
              change |= 0x0002;
            if (dev->hub_ports[w_index -1].suspend_changed)
              change |= 0x0004;
            if (dev->hub_ports[w_index -1].reset_changed)
              change |= 0x0010;

            dev->hub_ports[w_index -1].connect_changed = 0;
            dev->hub_ports[w_index -1].enable_changed = 0;
            dev->hub_ports[w_index -1].suspend_changed = 0;
            dev->hub_ports[w_index -1].reset_changed = 0;
            hub_port_changed (dev);
            break;
          default:
            goto unknown;
        }
        if (value > 0) {
          DBG (dev, "GetHub/PortStatus: transmitting status %d change %d\n",
              status, change);
          status = cpu_to_le16 (status);
          change = cpu_to_le16 (change);
          memcpy(req->buf, &status, sizeof(u16));
          memcpy(req->buf + sizeof(u16), &change, sizeof(u16));
        }
      }
      break;
    default:
    unknown:
      VDBG(dev, "unknown control req%02x.%02x v%04x i%04x l%d\n",
          ctrl->bRequestType, ctrl->bRequest,
          w_value, w_index, w_length);
  }

  /* device either stalls (value < 0) or reports success */
  return value;
}

static int __init hub_bind(struct usb_gadget *gadget, struct psjailb_device *dev)
{
  struct usb_ep *in_ep;
  const char *ep_name;

  /* support optional vendor/distro customization */
  if (idVendor) {
    if (!idProduct) {
      pr_err("idVendor needs idProduct!\n");
      return -ENODEV;
    }
    hub_device_desc.idVendor = cpu_to_le16(idVendor);
    hub_device_desc.idProduct = cpu_to_le16(idProduct);
  }

  usb_ep_autoconfig_reset(gadget);
  in_ep = usb_ep_autoconfig(gadget, &hub_endpoint_desc);
  if (!in_ep) {
    pr_err("%s: can't autoconfigure on %s\n",
        shortname, gadget->name);
    return -ENODEV;
  }
  ep_name = in_ep->name;
  in_ep->driver_data = in_ep;	/* claim */

  /* ok, we made sense of the hardware ... */
  dev->in_ep = in_ep;
  hub_device_desc.bMaxPacketSize0 = gadget->ep0->maxpacket;

  INFO(dev, "using %s, EP IN %s\n", gadget->name, ep_name);

  VDBG(dev, "hub_bind finished ok\n");

  return 0;
}
