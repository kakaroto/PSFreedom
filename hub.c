/*
 * hub.c -- PS3 Jailbreak exploit Gadget Driver
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

#include "hub.h"

static int hub_interrupt_queued = 0;
static void hub_interrupt_transmit(struct psfreedom_device *dev);

/* Taking first HUB vendor/product ids from http://www.linux-usb.org/usb.ids
 *
 * DO NOT REUSE THESE IDs with a protocol-incompatible driver!!  Ever!!
 * Instead:  allocate your own, using normal USB-IF procedures.
 */
#define DRIVER_VENDOR_NUM       0xaaaa          /* Atmel Corp */
#define DRIVER_PRODUCT_NUM      0xcccc          /* 4-Port Hub */


/*
 * DESCRIPTORS ...
 */


/* B.1  Device Descriptor */
static struct usb_device_descriptor hub_device_desc = {
  .bLength =            USB_DT_DEVICE_SIZE,
  .bDescriptorType =    USB_DT_DEVICE,
  .bcdUSB =             cpu_to_le16(0x0200),
  .bDeviceClass =       USB_CLASS_HUB,
  .bDeviceSubClass =    0x00,
  .bDeviceProtocol =    0x01,
  .idVendor =           cpu_to_le16(DRIVER_VENDOR_NUM),
  .idProduct =          cpu_to_le16(DRIVER_PRODUCT_NUM),
  .bcdDevice =          cpu_to_le16(0x0100),
  .iManufacturer =      0,
  .iProduct =           0,
  .bNumConfigurations = 1,
};

/* Hub Configuration Descriptor */
static struct usb_config_descriptor hub_config_desc = {
  .bLength =            USB_DT_CONFIG_SIZE,
  .bDescriptorType =    USB_DT_CONFIG,
  .wTotalLength =       USB_DT_CONFIG_SIZE + USB_DT_INTERFACE_SIZE + USB_DT_ENDPOINT_SIZE,
  .bNumInterfaces =     1,
  .bConfigurationValue =  1,
  .iConfiguration =     0,
  .bmAttributes =       USB_CONFIG_ATT_ONE | USB_CONFIG_ATT_WAKEUP | USB_CONFIG_ATT_SELFPOWER,
  .bMaxPower =          50,
};

/* Hub Interface Descriptor */
static const struct usb_interface_descriptor hub_interface_desc = {
  .bLength =            USB_DT_INTERFACE_SIZE,
  .bDescriptorType =    USB_DT_INTERFACE,
  .bInterfaceNumber =   0,
  .bNumEndpoints =      1,
  .bInterfaceClass =    USB_CLASS_HUB,
  .bInterfaceSubClass = 0,
  .bInterfaceProtocol = 0,
  .iInterface =         0,
};

/* Hub endpoint Descriptor */
static struct usb_endpoint_descriptor hub_endpoint_desc = {
  .bLength =            USB_DT_ENDPOINT_SIZE,
  .bDescriptorType =    USB_DT_ENDPOINT,
  .bEndpointAddress =   USB_DIR_IN | 0x02,
  .bmAttributes =       USB_ENDPOINT_XFER_INT,
  .wMaxPacketSize =     __constant_cpu_to_le16(8),
  .bInterval =          12,     // frames -> 32 ms
};

/* Hub class specific Descriptor */
static const struct usb_hub_header_descriptor hub_header_desc = {
  .bLength =            USB_DT_HUB_HEADER_SIZE (6),
  .bDescriptorType =    USB_DT_CS_HUB,
  .bNbrPorts = 6,
  .wHubCharacteristics = __constant_cpu_to_le16 (0x00a9),
  .bPwrOn2PwrGood = 20,
  .bHubContrCurrent = 100,
  .DeviceRemovable = 0x00,
  .PortPwrCtrlMask = 0xFF,
};


static void hub_port_changed (struct psfreedom_device *dev);


static void
switch_to_port (struct psfreedom_device *dev, unsigned int port)
{
  if (dev->current_port == port)
    return;
  DBG (dev, "Switching to port %d. Address is %d\n", port,
      dev->port_address[port]);
  dev->current_port = port;
  psfreedom_set_address (dev->gadget, dev->port_address[port]);
}

static void
hub_connect_port (struct psfreedom_device *dev, unsigned int port)
{
  if (port == 0 || port > 6)
    return;

  switch_to_port (dev, 0);

  /* Here, we must enable the port directly, otherwise we might loose time
     with the host asking for the status a few more times, and waiting for it to
     be enabled, etc.. and we might miss the 5seconds window in which we need
     to connect the JIG */
  dev->hub_ports[port-1].status |= PORT_STAT_CONNECTION;
  dev->hub_ports[port-1].status |= PORT_STAT_ENABLE;

  /* If the speed flag set is not the same as what the device suports, it will
     not work */
  if (psfreedom_is_high_speed ())
    dev->hub_ports[port-1].status |= PORT_STAT_HIGH_SPEED;
  else if (psfreedom_is_low_speed ())
    dev->hub_ports[port-1].status |= PORT_STAT_HIGH_SPEED;

  dev->hub_ports[port-1].change |= PORT_STAT_C_CONNECTION;
  hub_port_changed (dev);
}

static void
hub_disconnect_port (struct psfreedom_device *dev, unsigned int port)
{
  if (port == 0 || port > 6)
    return;

  switch_to_port (dev, 0);
  dev->hub_ports[port-1].status &= ~PORT_STAT_CONNECTION;
  dev->hub_ports[port-1].status &= ~PORT_STAT_ENABLE;
  dev->hub_ports[port-1].status &= ~PORT_STAT_HIGH_SPEED;
  dev->hub_ports[port-1].status &= ~PORT_STAT_LOW_SPEED;
  dev->hub_ports[port-1].change |= PORT_STAT_C_CONNECTION;
  hub_port_changed (dev);
}

static void hub_interrupt_complete(struct usb_ep *ep, struct usb_request *req)
{
  struct psfreedom_device *dev = ep->driver_data;
  int status = req->status;
  unsigned long flags;

  spin_lock_irqsave (&dev->lock, flags);
  DBG (dev, "Hub interrupt complete (status %d)\n", status);
  hub_interrupt_queued = 0;

  switch (status) {
    case 0:                             /* normal completion */
      if (ep == dev->hub_ep) {
        /* our transmit completed.
           see if there's more to go.
           hub_transmit eats req, don't queue it again. */
        //hub_interrupt_transmit(dev);
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
      hub_interrupt_queued = 0;
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

  hub_interrupt_queued = 1;
  status = usb_ep_queue(ep, req, GFP_ATOMIC);
  if (status) {
    ERROR(dev, "kill %s:  resubmit %d bytes --> %d\n",
        ep->name, req->length, status);
    usb_ep_set_halt(ep);
    hub_interrupt_queued = 0;
    /* FIXME recover later ... somehow */
  }
  spin_unlock_irqrestore (&dev->lock, flags);
}

static void hub_interrupt_transmit (struct psfreedom_device *dev)
{
  struct usb_ep *ep = dev->hub_ep;
  struct usb_request *req = dev->hub_req;
  u8 data = 0;
  int i;

  if (!ep)
    return;

  if (!req) {
    req = alloc_ep_req(ep, 8);
    dev->hub_req = req;
  }

  if (!req) {
    ERROR(dev, "hub_interrupt_transmit: alloc_ep_request failed\n");
    return;
  }

  req->complete = hub_interrupt_complete;

  for (i = 0; i < 6; i++) {
    if (dev->hub_ports[i].change != 0)
      data |= 1 << (i+1);
  }

  if (data != 0) {
    int err = 0;

    if (hub_interrupt_queued) {
      ERROR(dev, "hub_interrupt_transmit: Already queued a request\n");
      return;
    }

    /* Only queue one interrupt, and send it only once... If we don't do that
       then it will confuse the ps3, which will try to reset our device a few
       times and it will make it take over 15 seconds to get to plugging the JIG
       which will not work since it must be plugged in during boot in less
       than 5 seconds */
    memcpy (req->buf, &data, sizeof(data));
    req->length = sizeof(data);
    DBG (dev, "transmitting interrupt byte 0x%X\n", data);

    hub_interrupt_queued = 1;
    err = usb_ep_queue(ep, req, GFP_ATOMIC);
  } else {
    DBG (dev, "Nothing to report, freeing request, NAK-ing interrupt\n");
    if (hub_interrupt_queued)
      usb_ep_dequeue(ep, req);
    hub_interrupt_queued = 0;
  }

}

static void hub_port_changed (struct psfreedom_device *dev)
{
  hub_interrupt_transmit (dev);
}


static int set_hub_config(struct psfreedom_device *dev)
{
  int err = 0;

  hub_interrupt_queued = 0;
  err = usb_ep_enable(dev->hub_ep, &hub_endpoint_desc);
  if (err) {
    ERROR(dev, "can't start %s: %d\n", dev->hub_ep->name, err);
    goto fail;
  }
  dev->hub_ep->driver_data = dev;

fail:
  /* caller is responsible for cleanup on error */
  return err;
}

static void
hub_reset_config(struct psfreedom_device *dev)
{
  DBG(dev, "reset config\n");
  usb_ep_disable(dev->hub_ep);
  hub_interrupt_queued = 0;

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
hub_set_config(struct psfreedom_device *dev, unsigned number)
{
  int result = 0;
  struct usb_gadget *gadget = dev->gadget;

  hub_reset_config(dev);
  result = set_hub_config(dev);

  if (!result && !dev->hub_ep) {
    result = -ENODEV;
  }
  if (result) {
    hub_reset_config(dev);
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

static void hub_disconnect (struct usb_gadget *gadget)
{
  struct psfreedom_device *dev = get_gadget_data (gadget);

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
            memcpy(req->buf, &hub_config_desc, sizeof(hub_config_desc));
            value = sizeof(hub_config_desc);
            memcpy (req->buf + value, &hub_interface_desc,
                sizeof(hub_interface_desc));
            value += sizeof(hub_interface_desc);
            memcpy (req->buf + value, &hub_endpoint_desc,
                sizeof(hub_endpoint_desc));
            value += sizeof(hub_endpoint_desc);
            if (value >= 0)
              value = min(w_length, (u16)value);
            break;
          case USB_DT_STRING:
            value = 0;
            break;
        }
      }
      break;

    case USB_REQ_SET_CONFIGURATION:
      if (ctrl->bRequestType != 0) {
        goto unknown;
      }
      value = hub_set_config(dev, w_value);
      break;
    case USB_REQ_GET_CONFIGURATION:
      if (ctrl->bRequestType != USB_DIR_IN) {
        goto unknown;
      }
      *(u8 *)req->buf = 0;
      value = min(w_length, (u16)1);
      break;

    case USB_REQ_SET_INTERFACE:
      if (ctrl->bRequestType != USB_RECIP_INTERFACE) {
        goto unknown;
      }
      value = 0;
      break;
    case USB_REQ_GET_INTERFACE:
      if (ctrl->bRequestType != (USB_DIR_IN|USB_RECIP_INTERFACE)) {
        goto unknown;
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
          /* SET_HUB_FEATURE */
          case USB_RECIP_DEVICE:
            switch (w_value) {
              case 0: /* C_HUB_LOCAL_POWER */
              case 1: /* C_HUB_OVER_CURRENT */
                VDBG (dev, "SetHubFeature called\n");
                value = 0;
                break;
              default:
                value = -EINVAL;
                break;
            }
            break;
          case USB_RECIP_OTHER:
          /* SET_PORT_FEATURE */
            if (w_index == 0 || w_index > 6) {
              DBG (dev, "SetPortFeature: invalid port index %d\n", w_index);
              value = -EINVAL;
              break;
            }
            switch (w_value) {
              case 4: /* PORT_RESET */
                DBG (dev, "SetPortFeature PORT_RESET called\n");
                dev->hub_ports[w_index-1].change |= PORT_STAT_C_RESET;
                hub_port_changed (dev);
                value = 0;
                break;
              case 8: /* PORT_POWER */
                DBG (dev, "SetPortFeature PORT_POWER called\n");
                dev->hub_ports[w_index-1].status |= PORT_STAT_POWER;
                if (dev->status == INIT && w_index == 6) {
                  dev->status = HUB_READY;
                  SET_TIMER (150);
                }
                value = 0;
                break;
              case 0: /* PORT_CONNECTION */
              case 1: /* PORT_ENABLE */
              case 2: /* PORT_SUSPEND */
              case 3: /* PORT_OVER_CURRENT */
              case 9: /* PORT_LOW_SPEED */
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
          /* CLEAR_HUB_FEATURE */
          case USB_RECIP_DEVICE:
            switch (w_value) {
              case 0: /* C_HUB_LOCAL_POWER */
              case 1: /* C_HUB_OVER_CURRENT */
                VDBG (dev, "ClearHubFeature called\n");
                value = 0;
                break;
              default:
                value = -EINVAL;
                break;
            }
            break;
          case USB_RECIP_OTHER:
            /* CLEAR_PORT_FEATURE */
            if (w_index == 0 || w_index > 6) {
              DBG (dev, "ClearPortFeature: invalid port index %d\n", w_index);
              value = -EINVAL;
              break;
            }
            switch (w_value) {
              case 0: /* PORT_CONNECTION */
              case 1: /* PORT_ENABLE */
              case 2: /* PORT_SUSPEND */
              case 3: /* PORT_OVER_CURRENT */
              case 4: /* PORT_RESET */
              case 8: /* PORT_POWER */
              case 9: /* PORT_LOW_SPEED */
                value = 0;
                break;
              case 16: /* C_PORT_CONNECTION */
                DBG (dev, "ClearPortFeature C_PORT_CONNECTION called\n");
                dev->hub_ports[w_index-1].change &= ~PORT_STAT_C_CONNECTION;

                switch (dev->status) {
                  case DEVICE1_WAIT_DISCONNECT:
                    dev->status = DEVICE1_DISCONNECTED;
                    SET_TIMER (200);
                    break;
                  case DEVICE2_WAIT_DISCONNECT:
                    dev->status = DEVICE2_DISCONNECTED;
                    SET_TIMER (170);
                    break;
                  case DEVICE3_WAIT_DISCONNECT:
                    dev->status = DEVICE3_DISCONNECTED;
                    SET_TIMER (450);
                    break;
                  case DEVICE4_WAIT_DISCONNECT:
                    dev->status = DEVICE4_DISCONNECTED;
                    SET_TIMER (200);
                    break;
                  case DEVICE5_WAIT_DISCONNECT:
                    dev->status = DEVICE5_DISCONNECTED;
                    SET_TIMER (200);
                    break;
                  default:
                    break;
                }
                value = 0;
                break;
              case 20: /* C_PORT_RESET */
                DBG (dev, "ClearPortFeature C_PORT_RESET called\n");
                dev->hub_ports[w_index-1].change &= ~PORT_STAT_C_RESET;

                switch (dev->status) {
                  case DEVICE1_WAIT_READY:
                    if (w_index == 1)
                      dev->switch_to_port_delayed = w_index;
                    break;
                  case DEVICE2_WAIT_READY:
                    if (w_index == 2)
                      dev->switch_to_port_delayed = w_index;
                    break;
                  case DEVICE3_WAIT_READY:
                    if (w_index == 3)
                      dev->switch_to_port_delayed = w_index;
                    break;
                  case DEVICE4_WAIT_READY:
                    if (w_index == 4)
                      dev->switch_to_port_delayed = w_index;
                    break;
                  case DEVICE5_WAIT_READY:
                    if (w_index == 5)
                      dev->switch_to_port_delayed = w_index;
                    break;
                  case DEVICE6_WAIT_READY:
                    if (w_index == 6)
                      dev->switch_to_port_delayed = w_index;
                    break;
                  default:
                    break;
                }
                /* Delay switching the port because we first need to response
                   to this request with the proper address */
                if (dev->switch_to_port_delayed >= 0)
                  SET_TIMER (0);
                value = 0;
                break;
              case 17: /* C_PORT_ENABLE */
              case 18: /* C_PORT_SUSPEND */
              case 19: /* C_PORT_OVER_CURRENT */
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
          case USB_RECIP_DEVICE:
            /* GET_HUB_STATUS */
            status = 0;
            change = 0;
            break;
          case USB_RECIP_OTHER:
            /* GET_PORT_STATUS */
            if (w_index == 0 || w_index > 6) {
              DBG (dev, "GetPortstatus : invalid port index %d\n", w_index);
              value = -EINVAL;
              break;
            }
            status = dev->hub_ports[w_index -1].status;
            change = dev->hub_ports[w_index -1].change;
            break;
          default:
            goto unknown;
        }
        if (value > 0) {
          DBG (dev, "GetHub/PortStatus: transmtiting status %d change %d\n",
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
      ERROR (dev, "unknown control req%02x.%02x v%04x i%04x l%d\n",
          ctrl->bRequestType, ctrl->bRequest,
          w_value, w_index, w_length);
  }

  /* device either stalls (value < 0) or reports success */
  return value;
}

static int __init hub_bind(struct usb_gadget *gadget, struct psfreedom_device *dev)
{
  struct usb_ep *in_ep;

  gadget_for_each_ep (in_ep, gadget) {
    if (0 == strcmp (in_ep->name,
            psfreedom_get_endpoint_name (&hub_endpoint_desc)))
      break;
  }
  if (!in_ep) {
    ERROR (dev, "%s: can't find %s on %s\n",
        psfreedom_get_endpoint_name (&hub_endpoint_desc),
        shortname, gadget->name);
    return -ENODEV;
  }
  in_ep->driver_data = in_ep;   /* claim */

  /* ok, we made sense of the hardware ... */
  dev->hub_ep = in_ep;
  dev->hub_req = alloc_ep_req(in_ep, USB_BUFSIZ);
  if (!dev->req) {
    ERROR (dev, "Couldn't alloc hub request\n");
    return -ENOMEM;
  }


  /* The device's max packet size MUST be the same as ep0 */
  hub_device_desc.bMaxPacketSize0 = gadget->ep0->maxpacket;

  INFO(dev, "using %s, EP IN %s\n", gadget->name, in_ep->name);

  VDBG(dev, "hub_bind finished ok\n");

  return 0;
}
