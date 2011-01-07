/*
 * psfreedom_address.c -- PS3 Jailbreak exploit Gadget Driver
 *
 * Copyright (C) 2010 Youness Alaoui (KaKaRoTo)
 * Copyright (C) 2010 (DocMon)
 * Copyright (C) 2010 Miguel Boton (Waninkoko)
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
 * MSM72K controller driver, Copyright (C) 2008 Google, Inc.
 *
 * JZ4740 controller driver, Copyright (C) 2006-2008 Ingenic Semiconductor Inc.
 *
 */

#ifdef ENABLE_MUSB_CONTROLLER

/* Kernel 2.6.21 (N800/N900) needs this to compile */
#define MUSB_DEBUG 0

#ifdef ENABLE_MUSB_ARCHOS_GEN6_CONTROLLER
#include "../drivers/usb/musb/musbdefs.h"
#else
#include "../drivers/usb/musb/musb_core.h"
#endif

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
 * Returns: the name of the endpoint
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
#ifdef ENABLE_MUSB_ARCHOS_GEN6_CONTROLLER
    address = musb_readb(musb->pRegs, MGC_O_HDRC_FADDR);
#else
    address = musb_readb(musb->mregs, MUSB_FADDR);
#endif

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
#ifdef ENABLE_MUSB_ARCHOS_GEN6_CONTROLLER
    musb->bAddress = address;
    musb_writeb(musb->pRegs, MGC_O_HDRC_FADDR, address);
#else
    musb->address = address;
    musb_writeb(musb->mregs, MUSB_FADDR, address);
#endif
  }
}

#endif /* ENABLE_MUSB_CONTROLLER */

#ifdef ENABLE_MSM72K_CONTROLLER

/* Hack Alert: This was needed because for some
   unknown reason, container_of() would return a
   ui that diddn't contain the address information we wanted.
   This uses the offset from the usb_gadget supplied to find
   our value. Should hold while usb_info remains the same.
*/
#define USBDEVADDR (readu(*(unsigned int *)UI_ALLOC_ADDR + 12) + 0x0154)

static inline void writel(unsigned long l, unsigned long addr)
{
  *(volatile unsigned long __force *)addr = l;
}
static inline unsigned long readl(unsigned long addr)
{
  return *(volatile unsigned long __force *)addr;
}
static inline unsigned readu(unsigned addr)
{
  return *(volatile unsigned __force *)addr;
}

static int psfreedom_is_high_speed (void)
{
  return 1;
}

static int psfreedom_is_low_speed (void)
{
  return 0;
}

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

static u8 psfreedom_get_address (struct usb_gadget *g)
{
  unsigned long buffer = 0;
  u8 address = 0;

  buffer = readl(USBDEVADDR);
  /* The address is in the bits 25-32 */
  address = (u8) (buffer >> 25) & 0x7F;
  if (debug > 1)
    dev_vdbg(&g->dev, "***** Getting address : %d\n", address);

  return address;
}

static void psfreedom_set_address (struct usb_gadget *g, u8 address)
{

  /* Send the address in bits 25-32. Do not use the same method as the
     controller's SET_ADDRESS which sets bit 24 to '1' to tell the controller
     to delay the operation until a IN response is sent (response to the
     SET_ADDRESS must be sent with the old address).
  */
  writel((address << 25), USBDEVADDR);
  if (debug > 1)
    dev_vdbg(&g->dev, "***** Setting address to %d. New address: %d\n",
        address, psfreedom_get_address(g));
}

#endif /* ENABLE_MSM72K_CONTROLLER */

#ifdef ENABLE_JZ4740_CONTROLLER

#include "../drivers/usb/gadget/jz4740_udc.h"

#define JZ_REG_UDC_FADDR        0x00 /* Function Address 8-bit */

static inline uint8_t usb_readb (struct jz4740_udc *udc, size_t reg)
{
        return readb(udc->base + reg);
}

static inline void usb_writeb (struct jz4740_udc *udc, size_t reg, uint8_t val)
{
        writeb(val, udc->base + reg);
}

static inline void usb_change_epnum (struct usb_endpoint_descriptor *desc, uint8_t epnum)
{
        desc->bEndpointAddress &= ~0x0f;
        desc->bEndpointAddress |= epnum;
}

static int psfreedom_is_high_speed (void)
{
  return 1;
}

static int psfreedom_is_low_speed (void)
{
  return 0;
}

static char *psfreedom_get_endpoint_name (struct usb_endpoint_descriptor *desc)
{
  u8 address = desc->bEndpointAddress;
  u8 epnum = address & 0x0f;

  if (epnum == 1 && (address & USB_DIR_IN) == USB_DIR_IN)
    return "ep1in-bulk";
  else if (epnum == 2 && (address & USB_DIR_IN) == USB_DIR_IN)
    return "ep2in-int";
  else if ((epnum == 2 || epnum == 1) &&
      (address & USB_DIR_IN) == 0) {
    usb_change_epnum(desc, 1);
    return "ep1out-bulk";
  } else
    return NULL;
}

static u8 psfreedom_get_address (struct usb_gadget *g)
{
  struct jz4740_udc *dev = container_of(g, struct jz4740_udc, gadget);
  u8 address = 0;

  if (dev)
    address = usb_readb(dev, JZ_REG_UDC_FADDR);

  return address;
}

static void psfreedom_set_address (struct usb_gadget *g, u8 address)
{
  struct jz4740_udc *dev = container_of(g, struct jz4740_udc, gadget);

  if (dev) {
    dev->usb_address = address;
    usb_writeb(dev, JZ_REG_UDC_FADDR, address);
  }
}

#endif /* ENABLE_JZ4740_CONTROLLER */

#ifdef ENABLE_S3C_CONTROLLER

struct s3c_hsotg;
struct s3c_hsotg_req;

struct s3c_hsotg_ep {
        struct usb_ep           ep;
        struct list_head        queue;
        struct s3c_hsotg        *parent;
        struct s3c_hsotg_req    *req;
        struct dentry           *debugfs;

        spinlock_t              lock;

        unsigned long           total_data;
        unsigned int            size_loaded;
        unsigned int            last_load;
        unsigned int            fifo_load;
        unsigned short          fifo_size;

        unsigned char           dir_in;
        unsigned char           index;

        unsigned int            halted:1;
        unsigned int            periodic:1;
        unsigned int            sent_zlp:1;

        char                    name[10];
};

//#define S3C_HSOTG_EPS (8+1)   /* limit to 9 for the moment */
#define S3C_HSOTG_EPS   (6)

struct s3c_hsotg {
        struct device            *dev;
        struct usb_gadget_driver *driver;
        struct s3c_hsotg_plat    *plat;

        void __iomem            *regs;
        struct resource         *regs_res;
        int                     irq;

        struct dentry           *debug_root;
        struct dentry           *debug_file;
        struct dentry           *debug_fifo;

        struct usb_request      *ep0_reply;
        struct usb_request      *ctrl_req;
        u8                      ep0_buff[8];
        u8                      ctrl_buff[8];

        struct usb_gadget       gadget;
        struct s3c_hsotg_ep     eps[];
};

struct s3c_hsotg_req {
        struct usb_request      req;
        struct list_head        queue;
        unsigned char           in_progress;
        unsigned char           mapped;
};

static inline struct s3c_hsotg *to_hsotg(struct usb_gadget *gadget)
{
        return container_of(gadget, struct s3c_hsotg, gadget);
}

#define S3C_HSOTG_REG(x) (x)

/* Device mode registers */
#define S3C_DCFG                                S3C_HSOTG_REG(0x800)

#define S3C_DCFG_EPMisCnt_MASK                  (0x1f << 18)
#define S3C_DCFG_EPMisCnt_SHIFT                 (18)
#define S3C_DCFG_EPMisCnt_LIMIT                 (0x1f)
#define S3C_DCFG_EPMisCnt(_x)                   ((_x) << 18)

#define S3C_DCFG_PerFrInt_MASK                  (0x3 << 11)
#define S3C_DCFG_PerFrInt_SHIFT                 (11)
#define S3C_DCFG_PerFrInt_LIMIT                 (0x3)
#define S3C_DCFG_PerFrInt(_x)                   ((_x) << 11)

#define S3C_DCFG_DevAddr_MASK                   (0x7f << 4)
#define S3C_DCFG_DevAddr_SHIFT                  (4)
#define S3C_DCFG_DevAddr_LIMIT                  (0x7f)
#define S3C_DCFG_DevAddr(_x)                    ((_x) << 4)

#define S3C_DCFG_NZStsOUTHShk                   (1 << 2)

#define S3C_DCFG_DevSpd_MASK                    (0x3 << 0)
#define S3C_DCFG_DevSpd_SHIFT                   (0)
#define S3C_DCFG_DevSpd_HS                      (0x0 << 0)
#define S3C_DCFG_DevSpd_FS                      (0x1 << 0)
#define S3C_DCFG_DevSpd_LS                      (0x2 << 0)
#define S3C_DCFG_DevSpd_FS48                    (0x3 << 0)

static inline void writel(unsigned long l, unsigned long *addr)
{
        *(volatile unsigned long __force *)addr = l;
}

static inline unsigned long readl(unsigned long *addr)
{
        return *(volatile unsigned long __force *)addr;
}

static int psfreedom_is_high_speed (void)
{
  return 1;
}

static int psfreedom_is_low_speed (void)
{
  return 0;
}

static char *psfreedom_get_endpoint_name (struct usb_endpoint_descriptor *desc)
{
  u8 address = desc->bEndpointAddress;
  u8 epnum = address & 0x0f;

  if (epnum == 1 && (address & USB_DIR_IN) == USB_DIR_IN) {
    return "ep1in";
  } else if ((epnum == 2 || epnum == 3) &&
      (address & USB_DIR_IN) == USB_DIR_IN) {
    desc->bEndpointAddress &= ~0x0f;
    desc->bEndpointAddress |= 3;
    return "ep3in";
  } else if (epnum == 2 && (address & USB_DIR_IN) == 0) {
    return "ep2out";
  } else {
    return NULL;
  }
}

static u8 psfreedom_get_address (struct usb_gadget *g)
{
  u32 dcfg = readl(to_hsotg(g)->regs + S3C_DCFG);

  if (debug > 1)
    dev_vdbg(&g->dev, "***** DCFG value (get) : %x\n", dcfg);

  return (dcfg & S3C_DCFG_DevAddr_MASK) >> S3C_DCFG_DevAddr_SHIFT;
}

static void psfreedom_set_address (struct usb_gadget *g, u8 address)
{
  struct s3c_hsotg *hsotg = to_hsotg(g);
  u32 dcfg = readl(hsotg->regs + S3C_DCFG);

  dcfg |= 1 << 3; /* testing bit */

  dcfg &= ~S3C_DCFG_DevAddr_MASK;
  dcfg |= address << S3C_DCFG_DevAddr_SHIFT;

  writel(dcfg, hsotg->regs + S3C_DCFG);

  if (debug > 1)
    dev_vdbg(&g->dev, "***** Setting address to %d. New address: %d\n",
        address, psfreedom_get_address(g));

}

#endif /* ENABLE_S3C_CONTROLLER */
