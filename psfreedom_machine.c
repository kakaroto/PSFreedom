/*
 * psfreedom_address.c -- PS3 Jailbreak exploit Gadget Driver
 *
 * Copyright (C) 2010 Youness Alaoui (KaKaRoTo)
 * Copyright (C) 2010 (DocMon)
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

#ifdef ENABLE_MSM72K_CONTROLLER

#define USBDEVADDR ((unsigned)ui->addr + 0x0154)
#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

static inline void writel(unsigned long l, unsigned long addr)
{
	*(volatile unsigned long __force *)addr = l;
}

static inline unsigned long readl(unsigned long addr)
{
	return *(volatile unsigned long __force *)addr;
}

struct msm_request {
	struct usb_request req;

	/* saved copy of req.complete */
	void	(*gadget_complete)(struct usb_ep *ep,
					struct usb_request *req);


	struct usb_info *ui;
	struct msm_request *next;

	unsigned busy:1;
	unsigned live:1;
	unsigned alloced:1;

	dma_addr_t dma;
	dma_addr_t item_dma;

	struct ept_queue_item *item;
};

struct msm_endpoint {
	struct usb_ep ep;
	struct usb_info *ui;
	struct msm_request *req; /* head of pending requests */
	struct msm_request *last;
	unsigned flags;

	/* bit number (0-31) in various status registers
	** as well as the index into the usb_info's array
	** of all endpoints
	*/
	unsigned char bit;
	unsigned char num;

	/* pointers to DMA transfer list area */
	/* these are allocated from the usb_info dma space */
	struct ept_queue_head *head;
};

struct usb_info {
	/* lock for register/queue/device state changes */
	spinlock_t lock;

	/* single request used for handling setup transactions */
	struct usb_request *setup_req;

	struct platform_device *pdev;
	int irq;
	void *addr;

	unsigned state;
	unsigned flags;

	unsigned	online:1;
	unsigned	running:1;

	struct dma_pool *pool;

	/* dma page to back the queue heads and items */
	unsigned char *buf;
	dma_addr_t dma;

	struct ept_queue_head *head;

	/* used for allocation */
	unsigned next_item;
	unsigned next_ifc_num;

	/* endpoints are ordered based on their status bits,
	** so they are OUT0, OUT1, ... OUT15, IN0, IN1, ... IN15
	*/
	struct msm_endpoint ept[32];

	int *phy_init_seq;
	void (*phy_reset)(void);
	void (*hw_reset)(bool en);

	/* for notification when USB is connected or disconnected */
	void (*usb_connected)(int);

	struct work_struct work;
	unsigned phy_status;
	unsigned phy_fail_count;

	struct usb_gadget		gadget;
	struct usb_gadget_driver	*driver;

#define ep0out ept[0]
#define ep0in  ept[16]

	struct clk *clk;
	struct clk *pclk;
	struct clk *otgclk;
	struct clk *ebi1clk;

	unsigned int ep0_dir;
	u16 test_mode;

	u8 remote_wakeup;
};

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
  struct usb_info *ui = container_of(g, struct usb_info, gadget);
  unsigned long buffer = 0;
  u8 address = 0;

  if (ui) {
    buffer = readl(USBDEVADDR);
    /* Remove the possible 'delay operation' flag */
    buffer = buffer & (0 << 24);
    /* The address is in the bits 25-32 */
    address = (u8) (buffer >> 25) & 0x7F;
    dev_vdbg(&g->dev, "***** Getting address : %d\n", address);
  }

  return address;
}

static void psfreedom_set_address (struct usb_gadget *g, u8 address)
{
  struct usb_info *ui = container_of(g, struct usb_info, gadget);

  if (ui) {
    /* Send the address in bits 25-32. Do not use the same method as the
       controller's SET_ADDRESS which sets bit 24 to '1' to tell the controller
       to delay the operation until a IN response is sent (response to the
       SET_ADDRESS must be sent with the old address).
    */
    writel((address << 25), USBDEVADDR);
    dev_vdbg(&g->dev, "***** Setting address to %d. New address: %d\n",
        address, psfreedom_get_address(g));
  }
}

#endif /* ENABLE_MSM72K_CONTROLLER */
