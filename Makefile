# Specify KDIR on cmd line, example:
# make omap2 ARCH=arm CROSS_COMPILE=<path to arm-eabi-> KDIR=<path to kernel>

EXTRA_CFLAGS = -I/usr/include

obj-m	:= psfreedom.o 

ifndef KDIR
  KDIR := /lib/modules/$(shell uname -r)/build
  ifneq ($(shell if test -d $(KDIR); then echo yes; fi),yes)
    KDIR := /usr/src/linux
  endif
endif

PWD	:= $(shell pwd)


ifndef PSFREEDOM_PLATFORM
all:
	@echo "Please choose your platform by running 'make <platform>'." >&2
	@echo "You can also export the PSFREEDOM_PLATFORM environment variable before running 'make'" >&2
	@false
else
all: ${PSFREEDOM_PLATFORM}
endif

#Build rules

build:
	$(MAKE) -C pl3
	$(MAKE) -C $(KDIR) M=$(PWD) $(PARAM) EXTRA_CFLAGS="${EXTRA_CFLAGS}" EXTRAVERSION=${EXTRAVERSION} modules

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c Module.symvers modules.order
	rm -rf .tmp_versions

# Aliases for generic devices
igep: Igep
n900: build_omap1
n800: build_omap1
n810: build_omap1
n8x0: build_omap1
archos5it: build_omap1
droid: build_omap2
desire: build_msm72k
nexusone: build_msm72k
incredible: build_msm72k
evo4g: build_msm72k
gpone: build_msm72k
hero: build_msm72k
g1: build_msm72k

# Aliases for non generic devices
n900-power: N900-POWER
palmpre: PALMPRE
palmpixi: PALMPIXI
archos5: ARCHOS_GEN6
dingoo: DINGOO
iPhone: IPHONE

# Generic build rule for MSM72K controller
build_msm72k: EXTRA_CFLAGS+=-DENABLE_MSM72K_CONTROLLER -DUI_ALLOC_ADDR=0x`cat $(KDIR)/System.map|grep the_usb_info|cut -b 1-8`
build_msm72k: EXTRAVERSION:=
build_msm72k: build

# Generic build rule for OMAP1 MUSB controller
build_omap1: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
build_omap1: EXTRAVERSION:=-omap1
build_omap1: build

# Generic build rule for OMAP2 MUSB controller
build_omap2: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
build_omap2: EXTRAVERSION:=-omap2
build_omap2: build

# Build rules for non generic targets
# Don't forget to add a dependency on 'build'

N900-POWER: EXTRAVERSION:=$(shell if [ -f $(KDIR)/debian/changelog ]; then \
	 dpkg-parsechangelog -l$(KDIR)/debian/changelog | sed -ne 's/^Version: .*-maemo\(.*\)/.10power\1/p'; \
	fi)
N900-POWER: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
N900-POWER: build

PALMPRE: EXTRA_CFLAGS := -DENABLE_MUSB_CONTROLLER -DCONFIG_USB_GADGET_MUSB_HDRC
PALMPRE: EXTRAVERSION:=-joplin-3430
PALMPRE: build

PALMPIXI: EXTRA_CFLAGS := -DENABLE_MUSB_CONTROLLER -DCONFIG_USB_GADGET_MUSB_HDRC
PALMPIXI: EXTRAVERSION:=-chuck
PALMPIXI: build

ARCHOS_GEN6: EXTRA_CFLAGS += -DENABLE_MUSB_ARCHOS_GEN6_CONTROLLER
ARCHOS_GEN6: build_omap1

DINGOO: EXTRA_CFLAGS += -DENABLE_JZ4740_CONTROLLER
DINGOO: EXTRAVERSION:=
DINGOO: build

IPHONE: EXTRA_CFLAGS += -DENABLE_S3C_CONTROLLER -DNO_DELAYED_PORT_SWITCHING
IPHONE: KDIR := /usr/src/kernel_common/
IPHONE: EXTRAVERSION:=
IPHONE: build

Igep: EXTRA_CFLAGS := -DENABLE_MUSB_CONTROLLER 
Igep: KDIR	:= /usr/src/linux-omap-2.6/
Igep: EXTRAVERSION:=-omap3
Igep: PARAM:= ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabi-
Igep: build
