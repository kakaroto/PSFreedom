EXTRA_CFLAGS = -I/usr/include

obj-m	:= psfreedom.o 

ifndef KDIR
  KDIR := /lib/modules/$(shell uname -r)/build
  ifneq ($(shell if test -d $(KDIR); then echo yes; fi),yes)
    KDIR := /usr/src/linux
  endif
endif

PWD	:= $(shell pwd)


ifndef PLATFORM
all:
	@echo "Please choose your platform by running 'make <platform>'."
	@echo "You can also export the PLATFORM environment variable before running 'make'"
else
all: ${PLATFORM}
endif

#Build rules

build:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="${EXTRA_CFLAGS}" EXTRAVERSION=${EXTRAVERSION} modules

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -rf .tmp_versions

# Aliases for platforms

n900: N900
n800: N8x0
N800: N8x0
n810: N8x0
N810: N8x0
palmpre: PalmPre
PALMPRE: PalmPre
palmpixi: PalmPixi
PALMPIXI: PalmPixi
archos: ARCHOS
Archos: ARCHOS
desire: Desire
DESIRE: Desire

# Build configuration for each target
# Don't forget to add a dependency on 'build'

N900: KDIR := /usr/src/kernel-2.6.28/
N900: EXTRAVERSION:=-omap1
N900: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
N900: build

N8x0: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
N8x0: KDIR := /usr/src/kernel-source-diablo
N8x0: EXTRAVERSION:=-omap1
N8x0: build

PalmPre: EXTRA_CFLAGS := -DENABLE_MUSB_CONTROLLER
PalmPre: KDIR	:= /usr/src/linux-2.6.24
PalmPre: EXTRAVERSION:=-joplin-3430
PalmPre: build

PalmPixi: EXTRA_CFLAGS := -DENABLE_MUSB_CONTROLLER -DCONFIG_USB_GADGET_MUSB_HDRC
PalmPixi: KDIR	:= /usr/src/linux-2.6.24-pixi
PalmPixi: EXTRAVERSION:=-chuck
PalmPixi: build

ARCHOS: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
ARCHOS: KDIR   := /usr/src/linux-2.6.22.1
ARCHOS: EXTRAVERSION:=-omap1
ARCHOS: build

Desire: EXTRA_CFLAGS += -DENABLE_MSM72K_CONTROLLER -DDISABLE_FIRMWARE_HOTPLUG
Desire: KDIR := /usr/src/linux-2.6.32.9
Desire: EXTRAVERSION:=
Desire: build
