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
	@echo "Please choose your platform by running 'make <platform>'." >&2
	@echo "You can also export the PLATFORM environment variable before running 'make'" >&2
	@false
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
n900-power: N900-POWER
n800: N8x0
N800: N8x0
n810: N8x0
N810: N8x0
n8x0: N8x0
palmpre: PalmPre
PALMPRE: PalmPre
palmpixi: PalmPixi
PALMPIXI: PalmPixi
archos5: ARCHOS_GEN6
ARCHOS5: ARCHOS_GEN6
Archos5: ARCHOS_GEN6
archos_gen6: ARCHOS_GEN6
archos5it: ARCHOS_GEN7
ARCHOS5IT: ARCHOS_GEN7
Archos5IT: ARCHOS_GEN7
archos_gen7: ARCHOS_GEN7
desire: Desire
DESIRE: Desire
dingoo: Dingoo
DINGOO: Dingoo
nexus1-cm6: nexus1-cm6
NEXUS1-CM6: nexus1-cm6

# Build configuration for each target
# Don't forget to add a dependency on 'build'

N900: KDIR := /usr/src/kernel-2.6.28/
N900: EXTRAVERSION:=-omap1
N900: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
N900: build

N900-POWER: KDIR := /usr/src/kernel-power-2.6.28/
N900-POWER: EXTRAVERSION:=$(shell if [ -f $(KDIR)/debian/changelog ]; then \
	 dpkg-parsechangelog -l$(KDIR)/debian/changelog | sed -ne 's/^Version: .*-maemo\(.*\)/.10power\1/p'; \
	fi)
N900-POWER: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
N900-POWER: build

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

ARCHOS_GEN6: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER -DENABLE_MUSB_ARCHOS_GEN6_CONTROLLER
ARCHOS_GEN6: KDIR   := /usr/src/linux-2.6.22.1-omap1
ARCHOS_GEN6: EXTRAVERSION:=-omap1
ARCHOS_GEN6: build

ARCHOS_GEN7: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
ARCHOS_GEN7: KDIR   := /usr/src/linux-2.6.27.10-omap1
ARCHOS_GEN7: EXTRAVERSION:=-omap1
ARCHOS_GEN7: build

Desire: EXTRA_CFLAGS += -DENABLE_MSM72K_CONTROLLER -DDISABLE_FIRMWARE_HOTPLUG
Desire: KDIR := /usr/src/linux-2.6.32.9
Desire: EXTRAVERSION:=
Desire: build

nexus1-cm6: EXTRA_CFLAGS += -DENABLE_MSM72K_CONTROLLER -DDISABLE_FIRMWARE_HOTPLUG
nexus1-cm6: KDIR := /usr/src/kernel-msm
nexus1-cm6: EXTRAVERSION:=
nexus1-cm6: build

Dingoo: EXTRA_CFLAGS += -DENABLE_JZ4740_CONTROLLER
Dingoo: KDIR := /usr/src/opendingux-kernel
Dingoo: EXTRAVERSION:=
Dingoo: build
