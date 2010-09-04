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
	@echo "You can also set the PLATFORM environment variable"
else
all: ${PLATFORM}
endif

n900: N900
N900: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
N900: KDIR := ~/kernel-2.6.28/
N900:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="${EXTRA_CFLAGS}" EXTRAVERSION=-omap1 modules

n810: N8x0
N810: N8x0
n800: N8x0
N800: N8x0
N8x0: EXTRA_CFLAGS += -DENABLE_MUSB_CONTROLLER
N8x0: KDIR := /usr/src/kernel-source-diablo
N8x0:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="${EXTRA_CFLAGS}" EXTRAVERSION=-omap1 modules

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -rf .tmp_versions
