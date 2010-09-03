EXTRA_CFLAGS = -I/usr/include -DENABLE_MUSB_CONTROLLER

obj-m	:= psfreedom.o 

KDIR	:= /home/kakaroto/kernel-2.6.28/
PWD	:= $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRAVERSION=-omap1 modules

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -rf .tmp_versions
