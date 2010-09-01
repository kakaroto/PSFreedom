EXTRA_CFLAGS = -I/usr/include

obj-m	:= psjailbreak.o 
obj-m	:= kernel-crash.o 
obj-m	:= hub.o 

KDIR	:= /home/kakaroto/kernel-2.6.28/
PWD	:= $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRAVERSION=-omap1 modules

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -rf .tmp_versions
