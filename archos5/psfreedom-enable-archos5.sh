#!/bin/sh
RC=0

/sbin/lsmod | grep g_blockdev_storage > /dev/null
if [ $? = 0 ]; then
    /sbin/rmmod g_blockdev_storage
fi

/sbin/lsmod |grep musb_hdrc >/dev/null
if [ $? = 0 ]; then
  /sbin/rmmod musb_hdrc
fi

insmod /lib/modules/musb_hdrc.ko mode_default=2

/sbin/lsmod |grep firmware_class >/dev/null
if [ $? != 0 ]; then
  /sbin/insmod /lib/modules/firmware_class.ko
fi

/sbin/lsmod | grep psfreedom > /dev/null                         
if [ $? != 0 ]; then                                         
    insmod psfreedom.ko
    RC=$?                                    
fi                                                                   
                                                            
if [ $RC != 0 ]; then                                              
    exit 1                                                      
fi                                                              

exit 0
