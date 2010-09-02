#!/bin/sh
RC=0

/sbin/lsmod | grep psjailbreak > /dev/null
if [ $? = 0 ]; then
    logger "$0: removing psjailbreak"
    /sbin/rmmod psjailbreak
fi

/usr/sbin/osso-usb-mass-storage-enable.sh
