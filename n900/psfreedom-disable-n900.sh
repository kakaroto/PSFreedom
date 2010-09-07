#!/bin/sh
RC=0

/sbin/lsmod | grep psfreedom > /dev/null
if [ $? = 0 ]; then
    logger "$0: removing psfreedom"
    /sbin/rmmod psfreedom
fi

/usr/sbin/osso-usb-mass-storage-enable.sh
