#!/bin/sh
RC=0

if grep -q psfreedom /proc/modules; then
    logger "$0: removing psfreedom"
    if lsmod | grep psfreedom | grep -q 4294967295; then
       /sbin/rmmod -f psfreedom
    else
      /sbin/rmmod psfreedom
    fi
fi

/usr/sbin/osso-usb-mass-storage-enable.sh
