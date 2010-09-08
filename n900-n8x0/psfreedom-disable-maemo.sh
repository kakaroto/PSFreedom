#!/bin/sh
RC=0

if grep -q psfreedom /proc/modules; then
    logger "$0: removing psfreedom"
    /sbin/rmmod -f psfreedom
fi

/usr/sbin/osso-usb-mass-storage-enable.sh
