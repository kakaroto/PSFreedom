#!/bin/sh
RC=0

/sbin/lsmod | grep psfreedom > /dev/null
if [ $? = 0 ]; then
    /sbin/rmmod psfreedom
fi

