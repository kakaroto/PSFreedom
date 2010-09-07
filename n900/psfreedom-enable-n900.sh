#!/bin/sh
RC=0

if grep -q g_file_storage /proc/modules; then
    logger "$0: removing g_file_storage"
    initctl emit G_FILE_STORAGE_REMOVE > /dev/null
    /sbin/rmmod g_file_storage
fi


if grep -q g_nokia /proc/modules; then
    logger "$0: removing g_nokia"

    initctl emit G_NOKIA_REMOVE > /dev/null

    PNATD_PID=`pidof pnatd`
    if [ $? = 0 ]; then
        kill $PNATD_PID
    else
        logger "$0: pnatd is not running"
    fi
    OBEXD_PID=`pidof obexd`
    if [ $? = 0 ]; then
        kill -HUP $OBEXD_PID
    else
        logger "$0: obexd is not running"
    fi
    SYNCD_PID=`pidof syncd`
    if [ $? = 0 ]; then
        kill $SYNCD_PID
    else
        logger "$0: syncd is not running"
    fi

    sleep 2
    /sbin/rmmod g_nokia
    if [ $? != 0 ]; then
        logger "$0: failed to rmmod g_nokia!"
        exit 1
    fi
fi

if ! grep -q psfreedom /proc/modules; then
    insmod psfreedom.ko
    RC=$?                                    
fi                                                                   
                                                            
if [ $RC != 0 ]; then                                              
    logger "$0: failed to install psfreedom module"                      
    exit 1                                                      
fi                                                              
                               

exit 0
