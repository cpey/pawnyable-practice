#!/usr/bin/env python3

# Example of use:
#
# $ ./tools/transfer.py -f ./qemu/rootfs.cpio -r tools/run.sh src/01.exploit/exploit
# [+] __init__: Successfully created new process (PID=44766)
# [+] upload: Uploading...
# Uploading... 0/6180
# ...
# Uploading... 6000/6180
# /tmp[ptrlib]$  $ ./exploit
# .[ptrlib]$ /exploit
# Hello, World!!!

from ptrlib import *
import time
import base64
import os
import argparse
import time

def run(cmd):
    sock.sendlineafter("$ ", cmd)
    sock.recvline()

def upload(filename, run_cmd):
    with open(filename, "rb") as f:
        payload = bytes2str(base64.b64encode(f.read()))

    global sock
    #sock = Socket("HOST", PORT) # remote
    sock = Process(run_cmd)

    run('cd /tmp')

    logger.info("Uploading...")
    for i in  range(0, len(payload), 512):
        print (f"Uploading... {i:x}/{len(payload):x}")
        run('echo "{}" >> b64exp'.format(payload[i:i+512]))
        run('base64 -d b64exp > exploit')

    run('rm b64exp')
    run('chmod +x exploit')

    sock.interactive()

if __name__=='__main__':
    parser = argparse.ArgumentParser(
                    prog='transfer.py',
                    description='Upload binary to remote via nc, using base64',
                    epilog='Text at the bottom of help')
    parser.add_argument('filename', help="Binary to upload")
    parser.add_argument('-r', '--run', help="Qemu run script")
    parser.add_argument('-l', '--linux', help="Linux kernel")
    parser.add_argument('-f', '--rootfs', help="Root filesystem")
    args = parser.parse_args()

    run_cmd = [args.run]
    if (args.linux):
        run_cmd.extend(['-l', args.linux])
    if (args.rootfs):
        run_cmd.extend(['-r', args.rootfs])

    upload(args.filename, run_cmd)
