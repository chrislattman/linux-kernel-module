# Linux Kernel Module

This module is posted for educational purposes only.

To test this module, run `make` then `sudo insmod mymodule.ko` to insert it.

Run `sudo dmesg` to see the printk messages.

To hide this module once it's inserted, run `kill -63 1` (this module hooks the `kill` system call). Verify that it works by running `lsmod | grep mymodule` and/or `cat /proc/modules | grep mymodule`.

Run `kill -63 1` to unhide this module, and `sudo rmmod mymodule` to remove it.

Tested with Linux 6.7.9 on x86-64.
