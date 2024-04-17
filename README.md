# Linux Kernel Module

This module is posted for educational purposes only.

To test this module, run `make` then `sudo insmod mymodule.ko` to insert it.

Run `sudo dmesg` to see the printk messages (`sudo dmesg -C` clears all messages).

To hide this module once it's inserted, run `kill -63 1` (this module hooks the `sys_kill` system call (a kernel function), which the `kill` command calls internally via the `int kill(pid_t, int)` C library function). Verify that it works by running `lsmod | grep mymodule` and/or `cat /proc/modules | grep mymodule`.

Run `kill -63 1` again to unhide this module, and `sudo rmmod mymodule` to remove it.

Tested with Linux v6.7.9 (using Fedora Server 39) on x86-64 and aarch64.
