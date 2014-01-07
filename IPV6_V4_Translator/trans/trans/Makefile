# to compile this module (as a separate module, not integrated to 
# kernel tree), use fololwing command:
# make -C /path/to/your/linux/source SUBDIRS=$PWD modules
#
# e.g.
# make -C /usr/src/linux-2.6.23 SUBDIRS=$PWD modules
#

build-and-copy:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) modules

obj-m := ip_v6_v4.o
.PHONY: clean build-and-copy snapshot

