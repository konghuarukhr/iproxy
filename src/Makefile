# https://www.kernel.org/doc/Documentation/kbuild/modules.txt

KDIR=/lib/modules/$(shell uname -r)/build
#export CROSS_COMPILE=
#KDIR=/root/android/kernel/msm

ifeq ($(m),client)
obj-m := iproxy-client.o
iproxy-client-y := client.o route.o masq.o
ccflags-y := -D_IPR_CLIENT
else
obj-m := iproxy-server.o
iproxy-server-y := server.o xlate.o route.o masq.o
ccflags-y := -D_IPR_SERVER
endif

ifeq ($(d),debug)
ccflags-y += -DDEBUG -g -Wall
else
ccflags-y += -O2
endif

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -rf route-cli

tool:
	cc $(ccflags-y) route-cli.c ugenl-helper.c -o route-cli

help:
	@echo "usage:"
	@echo "    make [m={client|server}] [d=debug]"
	@echo "    make clean"
