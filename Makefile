KERNELDIR:=/lib/modules/$(shell uname -r)/build

obj-m = icmpshell.o
icmpshell-objs = main.o

all: icmpshell.ko

icmpshell.ko: main.c
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
