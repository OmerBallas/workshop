CONFIG_MODULE_SIG=n
obj-m += firewall.o
firewall-objs+= ./src/firewall.o ./src/statemachine.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
