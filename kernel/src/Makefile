ifneq ($(KERNELRELEASE),)
    obj-m += nomount.o
    CFLAGS_nomount.o += -fno-optimize-sibling-calls

    ifneq ($(filter y 1,$(USE_KPROBES)),)
        $(info NoMount: Hook type: Forced Kprobes)
        ccflags-y += -DNM_BACKEND_KPROBES
    else ifneq ($(filter y 1,$(USE_FTRACE)),)
        $(info NoMount: Hook type: Forced Ftrace)
        ccflags-y += -DNM_BACKEND_FTRACE
    else ifneq ($(filter y 1,$(CONFIG_DYNAMIC_FTRACE)),)
        $(info NoMount: Hook type: Auto-detected Ftrace)
        ccflags-y += -DNM_BACKEND_FTRACE
    else ifneq ($(filter y 1,$(CONFIG_KPROBES)),)
        $(info NoMount: Hook type: Auto-detected Kprobes)
        ccflags-y += -DNM_BACKEND_KPROBES
    endif

else
    KDIR ?= /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

endif
