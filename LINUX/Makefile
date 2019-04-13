CONFIG_OPP:=m
opp_lin-objs := opp.o opp_linux.o
obj-$(CONFIG_OPP) = opp_lin.o

M:=$(CURDIR)
SRC ?= $(KSRC)
EXTRA_CFLAGS := -I$(NSRC)/ -I$(NSRC)/LINUX -I$(NSRC)/sys -I$(M)/../sys -I$(M) -DCONFIG_NETMAP

all:	build
build:
	make -C $(SRC) M=$(CURDIR) \
		CONFIG_NETMAP=m CONFIG_NETMAP_VALE=y CONFIG_OPP=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' \
		KBUILD_EXTRA_SYMBOLS=$(NSRC)/Module.symvers
	ls -l `find . -name \*.ko`
clean:
	(rm -rf *.o *.ko modules.order opp.mod.c Module.symvers)

$(obj)/opp.o:	$(M)/../sys/contrib/opp/opp.c
	$(call cmd,cc_o_c)
	$(call cmd,modversions)
$(obj)/opp_linux.o:	$(M)/opp_linux.c
	$(call cmd,cc_o_c)
	$(call cmd,modversions)
