## FlowBlaze (Open Packet Processor) module for VALE (mSwitch) software switch with long-lived flow detector

These code are mostly educational purpose but useful to understand FlowBlaze (Open Packet
Processor) with code.
Neither baremetal machine nor hardware NIC is required, while they perform well
even in baremetal environment.  (e.g., 8.7 Mpps with a single core of Xeon
E3-1231 v3 and Intel X540 10Gbps NIC).

These code implement two major components:
- VALE module that resembles the hardware model (e.g., registers) of
  FlowBlaze
- Long-lived flow detector logic

The former is based on description in Section 2.2, and the latter is based on
the second paragraph of Section 2.3 in the original Open Packet Processor paper
[1].  The entire code was used in Section 5 of the later version of the paper [2].

[1] Giuseppe Bianchi, Marco Bonola, Salvatore Pontarelli,
Davide Sanvito, Antonio Capone, Carmelo Cascone, "Open Packet Processor: a
programmable architecture for
wire speed platform-independent stateful in-network
processing", arxiv, 2016 https://arxiv.org/pdf/1605.01977.pdf

[2] Salvatore Pontarelli, Roberto Bifulco, Marco Bonola, Carmelo Cascone,
Marco Spaziani, Valerio Bruschi, Davide Sanvito, Giuseppe Siracusano,
Antonio Capone, Michio Honda, Felipe Huici and Giuseppe Bianchi, "FlowBlaze:
Stateful Packet Processing in Hardware", NSDI 2019
https://www.usenix.org/system/files/nsdi19spring_pontarelli_prepub.pdf

## Installation

I tested these code with Linux 5.0 and FreeBSD 13-CURRENT

### Compile

1. Install and load [netmap](https://github.com/luigirizzo/netmap) in either FreeBSD or
   Linux. If you use Linux, export several functions by editing
LINUX/netmap_linux.c:
```
 EXPORT_SYMBOL(netmap_vale_attach);
 EXPORT_SYMBOL(netmap_vale_detach);
+EXPORT_SYMBOL(netmap_vale_list);
 EXPORT_SYMBOL(nm_vi_create);
 EXPORT_SYMBOL(nm_vi_destroy);
```
I will obviate this step by fixing the netmap repository ASAP.

Also, compile `netmap/apps/vale-ctl` and export the path to the executable.

2. (Linux) Assuming kernel source at /root/src and netmap source at /root/netmap,
```
cd opp/LINUX
make KSRC=/root/src NSRC=/root/netmap # this produces opp kernel module
cd ..
make NSRC=/root/netmap # compile oppctl. For FreeBSD, use gmake
```

2. (FreeBSD)
```
cd opp/sys/contrib/opp
make clean; make
```

### Load

```
vale-ctl -n vi0
vale-ctl -n vi1
vale-ctl -a valeo:vi0
vale-ctl -a valeo:vi1

# Linux
cd opp/LINUX
insmod ./opp_lin.ko

# FreeBSD
cd opp/sys/contrib/opp
kldload ./opp.ko
```

### Run

A following example applies long flow detection
for a UDP flow between 10.0.0.1:50000 and 10.0.0.2:60000
```
cd opp
./oppctl 1 10.0.0.1 50000 10.0.0.2 60000 udp # use 2 for the first argument for
remove
pkt-gen -i vi0
(in another terminal)
pkt-gen -i vi1 -f tx -s 10.0.0.1:50000 -d 10.0.0.2:60000
(stop them just with ctrl+c)
```

### Unload

```
# Linux
rmmod opp_lin
# FreeBSD
kldunload opp

vale-ctl -d valeo:vi1
vale-ctl -d valeo:vi0
vale-ctl -r vi1
vale-ctl -r vi0
```
### Author and contact

Michio Honda (micchie AT sfc DOT wide DOT ad DOT ad DOT jp, or Tweet to @michioh)
