/*
 *  BSD LICENSE
 *
 * Copyright(c) 2015 NEC Europe Ltd. All rights reserved.
 *  All rights reserved.
 * Author: Michio Honda
 *
 * Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *    * Neither the name of NEC Europe Ltd. nor the names of
 *      its contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined(__FreeBSD__)
#include <sys/cdefs.h> /* prerequisite */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>   /* cdevsw struct */
#include <sys/module.h>
#include <sys/conf.h>

/* to compile netmap_kern.h */
#include <sys/malloc.h>
#include <machine/bus.h>
#include <sys/socket.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/sockio.h> /* XXX _IOWR. Should we use ioccom.h ? */
#include <sys/proc.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <netinet/in.h> /* struct in_addr in ip.h */
#include <netinet/in_pcb.h> /* struct inpcb */
#include <netinet/ip.h> /* struct ip */
#include <netinet/ip6.h> /* struct ip6 */
#include <netinet6/in6_var.h> /* in6_sprintf */
#include <netinet/tcp_var.h> /* V_tcbinfo */
/* For debug */
#include <net/if_arp.h>
#include <netinet/tcp.h> /* struct tcp_hdr */

/* For opp_pcb_clash() */
#include "opt_inet6.h"
#include "opt_sctp.h"
#include <sys/protosw.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#ifdef SCTP
#include <netinet/sctp_pcb.h>
#endif /* SCTP */
#ifdef INET6
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6protosw.h>
#endif
extern struct protosw inetsw[];
#define WITH_VALE

#define OPP_RWLOCK_T	struct rwlock
#define	OPP_RWINIT(_lock, _m)	rw_init(_lock, _m)
#define OPP_WLOCK()	rw_wlock(&opp_global.lock)
#define OPP_WUNLOCK()	rw_wunlock(&opp_global.lock)
#define OPP_RLOCK()	rw_rlock(&opp_global.lock)
#define OPP_RUNLOCK()	rw_runlock(&opp_global.lock)

#define OPP_LIST_INIT(_head)	LIST_INIT(_head)
#define OPP_LIST_ENTRY(_type)	LIST_ENTRY(_type)
#define OPP_LIST_ADD(_head, _n, _pos) 	LIST_INSERT_HEAD(_head, _n, _pos)
#define OPP_LIST_DEL(_n, _pos)		LIST_REMOVE(_n, _pos)
LIST_HEAD(opp_flowlist, opp_flow_key);
#define OPP_LIST_FOREACH	LIST_FOREACH
#define OPP_LIST_FOREACH_SAFE	LIST_FOREACH_SAFE
#define OPP_FLOW_LIST	struct opp_flowlist

#define OPP_GET_VAR(lval)	(lval)
#define OPP_SET_VAR(lval, p)	((lval) = (p))

#define MODULE_GLOBAL(__SYMBOL) V_##__SYMBOL
#elif defined (linux)

#include <bsd_glue.h> /* from netmap-release */
#include <bsd_glue_opp.h>
#endif /* linux */

/* Common headers */
#include <net/opp.h>
#include <contrib/opp/opp_kern.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h> /* XXX Provide path in Makefile */
#include <dev/netmap/netmap_bdg.h> /* XXX Provide path in Makefile */

static inline void
ip_sprintf(char *buf, const struct in_addr *addr)
{
	const uint8_t *p = (const uint8_t *)addr;
	sprintf(buf, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

/*
 * Packet metadata
 */
struct opp_ptrs {
	uint8_t *eh; // out of hash
	uint8_t *nh; // out of hash
	uint32_t *saddr;
	uint32_t *daddr;
	uint16_t *sport;
	uint16_t *dport;
	uint8_t *proto;
	uint8_t addrlen;
	uint16_t in_port; // out of hash
	/* some hole here */
};

/*
 * Packet parser
 */

/* from tcp_lro.c iph->ip_sum = 0xffff ^ do_csum_data(...) */
static inline uint16_t
ipv4_csum(uint16_t *raw, int len)
{
	uint32_t csum;
	csum = 0;
	while (len > 0) {
		csum += *raw;
		raw++;
		csum += *raw;
		raw++;
		len -= 4;
	}
	csum = (csum >> 16) + (csum & 0xffff);
	csum = (csum >> 16) + (csum & 0xffff);
	return (uint16_t)csum;
}

static int
opp_pkt2ptrs(uint8_t *buf, u_int in_port, struct opp_ptrs *ptrs)
{
	uint16_t et;

	ptrs->eh = buf;
	et = ntohs(*((uint16_t *)(buf + ETHER_ADDR_LEN * 2)));
	if (et == ETHERTYPE_IP) {
		struct nm_iphdr *iph = (struct nm_iphdr *)(buf + ETHER_HDR_LEN);
		uint16_t sum;

		sum = iph->check;
		iph->check = 0;
		if (unlikely(sum !=
		    (0xffff ^ ipv4_csum((uint16_t *)iph, sizeof(*iph))))) {
			/* Ignore bad checksum to cope with pkt-gen ;) */
			iph->check = sum;
			nm_prdis("wrong checksum!");
			//return -1;
		}
		iph->check = sum;
		ptrs->proto = (uint8_t *)&iph->protocol;
		ptrs->saddr = (uint32_t *)&iph->saddr;
		ptrs->daddr = (uint32_t *)&iph->daddr;
		ptrs->sport = (uint16_t *)
			((uint8_t *)iph + ((iph->version_ihl & 0xf) << 2));
		ptrs->dport = ptrs->sport + 1;
		ptrs->addrlen = 4;
		ptrs->nh = (uint8_t *)iph;
	} else if (et == ETHERTYPE_IPV6) {
		struct nm_ipv6hdr *ip6 = (struct nm_ipv6hdr *)
			(buf + ETHER_HDR_LEN);

		ptrs->proto = (uint8_t *)&ip6->nexthdr;
		ptrs->saddr = (uint32_t *)ip6->saddr;
		ptrs->daddr = (uint32_t *)ip6->daddr;
		ptrs->sport = (uint16_t *)
			((uint8_t *)ip6 + sizeof(*ip6));
		ptrs->dport = ptrs->sport + 1;
		ptrs->addrlen = 4;
		ptrs->nh = (uint8_t *)ip6;
	} else {
		nm_prinf("unsupported protocol (0x%x)", et);
		return -1;
	}
	ptrs->in_port = in_port;
	return 0;
}

/*
 * This software board has relatively small number of small registers
 */
#define OPP_XFSM_TABLE_ROW	65536
#define OPP_FLOWHASHSIZ	16384
#define OPP_FLOW_REGISTERS	32
#define OPP_GLOBAL_REGISTERS	32
#define OPP_GREG_TIME	(OPP_GLOBAL_REGISTERS-1)
typedef uint8_t		opp_conds_t;
typedef uint8_t		opp_state_t;
typedef uint32_t	opp_rgstr_t;
#define OPP_UPDATE_FUNCTIONS	8
#define OPP_ACTIONS		8
enum opp_actions {OPP_DROP=0, OPP_PASS, OPP_SETTOS};

static inline opp_rgstr_t
opp_microtime(void)
{
	struct timeval tv;

	microtime(&tv);
	return (opp_rgstr_t) (tv.tv_sec & 0xffff) * 1000000 + tv.tv_usec;
}

/*
 * Flow Key XXX ethernet addresses and 5 tuple only
 */
struct opp_flow_key {
	OPP_LIST_ENTRY(opp_flow_key) next;
	u_int bdg_port; /* originated port, only for management */
	struct timeval start;

	/* below are defined by the programmer */
	struct ether_header ether;
	struct {
		union {
			in_addr_t ipv4;
			in6_addr_t ipv6;
		};
		uint16_t port;
	} src;
	struct {
		union {
			in_addr_t ipv4;
			in6_addr_t ipv6;
		};
		uint16_t port;
	} dst;
	uint8_t transport;

	opp_state_t state;
	opp_rgstr_t registers[OPP_FLOW_REGISTERS];
};

/*
 * Condition block building blocks
 */
#define BOOLCIRC(a, b, CMP)	((a) CMP (b))
typedef opp_conds_t (*opp_condition_block_t)(const struct opp_ptrs *ptrs,
					  opp_state_t state,
					  const opp_rgstr_t *registers);

/*
 * Register manipuration for update logic block
 */
static void
opp_reg_inc(opp_rgstr_t *reg)
{
	*reg = *reg + 1;
}

static void
opp_reg_set(opp_rgstr_t *reg, opp_rgstr_t val)
{
	*reg = val;
}

/*
 * Common prototype for update functions
 */
typedef void (*opp_update_fn_t)(struct opp_ptrs *, struct opp_flow_key *,
		opp_state_t);

/*
 * The XFSM table
 */
struct opp_xfsm_table {
	uint16_t match; /* state | c */
	opp_state_t next_state;
	opp_update_fn_t update_fns[OPP_UPDATE_FUNCTIONS];
	enum opp_actions actions[OPP_ACTIONS]; // in-order evaluation
};

/*
 * Execute actions and update logic block
 */
static void
opp_execute_actions(struct opp_ptrs *ptrs, struct opp_xfsm_table *x,
			struct opp_flow_key *fk)
{
	int i;
	int ret = OPP_DROP;

	for (i = 0; i < OPP_ACTIONS && x->actions[i]; i++) {
		switch (x->actions[i])
		{
		case OPP_SETTOS:
			{
			struct nm_iphdr *iph = (struct nm_iphdr *)ptrs->nh;

			iph->tos |= 0xfc;
			iph->check = 0;
			iph->check = (0xffff ^
				ipv4_csum((uint16_t *)iph, sizeof(*iph)));
			}
			break;
		case OPP_DROP:
			ret = OPP_DROP;
			break;
		case OPP_PASS:
			ret = OPP_PASS;
			break;
		}
	}
}

static void
opp_update_logic_block(struct opp_ptrs *ptrs, struct opp_xfsm_table *x,
			struct opp_flow_key *fk)
{
	int i;

	for (i = 0; i < OPP_UPDATE_FUNCTIONS && x->update_fns[i]; i++) {
		x->update_fns[i](ptrs, fk, x->next_state);
	}
}

/*
 * Gloal instance
 */
static struct opp_global {
	OPP_FLOW_LIST flowlist[OPP_FLOWHASHSIZ];
	OPP_RWLOCK_T	lock;
	int num_fks;
	uint32_t registers[OPP_GLOBAL_REGISTERS]; /* threshold */
	struct opp_xfsm_table *xfsm_table;
	opp_condition_block_t condition_block;
} opp_global;

/*
 * Flow Key routines
 */

/* taken from netmap implementation */
#define mix(a, b, c)                                                    \
do {                                                                    \
        a -= b; a -= c; a ^= (c >> 13);                                 \
        b -= c; b -= a; b ^= (a << 8);                                  \
        c -= a; c -= b; c ^= (b >> 13);                                 \
        a -= b; a -= c; a ^= (c >> 12);                                 \
        b -= c; b -= a; b ^= (a << 16);                                 \
        c -= a; c -= b; c ^= (b >> 5);                                  \
        a -= b; a -= c; a ^= (c >> 3);                                  \
        b -= c; b -= a; b ^= (a << 10);                                 \
        c -= a; c -= b; c ^= (b >> 15);                                 \
} while (/*CONSTCOND*/0)

static inline uint32_t
opp_rthash(struct opp_ptrs *ptrs)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key
	uint8_t *p;

	b += *ptrs->proto;

	p = (uint8_t *)ptrs->sport;
	b += p[1] << 16;
	b += p[0] << 8;
	p = (uint8_t *)ptrs->dport;
	b += p[1] << 16;
	b += p[0] << 8;

	p = (uint8_t *)ptrs->saddr + ptrs->addrlen - 4;
	b += p[3];
	a += p[2] << 24;
	a += p[1] << 16;
	a += p[0] << 8;
	p = (uint8_t *)ptrs->daddr + ptrs->addrlen - 4;
	b += p[3];
	a += p[2] << 24;
	a += p[1] << 16;
	a += p[0] << 8;

	mix(a, b, c);
#define OPP_FLOW_RTHASH_MASK	(OPP_FLOWHASHSIZ-1)
	return (c & OPP_FLOW_RTHASH_MASK);
}
#undef mix

static int inline
opp_fk2ptrs(struct opp_flow_key *fk, struct opp_ptrs *ptrs)
{
	if (fk->ether.ether_type == ETHERTYPE_IP)
		ptrs->addrlen = 4;
	else if (fk->ether.ether_type == ETHERTYPE_IPV6)
		ptrs->addrlen = 16;
	else {
		nm_prinf("unsupported ether type 0x%x", fk->ether.ether_type);
		return -1;
	}
	ptrs->saddr = &fk->src.ipv4;
	ptrs->daddr = &fk->dst.ipv4;
	ptrs->sport = &fk->src.port;
	ptrs->dport = &fk->dst.port;
	ptrs->proto = &fk->transport;
	ptrs->in_port = fk->bdg_port;
	return 0;
}

static void
opp_ptrs2str(const struct opp_ptrs *ptrs, char *dst)
{
	char saddr[64], daddr[64];

	bzero(saddr, sizeof(saddr));
	bzero(daddr, sizeof(daddr));

	if (ptrs->addrlen == 4) {
		ip_sprintf(saddr, (const struct in_addr *)ptrs->saddr);
		ip_sprintf(daddr, (const struct in_addr *)ptrs->daddr);
	} else if (ptrs->addrlen == 16) {
		ip6_sprintf(saddr, (const struct in6_addr *)ptrs->saddr);
		ip6_sprintf(daddr, (const struct in6_addr *)ptrs->daddr);
	}
	sprintf(dst, "bdgport %u %s:%u<->%s:%u %u",
		ptrs->in_port, saddr,
		ntohs(*ptrs->sport), daddr, ntohs(*ptrs->dport), *ptrs->proto);
}	

static void
opp_fk2str(struct opp_flow_key *fk, char *dst)
{
	struct opp_ptrs ptrs;

	if (opp_fk2ptrs(fk, &ptrs))
		return;
	return opp_ptrs2str(&ptrs, dst);
}


static __inline int
opp_flow_match(struct opp_flow_key *k, struct opp_ptrs *p)
{
	int alen = p->addrlen;

	return ((alen == 4 && k->ether.ether_type == ETHERTYPE_IP) ||
		    (alen == 16 && k->ether.ether_type == ETHERTYPE_IPV6)) &&
		(*p->proto == k->transport) &&
		((*p->sport == k->src.port && *p->dport == k->dst.port) ||
		     (*p->sport == k->dst.port && *p->dport == k->src.port)) &&
		((!memcmp(p->saddr, &k->src.ipv4, alen) && 
		     !memcmp(p->daddr, &k->dst.ipv4, p->addrlen)) ||
		(!memcmp(p->saddr, &k->dst.ipv4, p->addrlen) && 
		    !memcmp(p->daddr, &k->src.ipv4, p->addrlen)));
}

/* writer-lock must be owned */
static void
opp_flow_key_free(struct opp_flow_key *fk)
{
	char buf[128];

	opp_fk2str(fk, buf);
	nm_prinf("%s", buf);

	OPP_LIST_DEL(fk, next);
	fk = NULL; // just for the case
	opp_os_free(fk);
	--opp_global.num_fks;
}

static struct opp_flow_key *
opp_flow_key_lookup(uint8_t *buf, struct opp_ptrs *p)
{
	struct opp_flow_key *fk = NULL;
	OPP_FLOW_LIST *head;

	OPP_RLOCK();
	/* Reverse flows are in the same bucket */
	head = &opp_global.flowlist[opp_rthash(p)];
	OPP_LIST_FOREACH(fk, head, next) {
		if (opp_flow_match(fk, p)) {
			nm_prlim(1, "match fk %p", fk);
			break;
		}
	}
	OPP_RUNLOCK();
	return fk;
}

/* We assume no identical key in the table */
static struct opp_flow_key *
opp_flow_key_alloc(struct opp_ptrs *ptrs)
{
	struct opp_flow_key *fk;

	fk = opp_os_malloc(sizeof(*fk));
	if (!fk)
		return NULL;
	bzero(fk, sizeof(*fk));
	fk->ether.ether_type = 
		ptrs->addrlen == 4 ? ETHERTYPE_IP : ETHERTYPE_IPV6;
	memcpy(&fk->src.ipv4, ptrs->saddr, ptrs->addrlen);
	memcpy(&fk->dst.ipv4, ptrs->daddr, ptrs->addrlen);
	fk->src.port = *ptrs->sport;
	fk->dst.port = *ptrs->dport;
	fk->transport = *ptrs->proto;
	fk->bdg_port = ptrs->in_port;
	return fk;
}

/*
 * Lookup function registered to mSwitch
 * We assume a bridge with OPP_NAME is already created
 */

static u_int
opp_lookup(struct nm_bdg_fwd *ft, uint8_t *ring_nr,
	struct netmap_vp_adapter *na, void *private_data)
{
	struct opp_flow_key *fk;
	struct opp_ptrs ptrs;
	opp_conds_t c;
	struct opp_xfsm_table *x;
	uint16_t i;

	// emulate dumb module
	//return netmap_bdg_idx(na) == 1 ? 2 : netmap_bdg_idx(na) == 2 ? 1 : NM_BDG_BROADCAST;
	/* Save the current time */
	opp_global.registers[OPP_GREG_TIME] = opp_microtime();

	if (opp_pkt2ptrs(ft->ft_buf, netmap_bdg_idx(na), &ptrs) < 0) {
		nm_prinf("failed to get ptrs");
		goto out;
	}

	fk = opp_flow_key_lookup(ft->ft_buf, &ptrs);
	/* fk is updated by update logic block */
	if (!fk) {
		char d[128];

		opp_ptrs2str(&ptrs, d);
		nm_prlim(1, "not found for %s", d);
		goto out;
	}
	c = opp_global.condition_block(&ptrs, fk->state, fk->registers);
	i = ((uint16_t)fk->state << 8) | c;
	x = opp_global.xfsm_table + i;
	nm_prdis("xfsm 0x%x", x->match);
	opp_execute_actions(&ptrs, x, fk);
	opp_update_logic_block(&ptrs, x, fk);
out:
	/* We use default learning bridge for routing decision */
	//return netmap_bdg_learning(ft, ring_nr, na);
	/* We assume packets are passed between port 1 and 2, and port 0
	 * is a management port (persistent virtual port)
	 */
	return ptrs.in_port == 1 ? 2 : ptrs.in_port == 2 ? 1 : NM_BDG_BROADCAST;
}

static void
opp_dtor(const struct netmap_vp_adapter *vpna)
{
	return;
}

/*
 * CLI
 */
static int
opp_config(struct nm_ifreq *data)
{
	struct oppreq *opr = (struct oppreq *)data;
	struct nmreq nmr;
	struct opp_flow_key *fk = NULL, *tmp;
	struct opp_ptrs ptrs;
	OPP_FLOW_LIST	*head;
	int error = 0, me;
	char dbgbuf[64]; /* just for debug message */

	struct nmreq_header hdr;
	struct nmreq_vale_list req;


	if (opr->or_cmd != OPP_ADD && opr->or_cmd != OPP_DEL)
		return EINVAL;

	bzero(&hdr, sizeof(hdr));
	bzero(&req, sizeof(req));
	strncpy(hdr.nr_name, opr->or_name, sizeof(hdr.nr_name));
	hdr.nr_body = (uintptr_t)&req;
	error = netmap_vale_list(&hdr);
	if (error) { /* invalid request of interface or bridge */
		nm_prinf("%s is not in the bridge", nmr.nr_name);
		return error;
	}
	me = req.nr_bridge_idx;
	/* get pointers to paramters */
	if (opr->or_family == AF_INET)
	       ptrs.addrlen = 4;
	else if (opr->or_family == AF_INET6)
	       ptrs.addrlen = 16;
	else {
		nm_prinf("invalid family %u", opr->or_family);
		return EINVAL;
	}
	ptrs.proto = &opr->or_transport;
	ptrs.saddr = &opr->or_src4.sin_addr.s_addr;
	ptrs.daddr = &opr->or_dst4.sin_addr.s_addr;
	ptrs.sport = &opr->or_src4.sin_port;
	ptrs.dport = &opr->or_dst4.sin_port;
	ptrs.in_port = me;
	OPP_WLOCK();

	/* Find an existing entry */
	head = &opp_global.flowlist[opp_rthash(&ptrs)];
	OPP_LIST_FOREACH(tmp, head, next) {
		if (opp_flow_match(tmp, &ptrs)) {
			fk = tmp;
			break;
		}
	}
	if (opr->or_cmd == OPP_DEL) {
		if (!fk) {
			nm_prinf("DEL: not registered");
			error = ENOENT;
			goto out_unlock;
		}
		opp_flow_key_free(fk);
	} else { /* OPP_ADD */
		if (fk) {
			nm_prinf("ADD: already registered");
			error = EBUSY;
			goto out_unlock;
		}
		fk = opp_flow_key_alloc(&ptrs);
		if (!fk) {
			error = ENOMEM;
			goto out_unlock;
		}
		OPP_LIST_ADD(head, fk, next);
		++opp_global.num_fks;
		opp_fk2str(fk, dbgbuf);
		nm_prinf("%s to bucket %u (total %u fks)",
			       	dbgbuf, opp_rthash(&ptrs), opp_global.num_fks);
	}
out_unlock:
	OPP_WUNLOCK();
	return (error);
}
static struct netmap_bdg_ops opp_ops = {opp_lookup, opp_config, opp_dtor};

/*
 * Initialize with the long flow differenciator TODO: do more modular
 */
static void opp_longflow_init(struct opp_global *);

/*
 * On kernel module load
 */
int
opp_init(void)
{
	int i;

	if (netmap_bdg_regops(OPP_BDG_NAME, &opp_ops, NULL, NULL)) {
		nm_prinf("no bridge named %s", OPP_BDG_NAME);
		return ENOENT;
	}


	bzero(&opp_global, sizeof(opp_global));
	OPP_RWINIT(&opp_global.lock, "opp lock");
	for (i = 0; i < OPP_FLOWHASHSIZ; i++)
		OPP_LIST_INIT(&opp_global.flowlist[i]);

	/* XFSM table is static. We use vmalloc() as this is potentially large
	 */
	opp_global.xfsm_table = opp_os_vmalloc(sizeof(struct opp_xfsm_table) *
			OPP_XFSM_TABLE_ROW);
	if (!opp_global.xfsm_table) {
		nm_prinf("failed to allocate %lu MB of xfsm table", OPP_XFSM_TABLE_ROW 
				* sizeof(struct opp_xfsm_table));
		return ENOMEM;
	}
	bzero(opp_global.xfsm_table,
			sizeof(*opp_global.xfsm_table) * OPP_XFSM_TABLE_ROW);

	/* Programmer-provided components */
	opp_longflow_init(&opp_global);

	nm_prinf("OPP: loaded module");
	return 0;
}

/*
 * On kernel module unload
 */
void
opp_fini(void)
{
	int error;
	int i;

	OPP_WLOCK();
	for (i = 0; i < OPP_FLOWHASHSIZ; i++) {
		OPP_FLOW_LIST *head = &opp_global.flowlist[i];
		struct opp_flow_key *fk, *tmp = NULL;
#if defined (linux)
		(void)tmp;
#endif /* linux */
		OPP_LIST_FOREACH_SAFE(fk, head, next, tmp) {
			opp_flow_key_free(fk);
		}
	}
	OPP_WUNLOCK();

	error = netmap_bdg_regops(OPP_BDG_NAME, NULL, NULL, NULL);
	if (error)
		nm_prinf("failed to release a bridge %d", error);

	opp_os_vfree(opp_global.xfsm_table);

	nm_prinf("OPP: Unloaded module");
}

/*
 * OS-specific loader/unloader
 */
#ifdef __FreeBSD__

void *
opp_os_malloc(size_t size)
{
        return malloc(size, M_DEVBUF, M_NOWAIT | M_ZERO);
}

void
opp_os_free(void *addr)
{
	free(addr, M_DEVBUF);
}

void *
opp_os_vmalloc(size_t size)
{
        return malloc(size, M_DEVBUF, M_NOWAIT | M_ZERO);
}

void
opp_os_vfree(void *addr)
{
	free(addr, M_DEVBUF);
}

static int
opp_loader(module_t mod, int type, void *data)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		error = opp_init();
		break;
	case MOD_UNLOAD:
		opp_fini();
		break;
	default:
		error = EINVAL;
		break;
	}
	return error;
}

DEV_MODULE(opp, opp_loader, NULL);
#endif /* __FreeBSD__ */


/*
 * Long Flow differentiator implementation
 */

/*
 * Condition block
 */

#define OPP_LF_FREG_COUNT	1
#define OPP_LF_FREG_TIMEO	0
#define OPP_LF_GREG_COUNT	1	// threshold
#define OPP_LF_GREG_TIMEO 	0
#define OPP_LF_STATE_SHORT	0
#define OPP_LF_STATE_LONG	1

/* opp_condition_block_t */
static opp_conds_t
opp_longflow_cb(const struct opp_ptrs *ptrs, opp_state_t state,
		const opp_rgstr_t *registers)
{
	opp_conds_t c = 0;

	/* We have two conditions: count and time */
	c |= BOOLCIRC(registers[OPP_LF_FREG_COUNT],
		       	opp_global.registers[OPP_LF_GREG_COUNT], >) <<
			OPP_LF_FREG_COUNT;
	c |= BOOLCIRC(registers[OPP_LF_FREG_TIMEO],
			opp_global.registers[OPP_GREG_TIME], <) <<
			OPP_LF_FREG_TIMEO;
	return c;
}

/*
 * update functions (opp_update_fn_t)
 */
static void
opp_longflow_add_count(struct opp_ptrs *ptrs, struct opp_flow_key *fk,
		opp_state_t next)
{
	opp_reg_inc(&fk->registers[OPP_LF_FREG_COUNT]);
}

static void
opp_longflow_clr_count(struct opp_ptrs *ptrs, struct opp_flow_key *fk,
		opp_state_t next)
{
	opp_reg_set(&fk->registers[OPP_LF_FREG_COUNT], 0);
}

static void
opp_longflow_update_to(struct opp_ptrs *ptrs, struct opp_flow_key *fk,
		opp_state_t next)
{
	opp_reg_set(&fk->registers[OPP_LF_FREG_TIMEO],
			opp_global.registers[OPP_GREG_TIME] + 
			opp_global.registers[OPP_LF_GREG_TIMEO]);
}

/* ==== XFSM TABLE BLUEPRINT FOR LONG FLOW DIFFERENCIATOR ====
          action      drop:0      pass:1   set_tos:2
        updatefn  updateto:0 add_count:1 clr_count:2
 
	state count timeout	nstate action updatefn
	0     0     0 		0      1      0,1
	0     0     1		0      1      0,2
	0     1     0 		1      1,2    0
	0     1     1		0      1      0,2,1
	1     0     0 		1      1,2    0        // impossible
	1     0     1		0      1      0,2,1    // impossible
	1     1     0 		1      1,2    0
	1     1     1		0      1      0,2,1
  ============================================================*/

static void
opp_longflow_init(struct opp_global *g)
{
	struct opp_xfsm_table *xt = (struct opp_xfsm_table *)g->xfsm_table;

	/*
	 * Condition block
	 */
	g->condition_block = opp_longflow_cb;

	/*
	 * Global registers
	 */
	g->registers[OPP_LF_GREG_TIMEO]	= 10000000; // expire us
	g->registers[OPP_LF_GREG_COUNT]	= 10;

	/*
	 * XFSM table
	 */
	/* short flow and R0 < G0 and R1 < G2 */
	xt->match = 0x0;
	xt->next_state = OPP_LF_STATE_SHORT;
	xt->actions[0] = OPP_PASS;
	xt->update_fns[0] = opp_longflow_update_to;
	xt->update_fns[1] = opp_longflow_add_count;
	xt++;

	xt->match = 0x1;
	xt->next_state = OPP_LF_STATE_SHORT;
	xt->actions[0] = OPP_PASS;
	xt->update_fns[0] = opp_longflow_update_to;
	xt->update_fns[1] = opp_longflow_clr_count;
	xt++;

	xt->match = 0x2;
	xt->next_state = OPP_LF_STATE_LONG;
	xt->actions[0] = OPP_PASS;
	xt->actions[1] = OPP_SETTOS;
	xt->update_fns[0] = opp_longflow_update_to;
	xt++;

	xt->match = 0x3;
	xt->next_state = OPP_LF_STATE_SHORT;
	xt->actions[0] = OPP_PASS;
	xt->update_fns[0] = opp_longflow_update_to;
	xt->update_fns[1] = opp_longflow_clr_count;
	xt->update_fns[2] = opp_longflow_add_count;
	xt++;

	xt->match = 0x4;
	xt->next_state = OPP_LF_STATE_LONG;
	xt->actions[0] = OPP_PASS;
	xt->actions[1] = OPP_SETTOS;
	xt->update_fns[0] = opp_longflow_update_to;
	xt++;

	xt->match = 0x5;
	xt->next_state = OPP_LF_STATE_SHORT;
	xt->actions[0] = OPP_PASS;
	xt->update_fns[0] = opp_longflow_update_to;
	xt->update_fns[1] = opp_longflow_clr_count;
	xt->update_fns[2] = opp_longflow_add_count;
	xt++;

	xt->match = 0x6;
	xt->next_state = OPP_LF_STATE_LONG;
	xt->actions[0] = OPP_PASS;
	xt->actions[1] = OPP_SETTOS;
	xt->update_fns[0] = opp_longflow_update_to;
	xt++;

	xt->match = 0x7;
	xt->next_state = OPP_LF_STATE_SHORT;
	xt->actions[0] = OPP_PASS;
	xt->update_fns[0] = opp_longflow_update_to;
	xt->update_fns[1] = opp_longflow_clr_count;
	xt->update_fns[2] = opp_longflow_add_count;
}
