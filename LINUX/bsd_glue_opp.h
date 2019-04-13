#ifndef _BSD_GLUE_MULTISTACK_H
#define _BSD_GLUE_MULTISTACK_H

#define OPP_RWLOCK_T	spinlock_t
#define	OPP_RWINIT(_lock, _m)	spin_lock_init(_lock)
#define OPP_WLOCK()	do {\
	spin_lock(&opp_global.lock); rcu_read_lock(); } while (0)
#define OPP_WUNLOCK()	do {\
	rcu_read_unlock(); spin_unlock(&opp_global.lock); } while (0)
#define OPP_RLOCK(_m)	rcu_read_lock()
#define OPP_RUNLOCK(_m)	rcu_read_unlock()

#define OPP_LIST_INIT(_head)	INIT_HLIST_HEAD(_head)
#define OPP_LIST_ENTRY(_type)	struct hlist_node
#define OPP_LIST_ADD(_head, _n, _pos) 	hlist_add_head_rcu(&((_n)->_pos), _head)
#define OPP_LIST_DEL(_n, _pos)	hlist_del_init_rcu(&((_n)->_pos))
#define OPP_LIST_FOREACH(_n, _head, _pos)		hlist_for_each_entry_rcu(_n, _head, _pos)
#define OPP_LIST_FOREACH_SAFE(_n, _head, _pos, _tvar)	hlist_for_each_entry_rcu(_n, _head, _pos)
#define OPP_FLOW_LIST	struct hlist_head

#define OPP_GET_VAR(lval)	rcu_dereference((lval))
#define OPP_SET_VAR(lval, p)	rcu_assign_pointer((lval), (p))

#define INET6_ADDRSTRLEN 46

typedef uint32_t tcp_seq;

/* IPv6 address presentation (taken from FreeBSD) */

#define satosin(sa)	((struct sockaddr_in *)(sa))
#define satosin6(sa)	((struct sockaddr_in6 *)(sa))
#define IN6_ARE_ADDR_EQUAL(a, b) ipv6_addr_equal(a, b)
#define ETHER_HDR_LEN	ETH_HLEN

#define	ETHER_ADDR_LEN		6

char *ip6_sprintf(char *, const struct in6_addr *);
/* From ethernet.h */
struct	ether_header {
	u_char	ether_dhost[ETHER_ADDR_LEN];
	u_char	ether_shost[ETHER_ADDR_LEN];
	u_short	ether_type;
};
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define ETHERTYPE_IPV6		0x86dd	/* IPv6 */

typedef uint32_t in_addr_t;
typedef struct in6_addr in6_addr_t;
#define	timercmp(a, b, CMP) \
		(((a)->tv_sec == (b)->tv_sec) ? \
		((a)->tv_usec CMP (b)->tv_usec) : \
		((a)->tv_sec CMP (b)->tv_sec))
#endif
