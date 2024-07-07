//
// Created by zhf on 24-4-5.
//
#include <linux/net.h>
#include <linux/inetdevice.h>
#include <linux/rcupdate.h>
#include "headers/support_tools.h"
#include "headers/ip_route_output_flow_without_cache.h"

static DEFINE_PER_CPU(struct rt_cache_stat, rt_cache_stat);
#define RT_FL_TOS(oldflp4) \
	((oldflp4)->flowi4_tos & (IPTOS_RT_MASK | RTO_ONLINK))
#define RT_CACHE_STAT_INC(field) raw_cpu_inc(rt_cache_stat.field)
#ifdef CONFIG_IP_ROUTE_CLASSID
static void set_class_tag(struct rtable *rt, u32 tag)
{
    if (!(rt->dst.tclassid & 0xFFFF))
        rt->dst.tclassid |= tag & 0xFFFF;
    if (!(rt->dst.tclassid & 0xFFFF0000))
        rt->dst.tclassid |= tag & 0xFFFF0000;
}
#endif

asmlinkage struct rtable *(*orig_ip_route_output_flow)(struct net *, struct flowi4 *flp, const struct sock *sk);
asmlinkage struct net_device *(*orig__ip_dev_find)(struct net *net, __be32 addr, bool devref);
asmlinkage __be32 (*orig_inet_select_addr)(const struct net_device *dev, __be32 dst, int scope);
asmlinkage int (*orig_ip_check_mc_rcu)(struct in_device *in_dev, __be32 mc_addr, __be32 src_addr, u8 proto);
asmlinkage void (*orig_fib_select_path)(struct net *net, struct fib_result *res,
                                struct flowi4 *fl4, const struct sk_buff *skb);
asmlinkage int (*orig_ip_mc_output)(struct net *net, struct sock *sk, struct sk_buff *skb);
asmlinkage int (*orig_ip_mr_input)(struct sk_buff *skb);
asmlinkage void (*orig_rt_add_uncached_list)(struct rtable *rt);

void resolve_ip_route_output_flow_inner_function_address(void){
    LOG_WITH_EDGE("start to resolve ip_route_output_flow inner function addres");
    orig__ip_dev_find = get_function_address("__ip_dev_find");
    LOG_RESOLVED(orig__ip_dev_find, "__ip_dev_find");
    orig_inet_select_addr = get_function_address("inet_select_addr");
    LOG_RESOLVED(orig_inet_select_addr, "inet_select_addr");
    orig_ip_check_mc_rcu = get_function_address("ip_check_mc_rcu");
    LOG_RESOLVED(orig_ip_check_mc_rcu, "ip_check_mc_rcu");
    orig_ip_mc_output = get_function_address("ip_mc_output");
    LOG_RESOLVED(orig_ip_mc_output, "ip_mc_output");
    orig_fib_select_path = get_function_address("fib_select_path");
    LOG_RESOLVED(orig_fib_select_path, "fib_select_path");
    orig_ip_mr_input = get_function_address("ip_mr_input");
    LOG_RESOLVED(orig_ip_mr_input, "ip_mr_input");
    orig_ip_route_output_flow = get_function_address("ip_route_output_flow");
    LOG_RESOLVED(orig_ip_route_output_flow, "ip_route_output_flow");
    orig_rt_add_uncached_list = get_function_address("rt_add_uncached_list");
    LOG_RESOLVED(orig_rt_add_uncached_list, "rt_add_uncached_list");
    LOG_WITH_EDGE("end to resolve ip_route_output_flow inner function addres");
}



// ---------------------------------- static ----------------------------------
static DEFINE_SPINLOCK(fnhe_lock);


static inline bool rt_is_expired(const struct rtable *rth) {
    return rth->rt_genid != rt_genid_ipv4(dev_net(rth->dst.dev));
}

static bool rt_cache_valid(const struct rtable *rt) {
    return rt &&
           rt->dst.obsolete == DST_OBSOLETE_FORCE_CHK &&
           !rt_is_expired(rt);
}


static u32 fnhe_hashfun(__be32 daddr)
{
    static siphash_aligned_key_t fnhe_hash_key;
    u64 hval;
    net_get_random_once(&fnhe_hash_key, sizeof(fnhe_hash_key));
    hval = siphash_1u32((__force u32)daddr, &fnhe_hash_key);
    return hash_64(hval, FNHE_HASH_SHIFT);
}

static void fnhe_flush_routes(struct fib_nh_exception *fnhe)
{
    struct rtable *rt;

    rt = rcu_dereference(fnhe->fnhe_rth_input);
    if (rt) {
        RCU_INIT_POINTER(fnhe->fnhe_rth_input, NULL);
        dst_dev_put(&rt->dst);
        dst_release(&rt->dst);
    }
    rt = rcu_dereference(fnhe->fnhe_rth_output);
    if (rt) {
        RCU_INIT_POINTER(fnhe->fnhe_rth_output, NULL);
        dst_dev_put(&rt->dst);
        dst_release(&rt->dst);
    }
}

static void ip_del_fnhe(struct fib_nh_common *nhc, __be32 daddr)
{
    struct fnhe_hash_bucket *hash;
    struct fib_nh_exception *fnhe, __rcu **fnhe_p;
    u32 hval = fnhe_hashfun(daddr);

    spin_lock_bh(&fnhe_lock);

    hash = rcu_dereference_protected(nhc->nhc_exceptions,
                                     lockdep_is_held(&fnhe_lock));
    hash += hval;

    fnhe_p = &hash->chain;
    fnhe = rcu_dereference_protected(*fnhe_p, lockdep_is_held(&fnhe_lock));
    while (fnhe) {
        if (fnhe->fnhe_daddr == daddr) {
            rcu_assign_pointer(*fnhe_p, rcu_dereference_protected(
                    fnhe->fnhe_next, lockdep_is_held(&fnhe_lock)));
            /* set fnhe_daddr to 0 to ensure it won't bind with
             * new dsts in rt_bind_exception().
             */
            fnhe->fnhe_daddr = 0;
            fnhe_flush_routes(fnhe);
            kfree_rcu(fnhe, rcu);
            break;
        }
        fnhe_p = &fnhe->fnhe_next;
        fnhe = rcu_dereference_protected(fnhe->fnhe_next,
                                         lockdep_is_held(&fnhe_lock));
    }

    spin_unlock_bh(&fnhe_lock);
}

static struct fib_nh_exception *find_exception(struct fib_nh_common *nhc,
                                               __be32 daddr)
{
    struct fnhe_hash_bucket *hash = rcu_dereference(nhc->nhc_exceptions);
    struct fib_nh_exception *fnhe;
    u32 hval;

    if (!hash)
        return NULL;

    hval = fnhe_hashfun(daddr);

    for (fnhe = rcu_dereference(hash[hval].chain); fnhe;
         fnhe = rcu_dereference(fnhe->fnhe_next)) {
        if (fnhe->fnhe_daddr == daddr) {
            if (fnhe->fnhe_expires &&
                time_after(jiffies, fnhe->fnhe_expires)) {
                ip_del_fnhe(nhc, daddr);
                break;
            }
            return fnhe;
        }
    }
    return NULL;
}

static inline struct in_device *self_defined__in_dev_get_rcu(const struct net_device *dev)
{
    return rcu_dereference(dev->ip_ptr);
}

static inline struct rtable *self_defined__ip_route_output_key(struct net *net,
                                                   struct flowi4 *flp)
{
    return self_defined_ip_route_output_key_hash(net, flp, NULL);
}

static void ip_rt_fix_tos(struct flowi4 *fl4)
{
    __u8 tos = RT_FL_TOS(fl4);

    fl4->flowi4_tos = tos & IPTOS_RT_MASK;
    if (tos & RTO_ONLINK)
        fl4->flowi4_scope = RT_SCOPE_LINK;
}

// ---------------------------------- static ----------------------------------

asmlinkage struct rtable* hook_ip_route_output_flow(struct net * net, struct flowi4 *flp4, const struct sock *sk){
    struct rtable* result;
    // LOG_WITH_EDGE("ip_route_output_flow started");
    result =  self_defined_ip_route_output_flow(net, flp4, sk);
    // LOG_WITH_EDGE("ip_route_output_flow end");
    return result;
}

void add_ip_route_output_flow_to_hook(void){
    hooks[number_of_hook].name = "ip_route_output_flow";
    hooks[number_of_hook].function = hook_ip_route_output_flow;
    hooks[number_of_hook].original = &orig_ip_route_output_flow;
    number_of_hook += 1;
}

static void fill_route_from_fnhe(struct rtable *rt, struct fib_nh_exception *fnhe)
{
    rt->rt_pmtu = fnhe->fnhe_pmtu;
    rt->rt_mtu_locked = fnhe->fnhe_mtu_locked;
    rt->dst.expires = fnhe->fnhe_expires;

    if (fnhe->fnhe_gw) {
        rt->rt_flags |= RTCF_REDIRECTED;
        rt->rt_uses_gateway = 1;
        rt->rt_gw_family = AF_INET;
        rt->rt_gw4 = fnhe->fnhe_gw;
    }
}

static bool rt_bind_exception(struct rtable *rt, struct fib_nh_exception *fnhe,
                              __be32 daddr, const bool do_cache)
{
    bool ret = false;

    spin_lock_bh(&fnhe_lock);

    if (daddr == fnhe->fnhe_daddr) {
        struct rtable __rcu **porig;
        struct rtable *orig;
        int genid = fnhe_genid(dev_net(rt->dst.dev));

        if (rt_is_input_route(rt))
            porig = &fnhe->fnhe_rth_input;
        else
            porig = &fnhe->fnhe_rth_output;
        orig = rcu_dereference(*porig);

        if (fnhe->fnhe_genid != genid) {
            fnhe->fnhe_genid = genid;
            fnhe->fnhe_gw = 0;
            fnhe->fnhe_pmtu = 0;
            fnhe->fnhe_expires = 0;
            fnhe->fnhe_mtu_locked = false;
            fnhe_flush_routes(fnhe);
            orig = NULL;
        }
        fill_route_from_fnhe(rt, fnhe);
        if (!rt->rt_gw4) {
            rt->rt_gw4 = daddr;
            rt->rt_gw_family = AF_INET;
        }

        if (do_cache) {
            dst_hold(&rt->dst);
            rcu_assign_pointer(*porig, rt);
            if (orig) {
                dst_dev_put(&orig->dst);
                dst_release(&orig->dst);
            }
            ret = true;
        }

        fnhe->fnhe_stamp = jiffies;
    }
    spin_unlock_bh(&fnhe_lock);

    return ret;
}

static bool rt_cache_route(struct fib_nh_common *nhc, struct rtable *rt)
{
    struct rtable *orig, *prev, **p;
    bool ret = true;

    if (rt_is_input_route(rt)) {
        p = (struct rtable **)&nhc->nhc_rth_input;
//        LOG_WITH_PREFIX("nhc->nhc_rth_input"); // this line is never called
    } else {
        p = (struct rtable **)raw_cpu_ptr(nhc->nhc_pcpu_rth_output);
//        LOG_WITH_PREFIX("set nhc->nhc_pcpu_rth_output"); // this line is called
    }
    orig = *p;

    /* hold dst before doing cmpxchg() to avoid race condition
     * on this dst
     */
    dst_hold(&rt->dst);
    prev = cmpxchg(p, orig, rt);
    if (prev == orig) {
        if (orig) {
            orig_rt_add_uncached_list(orig);
            dst_release(&orig->dst);
        }
    } else {
        dst_release(&rt->dst);
        ret = false;
    }

    return ret;
}

static void rt_set_nexthop(struct rtable *rt, __be32 daddr,
                           const struct fib_result *res,
                           struct fib_nh_exception *fnhe,
                           struct fib_info *fi, u16 type, u32 itag,
                           const bool do_cache)
{
    bool cached = false;

    if (fi) {
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);

        if (nhc->nhc_gw_family && nhc->nhc_scope == RT_SCOPE_LINK) {
            rt->rt_uses_gateway = 1;
            rt->rt_gw_family = nhc->nhc_gw_family;
            /* only INET and INET6 are supported */
            if (likely(nhc->nhc_gw_family == AF_INET))
                rt->rt_gw4 = nhc->nhc_gw.ipv4;
            else
                rt->rt_gw6 = nhc->nhc_gw.ipv6;
        }

        ip_dst_init_metrics(&rt->dst, fi->fib_metrics);

#ifdef CONFIG_IP_ROUTE_CLASSID
        if (nhc->nhc_family == AF_INET) {
            struct fib_nh *nh;

            nh = container_of(nhc, struct fib_nh, nh_common);
            rt->dst.tclassid = nh->nh_tclassid;
        }
#endif
        rt->dst.lwtstate = lwtstate_get(nhc->nhc_lwtstate);
        if (unlikely(fnhe))
        {
            // LOG_WITH_PREFIX("rt_bind_exception"); this line will never been called
            cached = rt_bind_exception(rt, fnhe, daddr, do_cache);
        }
        else if (do_cache){
            // LOG_WITH_PREFIX("rt_cache_route");
            // cached = rt_cache_route(nhc, rt);
            cached = false;
        }
        if (unlikely(!cached)) {
            /* Routes we intend to cache in nexthop exception or
             * FIB nexthop have the DST_NOCACHE bit clear.
             * However, if we are unsuccessful at storing this
             * route into the cache we really need to set it.
             */
            if (!rt->rt_gw4) {
                rt->rt_gw_family = AF_INET;
                rt->rt_gw4 = daddr;
            }
            orig_rt_add_uncached_list(rt);
        }
    } else
        orig_rt_add_uncached_list(rt);

#ifdef CONFIG_IP_ROUTE_CLASSID
#ifdef CONFIG_IP_MULTIPLE_TABLES
    set_class_tag(rt, res->tclassid);
#endif
    set_class_tag(rt, itag);
#endif
}

struct rtable *self_defined_ip_route_output_flow(struct net * net, struct flowi4 *flp4, const struct sock *sk){
    struct rtable *rt = self_defined__ip_route_output_key(net, flp4);
    // LOG_WITH_PREFIX("self defined ip route output flow");
    if (IS_ERR(rt))
        return rt;

    if (flp4->flowi4_proto) {
        flp4->flowi4_oif = rt->dst.dev->ifindex;
        rt = (struct rtable *)xfrm_lookup_route(net, &rt->dst,
                                                flowi4_to_flowi(flp4),
                                                sk, 0);
    }

    return rt;
}

struct rtable *self_defined_ip_route_output_key_hash(struct net *net, struct flowi4 *fl4,
                                        const struct sk_buff *skb){
    struct fib_result res = {
            .type		= RTN_UNSPEC,
            .fi		= NULL,
            .table		= NULL,
            .tclassid	= 0,
    };
    struct rtable *rth;

    fl4->flowi4_iif = LOOPBACK_IFINDEX;
    ip_rt_fix_tos(fl4);

    rcu_read_lock();
    rth = self_defined_ip_route_output_key_hash_rcu(net, fl4, &res, skb);
    rcu_read_unlock();

    return rth;
}

struct rtable *self_defined_ip_route_output_key_hash_rcu(struct net *net, struct flowi4 *fl4,
                                            struct fib_result *res,
                                            const struct sk_buff *skb){
    struct net_device *dev_out = NULL;
    int orig_oif = fl4->flowi4_oif;
    unsigned int flags = 0;
    struct rtable *rth;
    int err;

    if (fl4->saddr) {
        if (ipv4_is_multicast(fl4->saddr) ||
            ipv4_is_lbcast(fl4->saddr) ||
            ipv4_is_zeronet(fl4->saddr)) {
            rth = ERR_PTR(-EINVAL);
            goto out;
        }

        rth = ERR_PTR(-ENETUNREACH);

        /* I removed check for oif == dev_out->oif here.
         * It was wrong for two reasons:
         * 1. ip_dev_find(net, saddr) can return wrong iface, if saddr
         *    is assigned to multiple interfaces.
         * 2. Moreover, we are allowed to send packets with saddr
         *    of another iface. --ANK
         */

        if (fl4->flowi4_oif == 0 &&
            (ipv4_is_multicast(fl4->daddr) ||
             ipv4_is_lbcast(fl4->daddr))) {
            /* It is equivalent to inet_addr_type(saddr) == RTN_LOCAL */
            dev_out = orig__ip_dev_find(net, fl4->saddr, false);
            if (!dev_out)
                goto out;

            /* Special hack: user can direct multicasts
             * and limited broadcast via necessary interface
             * without fiddling with IP_MULTICAST_IF or IP_PKTINFO.
             * This hack is not just for fun, it allows
             * vic,vat and friends to work.
             * They bind socket to loopback, set ttl to zero
             * and expect that it will work.
             * From the viewpoint of routing cache they are broken,
             * because we are not allowed to build multicast path
             * with loopback source addr (look, routing cache
             * cannot know, that ttl is zero, so that packet
             * will not leave this host and route is valid).
             * Luckily, this hack is good workaround.
             */

            fl4->flowi4_oif = dev_out->ifindex;
            goto make_route;
        }

        if (!(fl4->flowi4_flags & FLOWI_FLAG_ANYSRC)) {
            /* It is equivalent to inet_addr_type(saddr) == RTN_LOCAL */
            if (!orig__ip_dev_find(net, fl4->saddr, false))
                goto out;
        }
    }


    if (fl4->flowi4_oif) {
        dev_out = dev_get_by_index_rcu(net, fl4->flowi4_oif);
        rth = ERR_PTR(-ENODEV);
        if (!dev_out)
            goto out;

        /* RACE: Check return value of inet_select_addr instead. */
        if (!(dev_out->flags & IFF_UP) || !self_defined__in_dev_get_rcu(dev_out)) {
            rth = ERR_PTR(-ENETUNREACH);
            goto out;
        }
        if (ipv4_is_local_multicast(fl4->daddr) ||
            ipv4_is_lbcast(fl4->daddr) ||
            fl4->flowi4_proto == IPPROTO_IGMP) {
            if (!fl4->saddr)
                fl4->saddr = orig_inet_select_addr(dev_out, 0,
                                              RT_SCOPE_LINK);
            goto make_route;
        }
        if (!fl4->saddr) {
            if (ipv4_is_multicast(fl4->daddr))
                fl4->saddr = orig_inet_select_addr(dev_out, 0,
                                              fl4->flowi4_scope);
            else if (!fl4->daddr)
                fl4->saddr = orig_inet_select_addr(dev_out, 0,
                                              RT_SCOPE_HOST);
        }
    }

    if (!fl4->daddr) {
        fl4->daddr = fl4->saddr;
        if (!fl4->daddr)
            fl4->daddr = fl4->saddr = htonl(INADDR_LOOPBACK);
        dev_out = net->loopback_dev;
        fl4->flowi4_oif = LOOPBACK_IFINDEX;
        res->type = RTN_LOCAL;
        flags |= RTCF_LOCAL;
        goto make_route;
    }

    err = fib_lookup(net, fl4, res, 0);
    if (err) {
        res->fi = NULL;
        res->table = NULL;
        if (fl4->flowi4_oif &&
            (ipv4_is_multicast(fl4->daddr) || !fl4->flowi4_l3mdev)) {
            /* Apparently, routing tables are wrong. Assume,
             * that the destination is on link.
             *
             * WHY? DW.
             * Because we are allowed to send to iface
             * even if it has NO routes and NO assigned
             * addresses. When oif is specified, routing
             * tables are looked up with only one purpose:
             * to catch if destination is gatewayed, rather than
             * direct. Moreover, if MSG_DONTROUTE is set,
             * we send packet, ignoring both routing tables
             * and ifaddr state. --ANK
             *
             *
             * We could make it even if oif is unknown,
             * likely IPv6, but we do not.
             */

            if (fl4->saddr == 0)
                fl4->saddr = orig_inet_select_addr(dev_out, 0,
                                              RT_SCOPE_LINK);
            res->type = RTN_UNICAST;
            goto make_route;
        }
        rth = ERR_PTR(err);
        goto out;
    }

    if (res->type == RTN_LOCAL) {
        if (!fl4->saddr) {
            if (res->fi->fib_prefsrc)
                fl4->saddr = res->fi->fib_prefsrc;
            else
                fl4->saddr = fl4->daddr;
        }

        /* L3 master device is the loopback for that domain */
        dev_out = l3mdev_master_dev_rcu(FIB_RES_DEV(*res)) ? :
                  net->loopback_dev;

        /* make sure orig_oif points to fib result device even
         * though packet rx/tx happens over loopback or l3mdev
         */
        orig_oif = FIB_RES_OIF(*res);

        fl4->flowi4_oif = dev_out->ifindex;
        flags |= RTCF_LOCAL;
        goto make_route;
    }

    orig_fib_select_path(net, res, fl4, skb);

    dev_out = FIB_RES_DEV(*res);

    make_route:
    rth = self_defined__mkroute_output(res, fl4, orig_oif, dev_out, flags);

    out:
    return rth;
}


struct rtable *self_defined__mkroute_output(const struct fib_result *res,
                                       const struct flowi4 *fl4, int orig_oif,
                                       struct net_device *dev_out,
                                       unsigned int flags)
{
    struct fib_info *fi = res->fi;
    struct fib_nh_exception *fnhe;
    struct in_device *in_dev;
    u16 type = res->type;
    struct rtable *rth;
    bool do_cache;

    in_dev = __in_dev_get_rcu(dev_out);
    if (!in_dev)
        return ERR_PTR(-EINVAL);

    if (likely(!IN_DEV_ROUTE_LOCALNET(in_dev)))
        if (ipv4_is_loopback(fl4->saddr) &&
            !(dev_out->flags & IFF_LOOPBACK) &&
            !netif_is_l3_master(dev_out))
            return ERR_PTR(-EINVAL);

    if (ipv4_is_lbcast(fl4->daddr))
        type = RTN_BROADCAST;
    else if (ipv4_is_multicast(fl4->daddr))
        type = RTN_MULTICAST;
    else if (ipv4_is_zeronet(fl4->daddr))
        return ERR_PTR(-EINVAL);

    if (dev_out->flags & IFF_LOOPBACK)
        flags |= RTCF_LOCAL;

    do_cache = true;
    if (type == RTN_BROADCAST) {
        flags |= RTCF_BROADCAST | RTCF_LOCAL;
        fi = NULL;
    } else if (type == RTN_MULTICAST) {
        flags |= RTCF_MULTICAST | RTCF_LOCAL;
        if (!orig_ip_check_mc_rcu(in_dev, fl4->daddr, fl4->saddr,
                             fl4->flowi4_proto))
            flags &= ~RTCF_LOCAL;
        else
            do_cache = false;
        /* If multicast route do not exist use
         * default one, but do not gateway in this case.
         * Yes, it is hack.
         */
        if (fi && res->prefixlen < 4)
            fi = NULL;
    } else if ((type == RTN_LOCAL) && (orig_oif != 0) &&
               (orig_oif != dev_out->ifindex)) {
        /* For local routes that require a particular output interface
         * we do not want to cache the result.  Caching the result
         * causes incorrect behaviour when there are multiple source
         * addresses on the interface, the end result being that if the
         * intended recipient is waiting on that interface for the
         * packet he won't receive it because it will be delivered on
         * the loopback interface and the IP_PKTINFO ipi_ifindex will
         * be set to the loopback interface as well.
         */
        do_cache = false;
    }

    fnhe = NULL;
    do_cache &= fi != NULL;
    if (fi) {
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);
        struct rtable __rcu **prth;

        fnhe = find_exception(nhc, fl4->daddr);
        if (!do_cache)
            goto add;
        if (fnhe) {
            prth = &fnhe->fnhe_rth_output;
            // LOG_WITH_PREFIX("prth = &fnhe->fnhe_rth_output;");
        } else {
            if (unlikely(fl4->flowi4_flags &
                         FLOWI_FLAG_KNOWN_NH &&
                         !(nhc->nhc_gw_family &&
                           nhc->nhc_scope == RT_SCOPE_LINK))) {
                do_cache = false;
                goto add;
            }
            prth = raw_cpu_ptr(nhc->nhc_pcpu_rth_output);
            // LOG_WITH_PREFIX("get raw_cpu_ptr(nhc->nhc_pcpu_rth_output);");
        }
        rth = rcu_dereference(*prth);
        if (rt_cache_valid(rth) && dst_hold_safe(&rth->dst))
        {
            // LOG_WITH_PREFIX("return rth cache");
            return rth;
        }
    }

    add:
    rth = rt_dst_alloc(dev_out, flags, type,
                       IN_DEV_ORCONF(in_dev, NOPOLICY),
                       IN_DEV_ORCONF(in_dev, NOXFRM));
    if (!rth)
        return ERR_PTR(-ENOBUFS);

    rth->rt_iif = orig_oif;

    RT_CACHE_STAT_INC(out_slow_tot);

    if (flags & (RTCF_BROADCAST | RTCF_MULTICAST)) {
        if (flags & RTCF_LOCAL &&
            !(dev_out->flags & IFF_LOOPBACK)) {
            rth->dst.output = orig_ip_mc_output;
            RT_CACHE_STAT_INC(out_slow_mc);
        }
#ifdef CONFIG_IP_MROUTE
        if (type == RTN_MULTICAST) {
			if (IN_DEV_MFORWARD(in_dev) &&
			    !ipv4_is_local_multicast(fl4->daddr)) {
				rth->dst.input = orig_ip_mr_input;
				rth->dst.output = orig_ip_mc_output;
			}
		}
#endif
    }

    rt_set_nexthop(rth, fl4->daddr, res, fnhe, fi, type, 0, do_cache);
    lwtunnel_set_redirect(&rth->dst);

    return rth;
}