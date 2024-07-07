//
// Created by zhf on 24-4-5.
//
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <net/dst_metadata.h>
#include "headers/support_tools.h"
#include "headers/ip_route_input_noref_without_cache.h"

static DEFINE_SPINLOCK(fnhe_lock);
static DEFINE_PER_CPU(struct rt_cache_stat, rt_cache_stat);
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

asmlinkage int (*orig_ip_error)(struct sk_buff *skb);
asmlinkage int (*orig_fib_multipath_hash)(const struct net *net, const struct flowi4 *fl4,
                                  const struct sk_buff *skb, struct flow_keys *flkeys);
asmlinkage int (*orig_ip_mc_validate_source)(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                                     u8 tos, struct net_device *dev,
                                     struct in_device *in_dev, u32 *itag);
asmlinkage int (*orig_inet_addr_onlink)(struct in_device *in_dev, __be32 a, __be32 b);
asmlinkage int (*orig_fib_validate_source)(struct sk_buff *skb, __be32 src, __be32 dst,
                                   u8 tos, int oif, struct net_device *dev,
                                   struct in_device *idev, u32 *itag);
asmlinkage void (*orig_fib_select_multipath)(struct fib_result *res, int hash);
asmlinkage int (*orig_ip_route_input_noref)(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                                                 u8 tos, struct net_device *dev);
extern asmlinkage int (*orig_ip_mr_input)(struct sk_buff *skb);
extern asmlinkage int (*orig_ip_forward)(struct sk_buff* skb);
extern asmlinkage int (*orig_ip_check_mc_rcu)(struct in_device *in_dev, __be32 mc_addr, __be32 src_addr, u8 proto);
extern asmlinkage void (*orig_rt_add_uncached_list)(struct rtable *rt);

void resolve_ip_route_input_noref_inner_function_address(void){
    LOG_WITH_EDGE("start to resolve ip_route_input_noref inner function address");
    orig_fib_multipath_hash = get_function_address("fib_multipath_hash");
    LOG_RESOLVED(orig_fib_multipath_hash, "fib_multipath_hash");
    orig_ip_mc_validate_source = get_function_address("ip_mc_validate_source");
    LOG_RESOLVED(orig_ip_mc_validate_source, "ip_mc_validate_source");
    orig_ip_error = get_function_address("ip_error");
    LOG_RESOLVED(orig_ip_error, "ip_error");
    orig_inet_addr_onlink = get_function_address("inet_addr_onlink");
    LOG_RESOLVED(orig_inet_addr_onlink, "inet_addr_onlink");
    orig_fib_validate_source = get_function_address("fib_validate_source");
    LOG_RESOLVED(orig_fib_validate_source, "fib_validate_source");
    orig_fib_select_multipath = get_function_address("fib_select_multipath");
    LOG_RESOLVED(orig_fib_select_multipath, "fib_select_multipath");
    LOG_WITH_EDGE("end to resolve ip_route_input_noref inner function address");
}

asmlinkage int hook_ip_route_input_noref(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                                                 u8 tos, struct net_device *dev){
    int result;
    // LOG_WITH_EDGE("ip_route_input_noref started");
    result = self_defined_ip_route_input_noref(skb, daddr, saddr, tos, dev);
    // LOG_WITH_EDGE("ip_route_input_noref ended");
    return result;
}

// --------------------------------- static ---------------------------------

static inline bool rt_is_expired(const struct rtable *rth) {
    return rth->rt_genid != rt_genid_ipv4(dev_net(rth->dst.dev));
}

static bool rt_cache_valid(const struct rtable *rt) {
    return rt &&
           rt->dst.obsolete == DST_OBSOLETE_FORCE_CHK &&
           !rt_is_expired(rt);
}

/* get device for dst_alloc with local routes */
static struct net_device *ip_rt_get_dev(struct net *net,
                                        const struct fib_result *res)
{
    struct fib_nh_common *nhc = res->fi ? res->nhc : NULL;
    struct net_device *dev = NULL;

    if (nhc)
        dev = l3mdev_master_dev_rcu(nhc->nhc_dev);

    return dev ? : net->loopback_dev;
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

static u32 fnhe_hashfun(__be32 daddr)
{
    static siphash_aligned_key_t fnhe_hash_key;
    u64 hval;
    net_get_random_once(&fnhe_hash_key, sizeof(fnhe_hash_key));
    hval = siphash_1u32((__force u32)daddr, &fnhe_hash_key);
    return hash_64(hval, FNHE_HASH_SHIFT);
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

static void ip_handle_martian_source(struct net_device *dev,
                                     struct in_device *in_dev,
                                     struct sk_buff *skb,
                                     __be32 daddr,
                                     __be32 saddr)
{
    RT_CACHE_STAT_INC(in_martian_src);
#ifdef CONFIG_IP_ROUTE_VERBOSE
    if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit()) {
        /*
         *	RFC1812 recommendation, if source is martian,
         *	the only hint is MAC header.
         */
        pr_warn("martian source %pI4 from %pI4, on dev %s\n",
                &daddr, &saddr, dev->name);
        if (dev->hard_header_len && skb_mac_header_was_set(skb)) {
            print_hex_dump(KERN_WARNING, "ll header: ",
                           DUMP_PREFIX_OFFSET, 16, 1,
                           skb_mac_header(skb),
                           dev->hard_header_len, false);
        }
    }
#endif
}

static inline struct in_device *self_defined__in_dev_get_rcu(const struct net_device *dev)
{
    return rcu_dereference(dev->ip_ptr);
}

static int ip_rt_bug(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    pr_debug("%s: %pI4 -> %pI4, %s\n",
             __func__, &ip_hdr(skb)->saddr, &ip_hdr(skb)->daddr,
             skb->dev ? skb->dev->name : "?");
    kfree_skb(skb);
    WARN_ON(1);
    return 0;
}


/* called in rcu_read_lock() section */
static int ip_route_input_mc(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                             u8 tos, struct net_device *dev, int our)
{
    struct in_device *in_dev = self_defined__in_dev_get_rcu(dev);
    unsigned int flags = RTCF_MULTICAST;
    struct rtable *rth;
    bool no_policy;
    u32 itag = 0;
    int err;

    err = orig_ip_mc_validate_source(skb, daddr, saddr, tos, dev, in_dev, &itag);
    if (err)
        return err;

    if (our)
        flags |= RTCF_LOCAL;

    no_policy = IN_DEV_ORCONF(in_dev, NOPOLICY);
    if (no_policy)
        IPCB(skb)->flags |= IPSKB_NOPOLICY;

    rth = rt_dst_alloc(dev_net(dev)->loopback_dev, flags, RTN_MULTICAST,
                       no_policy, false);
    if (!rth)
        return -ENOBUFS;

#ifdef CONFIG_IP_ROUTE_CLASSID
    rth->dst.tclassid = itag;
#endif
    rth->dst.output = ip_rt_bug;
    rth->rt_is_input= 1;

#ifdef CONFIG_IP_MROUTE
    if (!ipv4_is_local_multicast(daddr) && IN_DEV_MFORWARD(in_dev))
        rth->dst.input = orig_ip_mr_input;
#endif
    RT_CACHE_STAT_INC(in_slow_mc);

    skb_dst_drop(skb);
    skb_dst_set(skb, &rth->dst);
    return 0;
}

// --------------------------------- static ---------------------------------

int self_defined_ip_route_input_noref(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                         u8 tos, struct net_device *dev)
{
    struct fib_result res;
    int err;

    tos &= IPTOS_RT_MASK;
    rcu_read_lock();
    err = self_defined_ip_route_input_rcu(skb, daddr, saddr, tos, dev, &res);
    rcu_read_unlock();

    return err;
}

/* called with rcu_read_lock held */
int self_defined_ip_route_input_rcu(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                       u8 tos, struct net_device *dev, struct fib_result *res)
{
    /* Multicast recognition logic is moved from route cache to here.
     * The problem was that too many Ethernet cards have broken/missing
     * hardware multicast filters :-( As result the host on multicasting
     * network acquires a lot of useless route cache entries, sort of
     * SDR messages from all the world. Now we try to get rid of them.
     * Really, provided software IP multicast filter is organized
     * reasonably (at least, hashed), it does not result in a slowdown
     * comparing with route cache reject entries.
     * Note, that multicast routers are not affected, because
     * route cache entry is created eventually.
     */
    if (ipv4_is_multicast(daddr)) {
        struct in_device *in_dev = self_defined__in_dev_get_rcu(dev);
        int our = 0;
        int err = -EINVAL;

        if (!in_dev)
            return err;
        our = orig_ip_check_mc_rcu(in_dev, daddr, saddr,
                              ip_hdr(skb)->protocol);

        /* check l3 master if no match yet */
        if (!our && netif_is_l3_slave(dev)) {
            struct in_device *l3_in_dev;

            l3_in_dev = self_defined__in_dev_get_rcu(skb->dev);
            if (l3_in_dev)
                our = orig_ip_check_mc_rcu(l3_in_dev, daddr, saddr,
                                      ip_hdr(skb)->protocol);
        }

        if (our
            #ifdef CONFIG_IP_MROUTE
            ||
            (!ipv4_is_local_multicast(daddr) &&
             IN_DEV_MFORWARD(in_dev))
#endif
                ) {
            err = ip_route_input_mc(skb, daddr, saddr,
                                    tos, dev, our);
        }
        return err;
    }

    return self_defined_ip_route_input_slow(skb, daddr, saddr, tos, dev, res);
}

int self_defined_ip_mkroute_input(struct sk_buff *skb,
                            struct fib_result *res,
                            struct in_device *in_dev,
                            __be32 daddr, __be32 saddr, u32 tos,
                            struct flow_keys *hkeys)
{
#ifdef CONFIG_IP_ROUTE_MULTIPATH
    if (res->fi && fib_info_num_path(res->fi) > 1) {
        int h = orig_fib_multipath_hash(res->fi->fib_net, NULL, skb, hkeys);

        orig_fib_select_multipath(res, h);
    }
#endif

    /* create a routing cache entry */
    return self_defined__mkroute_input(skb, res, in_dev, daddr, saddr, tos);
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

int self_defined__mkroute_input(struct sk_buff *skb,
                           const struct fib_result *res,
                           struct in_device *in_dev,
                           __be32 daddr, __be32 saddr, u32 tos)
{
    struct fib_nh_common *nhc = FIB_RES_NHC(*res);
    struct net_device *dev = nhc->nhc_dev;
    struct fib_nh_exception *fnhe;
    struct rtable *rth;
    int err;
    struct in_device *out_dev;
    bool do_cache, no_policy;
    u32 itag = 0;

    /* get a working reference to the output device */
    out_dev = __in_dev_get_rcu(dev);
    if (!out_dev) {
        net_crit_ratelimited("Bug in ip_route_input_slow(). Please report.\n");
        return -EINVAL;
    }

    err = orig_fib_validate_source(skb, saddr, daddr, tos, FIB_RES_OIF(*res),
                              in_dev->dev, in_dev, &itag);
    if (err < 0) {
        ip_handle_martian_source(in_dev->dev, in_dev, skb, daddr,
                                 saddr);

        goto cleanup;
    }

    do_cache = res->fi && !itag;
    if (out_dev == in_dev && err && IN_DEV_TX_REDIRECTS(out_dev) &&
        skb->protocol == htons(ETH_P_IP)) {
        __be32 gw;

        gw = nhc->nhc_gw_family == AF_INET ? nhc->nhc_gw.ipv4 : 0;
        if (IN_DEV_SHARED_MEDIA(out_dev) ||
            orig_inet_addr_onlink(out_dev, saddr, gw))
            IPCB(skb)->flags |= IPSKB_DOREDIRECT;
    }

    if (skb->protocol != htons(ETH_P_IP)) {
        /* Not IP (i.e. ARP). Do not create route, if it is
         * invalid for proxy arp. DNAT routes are always valid.
         *
         * Proxy arp feature have been extended to allow, ARP
         * replies back to the same interface, to support
         * Private VLAN switch technologies. See arp.c.
         */
        if (out_dev == in_dev &&
            IN_DEV_PROXY_ARP_PVLAN(in_dev) == 0) {
            err = -EINVAL;
            goto cleanup;
        }
    }

    no_policy = IN_DEV_ORCONF(in_dev, NOPOLICY);
    if (no_policy)
        IPCB(skb)->flags |= IPSKB_NOPOLICY;

    fnhe = find_exception(nhc, daddr);
    if (do_cache) {
        if (fnhe)
            rth = rcu_dereference(fnhe->fnhe_rth_input);
        else
            rth = rcu_dereference(nhc->nhc_rth_input);
        if (rt_cache_valid(rth)) {
            skb_dst_set_noref(skb, &rth->dst);
            goto out;
        }
    }

    rth = rt_dst_alloc(out_dev->dev, 0, res->type, no_policy,
                       IN_DEV_ORCONF(out_dev, NOXFRM));
    if (!rth) {
        err = -ENOBUFS;
        goto cleanup;
    }

    rth->rt_is_input = 1;
    RT_CACHE_STAT_INC(in_slow_tot);

    rth->dst.input = orig_ip_forward;

    rt_set_nexthop(rth, daddr, res, fnhe, res->fi, res->type, itag,
                   do_cache);
    lwtunnel_set_redirect(&rth->dst);
    skb_dst_set(skb, &rth->dst);
    out:
    err = 0;
    cleanup:
    return err;
}


int self_defined_ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                               u8 tos, struct net_device *dev,
                               struct fib_result *res)
{
    struct in_device *in_dev = __in_dev_get_rcu(dev);
    struct flow_keys *flkeys = NULL, _flkeys;
    struct net    *net = dev_net(dev);
    struct ip_tunnel_info *tun_info;
    int		err = -EINVAL;
    unsigned int	flags = 0;
    u32		itag = 0;
    struct rtable	*rth;
    struct flowi4	fl4;
    bool do_cache = true;
    bool no_policy;

    /* IP on this device is disabled. */

    if (!in_dev)
        goto out;

    /* Check for the most weird martians, which can be not detected
     * by fib_lookup.
     */

    tun_info = skb_tunnel_info(skb);
    if (tun_info && !(tun_info->mode & IP_TUNNEL_INFO_TX))
        fl4.flowi4_tun_key.tun_id = tun_info->key.tun_id;
    else
        fl4.flowi4_tun_key.tun_id = 0;
    skb_dst_drop(skb);

    if (ipv4_is_multicast(saddr) || ipv4_is_lbcast(saddr))
        goto martian_source;

    res->fi = NULL;
    res->table = NULL;
    if (ipv4_is_lbcast(daddr) || (saddr == 0 && daddr == 0))
        goto brd_input;

    /* Accept zero addresses only to limited broadcast;
     * I even do not know to fix it or not. Waiting for complains :-)
     */
    if (ipv4_is_zeronet(saddr))
        goto martian_source;

    if (ipv4_is_zeronet(daddr))
        goto martian_destination;

    /* Following code try to avoid calling IN_DEV_NET_ROUTE_LOCALNET(),
     * and call it once if daddr or/and saddr are loopback addresses
     */
    if (ipv4_is_loopback(daddr)) {
        if (!IN_DEV_NET_ROUTE_LOCALNET(in_dev, net))
            goto martian_destination;
    } else if (ipv4_is_loopback(saddr)) {
        if (!IN_DEV_NET_ROUTE_LOCALNET(in_dev, net))
            goto martian_source;
    }

    /*
     *	Now we are ready to route packet.
     */
    fl4.flowi4_l3mdev = 0;
    fl4.flowi4_oif = 0;
    fl4.flowi4_iif = dev->ifindex;
    fl4.flowi4_mark = skb->mark;
    fl4.flowi4_tos = tos;
    fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
    fl4.flowi4_flags = 0;
    fl4.daddr = daddr;
    fl4.saddr = saddr;
    fl4.flowi4_uid = sock_net_uid(net, NULL);
    fl4.flowi4_multipath_hash = 0;

    if (fib4_rules_early_flow_dissect(net, skb, &fl4, &_flkeys)) {
        flkeys = &_flkeys;
    } else {
        fl4.flowi4_proto = 0;
        fl4.fl4_sport = 0;
        fl4.fl4_dport = 0;
    }

    err = fib_lookup(net, &fl4, res, 0);
    if (err != 0) {
        if (!IN_DEV_FORWARD(in_dev))
            err = -EHOSTUNREACH;
        goto no_route;
    }

    if (res->type == RTN_BROADCAST) {
        if (IN_DEV_BFORWARD(in_dev))
            goto make_route;
        /* not do cache if bc_forwarding is enabled */
        if (IPV4_DEVCONF_ALL(net, BC_FORWARDING))
            do_cache = false;
        goto brd_input;
    }

    if (res->type == RTN_LOCAL) {
        err = orig_fib_validate_source(skb, saddr, daddr, tos,
                                  0, dev, in_dev, &itag);
        if (err < 0)
            goto martian_source;
        goto local_input;
    }

    if (!IN_DEV_FORWARD(in_dev)) {
        err = -EHOSTUNREACH;
        goto no_route;
    }
    if (res->type != RTN_UNICAST)
        goto martian_destination;

    make_route:
    err = self_defined_ip_mkroute_input(skb, res, in_dev, daddr, saddr, tos, flkeys);
    out:	return err;

    brd_input:
    if (skb->protocol != htons(ETH_P_IP))
        goto e_inval;

    if (!ipv4_is_zeronet(saddr)) {
        err = orig_fib_validate_source(skb, saddr, 0, tos, 0, dev,
                                  in_dev, &itag);
        if (err < 0)
            goto martian_source;
    }
    flags |= RTCF_BROADCAST;
    res->type = RTN_BROADCAST;
    RT_CACHE_STAT_INC(in_brd);

    local_input:
    no_policy = IN_DEV_ORCONF(in_dev, NOPOLICY);
    if (no_policy)
        IPCB(skb)->flags |= IPSKB_NOPOLICY;

    do_cache &= res->fi && !itag;
    if (do_cache) {
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);

        rth = rcu_dereference(nhc->nhc_rth_input);
        if (rt_cache_valid(rth)) {
            skb_dst_set_noref(skb, &rth->dst);
            err = 0;
            goto out;
        }
    }

    rth = rt_dst_alloc(ip_rt_get_dev(net, res),
                       flags | RTCF_LOCAL, res->type,
                       no_policy, false);
    if (!rth)
        goto e_nobufs;

    rth->dst.output= ip_rt_bug;
#ifdef CONFIG_IP_ROUTE_CLASSID
    rth->dst.tclassid = itag;
#endif
    rth->rt_is_input = 1;

    RT_CACHE_STAT_INC(in_slow_tot);
    if (res->type == RTN_UNREACHABLE) {
        rth->dst.input= orig_ip_error;
        rth->dst.error= -err;
        rth->rt_flags	&= ~RTCF_LOCAL;
    }

    if (do_cache) {
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);

        rth->dst.lwtstate = lwtstate_get(nhc->nhc_lwtstate);
        if (lwtunnel_input_redirect(rth->dst.lwtstate)) {
            WARN_ON(rth->dst.input == lwtunnel_input);
            rth->dst.lwtstate->orig_input = rth->dst.input;
            rth->dst.input = lwtunnel_input;
        }

        // if (unlikely(!rt_cache_route(nhc, rth)))
        orig_rt_add_uncached_list(rth);
    }
    skb_dst_set(skb, &rth->dst);
    err = 0;
    goto out;

    no_route:
    RT_CACHE_STAT_INC(in_no_route);
    res->type = RTN_UNREACHABLE;
    res->fi = NULL;
    res->table = NULL;
    goto local_input;

    /*
     *	Do not cache martian addresses: they should be logged (RFC1812)
     */
    martian_destination:
    RT_CACHE_STAT_INC(in_martian_dst);
#ifdef CONFIG_IP_ROUTE_VERBOSE
    if (IN_DEV_LOG_MARTIANS(in_dev))
        net_warn_ratelimited("martian destination %pI4 from %pI4, dev %s\n",
                             &daddr, &saddr, dev->name);
#endif

    e_inval:
    err = -EINVAL;
    goto out;

    e_nobufs:
    err = -ENOBUFS;
    goto out;

    martian_source:
    ip_handle_martian_source(dev, in_dev, skb, daddr, saddr);
    goto out;
}

void add_ip_route_input_noref_to_hook(void){
    hooks[number_of_hook].name = "ip_route_input_noref";
    hooks[number_of_hook].function = hook_ip_route_input_noref;
    hooks[number_of_hook].original = &orig_ip_route_input_noref;
    number_of_hook += 1;
}