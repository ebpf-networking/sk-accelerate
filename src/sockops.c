#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "sockops.h"

/*
 * extract the key identifying the socket source of the TCP event
 */
static inline
void sk_extractv4_key(struct bpf_sock_ops *ops,
    struct sock_key *key)
{
    // keep ip and port in network byte order
    key->dst.ip4 = ops->remote_ip4;
    key->src.ip4 = ops->local_ip4;
    key->family = 2;

    // local_port is in host byte order, and
    // remote_port is in network byte order
    key->sport = (bpf_htonl(ops->local_port) >> 16);
    key->dport = READ_ONCE(ops->remote_port) >> 16;
}

// Returns service ip/port if the source ip/port is an endpoint
static inline
struct endpoints_to_service_value* is_endpoint(struct sock_key *key) {
    struct endpoints_to_service_key map_key = {};
    map_key.ip = key->src.ip4;
    map_key.port = key->sport;
    return bpf_map_lookup_elem(&endpoints_to_service_map, &map_key);
}

static inline
void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
    struct sock_key key = {};
    struct endpoints_to_service_value *service;

    sk_extractv4_key(skops, &key);

    service = is_endpoint(&key);
    if (service) {
        bpf_printk("is_endpoint() returned non null\n");
        struct sock_key key1 = {};
        struct sock_key value1 = {};

        key1.src.ip4 = key.dst.ip4;
        key1.sport = key.dport;
        key1.family = key.family;
        key1.dst.ip4 = key.src.ip4;
        key1.dport = key.sport;

        value1.src.ip4 = key.dst.ip4;
        value1.sport = key.dport;
        value1.family = key.family;
        value1.dst.ip4 = service->ip;
        value1.dport = service->port;

        bpf_map_update_elem(&sock_ops_aux_map, &key1, &value1, BPF_NOEXIST);

        struct sock_key key2 = {};
        struct sock_key value2 = {};

        key2.src.ip4 = service->ip;
        key2.sport = service->port;
        key2.family = key.family;
        key2.dst.ip4 = key.dst.ip4;
        key2.dport = key.dport;

        value2.src.ip4 = key.src.ip4;
        value2.sport = key.sport;
        value2.family = key.family;
        value2.dst.ip4 = key.dst.ip4;
        value2.dport = key.dport;

        bpf_map_update_elem(&sock_ops_aux_map, &key2, &value2, BPF_NOEXIST);
    }
    else {
        bpf_printk("is_endpoint() returned null\n");
    }

    // insert the source socket in the sock_ops_map
    int ret = bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
    bpf_printk("<<< ipv4 op = %d, port %d --> %d\n",
        skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
    if (ret != 0) {
        bpf_printk("FAILED: bpf_sock_hash_update ret: %d\n", ret);
    }

    ret = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
    if (ret != 0) {
        bpf_printk("FAILED: bpf_sock_ops_cb_flags_set() returned  %d\n", ret);
    }
}

static inline
void sk_extractv6_key(struct bpf_sock_ops *ops,
    struct sock_key *key)
{
    // keep ip and port in network byte order
    //__builtin_memset((void*)&key->dst.ip6, 0, 32);
    //__builtin_memset((void*)&key->src.ip6, 0, 32);
    //__builtin_memcpy((void*)&key->dst.ip6, (void*)&ops->remote_ip6, 32);
    //__builtin_memcpy((void*)&key->src.ip6, (void*)&ops->local_ip6, 32);
    key->dst.ip6[0] = ops->remote_ip6[0];
    key->dst.ip6[1] = ops->remote_ip6[1];
    key->dst.ip6[2] = ops->remote_ip6[2];
    key->dst.ip6[3] = ops->remote_ip6[3];
    key->src.ip6[0] = ops->local_ip6[0];
    key->src.ip6[1] = ops->local_ip6[1];
    key->src.ip6[2] = ops->local_ip6[2];
    key->src.ip6[3] = ops->local_ip6[3];
    key->family = 10;

    // local_port is in host byte order, and
    // remote_port is in network byte order
    key->sport = (bpf_htonl(ops->local_port) >> 16);
    key->dport = READ_ONCE(ops->remote_port) >> 16;
}

static inline
void bpf_sock_ops_ipv6(struct bpf_sock_ops *skops)
{
    struct sock_key key = {};

    sk_extractv6_key(skops, &key);

    // insert the source socket in the sock_ops_map
    int ret = bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
    bpf_printk("<<< ipv6 op = %d, port %d --> %d\n",
        skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
    if (ret != 0) {
        bpf_printk("FAILED: bpf_sock_hash_update ret: %d\n", ret);
    }
}

SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops)
{
    __u32 family, op;

    family = skops->family;
    op = skops->op;

    switch (op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            if (family == 2) { //AF_INET
                bpf_sock_ops_ipv4(skops);
            }
            else if (family == 10) { //AF_INET6
                // when remote_ip4 == 127.0.0.6, don't use it
                if (skops->remote_ip4 && skops->remote_ip4 != 0x600007f) {
                    //bpf_printk("remote_ip4: %x, local_ip4: %x\n", skops->remote_ip4, skops->local_ip4);
                    bpf_sock_ops_ipv4(skops);
                }
                else {
                    /*
                    bpf_printk("remote_ip6: %x:%x:%x:%x, local_ip6: %x:%x:%x:%x\n",
                            skops->remote_ip6[0],
                            skops->remote_ip6[1],
                            skops->remote_ip6[2],
                            skops->remote_ip6[3],
                            skops->local_ip6[0],
                            skops->local_ip6[1],
                            skops->local_ip6[2],
                            skops->local_ip6[3]);
                            */
                    bpf_sock_ops_ipv6(skops);
                }
            }
            break;
        case BPF_SOCK_OPS_STATE_CB:
            switch(skops->args[1]) {
                case BPF_TCP_CLOSE:
                case BPF_TCP_CLOSE_WAIT:
                case BPF_TCP_LAST_ACK:
                    //bpf_printk("remote = %x:%d, local = %x:%d\n", skops->remote_ip4, skops->remote_port, skops->local_ip4, skops->local_port);
                    bpf_printk("args[0] = %x, args[1] = %x\n", skops->args[0], skops->args[1]);
                    break;
            }
            break;
        default:
            bpf_printk("not supported op: %d\n", op);
            break;
        }
    return 0;
}

char _license[] SEC("license") = "GPL";
