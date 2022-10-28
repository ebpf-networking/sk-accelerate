/*
 * Most of this code is from reading and understanding the code here:
 * - https://github.com/cilium/cilium/tree/master/bpf/sockops
 * - https://github.com/cyralinc/os-eBPF
 * - https://github.com/zachidan/ebpf-sockops
 *
 */

#ifndef READ_ONCE
#define READ_ONCE(x)        (*(volatile typeof(x) *)&x)
#endif

// Hash key to the sock_ops_map. Supports both ipv4 and ipv6
struct sock_key {
    union {
        __u32 ip4;
        __u32 ip6[4];
    } src;
    union {
        __u32 ip4;
        __u32 ip6[4];
    } dst;
    __u8 family;
    __u8 pad1;
    __u16 pad2;
    // this padding required for 64bit alignment
    // else ebpf kernel verifier rejects loading
    // of the program
    __u32 pad3;
    __u32 sport;
    __u32 dport;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);   // dst IP
    __type(value, int);             // data
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_ops_map SEC(".maps") ;

// Hash key to the services_map. Supports both ipv4 and ipv6
struct service_key {
    union {
        __u32 ip4;
        __u32 ip6[4];
    } ip;
} __attribute__((packed));

struct service_value {
    char namespace[128];
    char name[128];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct service_key);        // dst service IP
    __type(value, struct service_value);    // service namespace + name
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} services_map SEC(".maps");

// Endpoints are kept in a map of hash maps. The key to the outer map is the service IP.
// The key to the inner maps are the pod IPs, and the value is a static number 0.
struct endpoint_outer_key {
    union {
        __u32 ip4;
        __u32 ip6[4];
    } ip;
} __attribute__((packed));

struct endpoint_inner_key {
    union {
        __u32 ip4;
        __u32 ip6[4];
    } ip;
} __attribute__((packed));

struct endpoints_inner_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct endpoint_inner_key);
    __type(value, __u32);
} endpoints_inner_map SEC(".maps");

// BPF_MAP_TYPE_HASH_OF_MAPS was introduced in kernel 4.12, so any recent kernel should support it
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1024);
    __type(key, struct endpoint_outer_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct endpoints_inner_map);
} endpoints_map SEC(".maps");
