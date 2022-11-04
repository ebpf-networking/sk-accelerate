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

// Endpoints IPs are kept in a map of hash maps. The key to the outer map is the 
// namespace+name pair. The key to the inner maps are the pod IPs, and the 
// value is a static number 0.
struct endpoints_ips_outer_key {
    char namespace[128];
    char name[128];
} __attribute__((packed));

struct endpoints_ips_inner_key {
    union {
        __u32 ip4;
        __u32 ip6[4];
    } ip;
} __attribute__((packed));

struct endpoints_ips_inner_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct endpoints_ips_inner_key);
    __type(value, __u32);
} endpoints_ips_inner_map SEC(".maps");

// BPF_MAP_TYPE_HASH_OF_MAPS was introduced in kernel 4.12, so any recent kernel should support it
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1024);
    __type(key, struct endpoints_ips_outer_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct endpoints_ips_inner_map);
} endpoints_ips_map SEC(".maps");

// Endpoints Ports are kept in a map of hash maps. The key to the outer map is the 
// namespace+name pair. The key to the inner maps are the ports, and the 
// value is a static number 0.
struct endpoints_ports_outer_key {
    char namespace[128];
    char name[128];
} __attribute__((packed));

struct endpoints_ports_inner_key {
    int port;
} __attribute__((packed));

struct endpoints_ports_inner_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct endpoints_ports_inner_key);
    __type(value, __u32);
} endpoints_ports_inner_map SEC(".maps");

// BPF_MAP_TYPE_HASH_OF_MAPS was introduced in kernel 4.12, so any recent kernel should support it
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1024);
    __type(key, struct endpoints_ports_outer_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct endpoints_ports_inner_map);
} endpoints_ports_map SEC(".maps");

// Endpoints-to-Service is a hashmap. The key is <pod ip>:<pod port>, and the value is <service ip>:<service port>
struct endpoints_to_service_key {
    union {
        __u32 ip4;
        __u32 ip6[4];
    } ip;
    __u32 pad;
    __u32 port;
} __attribute__((packed));

struct endpoints_to_service_value {
    union {
        __u32 ip4;
        __u32 ip6[4];
    } ip;
    __u32 pad;
    __u32 port;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct endpoints_to_service_key);
    __type(value, struct endpoints_to_service_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} endpoints_to_service_map SEC(".maps");

