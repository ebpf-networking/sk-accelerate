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
    __type(key, struct sock_key);                   // dst IP
    __type(value, int);        // data
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_ops_map SEC(".maps") ;
