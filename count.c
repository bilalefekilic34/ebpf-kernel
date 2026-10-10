#include <linux/bpf.h> 
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct limit_info {
    __u64 pkt_cnt;
    __u64 bytes_cnt; 
    __u64 limit;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32); 
    __type(value, __u8);  
} ip_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct limit_info);
} ip_limit_map SEC(".maps");

SEC("xdp")
int xdp_icmp_limiter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    __u32 pkt_len = data_end - data; 

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;

    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    struct limit_info *info = bpf_map_lookup_elem(&ip_limit_map, &src_ip);

    __u8 *blacklisted = bpf_map_lookup_elem(&ip_blacklist, &src_ip);
    if (blacklisted && *blacklisted == 1) {
        return XDP_DROP;
    }

    if (info) {
        __sync_fetch_and_add(&info->pkt_cnt, 1);
        __sync_fetch_and_add(&info->bytes_cnt, pkt_len); 

        if (info->pkt_cnt > info->limit)
            return XDP_DROP;
    } else {
        struct limit_info new_info = {
            .pkt_cnt = 1,
            .bytes_cnt = pkt_len,
            .limit = 50 
        };
        
        bpf_map_update_elem(&ip_limit_map, &src_ip, &new_info, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
