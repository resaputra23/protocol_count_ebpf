//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>


//kita gunakan tipe array untuk : BPF_MAP_TYPE_ARRAY

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 20);
} protocol_count SEC(".maps");

SEC("xdp")
int get_packet_protocol(struct xdp_md *ctx) {
    
    //1kita buat batas untuk memory location saat kita inspect packet, supaya tidak access diluar memory packet incoming
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    //2parse ethnern header ke 'data;
    //check bound akses memory
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    //3check IP packet dari data parse, jika bukan IP langsung kita passing 
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
    	return XDP_PASS;
    }

    //moving pointer ke header selanjutnya yaitu IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    

    //perhatikan disiniki kita akan buat 'key' adalah protcol
    //kita enstract protocol dari ip
    __u32 key = ip->protocol;
    __u64 *count = bpf_map_lookup_elem(&protocol_count, &key);
    if (count) {
       __sync_fetch_and_add(count, 1);
    }
    return XDP_PASS;

}
char __license[] SEC("license") = "Dual MIT/GPL";
