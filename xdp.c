#include "xdp.h"

#define IP_ADDR(X) (unsigned int)(192 + (168 << 8) + (1 << 16) + (X << 24))

#define RESTRICTED_CLIENT 193

SEC("xdp/route")

int process_xdp(struct xdp_md* ctx) {
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	struct ethhdr* eth = data;

	if(data + sizeof(struct ethhdr) > data_end) {
		return XDP_ABORTED;
	}

	if(bpf_ntohs(eth->h_proto) != ETH_H_IP) {
		return XDP_PASS;
	}

	//parsing for source IP
	struct iphdr* iph = data + sizeof(struct ethhrd);
	if(data + sizeof(struct ethhrd) + sizeof(struct iphdr) > data_end) {
		return XDP_ABORTED;
	}

	bpf_printk("Received TCP packet from source %x", iph->saddr);
	if(iph->saddr == IP_ADDRESS(RESTRICTED_CLIENT)) {
		return XDP_DROP;
	}

	return XDP_PASS;
}