#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

static inline __u16 csum_fold_helper(__u64 csum) {
	for(int i = 0; i < 4; i++) {
		if(csum >> 16) {
			csum = (csum & 0xffff) + (csum >> 16);
		}
	}

	return ~csum;
}

static inline __u16 iph_csum(struct iphdr* ipheader) {
	ipheader->check = 0;
	unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int*)ipheader, sizeof(struct iphdr), 0);
	
	return csum_fold_helper(csum);	
}