#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/ip.h>
#include <net/ipv6.h>


struct net_device *dev;
static char v6prefixp[16]; 
#define V4ADDR_MAX_LEN 32
#define V6PREFIX_MAX_LEN 64



static struct nf_hook_ops netfilter_ops_out;

void in4_ntop(char * buf, int addr)
{
    sprintf(buf, "%d.%d.%d.%d", addr&0xff, (addr>>8)&0xff, (addr>>16)&0xff, (addr>>24)&0xff);
}

void in6_ntop(char * dst, const unsigned char * src)
{
    const int NS_IN6ADDRSZ = 16;
    const int NS_INT16SZ = 2;

    char tmp[40], *tp; // 40 - maximum size of expanded (no ::) IPv6 address
    struct { int base, len; } best, cur;
    u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
    int i;

        
        memset(words, '\0', sizeof words);
        for (i = 0; i < NS_IN6ADDRSZ; i += 2)
                words[i / 2] = (src[i] << 8) | src[i + 1];
        best.base = -1;
        cur.base = -1;
        cur.len = 1;
        best.len = 1;
	  for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
                if (words[i] == 0) {
                        if (cur.base == -1)
                                cur.base = i, cur.len = 1;
                        else
                                cur.len++;
                } else {
                        if (cur.base != -1) {
                                if (best.base == -1 || cur.len > best.len)
                                        best = cur;
                                cur.base = -1;
                        }
                }
        }
        if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len)
                        best = cur;
        }
        if (best.base != -1 && best.len < 2)
                best.base = -1;

        tp = tmp;
        for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
                if (best.base != -1 && i >= best.base &&
                    i < (best.base + best.len)) {
                        if (i == best.base)
                                *tp++ = ':';
                        continue;
                }
               
                if (i != 0)
                        *tp++ = ':';
                tp += sprintf(tp, "%x", words[i]);
        }
       
        if (best.base != -1 && (best.base + best.len) ==
            (NS_IN6ADDRSZ / NS_INT16SZ))
                *tp++ = ':';
        *tp++ = '\0';
        strcpy(dst, tmp);
}

void in6_ntop2(char * buf, const struct in6_addr * addr)
{
    in6_ntop(buf, (char *)&addr->s6_addr);
}



void ip6_update_csum(struct sk_buff * skb, struct ipv6hdr * ip6hdr)
{
    __wsum sum1=0;
    __sum16 sum2=0;
    __sum16 oldsum = 0;

    switch (ip6hdr->nexthdr)
    {
    case IPPROTO_TCP:
    {
        struct tcphdr *th = tcp_hdr(skb);
        unsigned tcplen = 0;
        oldsum = th->check;
        tcplen = ntohs(ip6hdr->payload_len); /* TCP header + payload */

        th->check = 0;
        sum1 = csum_partial((char*)th, tcplen, 0); /* calculate checksum for TCP hdr+payload */
        sum2 = csum_ipv6_magic(&ip6hdr->saddr, &ip6hdr->daddr, tcplen, ip6hdr->nexthdr, sum1); /* add pseudoheader */
printk(KERN_ALERT " Updating TCP (over IPv6) checksum to %x (old=%x)\n", htons(sum2), htons(oldsum) );
        th->check = sum2;
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = udp_hdr(skb);
        unsigned udplen = ntohs(ip6hdr->payload_len); /* UDP hdr + payload */

        oldsum = udp->check;
        udp->check = 0;

        sum1 = csum_partial((char*)udp, udplen, 0); /* calculate checksum for UDP hdr+payload */
        sum2 = csum_ipv6_magic(&ip6hdr->saddr, &ip6hdr->daddr, udplen, ip6hdr->nexthdr, sum1); /* add pseudoheader */

        printk(KERN_ALERT " Updating UDP (over IPv6) checksum to %x (old=%x)\n", htons(sum2), htons(oldsum) );
        udp->check = sum2;
break;
    }

    case IPPROTO_ICMP:
        break;
    }
}





void ipv4_update_csum(struct sk_buff * skb, struct iphdr *iph)
{
    __wsum sum1=0;
    __sum16 sum2=0;
    __sum16 oldsum=0;

    int iphdrlen = ip_hdrlen(skb);

    switch (iph->protocol)
    {
    case IPPROTO_TCP:
 {
        /* ripped from tcp_v4_send_check fro tcp_ipv4.c */
        struct tcphdr *th = tcp_hdr(skb);
        unsigned tcplen = 0;

        /* printk(KERN_ALERT "iph=%p th=%p copy->len=%d, th->check=%x iphdrlen=%d thlen=%d\n",
           iph, th, skb->len, ntohs(th->check), iphdrlen, thlen); */

        skb->csum = 0;
        skb->ip_summed = CHECKSUM_COMPLETE;

        // calculate payload
        oldsum = th->check;
        th->check = 0;
        tcplen = ntohs(iph->tot_len) - iphdrlen; /* skb->len - iphdrlen; (may cause trouble due to padding) */
        sum1 = csum_partial((char*)th, tcplen, 0); /* calculate checksum for TCP hdr+payload */
        sum2 = csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, iph->protocol, sum1); /* add pseudoheader */
        printk(KERN_ALERT " Updating TCP (over IPv4) checksum to %04x (oldsum=%04x)\n", htons(sum2), htons(oldsum));
th->check = sum2;

        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = udp_hdr(skb);
        unsigned udplen = 0;


        oldsum = udp->check;
        udp->check = 0;
        udplen = ntohs(iph->tot_len) - iphdrlen;

        sum1 = csum_partial((char*)udp, udplen, 0);
        sum2 = csum_tcpudp_magic(iph->saddr, iph->daddr, udplen, iph->protocol, sum1);
        udp->check = sum2;
        printk(KERN_ALERT " Updating UDP (over IPv4) checksum to %04x (oldsum=%04x)\n", htons(sum2), htons(oldsum) );

        break;
    }
 case IPPROTO_ICMP:
    {
        /* do nothing here. ICMP does not use pseudoheaders for checksum calculation. */
        break;
    }
    default:
        break;
    }
}


static int ipv6_nat_ipv4(struct sk_buff *skb)
{

	char  buf3[64], buf4[64];
	char v6saddr[16], v6daddr[16];
	int err = -1;
	int tclass = 0;
	int flowlabel = 0;
	int len;

	struct net_device *eth0=dev_get_by_name(&init_net, "eth0");
	struct ipv6hdr * hdr6;
	struct iphdr * hdr4 = ip_hdr(skb);
	struct sk_buff * copy = 0;
	char v6prefixps[64];
	strcpy(v6prefixps, "4001:4490::");
	in6_pton(v6prefixps, 64, v6prefixp, '\0', NULL);

	memcpy(v6saddr, v6prefixp, 16);
	memcpy(v6saddr+12, &hdr4->saddr, 4);
	in6_ntop(buf3, v6saddr);
	strcpy(buf4, "4001:4490::c0a8:105");
	in6_pton(buf4, V6PREFIX_MAX_LEN, v6daddr, '\0', NULL);

	if (ntohs(hdr4->tot_len) > 1480) {
		printk(KERN_ALERT "#Too large IPv4 (len=%d) received, dropped. such errors so far.\n",
		ntohs(hdr4->tot_len));
		return -1;
	}


	copy = skb_copy(skb, GFP_ATOMIC);
	pskb_expand_head(copy, 20, 0, GFP_ATOMIC);
	skb_push(copy, sizeof(struct ipv6hdr) - sizeof(struct iphdr));
	skb_reset_network_header(copy);
	skb_set_transport_header(copy,40);
	hdr6 = ipv6_hdr(copy);
	tclass = 0; /* traffic class */	
	*(__be32 *)hdr6 = htonl(0x60000000 | (tclass << 20)) | flowlabel; /* version, priority, flowlabel */
	hdr6->payload_len = htons(ntohs(hdr4->tot_len) - sizeof(struct iphdr)); /* IPv6 length is a payload length, IPv4 is hdr+payload */
	hdr6->nexthdr     = hdr4->protocol;
	hdr6->hop_limit   = hdr4->ttl;
	//hdr6->hop_limit   = 31;
	memcpy(&hdr6->saddr, v6saddr, 16);
	memcpy(&hdr6->daddr, v6daddr, 16);

	copy->priority = skb->priority;
	copy->mark     = skb->mark;
	copy->protocol = htons(ETH_P_IPV6);

	ip6_update_csum(copy, hdr6);
	copy->dev=eth0;
	ip6_route_input(copy);

	if (skb_dst(copy) == NULL) {
		printk(KERN_ALERT "#Unable to find route, IPv6 packet not sent (IPv6 route errors so far)\n");
		return -1;
	}
	if (dst_mtu(skb_dst(copy))==0) {
		printk(KERN_ALERT "#Route with mtu=0 found, IPv6 packet not sent (IPv6 route errors so far).\n");
	return -1;
	}
	err=dst_output(copy);
	if (err==0) {
		printk("packet send");
		/* packet sent successfully */
	} else {
		printk(KERN_ALERT "#IPv4->IPv6: Packet transmission (ip6_forward()) failed. \n");
	}

	return 0;
}






unsigned int main_hook(unsigned int hooknum,
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
	struct iphdr * hdr = ip_hdr(skb);
	char v4sadr[32], v4dadr[32];
	int allow_pkts=0;
	in4_ntop(v4sadr, hdr->saddr);
      in4_ntop(v4dadr, hdr->daddr);

	allow_pkts=strcmp(v4dadr, "172.29.0.1");
	if(allow_pkts==0){
		printk("IPv4 recieved SRC :- %s :: DST :- %s ", v4sadr, v4dadr);
		printk("\n");
		ipv6_nat_ipv4(skb);
		//kfree_skb(skb);
	}
	return NF_ACCEPT;

}


static int strt(void)
{
        netfilter_ops_out.hook=main_hook;
        netfilter_ops_out.pf=PF_INET;
//      netfilter_ops_out.hooknum=NF_INET_POST_ROUTING;
//      netfilter_ops_out.priority=NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops_out);
        return 0;
}

static void cleanup(void)
{
        nf_unregister_hook(&netfilter_ops_out);
       /*unregister NF_IP_POST_ROUTING hook*/
}


module_init(strt);
module_exit(cleanup);

