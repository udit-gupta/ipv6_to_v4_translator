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
	struct ipv6hdr * hdr = ipv6_hdr(skb);
	struct iphdr   * iph;
	char buf[64], buf1[64];
	__u32 v4saddr, v4daddr;
	struct net_device *eth1=dev_get_by_name(&init_net, "eth1");
	
	struct sk_buff * copyy = 0;
	int err = -1;
	strcpy(buf, "172.29.0.1");
	in4_pton(buf, V4ADDR_MAX_LEN, (u8 *)&v4saddr, '\0', NULL);
	v4daddr = *( (__u32*)&(hdr->daddr.s6_addr[12]) );
	copyy = skb_copy(skb, GFP_ATOMIC);
	skb_pull(copyy, sizeof(struct ipv6hdr) - sizeof(struct iphdr));
	skb_reset_network_header(copyy);
      skb_set_transport_header(copyy,20);
    /* build IPv4 header */
      iph = ip_hdr(copyy);

      iph->ttl      = hdr->hop_limit;
      iph->saddr    = v4saddr;
      iph->daddr    = v4daddr;
      iph->protocol = hdr->nexthdr;
      *((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (0x00/*tos*/ & 0xff));
      iph->frag_off = htons(IP_DF);
      iph->tot_len  = htons(skb->len-20);
      iph->check    = 0;
      iph->check    = ip_fast_csum((unsigned char *)iph, iph->ihl);
	copyy->protocol = htons(ETH_P_IP);
	ipv4_update_csum(copyy, iph);
	copyy->dev=eth1;
	err = ip_route_input(copyy, v4daddr, v4saddr, 0, copyy->dev);
	    if (err==0) {
		err=dst_output(copyy);

         if (err == 0) {
		printk("SENT\n");
        } else {
            printk(KERN_ALERT "#IPv6->IPv4: Unable to send packet (ip_forward failed)/n");
        }
    } else {
        printk(KERN_ALERT "# Unable to find route, packet dropped. (failed routes for IPv4 so far)\n");
    }

return 1;
}






unsigned int main_hook(unsigned int hooknum,
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
	struct ipv6hdr * hdr = ipv6_hdr(skb);
	char v6prefix[64], v6sadr[64], v6dadr[64];
	in6_ntop2(v6sadr, &hdr->saddr);
      in6_ntop2(v6dadr, &hdr->daddr);
      in6_ntop(v6prefix, v6prefixp);
	printk("IPv6 recieved SRC :- %s :: DST :- %s", v6sadr, v6dadr);
	ipv6_nat_ipv4(skb);
	//kfree_skb(skb);
	return NF_ACCEPT;
}



static int strt(void)
{
	netfilter_ops_out.hook=main_hook;
      netfilter_ops_out.pf=PF_INET6;
//    netfilter_ops_out.hooknum=NF_INET_POST_ROUTING;
//    netfilter_ops_out.priority=NF_IP_PRI_FIRST;
      nf_register_hook(&netfilter_ops_out);
 /* register NF_IP_POST_ROUTING hook */
      return 0;
}

static void cleanup(void)
{
        nf_unregister_hook(&netfilter_ops_out);
       /*unregister NF_IP_POST_ROUTING hook*/
}


module_init(strt);
module_exit(cleanup);

