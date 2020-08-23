#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops nfho;
static unsigned int icmp_check(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct icmphdr *icmph;

  iph = ip_hdr(skb);
  icmph = icmp_hdr(skb);

  if (iph->protocol != IPPROTO_ICMP) {
    return NF_ACCEPT;
  }
  if (icmph->type != ICMP_ECHO) {
    return NF_ACCEPT;
  }

  printk(KERN_DEBUG
         "icmpshell: type=%d; code=%d\n",
         icmph->type,
         icmph->code);
  return NF_ACCEPT;
}

static int __init startup(void)
{
  printk(KERN_INFO "Loading icmpshell module\n");

  nfho.hook = icmp_check;
  nfho.hooknum = NF_INET_PRE_ROUTING;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FILTER;
  nf_register_net_hook(&init_net, &nfho);
  return 0;
}

static void __exit cleanup(void)
{
  nf_unregister_net_hook(&init_net, &nfho);
  printk(KERN_ALERT "Unloading icmpshell module\n");
}

MODULE_LICENSE("GPL");
module_init(startup);
module_exit(cleanup);
