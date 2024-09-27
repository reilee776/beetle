#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


//unsigned int hook_in_func(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)

//unsigned int nf_conntrack_pre_routing( struct net * net, u_int8_t pf, unsigned int hooknum, struct sk_buff * skb)
unsigned int nf_conntrack_pre_routing(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{

	return 0;
}

//unsigned int nf_conntrack_local_out( struct net * net, u_int8_t pf, unsigned int hooknum, struct sk_buff * skb)
unsigned int nf_conntrack_local_out( void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{

        return 0;
}

//unsigned int nf_conntrack_post_routing_helper( struct net * net, u_int8_t pf, unsigned int hooknum, struct sk_buff * skb)
unsigned int nf_conntrack_post_routing_helper(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{

        return 0;
}

//unsigned int nf_conntrack_post_routing_confirm( struct net * net, u_int8_t pf, unsigned int hooknum, struct sk_buff * skb)
unsigned int nf_conntrack_post_routing_confirm( void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{

        return 0;
}

//unsigned int nf_conntrack_local_in_helper( struct net * net, u_int8_t pf, unsigned int hooknum, struct sk_buff * skb)
unsigned int nf_conntrack_local_in_helper( void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{

        return 0;
}

//unsigned int nf_conntrack_local_in_confirm( struct net * net, u_int8_t pf, unsigned int hooknum, struct sk_buff * skb)
unsigned int nf_conntrack_local_in_confirm( void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{

        return 0;
}

static struct nf_hook_ops ipv4_conntrack_ops[] __read_mostly = {
	{
		.hook 		= nf_conntrack_pre_routing,
		.pf 		= NFPROTO_IPV4,
		.hooknum 	= NF_INET_PRE_ROUTING,
		.priority 	= NF_IP_PRI_CONNTRACK,
	},
	{
		.hook           = nf_conntrack_local_out,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_LOCAL_OUT,
                .priority       = NF_IP_PRI_CONNTRACK,
	},
	{
		.hook           = nf_conntrack_post_routing_helper,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_POST_ROUTING,
                .priority       = NF_IP_PRI_CONNTRACK_HELPER,
	},
	{
		.hook           = nf_conntrack_post_routing_confirm,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_POST_ROUTING,
                .priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
	},
	{
		.hook           = nf_conntrack_local_in_helper,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_LOCAL_IN,
                .priority       = NF_IP_PRI_CONNTRACK_HELPER,
	},
	{
		.hook           = nf_conntrack_local_in_confirm,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_LOCAL_IN,
                .priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
	},
};

static int __init nd_nix_filter_init(void)
{

	return 0;
}

static void __exit nd_nix_filter_exit(void)
{

}


module_init(nd_nix_filter_init);
module_exit(nd_nix_filter_exit);
MODULE_LICENSE("GPL");

