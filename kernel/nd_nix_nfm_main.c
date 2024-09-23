/*
 * ==========================================================================
 * nd_nix_nfm
 * COPYRIGHTⓒ NETAND, ALL RIGHTS RESERVE
 * ==========================================================================
 */


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
#include <linux/in.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <net/netns/generic.h>
#include <net/net_namespace.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/pid_namespace.h>

#include <linux/ioctl.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/wait.h>
/*
*/
#include "nd_nix_nfm_common.h"

#include "libsrc/nd_nix_util_str.h"
#include "libsrc/nd_nix_rules.h"
#include "libsrc/nd_nix_log.h"

#define DRIVER_AUTH "Saber-toothed cat <pingye@netand.co.kr>"
#define DRIVER_DESC "NETAND's network filtering driver that runs on Linux"

#define NETLINK_USER 31

#define _SUPP_SRCIP_IN_RULE

static const char *module_version = "1.0.0"; 

struct nd_service_rule_data_new 	nd_list_service_rules_new;

static void nd_nix_hook_recv_cmd( struct sk_buff * skb);

/*
static DEFINE_RAW_SPINLOCK(nd_list_lock);
*/

#define PORT_TABLE_SIZE 256 //
static struct hlist_head port_table[PORT_TABLE_SIZE];

#define MODE_ON 	1
#define MODE_OFF	0
#define MODE_WARN	2

static const unsigned int MINOR_BASE = 0;
static const unsigned int MINOR_NUM = 1;

#define NOD_MAJOR 100

wait_queue_head_t log_wait_queue = __WAIT_QUEUE_HEAD_INITIALIZER(log_wait_queue);

static struct class *chardev_class = NULL;

struct log_entry log_list;

//LIST_HEAD(log_list);
DEFINE_MUTEX(log_mutex);

char g_ndlog_buffer[1024];

static int nd_major_number; 

struct rb_root nd_log_tree = RB_ROOT;
int nd_log_count = 0;
int nd_log_index = 0;

struct ns_data {
	struct sock *sk;
};

/*
 *
 */
unsigned int g_nLkmMode = 0;


/*
 *
 */
struct rule_list 	nd_rules;
struct session_list 	nd_sessions;

char *log_buffer[MAX_LOGS];


//struct sock		*nl_sk = NULL;

static unsigned int 	net_id;

unsigned int	session_m_cnt = 0;

static inline unsigned int hash_function(__be32 protocol, unsigned short port) {
	return (hash_32((unsigned long)(protocol ^ port), HASH_BITS(port_table))) % PORT_TABLE_SIZE;
}

size_t get_port_info_count(void) {
        size_t count = 0;
        struct port_info *info;
        unsigned long index;

        hash_for_each(port_table, index, info,node) {
                count++;
        }

        return count;
}


void save_port_info(__be32 protocol, unsigned short new_port) {
	struct port_info *info;
    	unsigned int index = hash_function(protocol, new_port);

    	info = kmalloc(sizeof(struct port_info), GFP_KERNEL);
    	if (!info) {
        	printk(KERN_ERR "Failed to allocate memory for port_info\n");
        	return;
    	}

    	info->protocol = protocol;
    	info->sport = new_port;

	hlist_add_head(&info->node, &port_table[index]);
	session_m_cnt ++;
}

bool check_port_info(__be32 protocol, unsigned short port) {
        struct port_info *info;
        struct hlist_node *tmp;
        unsigned int index = hash_function(protocol, port);
        hlist_for_each_entry_safe(info, tmp, &port_table[index], node) {
                if (info->protocol == protocol && info->sport == port) {
                        return true;
                }
        }
        return false;
}

bool remove_port_info(__be32 protocol, unsigned short port) {
    	struct port_info *info;
    	struct hlist_node *tmp;
    	unsigned int index = hash_function(protocol, port);
    	hlist_for_each_entry_safe(info, tmp, &port_table[index], node) {
        	if (info->protocol == protocol && info->sport == port) {
            		hlist_del(&info->node);
            		kfree(info);
			session_m_cnt --;
            		return true;
        	}
    	}
	return false;
}

/*
 *
 */
int nd_create_drop_except(void)
{
	struct nd_drop_except_rule_data *drop_except_rule_data;
	drop_except_rule_data = kmalloc (sizeof (struct nd_drop_except_rule_data), GFP_KERNEL );
	if (!drop_except_rule_data)
		return -1;

	return 0;
}


/*
 *
 */
struct nd_drop_rule_data *nd_create_default_drop(void)
{
        struct nd_drop_rule_data *drop_rule_data;

        drop_rule_data = kmalloc(sizeof (struct nd_drop_rule_data), GFP_KERNEL );
        if (!drop_rule_data)
                return NULL;

	return drop_rule_data;
}


/*
 *
 */
int nd_create_drop(void)
{
	struct nd_drop_rule_data *drop_rule_data;

	drop_rule_data = kmalloc(sizeof (struct nd_drop_rule_data), GFP_KERNEL );
	if (!drop_rule_data)
		return -1;

	return 0;
}


/*
 *
 */
int nd_create_fake_except(void)
{
	struct nd_fake_except_rule_data *fake_except_rule_data;
	
	fake_except_rule_data = kmalloc(sizeof (struct nd_fake_except_rule_data), GFP_KERNEL );
	if (!fake_except_rule_data)
		return -1;

	return 0;
}


/*
 *
 */
struct nd_fake_rule_data* nd_create_default_fake(void)
{
        struct nd_fake_rule_data *fake_rule_data;

        fake_rule_data = kmalloc(sizeof(struct nd_fake_rule_data), GFP_KERNEL );
        if (!fake_rule_data)
                return NULL;

	return fake_rule_data;
}


/*
 *
 */
int nd_create_fake(void)
{
	struct nd_fake_rule_data *fake_rule_data;
	
	fake_rule_data = kmalloc(sizeof(struct nd_fake_rule_data), GFP_KERNEL );
	if (!fake_rule_data)
		return -1;

	return 0;
}


/*
 *
 */
static void nd_nix_hook_recv_cmd( struct sk_buff * skb);

/*
 *
 */
static void nd_nix_hook_recv_cmd( struct sk_buff * skb)
{
	struct nlmsghdr *nlh;
	struct net 	*net;
	struct ns_data 	*_data;
	int 		pid, res,ret;
	struct sk_buff 	*skb_out;
	struct nd_cmd_data data, *recvdata;
	struct cmd_service_rule_pars_data *cmd_service_rule_pars;
	
	nlh = (struct nlmsghdr*)skb->data;
	recvdata = (struct nd_cmd_data*)nlmsg_data(nlh);
	data.cmd = recvdata->cmd;

	switch(recvdata->cmd)
	{
		case ND_CMD_MODE_ON:
			printk("[RECV] MOD ON - Activate kernel operation...\n");
			g_nLkmMode = MODE_ON;
			sprintf(data.data, "%d", g_nLkmMode);
		break;

		case ND_CMD_MODE_OFF:
			printk("[RECV] MOD OFF - Unactivate kernel operation...\n");
			g_nLkmMode = MODE_OFF;
			sprintf(data.data, "%d", g_nLkmMode);
		break;

		case ND_CMD_MODE_WARN:
			printk("[RECV] MOD WARN - Unactivate kernel operation...\n");
			g_nLkmMode = MODE_WARN;
			sprintf(data.data, "%d", g_nLkmMode);
		break;
	
		case ND_CMD_MODE_GET:
			printk("[RECV] MOD GET - Get the current operating mode status...\n");
			
			sprintf(data.data, "%d", g_nLkmMode);
		break;

		case ND_CMD_RULE_ADD:
			printk("[RECV] RULE ADD - Add a service policy using new information requested by the administrator. [%s]..\n", recvdata->data);
			cmd_service_rule_pars = kmalloc (sizeof (struct cmd_service_rule_pars_data), GFP_KERNEL);
			if (cmd_service_rule_pars == NULL)	
			{
				printk("operation failed - Memory dynamic allocation operation failed.\n");
				break;
			}

			
			ret= nd_get_struct_data_by_type (recvdata->data, cmd_service_rule_pars);
			if (ret != 0 )		{
				printk ("operation failed - Data parsing operation failed\n");
				
				if (cmd_service_rule_pars)
					kfree (cmd_service_rule_pars);

				break;
			}

			switch (cmd_service_rule_pars->rule_type)
			{
				case INDX_RULE_TYPE_SERVICE:

					ret = nd_add_service(cmd_service_rule_pars->service, cmd_service_rule_pars->forward, cmd_service_rule_pars->rule_type, cmd_service_rule_pars->data);
					if (ret == 0 )		{
						printk ("Successfully added policy - Service name [%u] has been added...\n", cmd_service_rule_pars->service );
					}
				break;

				case INDX_RULE_TYPE_FAKEEXCEPT:

					//ret = nd_add_fakeExcept_in_service_rule(cmd_service_rule_pars->service, cmd_service_rule_pars->data);
					if (ret == 0 )          {
                                                printk ("Successfully added policy - Added exception policy %u included in service name %u.\n",cmd_service_rule_pars->data, cmd_service_rule_pars->service );
                                        }

				break;

				case INDX_RULE_TYPE_SOURCEIPS:

					//ret = nd_add_sourceip_in_service_rule(cmd_service_rule_pars->service, cmd_service_rule_pars->data);
					if (ret == 0 )		{
						printk ("Successfully added policy - Added ipaddress policy %u included in service name %u.\n",cmd_service_rule_pars->data, cmd_service_rule_pars->service );
					}
				break;

				case INDX_RULE_TYPE_DROPEXCEPT:

					ret = nd_add_dropExcept_in_service_rule(cmd_service_rule_pars->service, cmd_service_rule_pars->data);
					if (ret == 0 )		{
						printk ("Successfully added policy - Added exception policy %u included in service name %u.\n",cmd_service_rule_pars->data, cmd_service_rule_pars->service );
					}
				break;
			}
			
			if (cmd_service_rule_pars)	
				kfree (cmd_service_rule_pars);
		break;

		case ND_CMD_RULE_DEL:

			cmd_service_rule_pars = kmalloc (sizeof (struct cmd_service_rule_pars_data), GFP_KERNEL);
                        if (cmd_service_rule_pars == NULL)
                        {
                                printk("operation failed - Memory dynamic allocation operation failed.\n");
                                break;
                        }


                        ret= nd_get_struct_data_by_type (recvdata->data, cmd_service_rule_pars);
                        if (ret != 0 )          {
                                printk ("operation failed - Data parsing operation failed\n");
                        }

			switch (cmd_service_rule_pars->rule_type)
                        {
				case INDX_RULE_TYPE_SERVICE:

					ret = nd_del_service(cmd_service_rule_pars->service);
					if (ret == 0 )		{
						printk ("Successfully deleted policy - Service name [%u] has been deleted...\n", cmd_service_rule_pars->service );
					}
					
				break;

				case INDX_RULE_TYPE_FAKEEXCEPT:

					//ret = nd_del_fakeExcept_in_service_rule(cmd_service_rule_pars->service, cmd_service_rule_pars->data);
					if (ret == 0 )		{
						printk ("Successfully deleted policy - deleted exception %u included in service name %u\n",cmd_service_rule_pars->data, cmd_service_rule_pars->service );
					}
				break;

				case INDX_RULE_TYPE_SOURCEIPS:

					//ret = nd_del_sourceip_in_service_rule(cmd_service_rule_pars->service, cmd_service_rule_pars->data);
					if (ret == 0 )		{
						printk ("Successfully deleted policy - deleted exception %u included in service name %u\n",cmd_service_rule_pars->data, cmd_service_rule_pars->service );

					}

				case INDX_RULE_TYPE_DROPEXCEPT:

					//ret = nd_del_dropExcept_in_service_rule(cmd_service_rule_pars->service, cmd_service_rule_pars->data);
					if (ret == 0 )          {
                                                printk ("Successfully deleted policy - deleted exception %u included in service name %u\n",cmd_service_rule_pars->data, cmd_service_rule_pars->service );
                                        }

				break;
			}


			if (cmd_service_rule_pars)
				kfree (cmd_service_rule_pars);
				
		break;

		case ND_CMD_RULE_RESET:
			printk("[RECV] RESET - Delete all data being added...\n");
			
			ret = nd_nfm_del_default_all_rule();
			if (ret == 0)		{
				sprintf (data.data, "All successfully registered policies have been reset.");
			}
			else
			{
				sprintf (data.data, "The policy reset operation has failed.");
			}

		break;

		case ND_CMD_RULE_GET:

			cmd_service_rule_pars = kmalloc (sizeof (struct cmd_service_rule_pars_data), GFP_KERNEL);
                        if (cmd_service_rule_pars == NULL)
                        {
                                printk("operation failed - Memory dynamic allocation operation failed.\n");
                                break;
                        }

                        ret= nd_get_struct_data_by_type (recvdata->data, cmd_service_rule_pars);
                        if (ret != 0 )          {
                                //printk ("operation failed - Data parsing operation failed\n");
				//nd_nfm_get_rule_info(cmd_service_rule_pars->service, 0, data.data);
				break;
                        }

			switch (cmd_service_rule_pars->rule_type)
                        {
                                case INDX_RULE_TYPE_SERVICE:
					//nd_nfm_get_rule_info(cmd_service_rule_pars->service, 0, data.data);

				break;

				case INDX_RULE_TYPE_FAKEEXCEPT:
				
				break;

				case INDX_RULE_TYPE_DROPEXCEPT:

				break;
			}

			if (cmd_service_rule_pars)
                                kfree (cmd_service_rule_pars);


		break;

		case ND_CMD_RULE_SEARCH:
			printk("[RECV] RESET - Search rule...\n");
			
		break;
	}
	
	pid = nlh->nlmsg_pid;
	net = get_net_ns_by_pid(pid);

	_data = net_generic(net, net_id);
	if (_data == NULL || _data->sk == NULL)		{
		return ;
	}

	skb_out = nlmsg_new(sizeof(data), 0);
	if (!skb_out)
	{
		printk("Failed to allocate new skb\n");
		return;
	}

	nlh = nlmsg_put(skb_out, 0,0, NLMSG_DONE, sizeof(data), 0 );
	NETLINK_CB(skb_out).dst_group = 0;
	memcpy(nlmsg_data(nlh), &data, sizeof(data));
	res = nlmsg_unicast(_data->sk, skb_out, pid);
	if (res < 0 )
		printk ("Error while sending bak to user\n");
}

static long nd_device_ioctl (struct file *file, unsigned int cmd, unsigned long arg)	{

	int ret = 0, i = 0;
	char *logs;
	struct cmd_service_rule_pars_data cmd_service_rule_pars;
	struct cmd_service_sub_rule_pars_data cmd_service_subrule_pars; 
	//struct cmd_sub_rule_pars_data cmd_service_subrule_pars;

	static char data[MAX_STRING_LENGTH];
	
	struct nd_cmd_data cmd_data;
	char cmd_str_data[MAX_STRING_LENGTH] = {0,};
	char log_buffer[MAX_LOGS * LOG_MSG_SIZE];

	switch (cmd)		{
		case IOCTL_GET_CONNECTSESSIONCNT:
			sprintf (cmd_str_data,"%d", session_m_cnt);
			if (copy_to_user ((char __user *)arg, cmd_str_data, strlen(cmd_str_data) + 1))	{
				return -EFAULT;
			}
			printk ("now managed  connect session count [%s]\n", cmd_str_data);
		break;
		case IOCTL_GET_VERSION:
			if (copy_to_user ((char __user *)arg, module_version, strlen(module_version) +1))	{
				return -EFAULT;
			}
		break;

		case IOCTL_ON_MODE:
			printk("[RECV] MOD ON - Activate kernel operation...\n");
			if (g_nLkmMode != MODE_ON)
                        	g_nLkmMode = MODE_ON;
		break;

		case IOCTL_OFF_MODE:
			printk("[RECV] MOD OFF - Activate kernel operation...\n");
			if (g_nLkmMode != MODE_OFF)
                        	g_nLkmMode = MODE_OFF;
		break;

		case IOCTL_GET_MODE:
			printk("[RECV] GET MODE...\n");
			sprintf (cmd_str_data, "%s", (g_nLkmMode == MODE_ON)? "MODE_ON": "MODE_OFF");
			if (copy_to_user((char __user *)arg, cmd_str_data, strlen(cmd_str_data) +1))      {
                                return -EFAULT;
                        }
			printk ("now mode is [%s] ..\n", cmd_str_data);

		break;

		case IOCTL_ADD_SERVICE_POLICY:
			printk ("[RECV] ADD - IOCTL_ADD_SERVICE_POLICY...\n");

			if (copy_from_user(&cmd_service_rule_pars, (struct cmd_service_rule_pars_data*)arg, sizeof (struct cmd_service_rule_pars_data)))     {
				return -EFAULT;
			}
			
			ret = nd_add_service(cmd_service_rule_pars.service, cmd_service_rule_pars.forward, cmd_service_rule_pars.rule_type, cmd_service_rule_pars.data);
			if (ret == 0 )          {
				printk ("Successfully added policy - Service name [%u] has been added...\n", cmd_service_rule_pars.service );
				cmd_service_rule_pars.ret = ret;
			}
			else
			{
				cmd_service_rule_pars.ret = ret;
			}
			
			if (copy_to_user((struct cmd_service_rule_pars_data *)arg, &cmd_service_rule_pars, sizeof(cmd_service_rule_pars)))	{
				return -EINVAL;
			}
		break;
		
		case IOCTL_ADD_FAKEEXCEPT_POLICY:
			if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data*)arg, sizeof (struct cmd_service_sub_rule_pars_data)))     {
				return -EFAULT;
			}		

			ret = nd_add_fakeExcept_in_service_rule(cmd_service_subrule_pars.service, cmd_service_subrule_pars.type, cmd_service_subrule_pars.saddr, cmd_service_subrule_pars.eaddr);
			if (ret == 0 )          {
				printk ("Successfully added policy - Added exception policy included in service name %u.\n", cmd_service_subrule_pars.service );
			}

			cmd_service_subrule_pars.ret = ret;

			if (copy_to_user((struct cmd_service_sub_rule_pars_data *)arg, &cmd_service_subrule_pars, sizeof(cmd_service_subrule_pars)))      {
                                return -EINVAL;
                        }


		break;

		case IOCTL_ADD_SOURCEIPS_POLICY:
			if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data*)arg, sizeof (struct cmd_service_sub_rule_pars_data)))     {
                                return -EFAULT;
                        }
#ifdef ND_SUPP_RULE_IPRANGE
			ret = nd_add_sourceip_in_service_rule(cmd_service_subrule_pars.service, cmd_service_subrule_pars.type, cmd_service_subrule_pars.saddr, cmd_service_subrule_pars.eaddr);
#else
			ret = nd_add_sourceip_in_service_rule(cmd_service_rule_pars->service, cmd_service_rule_pars->data);
#endif
                        if (ret == 0 )          {
				printk ("Successfully added policy - Added ipaddress policy %u included in service name %u.\n",cmd_service_rule_pars.data, cmd_service_rule_pars.service );
			}

		break;

		case IOCTL_ADD_DROPEXCEPT_POLICY:
			 ret = nd_add_dropExcept_in_service_rule(cmd_service_rule_pars.service, cmd_service_rule_pars.data);
                         if (ret == 0 )          {
                               printk ("Successfully added policy - Added exception policy %u included in service name %u.\n",cmd_service_rule_pars.data, cmd_service_rule_pars.service );
                         }

		break;

		case IOCTL_MOD_SERVICE_POLICY:
			if (copy_from_user(&cmd_service_rule_pars, (struct cmd_service_rule_pars_data*)arg, sizeof (struct cmd_service_rule_pars_data)))     {
                                return -EFAULT;
                        }

			ret = nd_mod_service_to_index(&cmd_service_rule_pars);
			if (ret == 0)		{
				printk ("Successfully moded policy - Service name [%u] has been moded...\n", cmd_service_rule_pars.service);
			}

		break;

		case IOCTL_MOD_FAKEEXCEPT_POLICY:
			if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data*)arg, sizeof (struct cmd_service_sub_rule_pars_data)))     {
                                return -EFAULT;
                        }

			ret = nd_mod_fakeExcept_in_service_rule_to_index(&cmd_service_subrule_pars);
			if (ret == 0 )		{
				printk ("Successfully moded policy - exception policy has been modified...\n");
			}

		break;

		case IOCTL_MOD_SOURCEIPS_POLICY:
			if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data*)arg, sizeof (struct cmd_service_sub_rule_pars_data)))     {
                                return -EFAULT;
                        }

			ret = nd_mod_sourceIp_in_service_rule_to_index(&cmd_service_subrule_pars);
                        if (ret == 0 )          {
	
                                printk ("Successfully moded policy - sourceips policy has been modified...\n");
                        }
		break;

		case IOCTL_MOD_DROPEXCEPT_POLICY:
			if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data*)arg, sizeof (struct cmd_service_sub_rule_pars_data)))     {
                                return -EFAULT;
                        }

		break;

		case IOCTL_DEL_SERVICE_POLICY:

			if (copy_from_user(&cmd_service_rule_pars, (struct cmd_service_rule_pars_data*)arg, sizeof (cmd_service_rule_pars)))     {
                                return -EFAULT;
                        }
			
			ret = nd_del_service(cmd_service_rule_pars.service);
                        if (ret == 0 )          {
 	                       printk ("Successfully deleted policy - Service name [%u] has been deleted...\n", cmd_service_rule_pars.service );
                        }
		break;

		case IOCTL_DEL_FAKEEXCEPT_POLICY:
			if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data*)arg, sizeof (struct cmd_service_sub_rule_pars_data)))     {
                                return -EFAULT;
                        }
			
			ret = nd_del_fakeExcept_in_service_rule(cmd_service_subrule_pars.service, cmd_service_subrule_pars.type, cmd_service_subrule_pars.saddr, cmd_service_subrule_pars.eaddr);
			if (ret == 0 )          {
	                        printk ("Successfully deleted policy - deleted exception included in service name %u\n",cmd_service_subrule_pars.service );
			}
		break;

		case IOCTL_DEL_SOURCEIPS_POLICY:
			if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data*)arg, sizeof (struct cmd_service_sub_rule_pars_data)))     {
                                return -EFAULT;
                        }
			
			ret = nd_del_sourceip_in_service_rule(cmd_service_subrule_pars.service, cmd_service_subrule_pars.type, cmd_service_subrule_pars.saddr, cmd_service_subrule_pars.eaddr);
                        if (ret == 0 )          {
	                        printk ("Successfully deleted policy - deleted exception %u included in service name %u\n",cmd_service_subrule_pars.saddr, cmd_service_subrule_pars.service );
                        }

		
		break;

		case IOCTL_DEL_DROPEXCEPT_POLICY:
			if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data*)arg, sizeof (struct cmd_service_sub_rule_pars_data)))     {
                                return -EFAULT;
                        }

			ret = nd_del_dropExcept_in_service_rule(cmd_service_rule_pars.service, cmd_service_rule_pars.data);
                        if (ret == 0 )          {
	                        printk ("Successfully deleted policy - deleted exception %u included in service name %u\n",cmd_service_rule_pars.data, cmd_service_rule_pars.service );
                        }

		break;

		case IOCTL_MOD_POLICY:
			if (copy_from_user(&cmd_data, (struct nd_cmd_data*)arg, sizeof (cmd_data)))     {
                                return -EFAULT;
                        }

			printk ("nd_device_ioctl :: IOCTL_MOD_POLICY RECV DATA(%s)\n", cmd_data.data);
		break;

		case IOCTL_GET_SERVICE_POLICY_INDEX:
			if (copy_from_user(&cmd_service_rule_pars, (struct cmd_service_rule_pars_data*)arg, sizeof (cmd_service_rule_pars)))     {
                                return -EFAULT;
                        }

                        ret = nd_nfm_get_service_rule_index(&cmd_service_subrule_pars);

                        cmd_service_subrule_pars.ret = ret;
                        if (copy_to_user((struct cmd_service_sub_rule_pars_data *)arg, &cmd_service_subrule_pars, sizeof(cmd_service_subrule_pars)))      {
                                return -EINVAL;
                        }
                break;


		case IOCTL_GET_FAKEEXCEPT_POLICY_INDEX:
			if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data*)arg, sizeof (struct cmd_service_sub_rule_pars_data)))     {
                                return -EFAULT;
                        }
			
			ret = nd_nfm_get_fakeExcept_rule_index(&cmd_service_subrule_pars);
			
			cmd_service_subrule_pars.ret = ret;
			if (copy_to_user((struct cmd_service_sub_rule_pars_data *)arg, &cmd_service_subrule_pars, sizeof(cmd_service_subrule_pars)))      {
                                return -EINVAL;
                        }
		break;

		case IOCTL_GET_SOURCEIPS_POLICY_INDEX:
			if (copy_from_user(&cmd_service_subrule_pars, (struct cmd_service_sub_rule_pars_data*)arg, sizeof (struct cmd_service_sub_rule_pars_data)))     {
                                return -EFAULT;
                        }

                        ret = nd_nfm_get_sourceIp_rule_index(&cmd_service_subrule_pars);

                        cmd_service_subrule_pars.ret = ret;
                        if (copy_to_user((struct cmd_service_sub_rule_pars_data *)arg, &cmd_service_subrule_pars, sizeof(cmd_service_subrule_pars)))      {
                                return -EINVAL;
                        }

		break;

		case IOCTL_GET_POLICY:

			nd_nfm_get_rule_info(data);

			if (copy_to_user((char __user*)arg, data, sizeof (data))) {
				return -EFAULT;
			}			
		break;

		case IOCTL_GET_SERVICE_POLICY:
			if (copy_from_user(&cmd_str_data, (char __user *)arg, MAX_STRING_LENGTH))	{

				return -EFAULT;
			}

			nd_nfm_get_service_rules(cmd_str_data);

			if (copy_to_user((char __user *)arg, cmd_str_data, sizeof (cmd_str_data)))	{
				return -EFAULT;
			}
		break;

		case IOCTL_GET_FAKEEXCEPT_POLICY:
			if (copy_from_user(&cmd_str_data, (char __user *)arg, MAX_STRING_LENGTH))	{
				return -EFAULT;
			}

			nd_nfm_get_fakeexcept_rules(cmd_str_data);

			if (copy_to_user((char __user*)arg, cmd_str_data, sizeof(cmd_str_data)))	{
				return -EFAULT;
			}
	
		break;

		case IOCTL_GET_SOURCEIPS_POLICY:
		break;

		case IOCTL_GET_DROPEXCEPT_POLICY:
		break;

		case IOCTL_RESET_POLICY:
			printk ("[RECV] RESET - Delete all data being added...\n");
			
			ret = nd_nfm_del_default_all_rule();
			if (ret == 0 )	{
				printk ("nd_device_ioctl :: All successfully registered olicies have been reset.");
			}
			else		{
				printk ("nd_device_ioctl :: The policy reset operation has failed.");
			}	

		break;

		case IOCTL_GET_LOG:
			printk ("[RECV] GETLOG - Get kernel log \n");
#ifdef _LOG_SUPP
			/*			
			//ret = get_logs((char __user *)arg, sizeof(log_buffer));
			ret = get_logs(log_buffer);
			if (ret < 0 )	{
				printk ("get_log :: failed to get logs...");
			}
			*/
			logs = kmalloc((1024 * 256), GFP_KERNEL);
			if (!logs)	return -EINVAL;
			
			for (i = 0 ; i < nd_log_count ; i ++ )		{
				snprintf (logs + (i * LOG_SIZE), LOG_SIZE, "%s\n", log_buffer[(nd_log_index+i) % MAX_LOGS]);
			}
			

			if (copy_to_user ((char __user*)arg, logs, MAX_LOGS * LOG_SIZE))		{
		
				return -EFAULT;
			}
			kfree (logs);

			for (i = 0; i < nd_log_count ; i ++ )
			{
				kfree (log_buffer[i]);
				log_buffer[i] = NULL;
			}

			nd_log_count = 0;

#endif
		default:
			return -EINVAL;

	}

	return 0;
}

static int nd_ioctl_open(struct inode * inode, struct file *file)
{
	return 0;
}

static int nd_ioctl_close(struct inode *inode, struct file *file)
{
	return 0;
}

/*
 *
 */
unsigned int nd_nix_hook_inbound_func(void * priv, struct sk_buff * skb, const struct nf_hook_state * state )
{
	unsigned char 	*h;
	struct tcphdr 	*tcph;
	struct tcphdr *tcp_header;
	uint16_t 	sport 	= 0, 
			dport 	= 0, 
			datalen = 0;
	int 		nChkRuleResult = ND_ACT_FLOWRULE_NOTFOUND;
	
	struct nd_packets_applied_to_policy *collect_data;
	struct nd_5tuple_data current_5tuple;
	struct iphdr * iph = (struct iphdr*) skb_network_header(skb);

	if (g_nLkmMode != MODE_ON)
	{
		goto InboundExit;
	}

	switch (iph->protocol)		{
		case IPPROTO_TCP:
		{

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0) )
			if (likely(skb_transport_header(skb) == (unsigned char *)iph )) )			{
				printk ("transport_header is not set for kernel 0x%x\n", LINUX_VERSION_CODE);
#else
			if (!skb_transport_header_was_set(skb))							{
#endif
				h = (unsigned char *)iph + (iph->ihl << 2 );
			}
			else
			{
				h = skb_transport_header(skb);
			}

			tcph = (struct tcphdr *)h;
                        sport = (unsigned int)ntohs(tcph->source);
                        dport = (unsigned int)ntohs(tcph->dest);

			memset (&current_5tuple, 0x00, sizeof (current_5tuple));
			current_5tuple.sport = sport;
			current_5tuple.dport = dport;
			current_5tuple.saddr = iph->saddr;
			current_5tuple.daddr = iph->daddr;
			current_5tuple.hook  = state->hook;

#ifdef _SUPP_SRCIP_IN_RULE
			collect_data = (struct nd_packets_applied_to_policy*)kmalloc (sizeof (struct nd_packets_applied_to_policy),GFP_KERNEL); 
			nChkRuleResult =  nd_nfm_comfirm_the_policy_for_incoming_packet(current_5tuple, &collect_data);
			if ( dport != 22)	{
				//printk ("[inbound] source ip:%pI4(%u),dest ip: %pI4(%u), sport: %u,  dport : %u , result = %d\n", &iph->saddr,iph->saddr, &iph->daddr,iph->daddr, sport, dport, nChkRuleResult);
			}
			
			if (nChkRuleResult == ND_ACT_FLOWRULE_APPLY)	{
				//printk ("source address : %u/%u\n", htons(iph->saddr), iph->saddr);
#else

			nChkRuleResult = nd_nfm_chk_rule_v2(current_5tuple, &fakeport);
			if (nChkRuleResult == ND_POLICY_APPLY)		{

#endif
				if (    iph->saddr == ND_LOOPBACK &&
                                        iph->daddr == ND_LOOPBACK
                                )       {

                                        if (collect_data)
                                                kfree (collect_data);

                                        goto InboundExit;
                                }
				
				if (tcph->rst ||tcph->fin)	{
					if(check_port_info(skb->protocol, sport) == true)
					{
						remove_port_info(skb->protocol, sport);
					}
				}
				else 
				{
					if(check_port_info(skb->protocol, sport) == false)
					{
						save_port_info(skb->protocol, sport);
					}
				}
				
#ifdef _SUPP_SRCIP_IN_RULE	
				printk ("[inbound packet] [nd_nix_nfm] forwarding destination port [%u] -> [%u].\n", ntohs(tcph->dest),collect_data->forwardport);
	
				tcph->dest	= htons(collect_data->forwardport);
#else
				tcph->dest 	= htons(fakeport);
#endif
				datalen		= skb->len - iph->ihl*4;

				tcph->check	= 0;
				tcph->check	= tcp_v4_check( datalen, iph->saddr, iph->daddr, csum_partial((char*)tcph, datalen,0));
			}
#ifdef _SUPP_SRCIP_IN_RULE
			if (collect_data)
				kfree (collect_data);
#endif
		
			break;
		}

		case IPPROTO_UDP:
		{
			break;
		}

		default:
		{
			break;
		}
	};
	
InboundExit:
	
	return NF_ACCEPT;
} 


/*
 *
 */
unsigned int nd_nix_hook_outbound_func(void * priv, struct sk_buff * skb, const struct nf_hook_state * state )
{
	struct tcphdr 	*tcph;
	struct iphdr    *iph;
        uint16_t 	sport = 0, dport = 0;
        uint16_t 	datalen = 0;
	int nChkRuleResult = 0;

	struct nd_packets_applied_to_policy *collect_data;
	struct nd_5tuple_data current_5tuple;

        if (g_nLkmMode != MODE_ON)
        {
                return NF_ACCEPT;
        }

	iph = (struct iphdr *)skb_network_header(skb);

	switch (iph->protocol) {
                case IPPROTO_TCP:
                {
                        tcph = (struct tcphdr *)skb_transport_header(skb);
                        sport = (unsigned int)ntohs(tcph->source);
                        dport = (unsigned int)ntohs(tcph->dest);
			
			current_5tuple.sport = sport;
                        current_5tuple.dport = dport;
                        current_5tuple.saddr = iph->saddr;
                        current_5tuple.daddr = iph->daddr;
                        current_5tuple.hook  = state->hook;
#ifdef _SUPP_SRCIP_IN_RULE
                        collect_data = (struct nd_packets_applied_to_policy*)kmalloc (sizeof (struct nd_packets_applied_to_policy),GFP_KERNEL);
                        nChkRuleResult =  nd_nfm_comfirm_the_policy_for_incoming_packet(current_5tuple, &collect_data);
			/*
			if (sport != 22 )
				printk ("[outbound] source ip:%pI4(%u), dest ip: %pI4(%u),sport : %u,  dport : %u , result = %d\n", &iph->saddr,iph->saddr, &iph->daddr,iph->saddr, sport, dport, nChkRuleResult);
			*/
			
                        if (nChkRuleResult == ND_ACT_FLOWRULE_APPLY)    {
#else
			nChkRuleResult = nd_nfm_chk_rule_v2(current_5tuple, &fakeport);
			if (nChkRuleResult == ND_POLICY_APPLY)          {
#endif
			
				if (    iph->saddr == ND_LOOPBACK &&
                                        iph->daddr == ND_LOOPBACK
                                )       {

                                        if (collect_data)
                                                kfree (collect_data);

                                        goto Exit_function;
                                }
				
				if (check_port_info(skb->protocol, dport) == false)
				{
					if (collect_data)
						kfree (collect_data);

					goto Exit_function;
				}
				else 
				{
					if (tcph->rst ||tcph->fin )
					{
                                                remove_port_info(skb->protocol, dport);			
					}
				}
			
#ifdef _SUPP_SRCIP_IN_RULE
				printk ("[outbound packet] [nd_nix_nfm] forwarding source port [%u] -> [%u].\n", ntohs(tcph->source), collect_data->forwardport);
				tcph->source    = htons(collect_data->forwardport);
#else
				tcph->source 	= htons(fakeport);
#endif
				
				datalen 	= skb->len - iph->ihl*4;
				tcph->check 	= 0;
                                tcph->check 	= tcp_v4_check( datalen, iph->saddr, iph->daddr, csum_partial((char*)tcph, datalen,0)); 
			}

#ifdef _SUPP_SRCIP_IN_RULE
			if (collect_data)
				kfree (collect_data);
#endif
		
	

                        break;
                }
                default:
                {
                        break;
                }
        }
Exit_function:
	return NF_ACCEPT;
}

static int __net_init nd_netlink_init(struct net *net)
{
	struct ns_data *data;
	struct netlink_kernel_cfg cfg = {
		.input = nd_nix_hook_recv_cmd,
		.flags = NL_CFG_F_NONROOT_RECV,
	};

	struct sock *nl_sock = netlink_kernel_create(net, NETLINK_USER, &cfg);
	if (!nl_sock)	{
		//ERROR MSG
		return -1;
	}

	data = net_generic(net, net_id);
	data->sk = nl_sock;

	return 0;
}

static void __net_exit nd_netlink_exit(struct net *net)
{
	struct ns_data *data = net_generic(net, net_id);

	netlink_kernel_release(data->sk);
}

/*
 *
 */
struct netlink_kernel_cfg cfg = {
        .input = nd_nix_hook_recv_cmd,
};


/*
 *
 */
static struct nf_hook_ops nf_inbound_hook = {

	.hook		= nd_nix_hook_inbound_func,
	.pf		= PF_INET,
	.hooknum 	= NF_INET_PRE_ROUTING,
	.priority	= NF_IP_PRI_FIRST,
};


/*
 *
 */
static struct nf_hook_ops nf_outbound_hook = {
	.hook           = nd_nix_hook_outbound_func,
        .pf             = PF_INET,
        .hooknum        = NF_INET_LOCAL_OUT,
        .priority       = NF_IP_PRI_FIRST,

};

static struct pernet_operations net_ops __net_initdata = {
	.init 	= nd_netlink_init,
	.exit 	= nd_netlink_exit,
	.id	= &net_id,
	.size 	= sizeof(struct ns_data),
};


/*
 *
 */
struct file_operations fops = {
	.owner 		= THIS_MODULE,
	.open 		= nd_ioctl_open,
	.release 	= nd_ioctl_close,
	.unlocked_ioctl = nd_device_ioctl,
};


static int nd_nix_nfm_chardev_init(void)
{
	nd_major_number = register_chrdev(0, ND_DEVICE_NAME, &fops);

	if (nd_major_number < 0 )	{
		printk("Registering char device failed with %d\n", nd_major_number);
		return nd_major_number;
	}

	chardev_class = class_create(THIS_MODULE, ND_DEVICE_NAME);
	if (IS_ERR(chardev_class))	{
		unregister_chrdev(nd_major_number, ND_DEVICE_NAME);
		printk ("Failed to create class\n");
		return PTR_ERR(chardev_class);
	}
	if (device_create(chardev_class, NULL, MKDEV(nd_major_number, 0), NULL, ND_DEVICE_NAME) == NULL )	{
		class_destroy(chardev_class);
		unregister_chrdev(nd_major_number, ND_DEVICE_NAME);

		printk ("Failed to create device\n");
		return -1;
	}

	printk ("device created on /dev/%s\n", ND_DEVICE_NAME );

	return 0;
}

#ifdef _BAK_SRC
static int nd_nix_nfm_chardev_init_old(void)
{
	int alloc_ret = 0, cdev_err = 0;
	dev_t dev;
	
	printk ("nd_nix_nfm_chardev_init start..\n");

	alloc_ret = alloc_chrdev_region(&dev, MINOR_BASE, MINOR_NUM, ND_DEVICE_NAME);
	if (alloc_ret != 0 )	{
		printk ("alloc_chrdev_region = %d\n", alloc_ret);
		return -1;
	}

	printk ("nd_nix_nfm_chardev_init allo_chrdev_region after...\n");

	nd_major_number = MAJOR(dev);
	dev = MKDEV (nd_major_number, MINOR_BASE);

	printk ("nd_nix_nfm_chardev_init MKDEV after..\n");

	cdev_init(&chardev_cdev, &fops);
	printk ("nd_nix_nfm_chardev_init cdev_init after..\n");

	chardev_cdev.owner = THIS_MODULE;

	// add a char device to the system
	cdev_err = cdev_add(&chardev_cdev, dev, MINOR_NUM);
	if (cdev_err != 0) {
		printk("cdev_add = %d\n", cdev_err);
		unregister_chrdev_region(dev, MINOR_NUM);
		return -1;
	}

	printk ("nd_nix_nfm_chardev_init cdev_add after..\n");

	chardev_class = class_create(THIS_MODULE, ND_DEVICE_NAME);
	if (IS_ERR(chardev_class)) {
		printk("class_create\n");
		cdev_del(&chardev_cdev);
		unregister_chrdev_region(dev, MINOR_NUM);
		return -1;
	}

	printk ("nd_nix_nfm_chardev_init class_create after..\n");

	device_create(chardev_class, NULL, MKDEV(chardev_major, 0),
		NULL, ND_DEVICE_NAME);

	printk ("nd_nix_nfm_chardev_init device_create after ...\n");

	return 0;
}
#endif //_BAK_SRC

static void  nd_nix_nfm_chardev_exit(void)
{
	if (chardev_class)	{
		device_destroy(chardev_class, MKDEV(nd_major_number, 0));
		class_destroy(chardev_class);
	}

	if (nd_major_number >= 0 )	{
		unregister_chrdev(nd_major_number, ND_DEVICE_NAME);
	}

}

/*
 *
 */
static int __init nd_nix_nfm_init(void)
{
	printk("nd_nix_nfm_init start .....\n");

	//add_log("netand network fltdrv start...\n");

//	mutex_init(&log_mutex);
//	INIT_LIST_HEAD (&log_list.list);
	INIT_LIST_HEAD (&nd_list_service_rules_new.list);

//	add_log("netand network fltdrv start...");
/*
	//////////////////////////////////////////////////////
	int i;
    	for (i = 0; i < PORT_TABLE_SIZE; i++) {
        	INIT_HLIST_HEAD(&port_table[i]);
    	}
	///////////////////////////////////////////////////////
*/
//	 nd_major_number = register_chrdev(NOD_MAJOR, ND_DEVICE_NAME, &fops);

	nf_register_net_hook (&init_net, &nf_inbound_hook);
	nf_register_net_hook (&init_net, &nf_outbound_hook);

//	add_log("netand network fltdrv start...TEST1111");
//	add_log("netand network fltdrv start...TEST2222");
	register_pernet_subsys(&net_ops);


	//
	nd_major_number = register_chrdev(NOD_MAJOR, ND_DEVICE_NAME, &fops);
	if (nd_major_number < 0)	{
		printk("ERROR register error...\n");
	}

	nd_nix_nfm_chardev_init();
	//
	
	return 0;
}

static void __exit nd_nix_nfm_exit(void)
{
	struct log_entry *log, *ltmp;
	printk ("unload nd_nix_nfm kernul module...\n");

	nd_nfm_del_default_all_rule();
	
	nf_unregister_net_hook (&init_net, &nf_inbound_hook);
	nf_unregister_net_hook (&init_net, &nf_outbound_hook);

	unregister_pernet_subsys(&net_ops);
	//unregister_chrdev(/*nd_major_number*/NOD_MAJOR, ND_DEVICE_NAME);
	nd_nix_nfm_chardev_exit();

	//////
	int i;
    	struct port_info *info;
    	struct hlist_node *tmp;
	for (i = 0; i < PORT_TABLE_SIZE; i++) {
       		 hlist_for_each_entry_safe(info, tmp, &port_table[i], node) {
            		hlist_del(&info->node);
            		kfree(info);
        	}
    	}

	mutex_lock(&log_mutex);
/*
	list_for_each_entry_safe (log, ltmp, &log_list.list, list)	{
		list_del(&log->list);
		kfree(log);
	}	
*/
//	mutex_unlock(&log_mutex);

	

	return;
}

module_init(nd_nix_nfm_init);
module_exit(nd_nix_nfm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTH);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_VERSION("1.0.0");


