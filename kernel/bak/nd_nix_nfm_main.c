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
/*
*/
#include "nd_nix_nfm_common.h"

#include "libsrc/nd_nix_util_str.h"
#include "libsrc/nd_nix_rules.h"
//#include "nd_nix_nfm_rules.h"
//#include "nd_nix_nfm_rules_new.h"

#define DRIVER_AUTH "Saber-toothed cat <pingye@netand.co.kr>"
#define DRIVER_DESC "NETAND's network filtering driver that runs on Linux"

#define NETLINK_USER 31

struct nd_service_rule_data_new 	nd_list_service_rules_new;

/*
static DEFINE_RAW_SPINLOCK(nd_list_lock);
*/

#define MODE_ON 	1
#define MODE_OFF	0
#define MODE_WARN	2

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
//struct sock		*nl_sk = NULL;

static unsigned int 	net_id;
/*
 *
 */
#ifdef _EXTERN_IMPLEMENT
int check_delimiters(char *input) {
    char *pipe, *comma;

    pipe = strchr(input, '|');
    comma = strchr(input, ',');

    if (pipe == NULL || comma == NULL) {
        return -1;
    }

    return 0;
}


/*
 *
 */
int check_pipes(char *input)	{
	char *pipe;

	pipe = strchr(input, '|');

	if (pipe == NULL)	{
		return -1;
	}
	
	return 0;
}


/*
 *
 */
int check_commas(char *input)	{
	char *comma;

	comma = strchr(input, ',');
	
	if (comma == NULL)	{
		return -1;
	}

	return 0;
}
#endif ///_EXTERN_IMPLEMENT

#ifdef _EXTERN_IMPLEMENT
/*
 * -----------------------------------------------------------------------------------
 */
int nd_get_struct_data_by_type(char * szData, struct cmd_rule_pars_data *_data)
{
	struct cmd_rule_pars_data *data = _data;
	char  *szpars, *token;
	int ret = 0, nIndex = 0;
	
	if (!data)
		return -1;

	if (szData == NULL || strlen(szData) <= 0)
		return -1;

	szpars = kstrdup(szData, GFP_KERNEL );		
	while (( token = strsep(&szpars, "|")) != NULL)   {
		
		if (token)	
		{
			if (nIndex  == INDX_RULE_TYPE)	{
					
				ret = kstrtou32(token, 10, &data->rule_type);
				if (ret != 0 )		{
						
					printk ("kstrtou32 result [%u]\n", data->rule_type);
					return -1;
				}
			}
			
			else if (nIndex > (int)INDX_RULE_TYPE)	{

				if (data->rule_type == INDX_RULE_TYPE_SERVICE)	{

					if (nIndex == INDX_SVC_RULE_SERVICE )		{
						
						ret = kstrtou16(token, 10, &data->service);
						if (ret != 0)   {
							printk ("nd_get_struct_data_by_type :: failed to convert a service string to an service\n");
						}

						else 
						{
							//printk ("nd_get_struct_data_by_type :: success to convert a service string to an service [%u]\n", data->service);
						}
					}

					else if (nIndex ==  INDX_SVC_RULE_FAKEPORT )	{	
							
						ret = kstrtou16(token, 10, &data->fakeport);
						if (ret != 0)   {
							printk ("nd_get_struct_data_by_type :: failed to convert a fakeport string to an service\n");
						}

						else 	{
							//printk ("nd_get_struct_data_by_type :: success to conver a fakeport string to an service [%u]\n", data->fakeport);
						}
					}

					else if (nIndex == INDX_SVC_RULE_MODE )		{

						ret = kstrtou32(token, 10, &data->mode);
						if (ret != 0)   {
							printk ("nd_get_struct_data_by_type :: failed to convert a mode string to an service\n");
						}

						else 	{
							//printk ("nd_get_struct_data_by_type :: success to conver a mode string to an service [%u]\n", data->mode); 
						}
					}
				}

				else if (data->rule_type == INDX_RULE_TYPE_FAKEEXCEPT){
					
					if (nIndex == INDX_FAKEEXCEPT_RULE_SERVICE )	{
						
						ret = kstrtou16(token, 10, &data->service);
						if (ret != 0)   {
							printk ("nd_get_struct_data_by_type :: failed to convert a service string to an fakeexcept\n");
						}

						else 	{
							//printk ("nd_get_struct_data_by_type :: success to convert a service string to an fakeexcept [%u]\n", data->service);
						}
						

					}

					else if (nIndex == INDX_FAKEEXCEPT_RULE_EXADDR ) {
						
						ret = kstrtou32(token, 10, &data->address);
						if (ret != 0)   {
							printk ("nd_get_struct_data_by_type :: failed to convert a fake address string to an fakeexcept\n");
						}

						else	{
							//printk ("nd_get_struct_data_by_type :: success to convert a fake address string to an fakeexcept [%u]\n", data->address);
						}
			
					}
				}

				else if (data->rule_type == INDX_RULE_TYPE_DROPEXCEPT){
					if (nIndex == INDX_DROPEXCEPT_RULE_SERVICE )	{
						ret = kstrtou16(token, 10, &data->service);
						if (ret != 0)   {
							printk ("nd_get_struct_data_by_type :: failed to convert a service string to an dropexcept\n");
						}

						else	{
							//printk ("nd_get_struct_data_by_type :: success to convert a service string to an dropexcept [%u]\n", data->service );
						}
					}
					
					else if (nIndex == INDX_DROPEXCEPT_RULE_EXADDR ) {
						ret = kstrtou32(token, 10, &data->address);
						if (ret != 0)   {
							printk ("nd_get_struct_data_by_type :: failed to convert a drop address string to an dropexcept\n");
						}

						else 	{
							//printk ("nd_get_struct_data_by_type :: success to convert a drop address string to an dropexcept [%u]\n", data->address );
						}
					}
				}

				else
				{

				}
			}
		}
		nIndex ++;
	}
	
	if (szpars)
		kfree (szpars);

	return -0;
}
#endif //////_EXTERN_IMPLEMENT

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


#ifdef _EXTERN_IMPLEMENT
/*
 *
 */
void* nd_make_empty_targetitem_by_ruletype(__u32 uRuleType)
{
	struct nd_service_rule_data     *service;
        struct nd_fake_rule_data        *fake;
        struct nd_fake_except_rule_data *fakeExcept;
        struct nd_drop_rule_data        *drop;
        struct nd_drop_except_rule_data *dropExcept;

	switch (uRuleType)		{
		case INDX_RULE_TYPE_SERVICE:
		{
			service = kmalloc (sizeof (struct nd_service_rule_data), GFP_KERNEL );
			if (!service)		{
				return NULL;
			}
			
			INIT_LIST_HEAD(&service->list);

			return service;
		}	
		break;

		case INDX_RULE_TYPE_FAKE:
		{
			fake = kmalloc (sizeof (struct nd_fake_rule_data), GFP_KERNEL );
			if (!fake)		{
				return NULL;
			}

			INIT_LIST_HEAD(&fake->list);
	
			return fake;
		}
		break;

		case INDX_RULE_TYPE_FAKEEXCEPT:
		{
			fakeExcept = kmalloc (sizeof (struct nd_fake_except_rule_data), GFP_KERNEL );
			if (!fakeExcept)	{
				return NULL;
			}

			INIT_LIST_HEAD (&fakeExcept->list);

			return fakeExcept;
		}
		break;

		case INDX_RULE_TYPE_DROP:
		{
			drop = kmalloc (sizeof (struct nd_drop_rule_data), GFP_KERNEL );
			if (!drop)		{
				return NULL;
			}

			INIT_LIST_HEAD (&drop->list);

			return drop;
		}
		break;

		case INDX_RULE_TYPE_DROPEXCEPT:
		{
			dropExcept = kmalloc (sizeof (struct nd_drop_except_rule_data), GFP_KERNEL );
			if (!dropExcept)		{
				return NULL;
			}

			INIT_LIST_HEAD (&drop->list);

			return dropExcept;
		}
		break;

		default:
		{
			return NULL;
		}
		break;

	}

	return NULL;
}
//#endif //_EXTERN_IMPLEMENT

/*
 *
 */
int nd_check_targetItem_in_targetlinkedlist(struct list_head *head,void * struct_data, __u32 uType)
{
	struct nd_service_rule_data_new	*service, *service_temp;
	struct nd_fake_rule_data	*fake, *fake_temp;
	struct nd_fake_except_rule_data *fakeExcept, *fakeExcept_temp;
	struct nd_drop_rule_data	*drop, *drop_temp;
	struct nd_drop_except_rule_data	*dropExcept, *dropExcept_temp;

	struct list_head	*pos, *next;
	if (list_empty(head))             {

		return ND_CHECK_NO; // notfound
        }

	if (uType == INDX_RULE_TYPE_SERVICE)		{
		
		service = (struct nd_service_rule_data_new*)struct_data;
		list_for_each_safe (pos, next, head)	{
			service_temp = list_entry ( pos, struct nd_service_rule_data_new, list );
			if (!service_temp)		{
				return ND_CHECK_NO; // error
			}

			if (service_temp->service == service->service)	{
				return ND_CHECK_OK;
			}
		}
	}
	else if (uType == INDX_RULE_TYPE_FAKE)	{
		fake	= (struct nd_fake_rule_data*)struct_data;
		list_for_each_safe (pos, next, head)	{
			fake_temp = list_entry ( pos, struct nd_fake_rule_data, list );
			if (!fake_temp)			{
				return ND_CHECK_NO;
			}


			if (fake_temp->fakeport == fake->fakeport)	{
				return ND_CHECK_OK;
			}

		}
	}
	else if (uType == INDX_RULE_TYPE_FAKEEXCEPT)	{
		fakeExcept = (struct nd_fake_except_rule_data*)struct_data;
		list_for_each_safe (pos, next, head )	{
			fakeExcept_temp = list_entry ( pos, struct nd_fake_except_rule_data, list);
			if (!fakeExcept_temp)
				return ND_CHECK_NO;

			if (fakeExcept_temp->remoteAddr == fakeExcept->remoteAddr)	{
				return ND_CHECK_OK;
			}
		}
	}
	else if (uType == INDX_RULE_TYPE_DROP)	{
		drop 	= (struct nd_drop_rule_data*)struct_data;
		list_for_each_safe ( pos, next, head )	{
			drop_temp = list_entry (pos, struct nd_drop_rule_data, list );
			if (drop_temp)	
				return ND_CHECK_NO;

			if (drop_temp->remoteAddr == drop->remoteAddr)		{
				return ND_CHECK_OK;
			}
		}
	}
	else if (uType == INDX_RULE_TYPE_DROPEXCEPT)	{
		dropExcept = (struct nd_drop_except_rule_data*)struct_data;
		list_for_each_safe ( pos, next, head)	{
			dropExcept_temp = list_entry ( pos, struct nd_drop_except_rule_data, list );
			if (!dropExcept_temp)	{
				return ND_CHECK_NO;
			}

			if (dropExcept_temp->remoteAddr == dropExcept->remoteAddr)	{
				return ND_CHECK_OK;
			}
		}
	
	}
	else
	{
		return ND_CHECK_NO;
	}

	return ND_CHECK_NO;
}
//#endif //_EXTERN_IMPLEMENT

/*
 *
 */
int nd_mod_dropExcept_in_service_rule(__u16 _uService, __u32 _uDropExceptIp, __u32 _uDropExcept_modIp)
{
	struct nd_service_rule_data_new *service_rule;
        struct nd_drop_except_rule_data *drop_except;

        struct list_head * pos, *next;
        struct list_head *droppos, *dropnext;

        __u32 uBakDropExceptIp = 0;

        bool bChkOrg = false, bChkModify = false;

        list_for_each_safe (pos, next, &nd_list_service_rules_new.list)          {

                service_rule = list_entry (pos, struct nd_service_rule_data_new, list );
                if (!service_rule)      {
                        return -1;
                }

                if (service_rule->service == _uService )                {
                        if (!list_empty (&service_rule->dropExcept.list))       {
                                bChkOrg = false, bChkModify = false;
                                list_for_each_safe (droppos, dropnext, &service_rule->dropExcept.list)  {
                                        drop_except = list_entry (droppos, struct nd_drop_except_rule_data, list);
                                        if (drop_except)        {
                                                if (drop_except->remoteAddr == _uDropExceptIp)       {
                                                        if (bChkModify == true)
                                                        {
                                                                return -1;
                                                        }
                                                        bChkOrg = true;
                                                        uBakDropExceptIp = drop_except->remoteAddr;
                                                        drop_except->remoteAddr = _uDropExcept_modIp;
                                                }
                                                if (drop_except->remoteAddr == _uDropExcept_modIp)   {
                                                        bChkModify = true;

                                                        if (bChkOrg == true)    {
                                                                drop_except->remoteAddr = uBakDropExceptIp;
                                                        }
                                                        return -1;
                                                }
                                        }
                                }
                        }
                }
        }

        if (bChkOrg == true && bChkModify == false)
                return 0;

        return -1;


}

//#endif //_EXTERN_IMPLEMENT

/*
 *
 */
int nd_del_dropExcept_in_service_rule(__u16 _uService, __u32 _uDropExceptIp)
{
	struct nd_service_rule_data_new *service_rule;
        struct nd_drop_except_rule_data *drop_except;

        struct list_head * pos, *next;
	struct list_head *droppos, *dropnext;

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)		{
		service_rule = list_entry (pos , struct nd_service_rule_data_new, list);
		
		if (service_rule)	{
			
			if (!list_empty (&service_rule->dropExcept.list))	{
				
				list_for_each_safe (droppos, dropnext, &service_rule->dropExcept.list)	{
					drop_except = list_entry (droppos, struct nd_drop_except_rule_data, list);

					if (drop_except)	{
						list_del (droppos);
						kfree (drop_except);

						return 0;
					}
				}
			}
		}
	}

	return -1;
}

/*
 *
 */
int nd_add_dropExcept_in_service_rule(__u16 _uService, __u32 _uDropExceptIp)
{
	struct nd_service_rule_data_new *service_rule;
	struct nd_drop_except_rule_data *drop_except;	

	struct list_head * pos, *next;
        int ret = 0;

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

                service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
                if (!service_rule)      {
                        return -1;
                }
		
		if (service_rule->service == _uService )                {

			drop_except = kmalloc (sizeof(struct nd_drop_except_rule_data), GFP_KERNEL );
                        if (!drop_except)
                                return -1;

			drop_except->remoteAddr = _uDropExceptIp;

			if (!list_empty (&service_rule->dropExcept.list))	{
				ret = nd_check_targetItem_in_targetlinkedlist(&service_rule->dropExcept.list, drop_except, INDX_RULE_TYPE_DROPEXCEPT);

                                if (ret == ND_CHECK_OK )
                                {
                                        printk ("already exist target exception rule....[%u]\n", _uDropExceptIp);
                                        kfree (drop_except);
                                        return -1;
                                }

			}

			INIT_LIST_HEAD (&drop_except->list);
                        list_add_tail (&drop_except->list, &service_rule->dropExcept.list);
		}
	}

	return 0;
}


/*
 *
 */
int nd_mod_fakeExcept_in_service_rule(__u16 _uService, __u32 _uFakeExceptIp, __u32 _uFakeExcept_modIp)
{
	struct nd_service_rule_data_new *service_rule;
        struct nd_fake_except_rule_data *fake_except;

        struct list_head * pos, *next;
        struct list_head *fakepos, *fakenext;
	
	__u32 uBakFakeExceptIp = 0;

	bool bChkOrg = false, bChkModify = false;

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)		{

		service_rule = list_entry (pos, struct nd_service_rule_data_new, list );
		if (!service_rule)	{
			return -1;
		}

		if (service_rule->service == _uService )		{
			if (!list_empty (&service_rule->fakeExcept.list))	{
				bChkOrg = false, bChkModify = false;
				list_for_each_safe (fakepos, fakenext, &service_rule->fakeExcept.list)	{
					fake_except = list_entry (fakepos, struct nd_fake_except_rule_data, list);
					if (fake_except)	{
						if (fake_except->remoteAddr == _uFakeExceptIp)	{
							if (bChkModify == true)
							{
								return -1;
							}
							bChkOrg = true;
							uBakFakeExceptIp = fake_except->remoteAddr;
							fake_except->remoteAddr = _uFakeExcept_modIp;
						}	
						if (fake_except->remoteAddr == _uFakeExcept_modIp)	{
							bChkModify = true;

							if (bChkOrg == true)	{
								fake_except->remoteAddr = uBakFakeExceptIp;
							}
							return -1;
						}
					}
				}
			}
		}
	}

	if (bChkOrg == true && bChkModify == false)
		return 0;

	return -1;
}


/*
 *
 */
int nd_del_fakeExcept_in_service_rule(__u16 _uService, __u32 _uFakeExceptIP)
{
	struct nd_service_rule_data_new *service_rule;
        struct nd_fake_except_rule_data *fake_except;

        struct list_head * pos, *next;
	struct list_head *fakepos, *fakenext;
        int ret = 0;
	bool bFinded = false, bFindedService = false;
		
	
	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

                service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
                if (!service_rule)      {
                        return -1;
                }

                if (service_rule->service == _uService )                {
			bFindedService = true;
                        if (!list_empty (&service_rule->fakeExcept.list))       {

                                list_for_each_safe (fakepos, fakenext, &service_rule->fakeExcept.list)  {
                                        fake_except = list_entry (fakepos, struct nd_fake_except_rule_data, list);
                                        if (fake_except)        {
						ret = nd_check_targetItem_in_targetlinkedlist(&service_rule->fakeExcept.list, fake_except, INDX_RULE_TYPE_FAKEEXCEPT);

						if (ret == ND_CHECK_OK )
						{
							
							bFinded = true;
						}
                                        }
                                }
                        }
                }
        }

	if (bFindedService == false)
        {
                printk ("failed to delete target service rule - service[%u] rule is not found\n", _uService);
                return -1;
        }


	if (bFinded == false)		{

		printk ("failed to delete target fakeExcept rule in service rule - [%u] is not found\n", _uService);
		return -1;
	}

        list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

                service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
                if (!service_rule)      {
                        return -1;
                }

                if (service_rule->service == _uService )                {

                        if (!list_empty (&service_rule->fakeExcept.list))       {
	
				list_for_each_safe (fakepos, fakenext, &service_rule->fakeExcept.list)	{
					fake_except = list_entry (fakepos, struct nd_fake_except_rule_data, list);
					if (fake_except)	{
						if (fake_except->remoteAddr == _uFakeExceptIP)	{

							printk ("delete target data : [%u]/[%u]\n", fake_except->remoteAddr, _uFakeExceptIP);
							list_del(fakepos);
							kfree (fake_except);

							return 0;
						}
					}
				}
                        }
                }
	}

        return -1;

}

/*
 *
 */
int nd_add_fakeExcept_in_service_rule(__u16 _uService, __u32 _uFakeExceptIp)	
{
	struct nd_service_rule_data_new *service_rule;
	struct nd_fake_except_rule_data *fake_except;

	struct list_head * pos, *next;
	int ret = 0;

	bool bFinded = false, bFindedService = false;

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

                service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
                if (!service_rule)      {
                        return -1;
                }

                if (service_rule->service == _uService )                {

			bFindedService = true;
                        fake_except = kmalloc (sizeof(struct nd_fake_except_rule_data), GFP_KERNEL );
                        if (!fake_except)
                                return -1;

                        fake_except->remoteAddr = _uFakeExceptIp;


                        if (!list_empty (&service_rule->fakeExcept.list))       {
                                ret = nd_check_targetItem_in_targetlinkedlist(&service_rule->fakeExcept.list, fake_except, INDX_RULE_TYPE_FAKEEXCEPT);

                                if (ret == ND_CHECK_OK )
                                {
					bFinded = true;
                                }
                        }
                }
        }

	if (bFindedService == false)
	{
		printk ("failed to added target service rule - service[%u] rule is not found\n", _uService);
		return -1;
	}

	if (bFinded == true )
	{
		printk ("failed to added target service rule - [%u] is alread exist in service[%u] rule\n", _uFakeExceptIp, _uService);
		return -1;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)		{

		service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
		if (!service_rule)	{
			return -1;
		}

		if (service_rule->service == _uService )		{

			fake_except = kmalloc (sizeof(struct nd_fake_except_rule_data), GFP_KERNEL );
                        if (!fake_except)
                                return -1;

			fake_except->remoteAddr = _uFakeExceptIp;		


			if (!list_empty (&service_rule->fakeExcept.list))	{
				ret = nd_check_targetItem_in_targetlinkedlist(&service_rule->fakeExcept.list, fake_except, INDX_RULE_TYPE_FAKEEXCEPT);
				
				if (ret == ND_CHECK_OK )
				{
					printk ("already exist target exception rule....[%u]\n", _uFakeExceptIp);
					kfree (fake_except);
					return -1;
				}
			}

			INIT_LIST_HEAD (&fake_except->list);
			list_add_tail (&fake_except->list, &service_rule->fakeExcept.list);		
			return 0;
		}
	}

	return -1;
	
}


/*
 *
 */
int nd_mod_service(__u16 _uService, __u16 _uMod_Service)	{
	
	struct nd_service_rule_data_new *service;
	/*
        struct nd_fake_except_rule_data *fakeExcept;
        struct nd_drop_except_rule_data *dropExcept;
	*/
        struct list_head *pos, *next;
        /*struct list_head *fakeEpos, *fakeEnext;*/
        /*struct list_head *dropEpos, *dropEnext;*/
	bool bFindTarService = false, bFindModService = false;

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)	{
		
		service = list_entry (pos, struct nd_service_rule_data_new, list );
		if (service)		{

			if (service->service == _uService)	{
				bFindTarService = true;
			}

			if (service->service == _uMod_Service)	{
				bFindModService = true;
			}
		}
	}


	if (bFindTarService == false)		{

		return -1;
	}

	if (bFindModService == true)		{
		
		return -1;
	}
	

        list_for_each_safe (pos, next, &nd_list_service_rules_new.list) {
                service = list_entry (pos, struct nd_service_rule_data_new, list );

                if (service)    {


                        if (service->service == _uService )     {			
				service->service = _uMod_Service;
			}
               }
        }

        return 0;

}

/*
 *
 */
int nd_nfm_del_default_all_rule(void)	{
	
	struct nd_service_rule_data_new *service;
	struct nd_fake_except_rule_data *fakeExcept;
	struct list_head *pos, *next;
        struct list_head *fakeEpos, *fakeEnext;
	

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)		{
		service = list_entry (pos, struct nd_service_rule_data_new, list );
		if (service )		{
			
			if (!list_empty(&service->fakeExcept.list))	{
			
				list_for_each_safe (fakeEpos, fakeEnext, &service->fakeExcept.list)	{

					fakeExcept = list_entry (fakeEpos, struct nd_fake_except_rule_data, list);
					if (fakeExcept)
					{
						list_del(fakeEpos);

						kfree (fakeExcept);
					}
				}
			}
		}

		list_del (pos);
		kfree (service);
	}

	return 0;
}

/*
 *
 */
int nd_del_service(__u16 _uService)	{
	
	struct nd_service_rule_data_new *service;
	struct nd_fake_except_rule_data *fakeExcept;
	struct nd_drop_except_rule_data *dropExcept;
	struct list_head *pos, *next;
	struct list_head *fakeEpos, *fakeEnext;
	struct list_head *dropEpos, *dropEnext;
	bool bFinded = false;


        if (!list_empty (&nd_list_service_rules_new.list))
        {
                list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

                        service = list_entry (pos, struct nd_service_rule_data_new, list);
                        if (service)
                        {
                                if (service->service == _uService)         {
					bFinded = true;
                                }
                        }
                }
        }

	if (bFinded == false	)		{

		printk ("failed to delete target service rule - [%u] is not found\n", _uService);
		return -1;
	}


	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)	{
		service = list_entry (pos, struct nd_service_rule_data_new, list );

		if (service)	{

			if (service->service == _uService )	{
				
				if (!list_empty (&service->fakeExcept.list))	{
					
					list_for_each_safe (fakeEpos, fakeEnext, &service->fakeExcept.list)	{
						fakeExcept = list_entry (fakeEpos, struct nd_fake_except_rule_data, list);

						if (fakeExcept)		{

							list_del(fakeEpos);
							kfree (fakeExcept);
						}
					}
				}

				if (!list_empty (&service->dropExcept.list))	{
					list_for_each_safe (dropEpos, dropEnext, &service->dropExcept.list)	{
						dropExcept = list_entry (dropEpos, struct nd_drop_except_rule_data, list);

						if (dropExcept)		{
							list_del (dropEpos);
							kfree (dropEpos);
							return 0;
						}	
					}
				}
			}
			list_del(pos);
			kfree (service);
			return 0;
		}
	}
	
	return -1;
}


/*
 *
 */
int nd_add_service(__u16 _uService, __u16 _uFakePort, __u32 _uMode)
{
	struct nd_service_rule_data_new *service_rule;
	struct list_head *pos, *next;

	if (!list_empty (&nd_list_service_rules_new.list))
	{
		list_for_each_safe (pos, next, &nd_list_service_rules_new.list)		{

			service_rule = list_entry (pos, struct nd_service_rule_data_new, list);
			if (service_rule)
			{
				if (service_rule->service == _uService)		{

					printk ("nd_add_service :: failed to add service rule...[%u]\n", _uService);
					return -1;
				}
			}
		}
	}

	service_rule = kmalloc (sizeof (struct nd_service_rule_data_new), GFP_KERNEL );
	if (!service_rule)
		return -1;

	service_rule->service 	= _uService;
	service_rule->fakeport 	= _uFakePort;
	service_rule->mode 	= _uMode;

	INIT_LIST_HEAD (&service_rule->fakeExcept.list);
	INIT_LIST_HEAD (&service_rule->dropExcept.list);

	INIT_LIST_HEAD (&service_rule->list);
	list_add_tail (&service_rule->list, &nd_list_service_rules_new.list);
	
	return 0;
}

/*
 *
 */
int nd_nfm_chk_rule_v2( struct nd_5tuple_data tuples, __u16 *fakeport)
{
	struct nd_service_rule_data_new *service/*, *service_temp*/;
        struct nd_fake_except_rule_data *fakeExcept/*, *fakeExcept_temp*/;
        //struct nd_drop_except_rule_data *dropExcept, *dropExcept_temp;	

	struct list_head *spos, *snext, *fepos, *fenext;

	int result = 0;
	__u16 service_port = 0;
	__u16 standard_port = 0;
	__u32 except_addr =0;
  	//__u16 ret_fakeport = 0;

	list_for_each_safe (spos, snext, &nd_list_service_rules_new.list)          {

                service = list_entry (spos, struct nd_service_rule_data_new, list );
                if (!service)      {
                        return ND_PLOICY_EXCLUSION;
                }

		if (tuples.hook == NF_INET_PRE_ROUTING)	{
			service_port = tuples.dport;
			standard_port = service->service;
			except_addr = tuples.saddr;
		}

		else if (tuples.hook == NF_INET_LOCAL_OUT)	{
		/*
		//	printk ("OUTBOUND tuples info [%u][%u][%u][%u]\n", tuples.saddr, tuples.daddr, tuples.dport, tuples.sport);
		*/
			service_port = tuples.sport;
			standard_port = service->fakeport;
			except_addr = tuples.daddr;
		}

		/*	
		//printk ("service_port = %u | standardport = %u \n", service_port, standard_port);		
		*/

                if (standard_port == service_port )                {
			/*
			//printk ("service->service[%u] == service_port[%u]\n", service->service, service_port );
			///<CHK EXCEPT IPADDRESS[FAKE]>
			*/

			list_for_each_safe (fepos, fenext, &service->fakeExcept.list)	{
				fakeExcept = list_entry (fepos, struct nd_fake_except_rule_data, list );
				if (fakeExcept->remoteAddr == except_addr)			{

					if (service->mode == ND_RULE_MODE_INDIVIDUAL)	{
						result = ND_POLICY_APPLY;
						break;
					}

					else  // ND_RULE_MODE_GENERAL
					{
						return ND_POLICY_EXCEPT;	
					}
				}
			}
			if (tuples.hook == NF_INET_PRE_ROUTING) 	{
				*fakeport = service->fakeport;
			}
			else if (tuples.hook == NF_INET_LOCAL_OUT)	{
				*fakeport = service->service;
			}

			return ND_POLICY_APPLY;
		}
	}


	return ND_PLOICY_EXCLUSION;
}
#endif //_EXTERN_IMPLEMENT

/*
 *
 */
static void nd_nix_hook_recv_cmd( struct sk_buff * skb);



/*
 *
 */
int nd_nix_get_service2tuple_from_cmddata(char* szCmdData, struct nd_service_2tuple_data * tuple_data)
{
	char *items = NULL, *item = NULL ;
	int ret = 0, i = 0;
	if (szCmdData && check_pipes(szCmdData) == 0)
	{
		items = kstrdup ( szCmdData, GFP_KERNEL);
		if (items == NULL)
		{
			return -1;
		}

		for (i = 0 ; i < 2 ; i ++ )		{
			item = strsep(&items, "|");

			if (item)
			{
				if (i == INDX_SVC_REALPORT)	{
					printk ("nd_nix_get_service2tuple_from_cmddata : realport [%s]\n", item);
					if (tuple_data == NULL)		{
						printk("nd_nix_get_service2tuple_from_cmddata : tuple_data->readport == NULL\n");
						return -1;
					}
					ret = kstrtou16(item, 10, &tuple_data->realport);
					if (ret != 0)		{

						///failed
					}
				}

				if (i == INDX_SVC_FAKEPORT)	{
					printk ("nd_nix_get_service2tuple_from_cmddata : fakelport [%s]\n", item);
					if (tuple_data == NULL)               {
                                                printk("nd_nix_get_service2tuple_from_cmddata : tuple_data->fakeport == NULL\n");
                                                return -1;
                                        }

					ret = kstrtou16(item, 10, &tuple_data->fakeport);
					if (ret != 0)		{
						///failed
					}
				}
			}
		}
	}
	else	{

		return -1;
	}

	return 0;
	
}


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
	struct cmd_rule_pars_data *cmd_rule_pars;
	
	
	nlh = (struct nlmsghdr*)skb->data;
	recvdata = (struct nd_cmd_data*)nlmsg_data(nlh);

	data.cmd = recvdata->cmd;

	//printk("nd_nix_hook_recv_cmd recv data :cmd[%u], data[%s]\n", recvdata->cmd, recvdata->data);

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
			//printk("[RECV] RULE ADD - Add a service policy using new information requested by the administrator. [%s]..\n", recvdata->data);
			cmd_rule_pars = kmalloc (sizeof (struct cmd_rule_pars_data), GFP_KERNEL);
			if (cmd_rule_pars == NULL)	
			{
				printk("operation failed - Memory dynamic allocation operation failed.\n");
				break;
			}

			
			ret= nd_get_struct_data_by_type (recvdata->data, cmd_rule_pars);
			if (ret != 0 )		{
				printk ("operation failed - Data parsing operation failed\n");
				
				if (cmd_rule_pars)
					kfree (cmd_rule_pars);

				break;
			}

			switch (cmd_rule_pars->rule_type)
			{
				case INDX_RULE_TYPE_SERVICE:

					ret = nd_add_service(cmd_rule_pars->service, cmd_rule_pars->fakeport, cmd_rule_pars->mode);
					if (ret == 0 )		{
						printk ("Successfully added policy - Service name [%u] has been added...\n", cmd_rule_pars->service );
					}
				break;

				case INDX_RULE_TYPE_FAKEEXCEPT:

					ret = nd_add_fakeExcept_in_service_rule(cmd_rule_pars->service, cmd_rule_pars->address);
					if (ret == 0 )          {
                                                printk ("Successfully added policy - Added exception policy %u included in service name %u...\n",cmd_rule_pars->address, cmd_rule_pars->service );
                                        }

				break;

				case INDX_RULE_TYPE_DROPEXCEPT:

					ret = nd_add_dropExcept_in_service_rule(cmd_rule_pars->service, cmd_rule_pars->address);
					if (ret == 0 )		{
						printk ("Successfully added policy - Added exception policy %u included in service name %u...\n",cmd_rule_pars->address, cmd_rule_pars->service );
					}
				break;
			}
			
			if (cmd_rule_pars)	
				kfree (cmd_rule_pars);
		break;

		case ND_CMD_RULE_DEL:

			cmd_rule_pars = kmalloc (sizeof (struct cmd_rule_pars_data), GFP_KERNEL);
                        if (cmd_rule_pars == NULL)
                        {
                                printk("operation failed - Memory dynamic allocation operation failed.\n");
                                break;
                        }


                        ret= nd_get_struct_data_by_type (recvdata->data, cmd_rule_pars);
                        if (ret != 0 )          {
                                printk ("operation failed - Data parsing operation failed\n");
                        }

			switch (cmd_rule_pars->rule_type)
                        {
				case INDX_RULE_TYPE_SERVICE:
					ret = nd_del_service(cmd_rule_pars->service);
					if (ret == 0 )		{
						printk ("Successfully deleted policy - Service name [%u] has been deleted...\n", cmd_rule_pars->service );
					}
					
				break;

				case INDX_RULE_TYPE_FAKEEXCEPT:
					ret = nd_del_fakeExcept_in_service_rule(cmd_rule_pars->service, cmd_rule_pars->address);
					if (ret == 0 )		{
						printk ("Successfully deleted policy - deleted exception policy %u included in service name %u...\n",cmd_rule_pars->address, cmd_rule_pars->service );
					}
				break;

				case INDX_RULE_TYPE_DROPEXCEPT:
					ret = nd_del_dropExcept_in_service_rule(cmd_rule_pars->service, cmd_rule_pars->address);
					if (ret == 0 )          {
                                                printk ("Successfully deleted policy - deleted exception policy %u included in service name %u...\n",cmd_rule_pars->address, cmd_rule_pars->service );
                                        }

				break;
			}


			if (cmd_rule_pars)
				kfree (cmd_rule_pars);
				
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


/*
 *
 */
unsigned int nd_nix_hook_inbound_func(void * priv, struct sk_buff * skb, const struct nf_hook_state * state )
{
	unsigned char 	*h;
	struct tcphdr 	*tcph;
	
	uint16_t 	sport 	= 0, 
			dport 	= 0, 
			datalen = 0;
	__u16 		fakeport;
	int 		nChkRuleResult = 0;

	struct nd_5tuple_data current_5tuple;
	struct iphdr * iph = (struct iphdr*) skb_network_header(skb);

	if (g_nLkmMode == MODE_OFF)
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
			
			nChkRuleResult = nd_nfm_chk_rule_v2(current_5tuple, &fakeport);
			/*
			//printk ("[RET:%u] inbound check source ipaddr [%u] destaddr [%u] :: source port [%u] destport [%u]\n",nChkRuleResult, current_5tuple.saddr, current_5tuple.daddr, current_5tuple.sport, current_5tuple.dport);
			*/

			if (nChkRuleResult == ND_POLICY_APPLY)		{

				/*
				//printk ("this session is exist policy... so change port...[dest:%u(%u) -> %u(%u)]\n",ntohs(tcph->dest), tcph->dest, htons(fakeport), fakeport);
				*/
				
				tcph->dest 	= htons(fakeport);
				datalen		= skb->len - iph->ihl*4;

				tcph->check	= 0;
				tcph->check	= tcp_v4_check( datalen, iph->saddr, iph->daddr, csum_partial((char*)tcph, datalen,0));
			}
		
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
	__u16 		fakeport;
	int nChkRuleResult = 0;

	struct nd_5tuple_data current_5tuple;
        //struct nd_default_rule_data * rule = NULL;

        if (g_nLkmMode == MODE_OFF)
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
			nChkRuleResult = nd_nfm_chk_rule_v2(current_5tuple, &fakeport);
			/*
			//printk ("[RET:%u] outbound check source ipaddr [%u] destaddr [%u] :: source port [%u] destport [%u]\n",nChkRuleResult, current_5tuple.saddr, current_5tuple.daddr, current_5tuple.sport, current_5tuple.dport);
			*/

			if (nChkRuleResult == ND_POLICY_APPLY)          {
				/*
				printk ("this session is exist policy... so change port...[source:%u(%u) -> %u(%u)]\n",htons(tcph->source), tcph->source, htons(fakeport),fakeport);
				*/

				tcph->source 	= htons(fakeport);
				
				datalen 	= skb->len - iph->ihl*4;
				tcph->check 	= 0;
                                tcph->check 	= tcp_v4_check( datalen, iph->saddr, iph->daddr, csum_partial((char*)tcph, datalen,0)); 
			}
			else if (nChkRuleResult == ND_POLICY_EXCEPT)	{
			
				printk ("Current session meets exception policy...\n");
			}
	

                        break;
                }
                default:
                {
                        break;
                }
        }

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
static int __init nd_nix_nfm_init(void)
{
	printk("nd_nix_nfm_init start .....\n");

	INIT_LIST_HEAD (&nd_list_service_rules_new.list);

	nf_register_net_hook (&init_net, &nf_inbound_hook);
	nf_register_net_hook (&init_net, &nf_outbound_hook);

	//nl_sk = netlink_kernel_create (&init_net, NETLINK_USER, &cfg);
	register_pernet_subsys(&net_ops);
	
	return 0;
}

static void __exit nd_nix_nfm_exit(void)
{
	printk ("unload nd_nix_nfm kernul module...\n");
/* old linked list */

	nd_nfm_del_default_all_rule();
	//nd_nfm_del_default_all_rule(&nd_default_rules.list);
	
	
	nf_unregister_net_hook (&init_net, &nf_inbound_hook);
	nf_unregister_net_hook (&init_net, &nf_outbound_hook);

	//netlink_kernel_release (nl_sk);
/*
	if (nf_inbound_hook.hook)
		kfree (&nf_inbound_hook);

	if (nf_outbound_hook.hook)
		kfree (&nf_outbound_hook);
*/
	//netlink_kernel_release (nl_sk);
	unregister_pernet_subsys(&net_ops);

	return;
}

module_init(nd_nix_nfm_init);
module_exit(nd_nix_nfm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTH);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_VERSION("0.1");


