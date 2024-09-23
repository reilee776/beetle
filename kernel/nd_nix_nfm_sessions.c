#include "nd_nix_nfm_sessions.h"

/*
*/
#include "nd_nix_nfm_common.h"
#include "nd_nix_nfm_rules.h"

#define DRIVER_AUTH "Saber-toothed cat <pingye@netand.co.kr>"
#define DRIVER_DESC "NETAND's network filtering driver that runs on Linux"

int push_session_item(struct list_head * head, struct session_data * data)
{
	struct session_list * ses_list = (struct session_list*)kmalloc(sizeof(struct session_list), GPD_KERNEL);

	if (ses_list == NULL )
	{
		printk (KERNEL_INFO "kmalloc(): Failed allocate Rule\n");
		return 1;
	}

	ses_list->session = data;
	list_add_tail(&ses_list->list, head);

	return 0;
}

struct session_data * find_session_item(struct list_head * head, struct nd_5tuple_data * tuple_item, uint32_t hook)
{
	struct session_list     * temp = NULL;
        struct list_head        * pos  = NULL;

	list_for_each(pos, head)
	{
		temp = list_entry(pos, struct session_list, list);

		if ( hook == NF_INET_PRE_ROUTING)	{
			if (
				temp->session->sip == tuple_item->saddr &&
				temp->session->dip == tuple_item->daddr 
				
			)	{

				if (temp->session->isModify == WORK_INCOMPLETE)		{
					if (temp->session->org_destport == tuple_item->dport)	{
					}
				}
				else	{
					if (temp->session->fake_destport == tuple_item->dport)	{

					}

				}	

			}
		}
		else if (hook == NF_INET_LOCAL_OUT)	{
			if (
				temp->session->sip == tuple_item->daddr &&
				temp->session->sip == tuple_item->saddr &&
			)	{

			}

		}
		
	}
}

void delete_session_item(struct list_head *head, struct session_data * data)
{
	struct session_list 	* temp = NULL;
	struct list_head 	* pos  = NULL;
	
	list_for_each(pos, head)
	{
		temp = list_entry(pos, struct session_list, list);

		if (	temp->session->sip == data->sip ||
			temp->session->dip == data->dip ||
			temp->session->orgport_destport == data->orgport_destport 
		)
		{

		}
	}

}
