#include "nd_nix_rules.h"

#include <linux/string.h>
#include "nd_nix_util_str.h"

static DEFINE_RAW_SPINLOCK(nd_raw_spinlock);
/*
 *
 */
int nd_nfm_chk_iprang(__u32 ip, __u32 start, __u32 end)
{
        if ((ip & 0xFFFFFF00) != (start & 0xFFFFFF00) || (ip & 0xFFFFFF00) != (end & 0xFFFFFF00)) {

                return 0;
        }

        return (ip >= start && ip <= end);
}

/*
 *   * use to hook msg
 */
int nd_get_struct_data_by_type(char * szData,  struct cmd_service_rule_pars_data *_data)
{
	struct cmd_service_rule_pars_data *data = _data;
	char  *szpars, *token;
	int ret = 0, nIndex = 0;
	bool bService = false, bFakeExceptAddr = false, bMode = false;
	
	if (szData == NULL || strlen(szData) <= 0)
		return -1;

	szpars = kstrdup(szData, GFP_KERNEL );		
	while (( token = strsep(&szpars, "|")) != NULL)   {
		
		if (token)	
		{
			if (nIndex  == INDX_RULE_TYPE)	{
			
				ret = kstrtou32(token, 10, &data->rule_type);
				if (ret != 0 )		{
						
					printk ("kstrtou32 result\n");
					return -1;
				}
			}
			
			else if (nIndex > (int)INDX_RULE_TYPE)	{

				if (data->rule_type == INDX_RULE_TYPE_SERVICE)	{

					if (nIndex == INDX_SVC_RULE_SERVICE )		{

						if (token == NULL || strlen (token) <= 0 )
						{
							bService = false;
						}
						else
						{
							bService = true;
						
							ret = kstrtou16(token, 10, &data->service);
							if (ret != 0)   {
								printk ("nd_get_struct_data_by_type :: failed to convert a service string to an service[service:%s]\n", token);
							}

							else 
							{
								//printk ("nd_get_struct_data_by_type :: success to convert a service string to an service [%u]\n", data->service);
							}
						}
					}

					else if (nIndex ==  INDX_SVC_RULE_FAKEPORT )	{	
						if (token == NULL || strlen (token ) <= 0 )	
						{
							bFakeExceptAddr = false;
						}
						else
						{
							bFakeExceptAddr = true;

							ret = kstrtou16(token, 10, &data->forward);
							if (ret != 0)   {
								printk ("nd_get_struct_data_by_type :: failed to convert a fakeport string to an service[fakeport]\n");
							}

							else 	{
								//printk ("nd_get_struct_data_by_type :: success to conver a fakeport string to an service [%u]\n", data->fakeport);
							}
						}
					}

					else if (nIndex == INDX_SVC_RULE_MODE )		{
						if (token == NULL || strlen (token) <= 0)	
						{
							bMode = false;
						}
						else
						{
							bMode = true;

							ret = kstrtou32(token, 10, &data->data);
							if (ret != 0)   {
								printk ("nd_get_struct_data_by_type :: failed to convert a mode string to an service[mode]\n");
							}

							else 	{
								//printk ("nd_get_struct_data_by_type :: success to conver a mode string to an service [%u]\n", data->data); 
							}
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
						
						ret = kstrtou32(token, 10, &data->data);
						if (ret != 0)   {
							printk ("nd_get_struct_data_by_type :: failed to convert a fake address string to an fakeexcept\n");
						}

						else	{
							//printk ("nd_get_struct_data_by_type :: success to convert a fake address string to an fakeexcept [%u]\n", subservice->data);
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
						ret = kstrtou32(token, 10, &data->data);
						if (ret != 0)   {
							printk ("nd_get_struct_data_by_type :: failed to convert a drop address string to an dropexcept\n");
						}

						else 	{
							//printk ("nd_get_struct_data_by_type :: success to convert a drop address string to an dropexcept [%u]\n", data->data );
						}
					}
				}

				else if (data->rule_type == INDX_RULE_TYPE_SOURCEIPS) {
					if (nIndex == INDX_SOURCEIP_RULE_SERVICE )	{
						ret = kstrtou16(token, 10, &data->service);
						if (ret != 0)	{
							printk ("nd_get_struct_data_by_type :: failed to convert a service string to an service ip\n");
						}
		
					}
					else if (nIndex == INDX_SOURCEIP_RULE_EXADDR )	{
						ret = kstrtou32(token, 10, &data->data);
                                                if (ret != 0)   {
                                                        printk ("nd_get_struct_data_by_type :: failed to convert a service string to an service ip\n");
                                                }

					}
				}
			}
		}
		nIndex ++;
	}
	
	if (szpars)
		kfree (szpars);

	return -0;
}


/*
 * - use nd_add_sourceip_in_service_rule function
 */
int nd_check_targetItem_in_targetlinkedlist(struct list_head *head,void * struct_data, __u32 uType)
{
	struct nd_service_rule_data_new	*service, *service_temp;
	struct nd_fake_except_rule_data *fakeExcept, *fakeExcept_temp;
	struct nd_drop_except_rule_data	*dropExcept, *dropExcept_temp;
	struct nd_target_source_rule_data *sourceips, *sourceips_temp;

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

#ifdef _SUPP_FAKE_RULE
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
#endif //_SUPP_FAKE_RULE

	else if (uType == INDX_RULE_TYPE_FAKEEXCEPT)	{
		fakeExcept = (struct nd_fake_except_rule_data*)struct_data;
		list_for_each_safe (pos, next, head )	{
			fakeExcept_temp = list_entry ( pos, struct nd_fake_except_rule_data, list);
			if (!fakeExcept_temp)
				return ND_CHECK_NO;
			if (fakeExcept_temp->nType == INDX_RULE_IPADDR_SPECIFIC)
			{
				if (fakeExcept_temp->startIpaddr == fakeExcept->startIpaddr)	{
					return ND_CHECK_OK;
				}
			}
			else if (fakeExcept_temp->nType == INDX_RULE_IPADDR_HOSTRANGE )
			{
				if (	(fakeExcept_temp->startIpaddr == fakeExcept->startIpaddr) &&
					(fakeExcept_temp->endIpaddr == fakeExcept->endIpaddr)
				)	{

					return ND_CHECK_OK;
				}
			}
			else 
			{
				
			}
		}
	}

#ifdef _SUPP_DROP_RULE
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
#endif //_SUPP_DROP_RULE

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

	else if (uType == INDX_RULE_TYPE_SOURCEIPS )	{
		sourceips = (struct nd_target_source_rule_data*)struct_data;
		list_for_each_safe (pos, next, head )	{
			sourceips_temp = list_entry (pos, struct nd_target_source_rule_data, list );
			if (!sourceips_temp)	{
				return ND_CHECK_NO;
			}
#ifdef ND_SUPP_RULE_IPRANGE
			if (sourceips_temp->nType == INDX_RULE_IPADDR_SPECIFIC)		{
				if (sourceips_temp->startIpaddr == sourceips->startIpaddr)	{
					return ND_CHECK_OK;
				}
			}

			else if (sourceips_temp->nType == INDX_RULE_IPADDR_HOSTRANGE)	{
				if (	(sourceips_temp->startIpaddr == sourceips->startIpaddr) &&
					(sourceips_temp->endIpaddr   == sourceips->endIpaddr)	)
				{
					return ND_CHECK_OK;
				}
			}

#else
			if (sourceips_temp->remoteAddr == sourceips->remoteAddr)	{
				return ND_CHECK_OK;
			}
#endif
		}
	}
			
	else
	{
		return ND_CHECK_NO;
	}

	return ND_CHECK_NO;
}


/*
 * # not use ... dorp rule is not support
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


/*
 * # not use .. drop rule is not support
 */
int nd_del_dropExcept_in_service_rule(__u16 _uService, __u32 _uDropExceptIp)
{
        struct nd_service_rule_data_new *service_rule;
        struct nd_drop_except_rule_data *drop_except;

        struct list_head * pos, *next;
        struct list_head *droppos, *dropnext;

        list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {
                service_rule = list_entry (pos , struct nd_service_rule_data_new, list);

                if (service_rule)       {

                        if (!list_empty (&service_rule->dropExcept.list))       {

                                list_for_each_safe (droppos, dropnext, &service_rule->dropExcept.list)  {
                                        drop_except = list_entry (droppos, struct nd_drop_except_rule_data, list);

                                        if (drop_except)        {
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
 * - use to nd_device_ioctl function
 */
#ifdef ND_SUPP_RULE_IPRANGE
int nd_del_sourceip_in_service_rule(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uEipAddr)
#else
int nd_del_sourceip_in_service_rule(__u16 _uService, __u32 _uSourceIP)
#endif // ND_SUPP_RULE_IPRANGE
{
	if (_uService <= 0 || _uType < 0 || _uSipAddr <= 0 )
	{
		return ND_ERROR_INVALID_PARAMETER;
	}

	if ( 	_uType != INDX_RULE_IPADDR_SPECIFIC 
		&& _uType != INDX_RULE_IPADDR_HOSTRANGE	)
	{
		return ND_ERROR_DATA_MISMATCH; // or ND_ERROR_INVALID_PARAMETER
	}
	
	struct nd_service_rule_data_new *service_rule;
        struct nd_target_source_rule_data * sourceips;
        struct list_head *pos, *next, *srcpos, *srcnext;
	//int ret = 0;

	if (list_empty (&nd_list_service_rules_new.list))
	{
		return ND_ERROR_EMPTY_RULE;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)		{
		service_rule = list_entry (pos, struct nd_service_rule_data_new, list);
		if (service_rule)
		{
			if (service_rule->service == _uService )		{
				if (service_rule->mode != ND_SERVICE_SOUR_BASED_TYPE)	{
					printk ("failed to deleted target service rule - service[%u] rule type is source base ...\n", _uService);	
					return ND_ERROR_DATA_MISMATCH;
				}

				if (!list_empty (&service_rule->sourceips.list))	{

					list_for_each_safe (srcpos, srcnext, &service_rule->sourceips.list)	{
						sourceips = list_entry (srcpos, struct nd_target_source_rule_data, list);

#ifdef ND_SUPP_RULE_IPRANGE
						if (_uType == INDX_RULE_IPADDR_SPECIFIC)	{
							if (	sourceips && 
								(sourceips->startIpaddr == _uSipAddr)	)
							{
								raw_spin_lock(&nd_raw_spinlock);

								list_del(srcpos);
								kfree(sourceips);

								raw_spin_unlock(&nd_raw_spinlock);

								return ND_ERROR_SUCCESS;
							}
						}

						else if (_uType == INDX_RULE_IPADDR_HOSTRANGE)	{
							if (	sourceips &&
								(sourceips->startIpaddr == _uSipAddr) &&
								(sourceips->endIpaddr	== _uEipAddr)	)
							{
								raw_spin_lock(&nd_raw_spinlock);

								list_del(srcpos);
								kfree(sourceips);

								raw_spin_unlock(&nd_raw_spinlock);
								return ND_ERROR_SUCCESS;
							}
						}						
#else
						if (sourceips && sourceips->remoteAddr == _uSourceIP)		{

							raw_spin_lock(&nd_raw_spinlock);

							list_del(srcpos);
							kfree (sourceips);

							raw_spin_unlock(&nd_raw_spinlock);

							return ND_ERROR_SUCCESS;		
						}
#endif
					}
				}
			}
		}	
	}	
	
	return ND_ERROR_NOTFOUND_RULE;
}

/*
 * - use to nd_device_ioctl function
 */
#ifdef ND_SUPP_RULE_IPRANGE
int nd_add_sourceip_in_service_rule (__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uEipAddr)
#else
int nd_add_sourceip_in_service_rule (__u16 _uService, __u32 _uSourceIp)
#endif
{
	struct nd_service_rule_data_new *service_rule;
	struct nd_target_source_rule_data * sourceips;
	struct list_head *pos, *next;
	int ret = 0;

	if (list_empty (&nd_list_service_rules_new.list))
	{
		return -1;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)	{
		service_rule = list_entry (pos, struct nd_service_rule_data_new, list );
		if (service_rule)
		{

			if (service_rule->service == _uService )		{

				if (service_rule->mode != ND_SERVICE_SOUR_BASED_TYPE)           {

                                	printk ("failed to added target service rule - suervice[%u] rule type is source base ...\n", _uService);
                                	return -1;
                        	}

				
				sourceips = kmalloc (sizeof (struct nd_target_source_rule_data), GFP_KERNEL);
				if (sourceips == NULL )		{
					printk ("error message : failed to alloc(kmalloc) memory buffer....\n");
					return -1;
				}

#ifdef ND_SUPP_RULE_IPRANGE
				if (sourceips->nType == INDX_RULE_IPADDR_SPECIFIC)		{

					sourceips->startIpaddr = _uSipAddr;
				}

				else if (sourceips->nType == INDX_RULE_IPADDR_HOSTRANGE)		{
					sourceips->startIpaddr  = _uSipAddr;
					sourceips->endIpaddr	= _uEipAddr;
				}
#else
				sourceips->remoteAddr = _uSourceIp;
#endif

				if (!list_empty (&service_rule->sourceips.list))	{

					ret = nd_check_targetItem_in_targetlinkedlist(&service_rule->sourceips.list, sourceips, INDX_RULE_TYPE_SOURCEIPS);
					if (ret == ND_CHECK_OK)		{
						printk ("already exist target sources ip address....[%u]\n", _uSipAddr);
                                       		kfree (sourceips);
                                        	return -1;
					}
				}
				
				raw_spin_lock(&nd_raw_spinlock);

				INIT_LIST_HEAD (&sourceips->list);
                        	list_add_tail (&sourceips->list, &service_rule->sourceips.list);
				
				raw_spin_unlock(&nd_raw_spinlock);
			}
		}
	}
	return 0;
}

/*
 * - use to nd_device_ioctl function
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

                        if (!list_empty (&service_rule->dropExcept.list))       {
                                ret = nd_check_targetItem_in_targetlinkedlist(&service_rule->dropExcept.list, drop_except, INDX_RULE_TYPE_DROPEXCEPT);

                                if (ret == ND_CHECK_OK )
                                {
                                        printk ("already exist target exception rule....[%u]\n", _uDropExceptIp);
                                        kfree (drop_except);
                                        return -1;
                                }

                        }

			raw_spin_lock(&nd_raw_spinlock);

                        INIT_LIST_HEAD (&drop_except->list);
                        list_add_tail (&drop_except->list, &service_rule->dropExcept.list);

			raw_spin_unlock(&nd_raw_spinlock);
                }
        }

        return 0;
}

/*
 * - use to nd_device_ioctl function
 */
int nd_mod_fakeExcept_in_service_rule(__u16 _uService, __u32 _uFakeExceptIp, __u32 _uFakeExcept_modIp)
{
        struct nd_service_rule_data_new *service_rule;
        struct nd_fake_except_rule_data *fake_except;

        struct list_head * pos, *next;
        struct list_head *fakepos, *fakenext;


        bool bChkOrg = false, bChkModify = false;

        list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

                service_rule = list_entry (pos, struct nd_service_rule_data_new, list );
                if (!service_rule)      {
                        return -1;
                }

                if (service_rule->service == _uService )                {
                        if (!list_empty (&service_rule->fakeExcept.list))       {
                                bChkOrg = false, bChkModify = false;
                                list_for_each_safe (fakepos, fakenext, &service_rule->fakeExcept.list)  {
                                        fake_except = list_entry (fakepos, struct nd_fake_except_rule_data, list);
                                        if (fake_except)        {
#ifdef ND_SUPP_RULE_IPRANGE
						if (fake_except->nType == INDX_RULE_IPADDR_SPECIFIC)	{

						}
					
#else
                                                if (fake_except->remoteAddr == _uFakeExceptIp)  {

                                                        if (bChkModify == true)
                                                        {
                                                                return -1;
                                                        }
							raw_spin_lock(&nd_raw_spinlock);

                                                        bChkOrg = true;
                                                        uBakFakeExceptIp = fake_except->remoteAddr;
                                                        fake_except->remoteAddr = _uFakeExcept_modIp;

							raw_spin_unlock(&nd_raw_spinlock);
                                                }
                                                if (fake_except->remoteAddr == _uFakeExcept_modIp)      {
                                                        bChkModify = true;

                                                        if (bChkOrg == true)    {
								raw_spin_lock (&nd_raw_spinlick);

                                                                fake_except->remoteAddr = uBakFakeExceptIp;

								rqw_spin_unlock(&nd_raw_spinlock);
                                                        }
                                                        return -1;
                                                }
#endif
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
 * - use to nd_device_ioctl function
 */
#ifdef ND_SUPP_RULE_IPRANGE
int nd_del_fakeExcept_in_service_rule(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uEipAddr)
#else
int nd_del_fakeExcept_in_service_rule(__u16 _uService, __u32 _uFakeExceptIP)
#endif
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
                if (!service_rule)      
		{
                        return -1;
                }

                if (service_rule->service == _uService )                
		{

	
			list_for_each_safe (fakepos, fakenext, &service_rule->fakeExcept.list)	
			{

				fake_except = list_entry (fakepos, struct nd_fake_except_rule_data, list);
				if (fake_except)	{

#ifdef ND_SUPP_RULE_IPRANGE
					if (fake_except->nType == _uType)		{

						if (fake_except->nType == INDX_RULE_IPADDR_SPECIFIC)		{

							if (fake_except->startIpaddr == _uSipAddr )
							{
								printk ("delete target data : [%u]/[%u]\n", fake_except->startIpaddr, _uSipAddr);
								raw_spin_lock (&nd_raw_spinlock);

								list_del(fakepos);
								kfree (fake_except);			

								raw_spin_unlock(&nd_raw_spinlock);
							}

						}
						else if (fake_except->nType == INDX_RULE_IPADDR_HOSTRANGE)	{
							
							if (	(fake_except->startIpaddr == _uSipAddr)	&&
								(fake_except->endIpaddr == _uEipAddr)	)	
							{
								printk ("delete target data : [%u]/[%u]\n", fake_except->startIpaddr, _uSipAddr);

								raw_spin_lock (&nd_raw_spinlock);

                                                                list_del(fakepos);
                                                                kfree (fake_except);

								raw_spin_unlock (&nd_raw_spinlock);
							}
						}
					}
			
#else
					if (fake_except->remoteAddr == _uFakeExceptIP)	{


						printk ("delete target data : [%u]/[%u]\n", fake_except->remoteAddr, _uFakeExceptIP);

						raw_spin_lock (&nd_raw_spinlock );

						list_del(fakepos);
						kfree (fake_except);

						rqw_spin_unlock (&nd_raw_spinlock );

						return 0;
					}
#endif
				}
                        }
                }
	}
        return -1;
}


/*
 * - use to nd_device_ioctl function
 */
#ifdef ND_SUPP_RULE_IPRANGE
int nd_add_fakeExcept_in_service_rule(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uEipAddr)
#else
int nd_add_fakeExcept_in_service_rule(__u16 _uService, __u32 _uFakeExceptIp)	
#endif
{
	struct nd_service_rule_data_new *service_rule;
	struct nd_fake_except_rule_data *fake_except;

	struct list_head * pos, *next;
	int ret = 0;

	bool bFinded = false, bFindedService = false;

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

		if (list_empty (&nd_list_service_rules_new.list) )
		{
			printk ("is not exist added service rule...\n");
			return ND_ERROR_DATA_EMPTY;
		}
                service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
                if (!service_rule)      {
			printk ("nd_add_fakeExcept_in_service_rule : failed to get service list..\n");
                        return ND_ERROR_DATA_EMPTY;
                }

                if (service_rule->service == _uService )                {

			bFindedService = true;
                        fake_except = kmalloc (sizeof(struct nd_fake_except_rule_data), GFP_KERNEL );
                        if (!fake_except)	{
				printk ("nd_add_fakeExcept_in_service_rule : failed to alloc fake_except object..\n"); 
                                return ND_ERROR_ENOMEM;
			}
			
#ifdef ND_SUPP_RULE_IPRANGE
			fake_except->startIpaddr = _uSipAddr;
			fake_except->endIpaddr 	 = _uEipAddr;
			fake_except->nType	 = _uType;	
#else			
                        fake_except->remoteAddr = _uFakeExceptIp;
#endif

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
		return ND_ERROR_ENOMEM;
	}

	if (bFinded == true )
	{
		printk ("failed to added target service rule - [%u] is alread exist in service[%u] rule\n", /*_uFakeExceptIp*/_uSipAddr, _uService);
		return ND_ERROR_NOTFOUND_RULE;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)		{

		service_rule = list_entry (pos , struct nd_service_rule_data_new, list );
		if (!service_rule)	{
			return -1;
		}

		if (service_rule->service == _uService )		{

			if (service_rule->mode != ND_SERVICE_PORT_BASED_TYPE)		{
				
				printk ("failed to added target service rule - suervice[%u] rule type is port base ...\n", _uService);
				return ND_ERROR_DATA_MISMATCH;
			}

			fake_except = kmalloc (sizeof(struct nd_fake_except_rule_data), GFP_KERNEL );
                        if (!fake_except)
                                return ND_ERROR_ENOMEM;
#ifdef ND_SUPP_RULE_IPRANGE
			fake_except->startIpaddr = _uSipAddr;
			fake_except->endIpaddr	 = _uEipAddr;
			fake_except->nType	 = _uType;
#else
			fake_except->remoteAddr = _uFakeExceptIp;		
#endif


			if (!list_empty (&service_rule->fakeExcept.list))	{
				ret = nd_check_targetItem_in_targetlinkedlist(&service_rule->fakeExcept.list, fake_except, INDX_RULE_TYPE_FAKEEXCEPT);
				
				if (ret == ND_CHECK_OK )
				{
					printk ("already exist target exception rule....[%u]\n", _uSipAddr);
					kfree (fake_except);
					return ND_ERROR_ALREADEXIST_RULE;
				}
			}

			raw_spin_lock (&nd_raw_spinlock);

			INIT_LIST_HEAD (&fake_except->list);
			list_add_tail (&fake_except->list, &service_rule->fakeExcept.list);		

			raw_spin_unlock (&nd_raw_spinlock);
			return 0;
		}
	}

	return -1;
	
}


/*
 * - use to nd_device_ioctl function
 */
int nd_mod_service_to_index(struct cmd_service_rule_pars_data* service_data)	
{
	struct nd_service_rule_data_new *service;
        struct list_head *pos, *next;
	int index = 0;

	if (service_data == NULL )
	{
		return -1;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list) {

                service = list_entry (pos, struct nd_service_rule_data_new, list );
                if (service)            {

                        if (index == service_data->ret)      {

				service->service	= service_data->service;
                                service->fakeport       = service_data->forward;
                                service->ruleType       = service_data->rule_type;
                                service->mode           = service_data->data;

                                return 0;
                        }
			index ++;
                }
        }

	return 0;

}

/*
 * - use to nd_device_ioctl function
 */
int nd_mod_fakeExcept_in_service_rule_to_index(struct cmd_service_sub_rule_pars_data* sub_rule)
{
	struct nd_service_rule_data_new *service;
	struct nd_fake_except_rule_data *fakeExcept;
	struct list_head *pos, *next, *fpos, *fnext;
	int index = 0;

	if (sub_rule == NULL)	{
		return -1;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list) {

                service = list_entry (pos, struct nd_service_rule_data_new, list );
                if (service)            {

                        if (service->service == sub_rule->service)      {
				
				if (!list_empty(&service->fakeExcept.list))     {

					list_for_each_safe (fpos, fnext, &service->fakeExcept.list)     {

						fakeExcept = list_entry (fpos, struct nd_fake_except_rule_data, list);
						if (fakeExcept && (sub_rule->ret == index))
						{
							raw_spin_lock (&nd_raw_spinlock );
							
							fakeExcept->nType 	= sub_rule->type;
							fakeExcept->startIpaddr = sub_rule->saddr;
							fakeExcept->endIpaddr 	= sub_rule->eaddr;

							raw_spin_lock (&nd_raw_spinlock );
							return 0;
						}
						
						index ++;
					}
				}
                        }
                }
        }

	return -1;
}

/*
 * - use to nd_device_ioctl function
 */
int nd_mod_sourceIp_in_service_rule_to_index(struct cmd_service_sub_rule_pars_data* sub_rule)
{
        struct nd_service_rule_data_new 	*service;
        struct nd_target_source_rule_data 	*sourceips;
        struct list_head *pos, *next, *spos, *snext;
        int index = 0;

        if (sub_rule == NULL)   {
                return -1;
        }

        list_for_each_safe (pos, next, &nd_list_service_rules_new.list) {

                service = list_entry (pos, struct nd_service_rule_data_new, list );
                if (service)            {

                        if (service->service == sub_rule->service)      {

                                if (!list_empty(&service->sourceips.list))     {

                                        list_for_each_safe (spos, snext, &service->sourceips.list)     {

                                                sourceips = list_entry (spos, struct nd_target_source_rule_data, list);
                                                if (sourceips && (sub_rule->ret == index))
                                                {
							raw_spin_lock (&nd_raw_spinlock);

                                                        sourceips->nType       = sub_rule->type;
                                                        sourceips->startIpaddr = sub_rule->saddr;
                                                        sourceips->endIpaddr   = sub_rule->eaddr;

							raw_spin_unlock (&nd_raw_spinlock);
                                                        return 0;
                                                }

                                                index ++;
                                        }
                                }
                        }
                }
        }

        return -1;
}

/*
 * - use to nd_device_ioctl function
 */
int nd_nfm_del_default_all_rule(void)   {

        struct nd_service_rule_data_new *service;
        struct nd_fake_except_rule_data *fakeExcept;
        struct list_head *pos, *next;
        struct list_head *fakeEpos, *fakeEnext;

	raw_spin_lock (&nd_raw_spinlock );

        list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {
                service = list_entry (pos, struct nd_service_rule_data_new, list );

                if (service )           {

                        if (!list_empty(&service->fakeExcept.list))     {

                                list_for_each_safe (fakeEpos, fakeEnext, &service->fakeExcept.list)     {

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

	raw_spin_unlock (&nd_raw_spinlock );

        return 0;
}


/*
 *  - use to nd_device_ioctl function
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

	raw_spin_lock( &nd_raw_spinlock);
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
							
							raw_spin_unlock(&nd_raw_spinlock);							

							return 0;
						}	
					}
				}
			}
			list_del(pos);
			kfree (service);
			
			raw_spin_unlock (&nd_raw_spinlock);
			
			return 0;
		}
	}

	raw_spin_unlock (&nd_raw_spinlock );
	
	return -1;
}

/*
 * - use to nd_nix_hook_recv_cmd function
 */
int nd_add_service(__u16 _uService, __u16 _uFakePort, __u32 _uRuleType, __u32 _uMode)
{
        struct nd_service_rule_data_new *service_rule;
        struct list_head *pos, *next;

	if (_uRuleType != ND_SERVICE_PORT_BASED_TYPE && _uRuleType != ND_SERVICE_SOUR_BASED_TYPE )	{

		return ND_ERROR_DATA_MISMATCH;
	}


        if (!list_empty (&nd_list_service_rules_new.list))
        {
                list_for_each_safe (pos, next, &nd_list_service_rules_new.list)         {

                        service_rule = list_entry (pos, struct nd_service_rule_data_new, list);
                        if (service_rule)
                        {
                                if (service_rule->service == _uService)         {

                                        printk ("nd_add_service :: failed to add service rule...[%u]\n", _uService);
                                        return ND_ERROR_ALREADEXIST_RULE;
                                }
                        }
                }
        }

        service_rule = kmalloc (sizeof (struct nd_service_rule_data_new), GFP_KERNEL );
        if (!service_rule)
                return ND_ERROR_ALREADEXIST_RULE;

	raw_spin_lock (&nd_raw_spinlock );

        service_rule->service   = _uService;
        service_rule->fakeport  = _uFakePort;
	service_rule->ruleType  = _uRuleType;
        service_rule->mode      = _uMode;


	INIT_LIST_HEAD (&service_rule->sourceips.list);
        INIT_LIST_HEAD (&service_rule->fakeExcept.list);
        INIT_LIST_HEAD (&service_rule->dropExcept.list);

        INIT_LIST_HEAD (&service_rule->list);
        list_add_tail (&service_rule->list, &nd_list_service_rules_new.list);

	raw_spin_unlock (&nd_raw_spinlock );

        return ND_ERROR_SUCCESS;
}

/*
 *  - use to nd_device_ioctl function
 */
int nd_nfm_get_service_rule_index(__u16 _uService)
{
	struct nd_service_rule_data_new *service_rule;
        struct list_head * pos, * next;
	int index = 0;

        if (!list_empty (&nd_list_service_rules_new.list ))     {

                list_for_each_safe (pos, next,  &nd_list_service_rules_new.list)        {
                        service_rule = list_entry (pos, struct nd_service_rule_data_new, list);
                        if (service_rule )
                        {
				if (service_rule->service == _uService)	{
					return index;
				}
                        
				index ++;        
                        }
                }
        }

        return -1;

}

/*
 *  - use to nd_device_ioctl function
 */
int nd_nfm_get_fakeExcept_rule_index(struct cmd_service_sub_rule_pars_data* sub_rule)
{
	struct nd_service_rule_data_new *service;
        struct nd_fake_except_rule_data *fakeexcept;
        struct list_head *pos, *next, *fpos, *fnext;
	int  index = 0;
	bool bFind = false;
	

        if (sub_rule == NULL)
        {
                return -1;
        }

        list_for_each_safe (pos, next, &nd_list_service_rules_new.list) {

                service = list_entry (pos, struct nd_service_rule_data_new, list );
                if (service)            {

                        if (service->service == sub_rule->service)      {
			
				if (!list_empty (&service->fakeExcept.list))
                                {
	                                list_for_each_safe( fpos, fnext, &service->fakeExcept.list)        {
        	                                fakeexcept = list_entry (fpos, struct nd_fake_except_rule_data, list);
                                                if (fakeexcept)         {
							if (	fakeexcept->nType == sub_rule->type  		&& 
								fakeexcept->startIpaddr == sub_rule->saddr 	&& 
								fakeexcept->endIpaddr == sub_rule->eaddr )
							{
								bFind = true;
								return index;						
							}
						}

						index ++;
					}
				}
                        }
                }
        }

	return -1;
}

/*
 *  - use to nd_device_ioctl function
 */
int nd_nfm_get_sourceIp_rule_index(struct cmd_service_sub_rule_pars_data* sub_rule)
{
        struct nd_service_rule_data_new *service;
        struct nd_target_source_rule_data *sourceip;
        struct list_head *pos, *next, *spos, *snext;
        int index = 0;
        bool bFind = false;


        if (sub_rule == NULL)
        {
                return -1;
        }

        list_for_each_safe (pos, next, &nd_list_service_rules_new.list) {

                service = list_entry (pos, struct nd_service_rule_data_new, list );
                if (service)            {

                        if (service->service == sub_rule->service)      {

                                if (!list_empty (&service->sourceips.list))
                                {
                                        list_for_each_safe( spos, snext, &service->sourceips.list)        {
                                                sourceip = list_entry (spos, struct nd_target_source_rule_data, list);
                                                if (sourceip)         {
                                                        if (    sourceip->nType == sub_rule->type             &&
                                                                sourceip->startIpaddr == sub_rule->saddr      &&
                                                                sourceip->endIpaddr == sub_rule->eaddr )
                                                        {
                                                                bFind = true;
                                                                return index;
                                                        }
                                                }

                                                index ++;
                                        }
                                }
                        }
                }
        }

        return -1;
}

/*
 *  - use to nd_device_ioctl function
 */
int nd_nfm_get_service_rules(char *output)
{
	struct nd_service_rule_data_new *service_rule;
	struct list_head * pos, * next;
	int size = 0, len = 0;
	char szTmp[24] = {0,};

	if (output == NULL)
	{
		return -1;
	}	

	if (!list_empty (&nd_list_service_rules_new.list ))     {

		list_for_each_safe (pos, next,  &nd_list_service_rules_new.list)	{
			service_rule = list_entry (pos, struct nd_service_rule_data_new, list);
			if (service_rule )
			{
				memset (&szTmp, 0, sizeof (szTmp));
                                size = snprintf (szTmp, sizeof (szTmp), "%u|%u|%u|%u|||\n", service_rule->service,service_rule->fakeport, service_rule->ruleType, service_rule->mode);

                                strcat_safe (output + len, szTmp, ND_NETLINK_DATA_SIZE - len);

				len += size;
			}
		}
	}

	return 0;
}

/*
 *  - use to nd_device_ioctl function
 */
int nd_nfm_get_fakeexcept_rules(char * output)
{
	struct nd_service_rule_data_new *service_rule;
	struct nd_fake_except_rule_data *fakeexcept;
        struct list_head * pos, * next, *fpos, *fnext;
        int size = 0, len = 0;
	__u32 serviceport = 0;
        char szTmp[1024] = {0,};

        if (output == NULL)
        {
                return -1;
        }

	serviceport = string_to_u32(output);

	memset (output, 0, ND_NETLINK_DATA_SIZE);

	if (!list_empty (&nd_list_service_rules_new.list ))     {

                list_for_each_safe (pos, next,  &nd_list_service_rules_new.list)        {
                        service_rule = list_entry (pos, struct nd_service_rule_data_new, list);
                        if (service_rule )
                        {
				if (service_rule->service == serviceport)		{
					if (!list_empty (&service_rule->fakeExcept.list))
					{
						list_for_each_safe( fpos, fnext, &service_rule->fakeExcept.list)	{
							fakeexcept = list_entry (fpos, struct nd_fake_except_rule_data, list);
							if (fakeexcept)		{
								if (strlen(output) > 0 )		{
									strcat_safe (output + len, ",", ND_NETLINK_DATA_SIZE - len);
                                                                        len += 1;
								}

								memset (&szTmp, 0, sizeof (szTmp));
								size = snprintf (szTmp, sizeof (szTmp), "%u|%u|%u|", fakeexcept->nType,fakeexcept->startIpaddr, fakeexcept->endIpaddr);
								
								strcat_safe (output + len, szTmp, ND_NETLINK_DATA_SIZE - len);
								len += size;
							}
						}
					}
				}
                        }
                }
        }

	return 0;
}

/*
 * !! ## NOT USE
 */
int nd_nfm_get_sourceips_rules(char *output)
{
	struct nd_service_rule_data_new *service_rule;
        struct nd_target_source_rule_data *sourceips;
        struct list_head * pos, * next, *fpos, *fnext;
        int size = 0, len = 0;
        __u32 serviceport = 0;
        char szTmp[24] = {0,};

        if (output == NULL)
        {
                return -1;
        }

        serviceport = string_to_u32(output);

        memset (output, 0, ND_NETLINK_DATA_SIZE);

        if (!list_empty (&nd_list_service_rules_new.list ))     {

                list_for_each_safe (pos, next,  &nd_list_service_rules_new.list)        {
                        service_rule = list_entry (pos, struct nd_service_rule_data_new, list);
                        if (service_rule )
                        {
                                if (service_rule->service == serviceport)               {
                                        if (!list_empty (&service_rule->sourceips.list))
                                        {
                                                list_for_each_safe( fpos, fnext, &service_rule->sourceips.list)        {
                                                        sourceips = list_entry (fpos, struct nd_target_source_rule_data, list);
                                                        if (sourceips)         {
                                                                memset (&szTmp, 0, sizeof (szTmp));
                                                                size = snprintf (szTmp, sizeof (szTmp), "%u|%u|%u|\n", sourceips->nType,sourceips->startIpaddr, sourceips->endIpaddr);

                                                                strcat_safe (output + len, szTmp, ND_NETLINK_DATA_SIZE - len);

                                                                len += size;
                                                        }
                                                }
                                        }
                                }
                        }
                }
        }

        return 0;
}

/*
 *
 	output data size is 8192
 *
 */
///
//

/*
 *  - use to nd_device_ioctl function
 */
//int nd_nfm_get_rule_info(__u16 _uService, __u32 _uType, char *output )
int nd_nfm_get_rule_info(char *output )
{
	struct nd_service_rule_data_new *service_rule;
        struct nd_fake_except_rule_data *fakeexcept;
	struct nd_target_source_rule_data *sourceIps;
        struct list_head *pos, *next, *fepos, *fenext , *srcippos, *srcipnext;
	char sData[ND_NETLINK_DATA_SIZE] = {0,};
	char sExcept[ND_MAXCNTIP_ON_RULE*ND_IPADDR_U16_SIZE] = {0,};
	char sSourceIps[ND_MAXCNTIP_ON_RULE*ND_IPADDR_U16_SIZE] = {0,};
	char szTmp[16] = {0,};
	int nElen = 0, size = 0, len = 0, nTmp = 0;

	int _uType = 0;


	if (!list_empty (&nd_list_service_rules_new.list ))	{

		list_for_each_safe (pos, next, &nd_list_service_rules_new.list )	{
			service_rule = list_entry (pos, struct nd_service_rule_data_new, list);

			if (service_rule)	{
				
				
				if (
					_uType == ND_GET_RULE_ALL || 
					_uType == ND_GET_RULE_TARSERVICE
				)	{

					if (!list_empty (&service_rule->fakeExcept.list))	{
						
						list_for_each_safe (fepos, fenext, &service_rule->fakeExcept.list)	{
							fakeexcept = list_entry (fepos, struct nd_fake_except_rule_data, list );
							if (fakeexcept)		{
								if (strlen (sExcept) > 0)	{
									strcat_safe (sExcept + nElen, ",", (ND_MAXCNTIP_ON_RULE*ND_IPADDR_U16_SIZE) - nElen);
									nElen += 1;
								}
#ifdef ND_SUPP_RULE_IPRANGE								
								if (fakeexcept->nType == INDX_RULE_IPADDR_SPECIFIC)
								{								
									
									memset (&szTmp, 0, sizeof (szTmp));
									size = snprintf (szTmp, sizeof (szTmp), "%u,%u,0", fakeexcept->nType,fakeexcept->startIpaddr);

	                                                        	strcat_safe (sExcept + nElen, szTmp, (ND_MAXCNTIP_ON_RULE*ND_IPADDR_U16_SIZE) - nElen);
   	                                                        	nElen += size;
								}
								else if (fakeexcept->nType == INDX_RULE_IPADDR_HOSTRANGE)
								{
									memset (&szTmp, 0, sizeof (szTmp));
									size = snprintf (szTmp, sizeof (szTmp), "%u,%u,%u", fakeexcept->nType,fakeexcept->startIpaddr, fakeexcept->endIpaddr);
					
									strcat_safe (sExcept + nElen, szTmp, (ND_MAXCNTIP_ON_RULE*ND_IPADDR_U16_SIZE) - nElen);
									nElen += size;
								}
#else
								size = snprintf (szTmp,	sizeof (szTmp), "%u", fakeexcept->startIpaddr);						
								
								strcat_safe (sExcept + nElen, szTmp, (ND_MAXCNTIP_ON_RULE*ND_IPADDR_U16_SIZE) - nElen);
								nElen += size;
#endif

							
							}
						}
					}
					
					if (!list_empty (&service_rule->sourceips.list))	{
						list_for_each_safe (srcippos, srcipnext, &service_rule->sourceips.list)	{
							sourceIps = list_entry (srcippos, struct nd_target_source_rule_data, list );
							if (sourceIps)		{
								if (strlen (sSourceIps) > 0 )	{
									strcat_safe (sSourceIps + nTmp, ",", (ND_MAXCNTIP_ON_RULE*ND_IPADDR_U16_SIZE) - nTmp);
									nTmp += 1;
								}
#ifdef ND_SUPP_RULE_IPRANGE
								if (sourceIps->nType == INDX_RULE_IPADDR_SPECIFIC)
                                                                {
									memset (&szTmp, 0, sizeof (szTmp));
									size = snprintf (szTmp, sizeof (szTmp), "%u,%u,0", sourceIps->nType,sourceIps->startIpaddr);

									strcat_safe (sSourceIps + nTmp, szTmp, (ND_MAXCNTIP_ON_RULE*ND_IPADDR_U16_SIZE) - nTmp);
									nTmp += size;
								}

								else if (sourceIps->nType == INDX_RULE_IPADDR_HOSTRANGE)
                                                                {
									memset (&szTmp, 0, sizeof (szTmp));
                                                                        size = snprintf (szTmp, sizeof (szTmp), "%u,%u,%u", sourceIps->nType,sourceIps->startIpaddr,sourceIps->endIpaddr);

                                                                        strcat_safe (sSourceIps + nTmp, szTmp, (ND_MAXCNTIP_ON_RULE*ND_IPADDR_U16_SIZE) - nTmp);
                                                                        nTmp += size;
								}
#else
								memset (&szTmp, 0, sizeof (szTmp));
								size = snprintf (szTmp, sizeof (szTmp), "%u", sourceIps->remoteAddr);
								
								strcat_safe (sSourceIps + nTmp, szTmp, (ND_MAXCNTIP_ON_RULE*ND_IPADDR_U16_SIZE) - nTmp);
								nTmp += size;
#endif
							}
						}
					}

				}
				
				size = snprintf (sData, sizeof(sData), "%u|%u|%u|%s|%s|\n", service_rule->service, service_rule->fakeport, service_rule->mode, sExcept, sSourceIps);

				strcat_safe (output + len , sData, ND_NETLINK_DATA_SIZEMAX - len);
				
				memset (&szTmp, 	0, sizeof (szTmp));
				memset (&sExcept, 	0, sizeof (sExcept));
				memset (&sData, 	0, sizeof (sData));
				memset (&sSourceIps, 	0, sizeof (sSourceIps));
				len += size;

				nElen = 0;
				nTmp = 0;
			}
		}
	}

	return 0;
}

/*
 * # ifdef_SUPP_SRCIP_IN_RULE 
 * - use nd_nix_hook_inbound_func function
 * - use nd_nix_hook_outbound_func function
 */
int nd_nfm_comfirm_the_policy_for_incoming_packet(struct nd_5tuple_data tuples, struct nd_packets_applied_to_policy ** _collect_data )
{
	struct nd_service_rule_data_new 	*service;
	struct nd_fake_except_rule_data 	*fake_except;
	struct nd_target_source_rule_data 	*source_list;
	struct list_head *pos, *next;
	struct list_head *fpos, *fnext, *spos, *snext;
	__u32 _uSourceAddr = 0;
	bool bIstargetService = false, bIsExceptRule = false;
	int retChkdata = ND_ACT_FLOWRULE_NOTFOUND;

	if (list_empty (&nd_list_service_rules_new.list ))	{
		return ND_ACT_ERROR;
	}

	list_for_each_safe (pos, next, &nd_list_service_rules_new.list)	{
		service = list_entry (pos, struct nd_service_rule_data_new, list);
		if (service )	
		{
			if (tuples.hook == NF_INET_PRE_ROUTING)		{
				if (service->service == tuples.dport)		{
					bIstargetService = true;
					_uSourceAddr = tuples.saddr;
					break;
				}
			}
			else if(tuples.hook == NF_INET_LOCAL_OUT)		{
				if (service->fakeport == tuples.sport)			{
					bIstargetService = true;
					_uSourceAddr = tuples.daddr;
					break;
				}
			}
		}
	}


	if (bIstargetService == true )		{

		if ( service->mode 	== ND_SERVICE_PORT_BASED_TYPE)	
		{
			if (!list_empty (&service->fakeExcept.list ))		{

				list_for_each_safe (fpos, fnext, &service->fakeExcept.list)	{
					fake_except = list_entry (fpos, struct nd_fake_except_rule_data, list );
					if (fake_except)	{

						if (fake_except->nType == INDX_RULE_IPADDR_SPECIFIC)	{
#ifdef ND_SUPP_RULE_IPRANGE
							if (fake_except->startIpaddr == _uSourceAddr)
#else
							if (fake_except->remoteAddr == _uSourceAddr)
#endif
							{
								(*_collect_data)->mode  = ND_SERVICE_PORT_BASED_TYPE;
                                                        	retChkdata              = ND_ACT_FLOWRULE_FASS;
                                                        	bIsExceptRule = true;
                                                        	break;
							}
						}

						else if (fake_except->nType == INDX_RULE_IPADDR_HOSTRANGE)	{

							if (nd_nfm_chk_iprang(_uSourceAddr, fake_except->startIpaddr, fake_except->endIpaddr))
							{
								(*_collect_data)->mode  = ND_SERVICE_PORT_BASED_TYPE;
                                                        	retChkdata              = ND_ACT_FLOWRULE_FASS;
                                                        	bIsExceptRule = true;
                                                        	break;
							}							

						}

						else if (fake_except->nType == INDX_RULE_IPADDR_SUBNET)		{

						}
#ifndef ND_SUPP_RULE_IPRANGE
						if (fake_except->remoteAddr == _uSourceAddr/*tuples.saddr*/)
						{
							//FOUND!!!!!!!!!!!!i!
							(*_collect_data)->mode	= ND_SERVICE_PORT_BASED_TYPE;
							retChkdata 		= ND_ACT_FLOWRULE_FASS;
							bIsExceptRule = true;
							break;

							
						}					
#endif
					}
				}
			}
			if (bIsExceptRule == false)	{
				retChkdata = ND_ACT_FLOWRULE_APPLY;
				
			}
		}

		else if (service->mode 	== ND_SERVICE_SOUR_BASED_TYPE)	{
			
			if (!list_empty (&service->sourceips.list ))		{
				list_for_each_safe (spos, snext , &service->sourceips.list)	{
					source_list = list_entry (spos, struct nd_target_source_rule_data, list );
					if (source_list)	{

#ifdef ND_SUPP_RULE_IPRANGE
						if (source_list->nType == INDX_RULE_IPADDR_SPECIFIC)	{
							//FOUND!!!!!!!!!!!!!
                                                        (*_collect_data)->mode  = ND_SERVICE_SOUR_BASED_TYPE;
                                                        retChkdata              = ND_ACT_FLOWRULE_APPLY;
                                                        bIsExceptRule = true;
                                                        break;

						}

						else if (source_list->nType == INDX_RULE_IPADDR_HOSTRANGE)	{
							if (nd_nfm_chk_iprang(_uSourceAddr, source_list->startIpaddr, source_list->endIpaddr))	{
								//FOUND!!!!!!!!!!!!!
                                                        	(*_collect_data)->mode  = ND_SERVICE_SOUR_BASED_TYPE;
                                                        	retChkdata              = ND_ACT_FLOWRULE_APPLY;
                                                        	bIsExceptRule = true;
                                                        	break;
							}
						}

						else if (source_list->nType == INDX_RULE_IPADDR_SUBNET)	{

						}

#else
						if (source_list->remoteAddr == _uSourceAddr/*tuples.saddr*/)	
						{
							//FOUND!!!!!!!!!!!!!
							(*_collect_data)->mode	= ND_SERVICE_SOUR_BASED_TYPE;
							retChkdata		= ND_ACT_FLOWRULE_APPLY;
							bIsExceptRule = true;
							break;
						}
#endif //ND_SUPP_RULE_IPRANGE
					}
				}
			}

			if (bIsExceptRule == false)	{
				retChkdata = ND_ACT_FLOWRULE_FASS;
			}
		}
	}

	if (retChkdata == ND_ACT_FLOWRULE_APPLY)		{

		if (tuples.hook == NF_INET_PRE_ROUTING)	{
			(*_collect_data)->serviceport = tuples.saddr;
			(*_collect_data)->forwardport = service->fakeport;
		}
		else if (tuples.hook == NF_INET_LOCAL_OUT )	{
			(*_collect_data)->serviceport = tuples.saddr;
                        (*_collect_data)->forwardport = service->service;
		}
	}
	

	return retChkdata;
}

/*
 * # ifndef_SUPP_SRCIP_IN_RULE
 * - use nd_nix_hook_inbound_func function
 * - use nd_nix_hook_outbound_func function
 */
int nd_nfm_chk_rule_v2( struct nd_5tuple_data tuples, __u16 *fakeport)
{
	struct nd_service_rule_data_new *service/*, *service_temp*/;
        struct nd_fake_except_rule_data *fakeExcept/*, *fakeExcept_temp*/;

	struct list_head *spos, *snext, *fepos, *fenext;

	__u16 service_port = 0;
	__u16 standard_port = 0;
	__u32 except_addr =0;

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
			service_port = tuples.sport;
			standard_port = service->fakeport;
			except_addr = tuples.daddr;
		}

                if (standard_port == service_port )                {

			list_for_each_safe (fepos, fenext, &service->fakeExcept.list)	{
				fakeExcept = list_entry (fepos, struct nd_fake_except_rule_data, list );
#ifdef ND_SUPP_RULE_IPRANGE
				if (fakeExcept->nType == INDX_RULE_IPADDR_SPECIFIC)	{
					if (fakeExcept->startIpaddr == except_addr)	
					{
						return ND_POLICY_EXCEPT;
					}
				}
				else if (fakeExcept->nType == INDX_RULE_IPADDR_HOSTRANGE) {
					if ( nd_nfm_chk_iprang(except_addr, fakeExcept->startIpaddr, fakeExcept->endIpaddr))
					{
						return ND_POLICY_EXCEPT;
					}
				
				}
				else if (fakeExcept->nType == INDX_RULE_IPADDR_SUBNET)	{

				}
#else
				if (fakeExcept->remoteAddr == except_addr)			{

#ifdef NOT_SUPP_SOURCEIP
					
					if (service->mode == ND_RULE_MODE_INDIVIDUAL)	{
						result = ND_POLICY_APPLY;
						break;
					}

					else  // ND_RULE_MODE_GENERAL
					{
						return ND_POLICY_EXCEPT;	
					}
#else
					return ND_POLICY_EXCEPT;
#endif					
					
				}
#endif //ND_SUPP_RULE_IPRANGE
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

