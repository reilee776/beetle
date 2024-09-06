#ifndef _ND_NIX_NFM_RULES_H__
#define _ND_NIX_NFM_RULES_H__

#include "../nd_nix_nfm_common.h"


int nd_get_struct_data_by_type(char * szData, struct cmd_service_rule_pars_data *_data);

int nd_check_targetItem_in_targetlinkedlist(struct list_head *head,void * struct_data, __u32 uType);

int nd_mod_dropExcept_in_service_rule(__u16 _uService, __u32 _uDropExceptIp, __u32 _uDropExcept_modIp);

int nd_del_dropExcept_in_service_rule(__u16 _uService, __u32 _uDropExceptIp);

int nd_add_dropExcept_in_service_rule(__u16 _uService, __u32 _uDropExceptIp);

#ifdef ND_SUPP_RULE_IPRANGE
int nd_del_sourceip_in_service_rule(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uEipAddr);
#else
int nd_del_sourceip_in_service_rule(__u16 _uService, __u32 _uSourceIP);
#endif

#ifdef ND_SUPP_RULE_IPRANGE
int nd_add_sourceip_in_service_rule (__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uEipAddr);
#else
int nd_add_sourceip_in_service_rule(__u16 _uService, __u32 _uSourceIp );
#endif

int nd_mod_service_to_index(struct cmd_service_rule_pars_data* service_data);

int nd_mod_fakeExcept_in_service_rule_to_index(struct cmd_service_sub_rule_pars_data* sub_rule);

int nd_mod_sourceIp_in_service_rule_to_index(struct cmd_service_sub_rule_pars_data* sub_rule);

int nd_mod_fakeExcept_in_service_rule(__u16 _uService, __u32 _uFakeExceptIp, __u32 _uFakeExcept_modIp);
#ifdef ND_SUPP_RULE_IPRANGE
int nd_del_fakeExcept_in_service_rule(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uEipAddr);

#else
int nd_del_fakeExcept_in_service_rule(__u16 _uService, __u32 _uFakeExceptIP);
#endif


#ifdef ND_SUPP_RULE_IPRANGE
int nd_add_fakeExcept_in_service_rule(__u16 _uService, __u32 _uType, __u32 _uSipAddr, __u32 _uEipAddr);
#else
int nd_add_fakeExcept_in_service_rule(__u16 _uService, __u32 _uFakeExceptIp);
#endif

//int nd_mod_service(struct cmd_service_rule_pars_data *service_data);
//int nd_mod_service(__u16 _uService, __u16 _uMod_Service);

int nd_nfm_del_default_all_rule(void);

int nd_del_service(__u16 _uService);

/*
int nd_add_service(__u16 _uService, __u16 _uFakePort, __u32 _uMode);
*/
int nd_add_service(__u16 _uService, __u16 _uFakePort, __u32 _uRuleType, __u32 _uMode);

/*
int nd_nfm_get_rule_info(__u16 _uService, __u32 _uRuleType, char *output );
*/

int nd_nfm_get_service_rule_index(__u16 _uService);

int nd_nfm_get_sourceIp_rule_index(struct cmd_service_sub_rule_pars_data* sub_rule);

int nd_nfm_get_fakeExcept_rule_index(struct cmd_service_sub_rule_pars_data* sub_rule);

int nd_nfm_get_service_rules(char *output);

int nd_nfm_get_fakeexcept_rules(char * output);

int nd_nfm_get_sourceips_rules(char *output);

int nd_nfm_get_rule_info(char *output );

int nd_nfm_chk_rule_v2( struct nd_5tuple_data tuples, __u16 *fakeport);

int nd_nfm_comfirm_the_policy_for_incoming_packet(struct nd_5tuple_data tuples, struct nd_packets_applied_to_policy ** _collect_data );

//
int nd_nfm_add_bypass_rules (__u32 _saddr, __u32 _daddr);

int nd_nfm_del_bypass_rule (__u32 _saddr, __u32 _daddr );

int nd_nfm_get_bypass_rules (char *output);

int nd_nfm_chk_bypass_rule ( __u32 _saddr, __u32 _daddr );

int nd_nfm_reset_bypass_rule (void);

#endif ///_ND_NIX_NFM_RULES_H__
