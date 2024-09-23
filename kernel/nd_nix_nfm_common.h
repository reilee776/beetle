#ifndef _ND_NIX_NFM_COMMON_H__
#define _ND_NIX_NFM_COMMON_H__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#include <linux/ioctl.h>

#include <linux/list.h>
#include <linux/slab.h>  // for kcalloc and kfree
#include <linux/string.h>
#include <linux/inet.h>  // in4_pton
#include <linux/byteorder/generic.h> // htonl 

#define MAX_STRING_LENGTH	1024
#define MAX_VERSION_LENGTH	16

#define ND_LOOPBACK		16777343

#define MAXINUM_RULE_NAME 	45

#define ND_DEFA_RULE_MATCH 	1
#define ND_EXCP_RULE_MATCH	2

#define ND_RULE_NONE_MATCH 	0

#define WORK_INCOMPLETE		0
#define WORK_COMPLETE		1

#define EXCEPTION_PORTS_MAX 	32

#define EXCEPTION_RULE_ITEM_CNT	3

#define INDX_RULE_TYPE		0

#define ND_IOCTL_MAGIC		'N'

#define ND_TYPE_STRUCT		1
#define ND_TYPE_STRING		2

#define ND_IOCTL_TYPE		ND_TYPE_STRUCT

#define ND_SUPP_RULE_IPRANGE    1 

///
//DEFINED DEVICE NAME
#define ND_DEVICE_NAME "nd_nix_chardev"
//#define ND_DEVICE_NAME "nd_chardev"

///DEFIND PROTFORWARD RULE TYPE
//
#define ND_SERVICE_PORT_BASED_TYPE	1 // control base is PORT and support exception rule
#define ND_SERVICE_SOUR_BASED_TYPE	2 // control base is PORT, Source ipaddr and not support exception rule

//ERROR CODE
/// <common 0 ~ 20>
#define ND_ERROR_SUCCESS		0 	// (0x0) The operation completed successfully.
#define ND_ERROR_INVALID_FUNCTION	1 	// (0x1) Incorrect function.
#define ND_ERROR_DATA_EMPTY		2 	// (0x2) Data(rule item) is empty
#define ND_ERROR_DATA_MISMATCH		3 	// (0x3) 
#define ND_ERROR_INVALID_BUFFER		4 	// (0x4) Invalid buffer information
#define ND_ERROR_ENOMEM			5 	// (0x5) Memory creation failed
#define ND_ERROR_EFAULT                 6       // (0x6) When trying to access memory using an invalid pointer or when a system call refers to an invalid address.
#define ND_ERROR_INVALID_PARAMETER 	7	// (0x7) Invalid parameter.
//#define IOCTL_GET_CONNECTSESSIONCNT	8	// (0x8) Get Managed connect session count

/// <rule 21 ~ 50>
#define ND_ERROR_NOTFOUND_RULE		21 	// (0x15) No policy found
#define ND_ERROR_NOTFOUND_PARENT_RULE 	22 	// (0x16) There is no parent policy (if there is no service information entered when working with exception policy/service IP policy, etc.)
#define ND_ERROR_ALREADEXIST_RULE	23 	// (0x17) Attempting to enter a policy that already exists
#define ND_ERROR_EMPTY_RULE		24	// (0x18) Empty rule (linked list)

/// <device 51 ~ 70>
#define ND_ERROR_REGISTER_CHARDRV	51 	// (0x33) Registration operation for char drv failed
#define ND_ERROR_CREATEFAIL_CLSOBJ	52	// (0x34) Failed to create class object (exposed to sysfs filesystem and created for interaction with device drivers in user space)
#define ND_ERROR_CREATEFAIL_DEVICE	53	// (0x35) The device driver failed to expose the driver module to user space.
#define ND_ERROR_DESTORYFAIL_DEVICE	54	// (0x36) Failed to delete registered device information

//static char g_ndlog_buffer[1024];
//static DECLARE_WAIT_QUEUE_HEAD(log_wait_queue);
extern wait_queue_head_t log_wait_queue;
extern char g_ndlog_buffer[1024];
extern struct rb_root nd_log_tree;
extern int nd_log_count;

#define MAX_LOGS 256
#define LOG_MSG_SIZE 256
#define LOG_SIZE 1024

#define MAX_LOG_ENTRIES 100

extern struct log_entry log_list; 
extern struct mutex log_mutex; 
extern int nd_log_index;
extern char *log_buffer[MAX_LOGS];

/*
 *
 */
// <service port> | <fake port> | <rule type> | <source ips> | <except ips> |
//
///PORT BASED TYPE SAMPLE
//      21        |     1021    |     1       |              | 3232235786,3232235786 |
//
///SOURCE IP BASED TYPE SAMPLE
//      21        |     1021    |     2       |3232235786,3232235786 |     | 


extern struct nd_service_rule_data_new         nd_list_service_rules_new;

enum except_index	{
	
	INDX_SOURCE_IP 	= 1,
	INDX_DEST_IP	,
	INDX_PORTS	,
	INDX_EXCP_MAX
};

enum rule_index		{
	INDX_RULE_REALIP 	= 1,
	INDX_RULE_FAKEIP 	,
	INDX_RULE_EXCEPT 	,
	INDX_RULE_MAX
};

enum sevice_2tuple_index	{

	INDX_SVC_REALPORT	= 1,
	INDX_SVC_FAKEPORT	,
	INDX_SVC_MAX
};

enum rule_type_index		{

	INDX_RULE_TYPE_SERVICE	= 1,		// 1
	INDX_RULE_TYPE_FAKEEXCEPT	,	// 2
	INDX_RULE_TYPE_SOURCEIPS        ,	// 3
	INDX_RULE_TYPE_DROPEXCEPT	,	// 4
	INDX_RULE_TYPE_MAX
};

/*
enum rule_type_service_index_v2		{

	INDX_RULE_TYPE_SERVICE = 1,
	INDX_RULE_TYPE_FAKE	,
};
*/

enum rule_ipaddress_type_index 	{
	INDX_RULE_IPADDR_SPECIFIC	 =0,
	INDX_RULE_IPADDR_HOSTRANGE	,
	INDX_RULE_IPADDR_SUBNET		,
	INDX_RULE_IPADDR_MAX
};

enum rule_type_service_index	{

	INDX_SVC_RULE_SERVICE	= 1,
	INDX_SVC_RULE_FAKEPORT	,
	INDX_SVC_RULE_MODE	,
	INDX_SVC_RULE_MAX
};

enum rule_type_fakeexcept_index	{
	
	INDX_FAKEEXCEPT_RULE_SERVICE = 1,
	INDX_FAKEEXCEPT_RULE_EXADDR,
	INDX_FAKEEXCEPT_RULE_MAX
};

enum rule_type_dropexcept_index {

	INDX_DROPEXCEPT_RULE_SERVICE = 1,
	INDX_DROPEXCEPT_RULE_EXADDR,
	INDX_DROPEXCEPT_RULE_MAX
};

enum rule_type_sourceip_index	{

	INDX_SOURCEIP_RULE_SERVICE 	= 1,
	INDX_SOURCEIP_RULE_EXADDR	,
	INDX_SOURCEIP_RULE_MAX
};

/*
 * ==========================================================================
 * STRUCT
 */


///
//STRUCT RULEDATA
struct rule_data
{
        char name[MAXINUM_RULE_NAME];
	__u32 ruleid;
        __u8 action;
        __u8 protocol;
        __u32 sip;
	__u32 dip;
        __u16 realport;
        __u16 fakeport;
};


///
//STRUCT RULELIST
struct rule_list
{
        struct rule_data *data;
        struct list_head list;
};


///
//STRUCT CMD
struct nd_cmd_data {

        int cmd;
        char data[1024];
};

///
//STRUCT SERVICE 2TUPLE
struct nd_service_2tuple_data {
	__u16 realport;
	__u16 fakeport;
};

///
//STRUCT 5TUPLE
struct nd_5tuple_data {

	__u16	sport;
	__u16 	dport;
	
	__u32 	saddr;
	__u32	daddr;

	__u32   hook;  // direction
};

///
//
struct nd_packets_applied_to_policy {
	__u16 serviceport;
	__u16 forwardport;

	__u32 mode;
};


///
//STRUCT DEFAULTDATA_SUBRULE
//struct nd_sub_rule	{
struct nd_default_rule_sub_node		{

	__u32 exceptIpaddr;	
	struct list_head list;
};


///
//STRUCT DEFAULTDATA
struct nd_default_rule_data	{

	__u16 realport;
	__u16 fakeport;	
	
	struct list_head nd_sub_rules;
};


///
//STRUCT DEFAULTLIST
struct nd_default_rule_list	{
	struct nd_default_rule_data * rule;
	struct list_head	 list;
};


///
//STRUCT SESSIONDATA
struct session_data	{

	__u8 protocol;

	__u32 sip;
	__u32 dip;

	__u16 org_destport;
	__u16 fake_destport;
	__u16 clientport;
	
	__u32 isModify;
};

struct cmd_rule_pars_data
{
	__u32 rule_type;
	__u16 service;
	__u16 fakeport;
	__u32 mode;
	
	__u32 address;
};

struct cmd_service_rule_pars_data
{
	__u32 rule_type;
	__u16 service;
	__u16 forward;
	__u32 data;
	__u32 ret;
};

struct cmd_service_sub_rule_pars_data
{
	__u16 service;
	__u32 type;
	__u32 saddr;
	__u32 eaddr;
	__u32 ret;
};

struct cmd_subservice_rule_pars_data
{
	__u32 rule_type;
	__u16 service;
	__u32 data;//ipaddress
};

struct service_rule_pars_data
{
	__u16 service;
	__u16 fakeport;
	__u32 dropmode;
};

struct fakeexcept_rule_pars_data
{
	__u16 service;
	__u32 address;
};

struct dropexcept_rule_pars_data
{
	__u16 service;
	__u32 address;
};

struct port_info {
    __be32 protocol;
    __u16 sport;
    struct hlist_node node; // hash table node
};	

///
//STRUCT SESSIONLIST
struct session_list	{
	struct session_data * 	session;
	struct list_head 	list;
};
/*
 *==========================================================================
 */

struct nd_drop_except_rule_data	{
	__u32 remoteAddr;

	struct list_head list;
};

struct nd_drop_rule_data	{
	__u32 remoteAddr;

	struct nd_drop_except_rule_data drop_except;
	struct list_head list;
};

struct nd_target_source_rule_data {
//	__u32 remoteAddr;

	__u32 startIpaddr;
	__u32 endIpaddr;

	__u32 nType; // 0 : specific IP , 1 : HOST range IP , 2 : SubNet IP

	struct list_head list;
};

struct nd_fake_except_rule_data	{
	//__u32 remoteAddr;
	__u32 nType; // 0 : specific IP , 1 : HOST range IP , 2 : SubNet IP
	__u32 startIpaddr;
	__u32 endIpaddr;

	struct list_head list;
};

struct nd_fake_rule_data	{
	//__u16 readport;
	__u16 fakeport;

	struct nd_fake_except_rule_data fake_except;
	struct list_head list;
};

struct nd_service_rule_data	{
	__u16 service;

	struct nd_fake_rule_data fake_rule;
	struct nd_drop_rule_data drop_rule;
	struct list_head list;
};

struct nd_service_rule_data_new	{
	__u16 service;
	
	__u16 fakeport;
	
	__u32 ruleType;
	__u32 mode;

	struct nd_target_source_rule_data sourceips;
	struct nd_fake_except_rule_data fakeExcept;
	struct nd_drop_except_rule_data dropExcept;	
	struct list_head list;
};

/*
struct log_entry {
    struct rb_node node;
    int id;
    char message[256];
};
*/

struct log_entry {
    char message[LOG_MSG_SIZE];
    struct list_head list;
};
/*
 *==========================================================================
 *DEFINE
 */

#if ND_IOCTL_TYPE == ND_TYPE_STRUCT
///
//DEFINE IOCTL

#define IOCTL_ADD_SERVICE_POLICY 	_IOWR(ND_IOCTL_MAGIC, 0, 	struct cmd_service_rule_pars_data)
#define IOCTL_ADD_FAKEEXCEPT_POLICY 	_IOWR(ND_IOCTL_MAGIC, 1, 	struct cmd_service_sub_rule_pars_data)
#define IOCTL_ADD_SOURCEIPS_POLICY 	_IOWR(ND_IOCTL_MAGIC, 2, 	struct cmd_service_sub_rule_pars_data)
#define IOCTL_ADD_DROPEXCEPT_POLICY 	_IOWR(ND_IOCTL_MAGIC, 3, 	struct cmd_service_sub_rule_pars_data)

#define IOCTL_MOD_SERVICE_POLICY        _IOWR(ND_IOCTL_MAGIC, 4, 	struct cmd_service_rule_pars_data)
#define IOCTL_MOD_FAKEEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 5, 	struct cmd_service_sub_rule_pars_data)
#define IOCTL_MOD_SOURCEIPS_POLICY      _IOWR(ND_IOCTL_MAGIC, 6, 	struct cmd_service_sub_rule_pars_data)
#define IOCTL_MOD_DROPEXCEPT_POLICY     _IOWR(ND_IOCTL_MAGIC, 7, 	struct cmd_service_sub_rule_pars_data)

#define IOCTL_DEL_SERVICE_POLICY 	_IOWR(ND_IOCTL_MAGIC, 8, 	struct cmd_service_rule_pars_data)
#define IOCTL_DEL_FAKEEXCEPT_POLICY 	_IOWR(ND_IOCTL_MAGIC, 9, 	struct cmd_service_sub_rule_pars_data)
#define IOCTL_DEL_SOURCEIPS_POLICY 	_IOWR(ND_IOCTL_MAGIC, 10, 	struct cmd_service_sub_rule_pars_data)
#define IOCTL_DEL_DROPEXCEPT_POLICY 	_IOWR(ND_IOCTL_MAGIC, 11, 	struct cmd_service_sub_rule_pars_data)

#define IOCTL_RESET_POLICY 		_IO(ND_IOCTL_MAGIC,12)

#define IOCTL_GET_POLICY		_IOR(ND_IOCTL_MAGIC, 13, 	char [MAX_STRING_LENGTH])

#define IOCTL_GET_SERVICE_POLICY_INDEX	_IOR(ND_IOCTL_MAGIC, 14,        char [MAX_STRING_LENGTH])
#define IOCTL_GET_FAKEEXCEPT_POLICY_INDEX _IOWR(ND_IOCTL_MAGIC, 15,       struct cmd_service_sub_rule_pars_data)
#define IOCTL_GET_SOURCEIPS_POLICY_INDEX  _IOWR(ND_IOCTL_MAGIC, 16,       struct cmd_service_sub_rule_pars_data)

#define IOCTL_GET_SERVICE_POLICY	_IOR(ND_IOCTL_MAGIC, 17, 	char [MAX_STRING_LENGTH])
#define IOCTL_GET_FAKEEXCEPT_POLICY	_IOR(ND_IOCTL_MAGIC, 18, 	char [MAX_STRING_LENGTH])
#define IOCTL_GET_SOURCEIPS_POLICY	_IOR(ND_IOCTL_MAGIC, 19, 	char [MAX_STRING_LENGTH])
#define IOCTL_GET_DROPEXCEPT_POLICY	_IOR(ND_IOCTL_MAGIC, 20, 	char [MAX_STRING_LENGTH])
#define IOCTL_GET_CONNECTSESSIONCNT     _IOR(ND_IOCTL_MAGIC, 21,        char [MAX_STRING_LENGTH])
///
#define IOCTL_ON_MODE			_IO(ND_IOCTL_MAGIC, 30)
#define IOCTL_OFF_MODE			_IO(ND_IOCTL_MAGIC, 31) 
#define IOCTL_GET_MODE			_IOR(ND_IOCTL_MAGIC, 32, 	char [MAX_STRING_LENGTH])
#define IOCTL_GET_VERSION		_IOR(ND_IOCTL_MAGIC, 40, 	char [MAX_VERSION_LENGTH])
#define IOCTL_GET_LOG			_IOR(ND_IOCTL_MAGIC, 41,	char [MAX_STRING_LENGTH])

//#define IOCTL_DEL_POLICY _IOW(ND_IOCTL_MAGIC, 8, struct nd_cmd_data)
#define IOCTL_MOD_POLICY _IOW(ND_IOCTL_MAGIC, 9, struct nd_cmd_data)
//#define IOCTL_GET_POLICY _IOW(ND_IOCTL_MAGIC, 10, struct nd_cmd_data)
//#define IOCTL_RESET_POLICY _IOW(ND_IOCTL_MAGIC, 11, struct nd_cmd_data)

#elif ND_IOCTL_TYPE == ND_TYPE_STRING

#define IOCTL_ADD_POLICY _IOW(ND_IOCTL_MAGIC, 0, char *)
#define IOCTL_DEL_POLICY _IOW(ND_IOCTL_MAGIC, 1, char *)
#define IOCTL_MOD_POLICY _IOW(ND_IOCTL_MAGIC, 3, char *)
#define IOCTL_GET_POLICY _IOW(ND_IOCTL_MAGIC, 4, char *)
#define IOCTL_RESET_POLICY _IOW(ND_IOCTL_MAGIC, 5, char *)

#else

#define IOCTL_ADD_POLICY _IOW(ND_IOCTL_MAGIC, 0, char *)
#define IOCTL_DEL_POLICY _IOW(ND_IOCTL_MAGIC, 1, char *)
#define IOCTL_MOD_POLICY _IOW(ND_IOCTL_MAGIC, 3, char *)
#define IOCTL_GET_POLICY _IOW(ND_IOCTL_MAGIC, 4, char *)
#define IOCTL_RESET_POLICY _IOW(ND_IOCTL_MAGIC, 5, char *)

#endif


#define ND_PLOICY_EXCLUSION	0
#define ND_POLICY_APPLY		1
#define ND_POLICY_EXCEPT	2

///
//DEFINE TYPE_ACCORDING_TO_POLICE
#define ND_ACT_FLOWRULE_NOTFOUND 0
#define ND_ACT_FLOWRULE_FASS	1
#define ND_ACT_FLOWRULE_APPLY	2
#define ND_ACT_ERROR		-1

///
//DEFINE IPADDRESS
#define IPADDRESS(addr) \
        ((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]


///
//DEFINE PRODUCT MODE
#define ND_LKM_MODE_OFF         0
#define ND_LKM_MODE_ON          1
#define ND_LKM_MODE_WARN        2

#define ND_IPADDR_U16_SIZE	12

#define ND_MAXCNTIP_ON_RULE	80 //(1024 - (targetport[8] + forwardport[8] + mode [4] ))  = 1004 ==> 1004/12 = 80  

#define ND_NETLINK_DATA_SIZE 	1024


#define ND_NETLINK_DATA_SIZEMAX	8192

///
//DEFINE RULE MODE
#define ND_RULE_MODE_GENERAL	0  // For example, apply to a specific class or region
#define ND_RULE_MODE_INDIVIDUAL	1  // everyone General policy targeting

#define ND_CMD_MODE_ON          1001
#define ND_CMD_MODE_OFF         1002
#define ND_CMD_MODE_WARN        1003
#define ND_CMD_MODE_GET		1006

#define ND_CHECK_NO		0
#define ND_CHECK_OK		1


#define ND_GET_RULE_ALL		0
#define ND_GET_RULE_SERVICELIST	1
#define ND_GET_RULE_TARSERVICE	2

///
//DEFINE PRODUCT RUEL
#define ND_CMD_RULE             1004
#define ND_CMD_LOG              1005

#define ND_CMD_BASE                     1000

//#define ND_CMD_RUEL_BASE        ND_CMD_BASE + 100
#define ND_CMD_RULE_BASE	1000 + 100
#define ND_CMD_RULE_ADD         ND_CMD_RULE_BASE + 1
#define ND_CMD_RULE_DEL         ND_CMD_RULE_BASE + 2
#define ND_CMD_RULE_MODFY       ND_CMD_RULE_BASE + 3
#define ND_CMD_RULE_GET         ND_CMD_RULE_BASE + 4
#define ND_CMD_RULE_ALLSET      ND_CMD_RULE_BASE + 5
#define ND_CMD_RULE_ALLGET      ND_CMD_RULE_BASE + 6
#define ND_CMD_RULE_RESET       ND_CMD_RULE_BASE + 7

#define ND_CMD_RULE_SEARCH              ND_CMD_RULE_BASE + 300

///
//DEFINE PRODUCT LOGS
#define ND_CMD_LOG_BASE         ND_CMD_RULE_BASE + 200

#endif // _ND_NIX_NFM_COMMON_H__
