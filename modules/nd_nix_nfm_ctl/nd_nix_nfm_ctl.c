#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_USERSOCK 	2
#define MAX_PAYLOAD		2048

#define ND_CMD_MODE		"mode"
#define ND_CMD_INFO		"info"
#define ND_CMD_RULE		"rule"

#define ND_CMD_LOAD		"load"
#define ND_CMD_UNLOAD		"unload"

#define ND_CMD_STATE		"state"

#define ND_KERNEL_MODULE	"nd_nix_nfm"
#define ND_KERNEL_FILENAME	"nd_nix_nfm.ko"
#define ND_KERNEL_DIR		"/src/netand/src/nd_nix_nfm/kernel"	

#define NETLINK_USER	31

/*
 * COMMAND DEFINE
 */
#define ND_CMD_BASE			1000
#define ND_CMD_MODE_BASE		ND_CMD_BASE
#define ND_CMD_RULE_BASE		ND_CMD_BASE + 100

//[MODE]
#define ND_CMD_MODE_ON			ND_CMD_MODE_BASE + 1
#define ND_CMD_MODE_OFF			ND_CMD_MODE_BASE + 2
#define ND_CMD_MODE_WARN		ND_CMD_MODE_BASE + 3
#define ND_CMD_MODE_GET         	1006

//[RULE]
#define ND_CMD_RULE_ADD			ND_CMD_RULE_BASE + 1
#define ND_CMD_RULE_DEL			ND_CMD_RULE_BASE + 2
#define ND_CMD_RULE_MOD			ND_CMD_RULE_BASE + 3
#define ND_CMD_RULE_MODFY       	ND_CMD_RULE_BASE + 3
#define ND_CMD_RULE_GET         	ND_CMD_RULE_BASE + 4
#define ND_CMD_RULE_ALLSET      	ND_CMD_RULE_BASE + 5
#define ND_CMD_RULE_ALLGET      	ND_CMD_RULE_BASE + 6
#define ND_CMD_RULE_RESET       	ND_CMD_RULE_BASE + 7

#define ND_CMD_RULE_SEARCH		ND_CMD_RULE+BASE + 300

#define ND_CMD_MAXLEN			1024

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

void output_message(char ** argv);

struct nd_cmd_data {

        int cmd;
        char data[ND_CMD_MAXLEN];
};

int send_netlink_message(int argc, char ** argv)	{

	if (argc == 0 )
	{
		return 0;
	}

	if (argv[1] == NULL || strlen (argv[1]) <= 0 )
	{
		output_message(argv);
		return -1;
	}
	
	struct nd_cmd_data send_data, *recv_data;
	char * cmd = argv[1];
        char szData[ND_CMD_MAXLEN] = {0,};
        int nCmdNo = 0;
        //struct nd_cmd_data send_data, * recv_data;
        struct sockaddr_nl src_addr, dest_addr;
        struct nlmsghdr *nlh = NULL;

	
	if (strcasecmp (cmd, ND_CMD_MODE) == 0 )                {
                //printf ("send_netlink_message cmd MODE...\n");
		if (argv[2] == NULL || strlen (argv[2]) <= 0 )	{
			//output_message(argv);
			//return -1;
			nCmdNo = ND_CMD_MODE_GET;
			snprintf (szData, sizeof(szData), "MODE_GET");
		}

                if (strcasecmp (argv[2], "ON") == 0 )           {
                        nCmdNo = ND_CMD_MODE_ON;
			snprintf (szData, sizeof(szData), "MODE ON");
                }

                else if (strcasecmp (argv[2], "OFF") == 0 )     {
                        nCmdNo = ND_CMD_MODE_OFF;
			snprintf (szData, sizeof(szData), "MODE OFF");

                }

		else if (strcasecmp (argv[2], "WARN") == 0 )	{
			nCmdNo = ND_CMD_MODE_WARN;
			snprintf (szData, sizeof(szData), "MODE WARN");
		}

		else if (strcasecmp (argv[2], "GET") == 0 )	{
			nCmdNo = ND_CMD_MODE_GET;
			snprintf (szData, sizeof(szData), "MODE GET");
		}		

                else
                {
                        ///error
			//output_message(argv);
			nCmdNo = ND_CMD_MODE_GET;
                        snprintf (szData, sizeof(szData), "MODE GET");
			//return -1;
                }

        }

        else if (strcasecmp (cmd, ND_CMD_RULE) == 0 )   {
                // printf ("send_netlink_message cmd RULE...\n");

		if (argv[2] == NULL || strlen(argv[2]) <= 0 )	
		{
			output_message(argv);
			return -1;
		}

		if (strcasecmp (argv[2], "RESET") == 0 )
		{
			nCmdNo = ND_CMD_RULE_RESET;
                        snprintf (szData, sizeof(szData), "reset");
		}


		else 
		{
			if (argv[3] == NULL || strlen(argv[3]) <= 0 )
                        {
				if (strcasecmp (argv[2], "GET") == 0 )     {

                               		nCmdNo = ND_CMD_RULE_GET;
                                	snprintf (szData, sizeof(szData), argv[3]);
					goto net_link_trans;

                        	}
				else
				{
                                	output_message(argv);
                                	return -1;
				}
                        }

			if (strcasecmp (argv[2], "ADD") == 0 )          {
				if (argv[3] == NULL || strlen(argv[3]) <= 0 )
				{
					output_message(argv);
					return -1;
				}
				nCmdNo = ND_CMD_RULE_ADD;
				snprintf (szData, sizeof(szData), argv[3]);

			}

			else if (strcasecmp (argv[2], "DEL") == 0 )     {
				nCmdNo = ND_CMD_RULE_DEL;
				snprintf (szData, sizeof(szData), argv[3]);
			}

			else if (strcasecmp (argv[2], "MOD") == 0 )     {
				nCmdNo = ND_CMD_RULE_MOD;
				snprintf (szData, sizeof(szData), argv[3]);
			}

			else if (strcasecmp (argv[2], "GET") == 0 )	{

				nCmdNo = ND_CMD_RULE_GET;
				snprintf (szData, sizeof(szData), argv[3]);
			}
			
			else
			{
				output_message(argv);
				return -1;
			}
		}
        }

        else
        {
		output_message(argv);
		return -1;
        }


net_link_trans:

        sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
        if(sock_fd<0)
                return -1;

        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid(); /* self pid */

        bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

        memset(&dest_addr, 0, sizeof(dest_addr));
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0; /* For Linux Kernel */
        dest_addr.nl_groups = 0; /* unicast */

        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_flags = 0;

	send_data.cmd = nCmdNo;
        snprintf (send_data.data,sizeof(send_data.data), szData);
        memcpy(NLMSG_DATA(nlh), &send_data, sizeof(send_data));

        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        sendmsg(sock_fd,&msg,0);

        /* Read message from kernel */
        recvmsg(sock_fd, &msg, 0);
        recv_data = (struct nd_cmd_data *)NLMSG_DATA(nlh);

	if (	nCmdNo == ND_CMD_MODE_GET 	||
		nCmdNo == ND_CMD_MODE_ON 	||
		nCmdNo == ND_CMD_MODE_OFF	)	
	{

		printf("The operating mode currently being set in the kernel is [%s].\n", (recv_data->data[0] == '0')?"OFF":"ON");
	}
	else		
	{
        	//printf("Received message payload: %s\n", (char *)NLMSG_DATA(nlh));
        	//printf("Received message payload: [%d] [%s]\n", recv_data->cmd, recv_data->data);
		printf("%s\n", recv_data->data);
	}
        close(sock_fd);

	return 0;
}

int is_module_loaded(const char * module_name )	{

	FILE *fp	= NULL;
	char buffer[256] = {0,};
	int found = 0;

	fp = fopen("/proc/modules", "r");
	if (fp == NULL)		{
		perror("Error opening /proc/modules");
		return 0;
	}

	while (fgets(buffer, sizeof(buffer), fp)) {
		if (strstr(buffer, module_name))	{
			found = 1;

			break;
		}
	}

	fclose(fp);

	return found;
}

int ctrl_cmd(int argc, char **argv)		{

	int ret = 0;
	char *cmd = argv[1];
	char szCmdStr[1024] = {0,};

	if (strcmp(cmd, ND_CMD_MODE) == 0 )		{
		//printf ("insert cmd is mode....\n");
		send_netlink_message(argc, argv);
	}

	else if (strcmp(cmd, ND_CMD_INFO) == 0 ) 	{
		//printf ("insert cmd is info....\n");
		send_netlink_message(argc, argv);
	}
	
	else if (strcmp(cmd, ND_CMD_RULE) == 0 )	{
		//printf ("insert cmd is rule....\n");
		send_netlink_message(argc, argv);
	}
	
	else if (strcmp(cmd, ND_CMD_LOAD) == 0 )	{

		if (is_module_loaded(ND_KERNEL_MODULE) == 1)
                {
                        printf ("Module name %s is already loading...\n", ND_KERNEL_MODULE);
                }
                else
                {
			sprintf (szCmdStr, "insmod %s", ND_KERNEL_FILENAME);
		
			ret = system(szCmdStr);

			if (is_module_loaded(ND_KERNEL_MODULE) == 1)
			{
				printf ("Module name %s was loaded successfully\n", ND_KERNEL_MODULE);
			}

			else 
			{
				printf ("Loading of module name %s failed.(%d)\n", ND_KERNEL_MODULE, ret);
			}
                }

	}

	else if (strcmp(cmd, ND_CMD_UNLOAD) == 0) 	{
		if (is_module_loaded(ND_KERNEL_MODULE) != 1)
                {
			printf ("Module name %s is already unloading\n", ND_KERNEL_MODULE);
			return 0;
		}

		else 
		{
			sprintf (szCmdStr, "rmmod %s", ND_KERNEL_MODULE);

			ret = system(szCmdStr);

			if (is_module_loaded(ND_KERNEL_MODULE) != 1)
                	{
				printf ("Module name %s was unloaded successfully\n", ND_KERNEL_MODULE);
			}
			else
			{
				printf ("Unloading of module name %s failed.(%d)\n", ND_KERNEL_MODULE, ret);
			}

		}

	}

	else if (strcmp(cmd, ND_CMD_STATE) == 0 )	{
		
		if (is_module_loaded(ND_KERNEL_MODULE) == 1)
		{
			printf ("Module name %s is already loading...\n", ND_KERNEL_MODULE);
		}
		else 
		{
			printf ("Module name %s was not loaded...\n", ND_KERNEL_MODULE);
		}
	}

	else
	{
		//printf("Usage: %s <message>\n", argv[0]);
		output_message(argv);
	}

	return 0;
}

void output_message(char ** argv)
{
	//printf ("usage: %s [options] ...\n"
	printf ("usage: %s [load] [unload] [state]\n\
		\t[mode on] [mode off]\n\
		\t[rule add \"rule type|service port|mode or ipaddress|\"]\n\
		\t[rule mod \"rule type|service port|mode or ipaddress|\"]\n\
		\t[rule del \"rule type|service port|mode or ipaddress|\"]\n\
		\t[rule get \"rule type|service port\"]\n"

		"\trule type:\n"
		"\t\t\tservice rule = 1, forward except rule = 2, including target ip = 3\n"
		"\tmode:\n"
		"\t\t\tservice port base mode = 1, source ip base mode = 2\n"
		
        	"Options:\n"
        	"\tload\t\tLoad the kernel module (nd_nix_nfm).\n"
        	"\t\t\t>> (USE \'load\' to Load kernel modules into the system.)\n\n"
        	"\tunload\t\tUnload the kernel module (nd_nix_nfm).\n"
        	"\t\t\t>> (USE \'unload\' to Unoad kernel modules into the system.)\n\n"
        	"\tstate\t\tPrints the loading status of kernel modules.\n"
        	"\t\t\t>> (USE \'state\' to Prints the loading status of kernel modules.)\n\n"
        	"\tmode\t\tChange the operating mode of the kernel module.\n"
        	"\t\t\t>> (Use \'mode on\' to Turn on kernel operating mode.\n\
                   \tUse \'mode off\' to Turn off kernel operating mode.\n\
                   \tUse \'mode warn\' to Kernel cloud mode is turned on \n\
                    \tbut does not work. Only logs are left)\n\n"
        	"\tinfo\t\tPrints information supported by both kernel modules.\n\n"
        	"\trule\t\tSet policies in the kernel.\n"
        	"\t\t\t>> (Use \'rule add [parameter...]\' to Add a policy \n\
                   \tusing the information passed to the parameter.\n\
                   \tUse \'rule mod [parameter...]\' to Modify the policy \n\
                   \tusing the information passed to the parameter.\n\
                   \tUse \'rule del [parameter...]\' to Delete the policy \n\
                   \tusing the information passed in the parameter.)\n\
		   \tUse \'rule get [parameter...]\' to get the policy \n\
		   \tusing the information passed in the parameter.)\n"
	

        	"For bug reporting instructions, \nplease send to mail: <info@netand.co.kr>.\n\n", argv[0]);
	
}

int main(int argc, char** argv)
{
	if (argc < 2)
		output_message(argv);//printf("Usage: %s <message>\n", argv[0]);

	else
	{
		/*
		for (int i = 0 ; i < argc ; i++)
			printf("input data : [%d]:%s\n",i,argv[i]);
		*/
		ctrl_cmd(argc, argv);

		
	}

	return 0;
}
