
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define ND_IOCTL_MAGIC          'N'

#define MAX_STRING_LENGTH       256

#define ND_TYPE_STRUCT          1
#define ND_TYPE_STRING          2

#define ND_IOCTL_TYPE           ND_TYPE_STRUCT

#if ND_IOCTL_TYPE == ND_TYPE_STRUCT
///
//DEFINE IOCTL

#define IOCTL_ADD_POLICY _IOW(ND_IOCTL_MAGIC, 0, struct nd_cmd_data)
#define IOCTL_DEL_POLICY _IOW(ND_IOCTL_MAGIC, 1, struct nd_cmd_data)
#define IOCTL_MOD_POLICY _IOW(ND_IOCTL_MAGIC, 3, struct nd_cmd_data)
#define IOCTL_GET_POLICY _IOW(ND_IOCTL_MAGIC, 4, struct nd_cmd_data)

#elif ND_IOCTL_TYPE == ND_TYPE_STRING

#define IOCTL_ADD_POLICY _IOW(ND_IOCTL_MAGIC, 0, char *)
#define IOCTL_DEL_POLICY _IOW(ND_IOCTL_MAGIC, 1, char *)
#define IOCTL_MOD_POLICY _IOW(ND_IOCTL_MAGIC, 3, char *)
#define IOCTL_GET_POLICY _IOW(ND_IOCTL_MAGIC, 4, char *)

#else

#define IOCTL_ADD_POLICY _IOW(ND_IOCTL_MAGIC, 0, char *)
#define IOCTL_DEL_POLICY _IOW(ND_IOCTL_MAGIC, 1, char *)
#define IOCTL_MOD_POLICY _IOW(ND_IOCTL_MAGIC, 3, char *)
#define IOCTL_GET_POLICY _IOW(ND_IOCTL_MAGIC, 4, char *)

#endif

//#define ND_DEVICE_NAME "nd_nix_nfm"
#define ND_DEVICE_NAME "nd_nix_chardev"
#define DEVICE_PATH "/dev/nd_nix_chardev"

struct nd_cmd_data {

        int cmd;
        char data[1024];
};



int main()
{
	int ret = 0;
#if ND_IOCTL_TYPE == ND_TYPE_STRUCT

	struct nd_cmd_data cmd;

#endif

	int fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0 )	{

		printf ("failed to open device...\n");
		//ERROR MSG
		return -1;
	}
#if ND_IOCTL_TYPE == ND_TYPE_STRUCT
	cmd.cmd = 1111;
	sprintf (cmd.data, "Hello. kernel...");
#else
	char *string_to_send = "Hello. kernel...";
#endif

#if ND_IOCTL_TYPE == ND_TYPE_STRUCT
	ret = ioctl(fd, IOCTL_ADD_POLICY, &cmd);;
#else
	ret = ioctl(fd, IOCTL_ADD_POLICY, string_to_send) ; 
#endif
	if (ret < 0 )	{
		
		printf ("failed to ioctl function [%d]/[%d]\n", ret, errno);
		//ERROR MSG
		close (fd);
		return -1;
	}

	close(fd);

	return 0;


}

