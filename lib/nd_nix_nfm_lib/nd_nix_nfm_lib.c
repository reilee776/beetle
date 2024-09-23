#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include "nd_nix_nfm_lib.h"

int sdk_get_NdNixNfmDrv_ManagedSessionCnt(char * cnt)
{
	int ret = 0, fd = 0;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
        {
                return -1;
        }

        ret = ioctl (fd, IOCTL_GET_CONNECTSESSIONCNT, cnt);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

        close (fd);

        return 0;

}

int sdk_get_NdNixNfmDrv_version(char * version)
{
	int ret = 0, fd = 0;
	
	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
	{
		return -1;
	}

	ret = ioctl (fd, IOCTL_GET_VERSION, version);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}

int sdk_NdNixNfmDrv_start(void)
{
	int ret = 0;

        int fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )    {
                return -1;
        }

        ret = ioctl (fd, IOCTL_ON_MODE, NULL);
        if (ret < 0 )
        {
                close(fd);
                return -1;
        }

        close(fd);

        return 0;

}

int sdk_NdNixNfmDrv_stop(void)
{
	int ret = 0;

        int fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )    {
                return -1;
        }

        ret = ioctl (fd, IOCTL_OFF_MODE, NULL);
        if (ret < 0 )
        {
                close(fd);
                return -1;
        }

        close(fd);

        return 0;

}

int sdk_get_NdNixNfmDrv_state(char * sStatus)
{
	int ret = 0, fd = 0;
	
	fd = open (DEVICE_PATH, O_RDWR);
	if ( fd < 0 )	{
		return -1;
	}

	ret = ioctl (fd, IOCTL_GET_MODE, sStatus);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);
 	return 0;
}


int sdk_add_NdNixNfmDrv_service_policy(const struct cmd_service_rule_pars_data * service)
{
	int ret = 0;

	if (service == NULL )
		return -1;

	int fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )	{
		return -1;
	}

	ret = ioctl (fd, IOCTL_ADD_SERVICE_POLICY, service);
	if (ret < 0 )
	{
		close(fd);
		return -1;
	}
	/*
	if (service->ret == 0x01)
	{
		printf("ret value is 0x01\n");
	}
	*/

	close(fd);

	return 0;
}

int sdk_add_NdNixNfmDrv_fakeExcept_policy(const struct cmd_service_sub_rule_pars_data * fakeexcept)
{
	int ret = 0, fd = 0;
	
	if (fakeexcept == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_ADD_FAKEEXCEPT_POLICY, fakeexcept);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close(fd);

	return 0;
}

int sdk_add_NdNixNfmDrv_sourceips_policy(const struct cmd_service_sub_rule_pars_data * sourceips)
{
	int ret = 0, fd = 0;

	if (sourceips == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl(fd, IOCTL_ADD_SOURCEIPS_POLICY, sourceips);
	if (ret < 0 )	{
		close(fd);
		return -1;
	}

	close (fd);

	return 0;
}

int sdk_mod_NdNixNfmDrv_service_policy_to_index(const struct cmd_service_rule_pars_data * service)
{
	int ret = 0, fd = 0;
	
	if (service == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_MOD_SERVICE_POLICY, service);
	if (ret < 0 )		{
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}

int sdk_mod_NdNixNfmDrv_fakeexcept_policy_to_index(const struct cmd_service_sub_rule_pars_data * except)
{
	int ret = 0, fd = 0;

	if (except == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_MOD_FAKEEXCEPT_POLICY, except);
	if (ret < 0)		{
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}

int sdk_mod_NdNixNfmDrv_sourceips_policy_to_index(const struct cmd_service_sub_rule_pars_data * sourceips)
{
	int ret = 0, fd = 0;

	if (sourceips == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_MOD_SOURCEIPS_POLICY, sourceips);
	if (ret < 0 )		{
		close (fd);
		return -1;
	}
	
	close (fd);
        return 0;
}


int sdk_del_NdNixNfmDrv_service_policy(const struct cmd_service_rule_pars_data * service )
{

	int ret = 0, fd = 0;

	if ( service == NULL )
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;


	ret = ioctl (fd, IOCTL_DEL_SERVICE_POLICY, service );
	if (ret < 0 )	{
		close (fd);
		return -1;
	}

	close (fd);
	 
	return 0;
}

int sdk_del_NdNixNfmDrv_fakeexcept_policy(const struct cmd_service_sub_rule_pars_data * fakeexcept )
{

	int ret = 0, fd = 0;

	if (fakeexcept == NULL )
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_DEL_FAKEEXCEPT_POLICY, fakeexcept);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}

int sdk_del_NdNixNfmDrv_sourceips_policy(const struct cmd_service_sub_rule_pars_data * sourceips)
{
	int ret = 0, fd = 0;

	if (sourceips == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_DEL_SOURCEIPS_POLICY, sourceips);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}


int sdk_reset_NdNixNfmDrv_policy (void)			{
	
	int ret = 0;

        int fd = open(DEVICE_PATH, O_RDWR);
        if (fd < 0 )    {
                return -1;
        }

        ret = ioctl(fd, IOCTL_RESET_POLICY, NULL);;
        if (ret < 0 )   {

                close(fd);
                return -1;
        }

        close(fd);

	return 0;
}

int sdk_get_NdNixNfmDrv_policy (char * data)
{
	int ret = 0, fd = 0;
	
	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )	
		return -1;

	ret = ioctl (fd, IOCTL_GET_POLICY, data);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}

int sdk_get_NdNixNfmDrv_sourceips_policy_index(const struct  cmd_service_sub_rule_pars_data *sourceips )
{
	int ret = 0, fd = 0;

        if (sourceips == NULL )
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;

        ret = ioctl (fd, IOCTL_GET_SOURCEIPS_POLICY_INDEX, sourceips);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

        ret = sourceips->ret;

        close (fd);
        return ret;

}

int sdk_get_NdNixNfmDrv_fakeexcept_policy_index(const struct cmd_service_sub_rule_pars_data *fakeexcept )
{
	int ret = 0, fd = 0;

        if (fakeexcept == NULL )
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;

        ret = ioctl (fd, IOCTL_GET_FAKEEXCEPT_POLICY_INDEX, fakeexcept);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

	ret = fakeexcept->ret;

        close (fd);
        return ret;

}

int sdk_get_NdNixNfmDrv_service_policy_index(struct cmd_service_rule_pars_data * service )
{
	int ret = 0, fd = 0;
	if (service == NULL)
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_GET_SERVICE_POLICY_INDEX, service);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}


int sdk_get_NdNixNfmDrv_service_policy (char *data)
{
	int ret = 0, fd = 0;

	if (data == NULL )
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_GET_SERVICE_POLICY, data);
	if (ret < 0 )
	{
		close (fd);
		return -1;
	}

	close (fd);

	return 0;
}

int sdk_get_NdNixNfmDrv_fakeexcept_policy (char *data)
{
	int ret = 0, fd = 0;

        if (data == NULL )
                return -1;

        fd = open (DEVICE_PATH, O_RDWR);
        if (fd < 0 )
                return -1;

        ret = ioctl (fd, IOCTL_GET_FAKEEXCEPT_POLICY, data);
        if (ret < 0 )
        {
                close (fd);
                return -1;
        }

        close (fd);

        return 0;

}

int sdk_get_NdNixNfmDrv_logs(char *data)
{
	int ret = 0, fd = 0;

	if (data == NULL )
		return -1;

	fd = open (DEVICE_PATH, O_RDWR);
	if (fd < 0 )
		return -1;

	ret = ioctl (fd, IOCTL_GET_LOG, data);
	if (ret < 0)
	{
		close (fd);
		return -1;
	}

	close (fd);
	return 0;
}

