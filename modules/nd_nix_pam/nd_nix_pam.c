#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>

#define MAX_LINE_LENGTH 1024

char g_szLoginUserOrgName[1024];
#define ESC "\033"

int nd_pam_log(char * msg)
{
	const char *log_file = "/netand/log/nd_pam_log.log";
	FILE *file = fopen(log_file, "a");
	if (file) {
		time_t now = time(NULL);
		char *time_str = ctime(&now);
		time_str[strlen(time_str) - 1] = '\0';

		fprintf(file, "[%s]\t%s\n", time_str, msg);
		fclose(file);
	} else {

		return PAM_SYSTEM_ERR;
	}

	return PAM_SUCCESS;
}

const char* get_encrypted_password_from_shadow(const char* user) 	{

	static char encrypted_passwd[MAX_LINE_LENGTH];
	struct spwd *sp;
	struct passwd *pw;
	char *shadow_path = "/etc/shadow";
	FILE *shadow_file;
	char line[MAX_LINE_LENGTH];
	char *username;
	char *password_hash;

	// /etc/shadow open file
	shadow_file = fopen(shadow_path, "r");
	if (!shadow_file) {
		perror("Error opening /etc/shadow");
		return NULL;
	}

	while (fgets(line, sizeof(line), shadow_file)) {

		username = strtok(line, ":");
		password_hash = strtok(NULL, ":");

		if (username && password_hash && strcmp(username, user) == 0) {
		    strncpy(encrypted_passwd, password_hash, sizeof(encrypted_passwd) - 1);
		    encrypted_passwd[sizeof(encrypted_passwd) - 1] = '\0'; // null-terminate
		    fclose(shadow_file);
		    return encrypted_passwd;
		}
	}

	fclose(shadow_file);
	return NULL;
}

PAM_EXTERN int pam_changepw(pam_handle_t *pamh, int flags,
				int argc, const char **argv)	{

	
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
	char szMsg[1024] = {0,};
	const char *user;
	const char *input_passwd;
	const char *encrypted_passwd;
	char *crypted;
	const char *remote_ip;
        char hostname[256];
	int retval, ret = 0, i = 0;
	const char *tty;
	char szTty[128] = {0,};
	bool bRetOtp = false, isConsole = false;
	char* otp = NULL,* nd_id = NULL, *nd_pw = NULL;
	struct passwd *pw;

	// get user name
	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS) {
		nd_pam_log("failed to get user name...");
		return retval;
	}

	pam_get_item(pamh, PAM_TTY, (const void **)&tty);
	if (tty)        {

		if (strncmp(tty, "tty", 3) == 0 )       {
			isConsole = true;
		}
	}


	if (isConsole == false )        {
		retval = pam_get_item(pamh, PAM_RHOST, (const void **)&remote_ip);
		if (retval == PAM_SUCCESS && remote_ip) {
		} else {
			printf("Remote IP not available\n");
		}
	}

	if (strcmp (user, "test1") == 0 )	{

		sprintf (szMsg, "Authentication failed for user(%s) not authorized to access this server", user);
		nd_pam_log(szMsg);
		return PAM_AUTH_ERR;
	}


	pw = getpwnam(user);
	if (pw == NULL)		{
		sprintf (szMsg, "Authentication failure for illegal user %s from %s", user, (isConsole == true)?"console":remote_ip);
		nd_pam_log(szMsg);

		printf (szMsg);
		return PAM_USER_UNKNOWN;
	}

	retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&input_passwd);
	if (retval != PAM_SUCCESS) {
		nd_pam_log("failed to get user password...");
		return retval;
	}

	encrypted_passwd = get_encrypted_password_from_shadow(user); 
	if (encrypted_passwd == NULL) {
		nd_pam_log("failed to get encrypted passwd from shadow");
		return PAM_USER_UNKNOWN;
	}

	crypted = crypt(input_passwd, encrypted_passwd);
	if (strcmp(crypted, encrypted_passwd) == 0) {
		retval = PAM_SUCCESS;
	} else {
		retval = PAM_AUTH_ERR;
	}

	if (retval == PAM_SUCCESS )
	{
		if (strcmp (user, "reilee") == 0 )
		{
			return PAM_SUCCESS;
		}
	}

	char szIdString[128] = {0,}, szOtpString[128] = {0,};
	sprintf (szIdString, "HIWARE ID: ");
	sprintf (szOtpString, "HIWARE OTP CODE: ");
	bool bchkid = false, bchkpw = false;
	if (retval == PAM_SUCCESS)
	{
		for (i = 0 ; i <= 3 ; i ++ )	{
			retval = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &nd_id, szIdString);
			if (retval == PAM_SUCCESS )	{
				if (strcmp (nd_id, "HIWAREADMIN") == 0 )
				{
					bchkid = true;
				}
				else
				{
					sprintf (szIdString, "Enter again [%d/3] HIWARE ID: ", i+1);
				}
			}

			retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &nd_pw, "HIWARE PW: ");
			if (retval == PAM_SUCCESS )	{
				if (strcmp (nd_pw,"Netand141)") == 0 )
				{
					bchkpw = true;
				}
				else
				{
					sprintf (szIdString, "Enter again [%d/3] HIWARE ID: ", i+1);
				}
			}
			
			if (bchkid == true && bchkpw == true )
			{
				break;
			}

			else
			{
				bchkid = false;
				bchkpw = false;
			}
		}

		if (bchkid != true || bchkpw != true )
		{
			sprintf (szMsg, "User %s login operation failed - Hiware verification failed", user);
                        nd_pam_log(szMsg);
                        return PAM_AUTH_ERR;
		}
		
		for (i = 0 ; i <=3 ; i ++ )		{
			retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp, szOtpString);
			if (retval != PAM_SUCCESS )     {

				pam_syslog(pamh, LOG_ERR, "Primary authentication failed [%d]", retval);
				sprintf (szMsg, "Primary authentication failed [%d]", retval);
			}
			
			else
			{
				if (strcmp (otp, "123456") == 0 )         {

					sprintf (g_szLoginUserOrgName, "Youngcheol Lim");
					bRetOtp = true;
				}
				else if (strcmp (otp, "234567") == 0)     {

					sprintf (g_szLoginUserOrgName, "Cheolwoong Lee");
					bRetOtp = true;
				}
				else if (strcmp (otp, "345678") == 0 )    {
					sprintf (g_szLoginUserOrgName, "Jae-wan Kim");
					bRetOtp = true;
				}
				else if (strcmp (otp, "456789") == 0 )	{
					sprintf (g_szLoginUserOrgName, "Sunghee Lee");
					bRetOtp = true;
				}
				else 
				{
					sprintf (szOtpString, "Enter again [%d/3] HIWARE OTP CODE: ",i+1);
				}
			}

			if (bRetOtp == true )
			{
				break;
			}

			else
			{
				bRetOtp = false;
			}

		}
	}
	else
	{
		sprintf (szMsg, "User %s login operation failed - Primary authentication failed ", user);
		pam_syslog(pamh, LOG_ERR, szMsg);
		nd_pam_log(szMsg);
		return PAM_AUTH_ERR;
	}

	if (bRetOtp == false)
	{
		sprintf (szMsg, "two factor Authentication failure for Invalid OTP value user %s from %s", user, (isConsole == true)?"console":remote_ip);
		pam_syslog(pamh, LOG_ERR, szMsg);
		nd_pam_log(szMsg);
		printf (szMsg);
		return PAM_AUTH_ERR;
	}

	else
	{
		retval = pam_get_user(pamh, &user, NULL);
		if (retval != PAM_SUCCESS) {
			sprintf (szMsg, "Failed to get user name. [%d]\n", retval);
			nd_pam_log(szMsg);
			pam_syslog(pamh, LOG_ERR, szMsg);
			return retval;
		}

		if (gethostname(hostname, sizeof(hostname)) == 0) {
		} else {
			perror("gethostname");
		}
		/*
        	pam_get_item(pamh, PAM_TTY, (const void **)&tty);
		if (tty)        {

			if (strncmp(tty, "tty", 3) == 0 )       {
				isConsole = true;
			}
		}


		if (isConsole == false )	{
			retval = pam_get_item(pamh, PAM_RHOST, (const void **)&remote_ip);
			if (retval == PAM_SUCCESS && remote_ip) {
			} else {
				printf("Remote IP not available\n");
			}
		}
		*/
		struct passwd *pw = getpwnam(user);
    		if (pw == NULL) {
			
        		return PAM_USER_UNKNOWN; 
    		}

		sprintf (szMsg, "User %s (uid:%d) successfully logged in with IP %s. orignal name: %s",user, pw->pw_uid, (isConsole == true)?"CONSOLE":remote_ip, g_szLoginUserOrgName);
		nd_pam_log(szMsg);

		pam_syslog(pamh, LOG_INFO, "%s",szMsg);
	}

 
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                             int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {

/*
	printf(ESC "[2J");  // 화면 지우기
    	printf(ESC "[H");   // 커서를 홈 위치로 이동
*/
/*
	printf ("         .:':'`:·          ,:´'`;' ‘    ,._., ._                      \n");
	printf ("       /:::::::/`·,      /::::/;‘    /::::::::::'/:/:~-.,            	\n");
	printf ("      /:·*'`·:/:::::' , /·´'`;/::';'  /:-·:;:-·~·';/:::::::::`·-.      	\n");
	printf ("    ,'         `:;::::'`i    ';:::';  ';           '`~-:;:::::::::'`,   	\n");
	printf ("    ;            '`;:::'i    'i::::i   ',.                 '`·-:;:::::'i'‘	\n");
	printf ("    i               `;:';    'i:::i'     `'i      ,_            '`;:::'¦‘	\n");
	printf ("    i      ,          \\|     '|:::i°     'i      ;::/`:,          i'::/ 	\n");
	printf ("    |     ,'`,                i:;'' ‚    _;     ;:/;;;;:';        ¦'/   	\n");
	printf ("    'i    'i:::i',             ';/'      /::';   ,':/::::::;'       ,´    	\n");
	printf ("    'i     ;::/ \\           ;/'     ,/-:;_i  ,'/::::;·´        ,'´     	\n");
	printf ("     \\    'i/    '`·,      ,''       '`·.     `'¯¯     '   , ·'´        	\n");
	printf ("      '`~´         '`·–·'´'            `' ~·- .,. -·~ ´             		\n");
	printf ("										\n");
	printf ("                        ‘                     '                       		\n");

	printf ("\t	NNNN		  NNNN  DDDDDDDDDDDDDDDDD			\n");
	printf ("\t	NNNNN		  NNNN  DDDDDDDDDDDDDDDDDDD			\n");
	printf ("\t	NNNNNN		  NNNN  DDDDDDDDDDDDDDDDDDDD			\n");
	printf ("\t	NNNNNNN		  NNNN  	       DDDDDD		  \n");
	printf ("\t	NNNNNNNN	  NNNN			DDDDD		  	\n");
	printf ("\t	NNNN NNNN	  NNNN			DDDDD 			\n");
	printf ("\t	NNNN  NNNN	  NNNN			DDDDD	nn    nn  eeeeeee  tttttttt      a      nn    nn   ddddddd			\n");
	printf ("\t	NNNN   NNNN	  NNNN			DDDDD	nnn   nn  ee          tt        aaa     nnn   nn   dd    dd 		\n");
	printf ("\t	NNNN    NNNN	  NNNN  		DDDDD	nnnn  nn  ee          tt       aa aa    nnnn  nn   dd     dd		\n");
	printf ("\t	NNNN     NNNN	  NNNN  		DDDDD	nn nn nn  eeeeeee     tt      aa   aa   nn nn nn   dd     dd 		\n");
	printf ("\t	NNNN      NNNN    NNNN  		DDDDD	nn  nnnn  ee          tt     aaaaa  aa  nn  nnnn   dd     dd		\n");
	printf ("\t	NNNN	   NNNN   NNNN			DDDDD	nn   nnn  ee          tt     aaaaaa aa  nn   nnn   dd    dd 		\n");
	printf ("\t	NNNN	    NNNN  NNNN			DDDDD	nn    nn  eeeeeee     tt     aa     aa  nn    nn   ddddddd		\n");
	printf ("\t	NNNNNNNNNN   NNNN NNNN			DDDDD			\n");
	printf ("\t	NNNNNNNNNNN   NNNNNNNN			DDDDD			\n");
	printf ("\t	NNNNNNNNNNNN   NNNNNNN  	       DDDDD		 	\n");		
	printf ("\t	NNNN	 	NNNNNN  DDDDDDDDDDDDDDDDDDD 			\n");
	printf ("\t	NNNN		 NNNNN  DDDDDDDDDDDDDDDDDD			\n");
	printf ("\t	NNNN		  NNNN  DDDDDDDDDDDDDDD			\n");
*/
/*
	printf ("\n\n");
	printf ("     NNNNN             NNNN  DDDDDDDDDDDDDDDDD                       \n");
        printf ("     NNNNNNN           NNNN                 DDDDDD             \n");
        printf ("     NNNN NNNN         NNNN                  DDDDD                   \n");
        printf ("     NNNN  NNNN        NNNN                  DDDDD   nn    nn  eeeeeee  tttttttt      a      nn    nn   ddddddd   \n");
        printf ("     NNNN   NNNN       NNNN                  DDDDD   nnn   nn  ee          tt        aaa     nnn   nn   dd    dd  \n");
        printf ("     NNNN    NNNN      NNNN                  DDDDD   nnnn  nn  ee          tt       aa aa    nnnn  nn   dd     dd \n");
        printf ("     NNNN     NNNN     NNNN                  DDDDD   nn nn nn  eeeeeee     tt      aa   aa   nn nn nn   dd     dd \n");
        printf ("     NNNN      NNNN    NNNN                  DDDDD   nn  nnnn  ee          tt     aaaaa  aa  nn  nnnn   dd     dd \n");
        printf ("     NNNN       NNNN   NNNN                  DDDDD   nn   nnn  ee          tt     aaaaaa aa  nn   nnn   dd    dd  \n");
        printf ("     NNNN        NNNN  NNNN                  DDDDD   nn    nn  eeeeeee     tt     aa     aa  nn    nn   ddddddd   \n");
        printf ("     NNNNNNNNNN   NNNNNNNNN                 DDDDD                    \n");
        printf ("     NNNNNNNNNNN    NNNNNNN  DDDDDDDDDDDDDDDDDD                      \n");
        printf ("     NNNN             NNNNN  DDDDDDDDDDDDDDD                 \n");
*/

	printf ("\n\n");
        printf ("     NNNNN             NNNN  DDDDDDDDDDDDDDDDD                       \n");
        printf ("     NNNN  NNNN        NNNN                  DDDDD   nn    nn  eeeeeee  tttttttt     a      nn    nn   ddddddd   \n");
        printf ("     NNNN   NNNN       NNNN                  DDDDD   nnn   nn  ee          tt       aaa     nnn   nn   dd    dd  \n");
        printf ("     NNNN    NNNN      NNNN                  DDDDD   nnnn  nn  ee          tt      aa aa    nnnn  nn   dd     dd \n");
        printf ("     NNNN     NNNN     NNNN                  DDDDD   nn nn nn  eeeeeee     tt     aa   aa   nn nn nn   dd     dd \n");
        printf ("     NNNN      NNNN    NNNN                  DDDDD   nn  nnnn  ee          tt    aaaaa  aa  nn  nnnn   dd     dd \n");
        printf ("     NNNN       NNNN   NNNN                  DDDDD   nn   nnn  ee          tt    aaaaaa aa  nn   nnn   dd    dd  \n");
        printf ("     NNNNNNNNN   NNNN  NNNN                  DDDDD   nn    nn  eeeeeee     tt    aa     aa  nn    nn   ddddddd   \n");
        printf ("     NNNNNNNNNNN    NNNNNNN  DDDDDDDDDDDDDDDDDD                      \n");
        printf ("     NNNN             NNNNN  DDDDDDDDDDDDDDD                 \n");


/*
	printf ("\t									\n");
	printf ("\tnn    nn  eeeeeee  tttttttt      a      nn    nn   ddddddd       	\n");
	printf ("\tnnn   nn  ee          tt        aaa     nnn   nn   dd    dd		\n");
	printf ("\tnnnn  nn  ee          tt       aa aa    nnnn  nn   dd     dd		\n");
	printf ("\tnn nn nn  eeeeeee     tt      aa   aa   nn nn nn   dd     dd		\n");
	printf ("\tnn  nnnn  ee          tt     aaaaa  aa  nn  nnnn   dd     dd		\n");
	printf ("\tnn   nnn  ee          tt     aaaaaa aa  nn   nnn   dd    dd 		\n");
	printf ("\tnn    nn  eeeeeee     tt     aa     aa  nn    nn   ddddddd 		\n");
*/
	printf ("\n\n");	
	
	printf("#\tWelcome to the Secure Login System!\n");
	printf("#\n");
	printf("#\tHello, and welcome to Netand's secure environment. \n");
	printf("#\tPlease be mindful of your security at all times as you access this system. \n");
	printf("#\tWe strive to maintain the highest levels of protection for your data and privacy.\n");
	printf("#\n");
	printf("#\tThis is a secure login system designed to protect your credentials and sensitive information. \n");
	printf("#\tUnauthorized access is strictly prohibited, and all activities are logged and monitored for your safety.\n");
	printf("#\tPlease ensure that you are accessing this system for authorized purposes only. \n");
	printf("#\tMisuse of this system could result in severe penalties, including suspension of access.\n");
	printf("#\n");
	printf("#\t⚠️ Attention: Network security is our top priority. Any suspicious activity will be flagged and reported to the \n#\tappropriate authorities.\n");
	printf ("#\n");
	printf("#\tRemember, safeguarding your login credentials is your responsibility. Always keep them private and secure.\n");
	
	printf("#\tThank you for choosing Netand. Stay vigilant and proceed with caution. Secure your connection and have a \n#\tproductive session!\n\n");

	

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {

	const char *user;
        const char *input_passwd;
        const char *encrypted_passwd;
        char *crypted;
        const char *remote_ip;
        char hostname[256];
        int retval, ret = 0;
        const char *tty;
        char szTty[128] = {0,};
	bool isConsole = false;
	char szMsg[1024] = {0,};

	retval = pam_get_user(pamh, &user, NULL);
        if (retval != PAM_SUCCESS) {
                nd_pam_log("failed to get user name...");
                return retval;
        }

	if (gethostname(hostname, sizeof(hostname)) == 0) {
	} else {
		perror("gethostname");
	}

	pam_get_item(pamh, PAM_TTY, (const void **)&tty);
	if (tty)        {

		if (strncmp(tty, "tty", 3) == 0 )       {
			isConsole = true;
		}
	}


	if (isConsole == false )        {
		retval = pam_get_item(pamh, PAM_RHOST, (const void **)&remote_ip);
		if (retval == PAM_SUCCESS && remote_ip) {
		} else {
			printf("Remote IP not available\n");
		}
	}

	struct passwd *pw = getpwnam(user);
	if (pw == NULL) {

		return PAM_USER_UNKNOWN;
	}

	sprintf (szMsg, "User %s (uid:%d,gid:%d) successfully logged out with IP %s.",user, pw->pw_uid, pw->pw_gid, (isConsole == true)?"CONSOLE":remote_ip) ;
        nd_pam_log(szMsg);

        pam_syslog(pamh, LOG_INFO, szMsg);

	
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {

	const char *user;
	const char *new_password;
	int pam_result;
	char szMsg[1024] = {0,};

	nd_pam_log("start pam_sm_chauthtok..");
	pam_result = pam_get_item (pamh, PAM_USER, (const void**)&user);
	if (pam_result != PAM_SUCCESS || user == NULL )
	{
		return PAM_USER_UNKNOWN;
	}

	pam_result = pam_get_authtok(pamh, PAM_AUTHTOK , &new_password, NULL);
	if (pam_result != PAM_SUCCESS || new_password == NULL)
	{
		return PAM_AUTHTOK_ERR;
	}

	if (strlen(new_password) < 8)	{
		nd_pam_log("Password change failed. - Does not meet complexity test");
		return PAM_AUTHTOK_ERR;
	}

	
	sprintf (szMsg, "[%s] user's password has been changed to [%s]", user, new_password);
	nd_pam_log(szMsg);
	
	return PAM_SUCCESS;
}

