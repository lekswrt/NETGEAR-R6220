#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <sys/sysinfo.h>
#include <grp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "sc_util.h"
#include "sc_sessionid.h"

/* A multi-family sockaddr. */
typedef union {
	struct sockaddr sa;
	struct sockaddr_in sa_in;
#ifdef USE_IPV6
	struct sockaddr_in6 sa_in6;
	struct sockaddr_storage sa_stor;
#endif				/* USE_IPV6 */
} usockaddr;

extern usockaddr client_addr;

char sessionid_local_file[100] = "";
char sessionid_new_sessionid[100] = "";

extern char *ntoa(usockaddr * usaP);

//every ip have one session id.

int fd = -1;
static int try_lock()
{
	char *appname = "httpdsessionid";
	char lock_path[PATH_MAX];
	char *p;

	if ((appname=strrchr(sessionid_local_file, '/')) != NULL)
	{
		appname = appname+1;
	}

	sprintf(lock_path, "/var/lock/%s.lock", appname);
	p = lock_path + sizeof("/var/lock/");
	while (*p) {
		if (*p == '/') *p = '_';
		p++;
	}

	fd = open(lock_path, O_CREAT|O_WRONLY|O_TRUNC,S_IRUSR|S_IWUSR);
	if (fd < 0)
		return -1;
	if (lockf(fd,F_LOCK,0) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}
static void try_unlock()
{
	if (fd >= 0) {
		lockf(fd,F_ULOCK,0);
		close(fd);
	}
}

/* if client take Autherrization header, then verify session cookie; if not, do not verify. */
int sessionid_verify_sessionid_ok(char *sessionid_in_cookie)
{
	int verify_ok = 0;
	char *remoteip = ntoa(&client_addr);
	
	SC_CFPRINTF_SESSIONID("try verify session id\n");
	if (sessionid_in_cookie && sessionid_in_cookie[0])
	{
		char sessionid_in_local[100];
		memset(sessionid_in_local, 0, sizeof(sessionid_in_local));
		
		{
			try_lock();
			{
				FILE *fp = fopen(sessionid_local_file, "r");
				if (fp)
				{
					char *p;
					char local_sessionid_buf[1024];
					memset(local_sessionid_buf, 0, sizeof(local_sessionid_buf));
					fread(local_sessionid_buf, sizeof(local_sessionid_buf)-1, 1, fp);
					
					{
						char remoteip_with_equal[100];
						snprintf(remoteip_with_equal, sizeof(remoteip_with_equal), "%s=", remoteip);
						if (remoteip && remoteip[0] && (p=strstr(local_sessionid_buf, remoteip_with_equal))!=NULL)
						{
							strncpy(sessionid_in_local, p+strlen(remoteip_with_equal), SESSIONID_LEN);
						}
					}
					fclose(fp);
				} else
				{
					SC_CFPRINTF_SESSIONID("open %s for read fail\n", sessionid_local_file);
				}
			}
			try_unlock();
		}
	
		SC_CFPRINTF_SESSIONID("session id, local:%s, client:%s\n", sessionid_in_local, sessionid_in_cookie);
		if (strncmp(sessionid_in_local, sessionid_in_cookie, SESSIONID_LEN) == 0)
		{
			verify_ok = 1;
		}
	}
	
	SC_CFPRINTF_SESSIONID("verify sessionid for %s %s ok\n", remoteip, verify_ok?"":"not");
	return verify_ok;
}

int sessionid_valid_local_sessionid()
{
	int valid = 0;
	char sessionid_in_local[100] = "";
	char *remoteip = ntoa(&client_addr);
	
	memset(sessionid_in_local, 0, sizeof(sessionid_in_local));
	{
		try_lock();
		{
			FILE *fp = fopen(sessionid_local_file, "r");
			if (fp)
			{
				char *p;
				char local_sessionid_buf[1024];
				memset(local_sessionid_buf, 0, sizeof(local_sessionid_buf));
				fread(local_sessionid_buf, sizeof(local_sessionid_buf)-1, 1, fp);
				
				{
					char remoteip_with_equal[100];
					snprintf(remoteip_with_equal, sizeof(remoteip_with_equal), "%s=", remoteip);
					if (remoteip && remoteip[0] && (p=strstr(local_sessionid_buf, remoteip_with_equal))!=NULL)
					{
						strncpy(sessionid_in_local, p+strlen(remoteip_with_equal), SESSIONID_LEN);
					}
				}
				fclose(fp);
			} else
			{
				SC_CFPRINTF_SESSIONID("open %s for read fail\n", sessionid_local_file);
			}	
		}
		try_unlock();
	}
	
	if (strstr(sessionid_in_local, "sid"))
	{
		valid = 1;
	}
	SC_CFPRINTF_SESSIONID("sessionid %s for %s is %s valid\n", sessionid_in_local, remoteip, valid?"":"not");
	return valid;
}

void mess_string(char *string)
{
	char *p = string;
	if (p)
	{
			
	}
}

/* only just auth OK, then set session cookie also update the session cookie. */
int sessionid_update_device_sessionid(char *new_sessionid)
{
	// need lock
	// always the second get auth 
	char generated_sessionid[100] = "";
	char *remoteip = ntoa(&client_addr);
	
	{
		char uptime[100] = "";
		FILE *fp = fopen("/proc/uptime", "r");
		if (fp)
		{
			char *p;
			fread(uptime, sizeof(uptime), 1, fp);
			if ((p=strchr(uptime, '.')) != NULL)
			{
				*p = 0;
			}
			fclose(fp);	
		}
		memset(generated_sessionid, 'x', sizeof(generated_sessionid));
		srand(getpid());
		snprintf(generated_sessionid, sizeof(generated_sessionid), "sid%dxxx%sxxx%d", getpid(), uptime, rand());
		mess_string(&generated_sessionid[strlen("sid")]);
		{
			int i;
			for(i=0; i<sizeof(generated_sessionid); i++)
			{
				if (generated_sessionid[i] == 0)
				{
					generated_sessionid[i] = 'x';
				}
			}
		}
		generated_sessionid[SESSIONID_LEN] = 0;
	}
	
	if (new_sessionid)
	{
		strcpy(new_sessionid, generated_sessionid);
	}
	
	try_lock();
	{
		char local_sessionid_buf[1024];
		memset(local_sessionid_buf, 0, sizeof(local_sessionid_buf));
			
		FILE *fp = fopen(sessionid_local_file, "r");
		if (fp)
		{
			fread(local_sessionid_buf, sizeof(local_sessionid_buf)-1, 1, fp);
			fclose(fp);
		} else
		{
			SC_CFPRINTF_SESSIONID("open %s for read fail\n", sessionid_local_file);
		}

		fp = fopen(sessionid_local_file, "w");
		if (fp)
		{
			char *p;
			{
				char remoteip_with_equal[100];
				snprintf(remoteip_with_equal, sizeof(remoteip_with_equal), "%s=", remoteip);
				if (remoteip && remoteip[0]&& (p=strstr(local_sessionid_buf, remoteip_with_equal))!=NULL)
				{
					strncpy(p+strlen(remoteip_with_equal), generated_sessionid, SESSIONID_LEN);
					fwrite(local_sessionid_buf, strlen(local_sessionid_buf), 1, fp);
				} else
				{
					fwrite(local_sessionid_buf, strlen(local_sessionid_buf), 1, fp);
					fprintf(fp, "%s=%s\n", remoteip, generated_sessionid);
				}
			}
			fclose(fp);
		} else
		{
			SC_CFPRINTF_SESSIONID("open %s for write fail\n", sessionid_local_file);
		}
	}
	try_unlock();
	SC_CFPRINTF_SESSIONID("update sessionid %s for %s\n", generated_sessionid, remoteip);
	return 0;
}

char *sessionid_get_sessionid_from_cookie(char *cookie)
{
	static char sessionid[100];
	memset(sessionid, 0, sizeof(sessionid));
	
	if (cookie)
	{
		char *p;
		if ((p=strstr(cookie, SESSIONID_MAGICWORD"=")) != NULL)
		{
			p = p+strlen(SESSIONID_MAGICWORD"=");
			snprintf(sessionid, sizeof(sessionid), "%s", p);
			p = strchr(sessionid, ';');
			if (p)
			{
				*p = 0;
			}
		}
	}
	if (sessionid[0])
	{
		SC_CFPRINTF_SESSIONID("get sessionid %s out of cookie ok\n", sessionid);
	} else
	{
		SC_CFPRINTF_SESSIONID("get sessionid %s out of cookie %s fail\n", sessionid, cookie);
	}
	return sessionid;
}

int sessionid_delete_local_sessionid(const char *whichfunction)
{
	char local_sessionid_buf[1024];
	char *remoteip = ntoa(&client_addr);
	memset(local_sessionid_buf, 0, sizeof(local_sessionid_buf));

	SC_CFPRINTF_SESSIONID("!!!delete local sessionid by %s for %s\n", whichfunction, (remoteip && remoteip[0])?remoteip:"unknown");
	try_lock();
#if 1
	unlink(sessionid_local_file);
#else
	{
		FILE *fp = fopen(sessionid_local_file, "r");
		if (fp)
		{
			fread(local_sessionid_buf, sizeof(local_sessionid_buf)-1, 1, fp);
			fclose(fp);
		} else
		{
			SC_CFPRINTF_SESSIONID("open %s for read fail\n", sessionid_local_file);
		}

		fp = fopen(sessionid_local_file, "w");
		if (fp)
		{
			char *p;
			{
				char remoteip_with_equal[100];
				snprintf(remoteip_with_equal, sizeof(remoteip_with_equal), "%s=", remoteip);				
				if (remoteip && remoteip[0] && (p=strstr(local_sessionid_buf, remoteip_with_equal))!=NULL)
				{
					char tmp[SESSIONID_LEN+1];
					memset(tmp, 'x', SESSIONID_LEN);
					tmp[SESSIONID_LEN] = 0;
					strcpy(p+strlen(remoteip_with_equal), tmp);
				}
			}
			fwrite(local_sessionid_buf, strlen(local_sessionid_buf), 1, fp);
			fclose(fp);
		} else
		{
			SC_CFPRINTF_SESSIONID("open %s for write fail\n", sessionid_local_file);
		}
	}
#endif	
	try_unlock();
	return 0;
}