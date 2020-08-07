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

static int captive_is_apple = 0;

#define SC_CFPRINTF_FORCE(fmt, args...)    do{   FILE *fp=fopen("/dev/console", "a+"); if(fp) {fprintf(fp, "[%s::%s():%d] ", __FILE__, __FUNCTION__, __LINE__);fprintf(fp, fmt, ##args);fclose(fp);}}while(0)
static int captive_detecting_host(char *request_host)
{
	int i = 0;
	int is_host_for_detecting = 0;
	char *host_for_detecting[] = {
			"www.google.com",
			"as.xboxlive.com",
			"tgs.xboxlive.com",
			"macs.xboxlive.com",
			"as.xboxlive.com.local",
			"tgs.xboxlive.com.local",
			"macs.xboxlive.com.local",
			"updates1.netgear.com",
			"captive.apple.com",
			"www.appleiphonecell.com",
			"www.apple.com",
			"www.itools.info",
			"www.ibook.info",
			"www.airport.us",
			"www.thinkdifferent.us",
			"captive.apple.com",
			"www.appleiphonecell.com",
			"www.apple.com",
			"www.itools.info",
			"www.ibook.info",
			"www.airport.us",
			"www.thinkdifferent.us",
			"clients1.google.com",
			"clients3.google.com",
			"connectivitycheck.gstatic.com",
			"detectportal.firefox.com",
			"connectivitycheck.android.com",
			NULL};
	
	if (request_host)
	{
		for(i=0; host_for_detecting[i]; i++)
		{
			if (strcmp(host_for_detecting[i], request_host) == 0)
			{
				SC_CFPRINTF_FORCE("find captive host:%s\n", request_host);
				is_host_for_detecting = 1;
				
				if (strstr(host_for_detecting[i], "apple"))
				{
					SC_CFPRINTF_FORCE("apple captive\n");
					captive_is_apple = 1;
				}
				
				break;
			}
		}
	}
	return is_host_for_detecting;
}

static int captive_detecting_agent(char *request_agent)
{
	int i = 0;
	int is_detecting_agent = 1;
	char *normal_agent[] = {
			"Mozilla",
			"Chrome",
			"Safari",
			"Firefox",
			"UCBrowser",
			"MSIE",
			"Opera",
			"Edge",
			"SeaMonkey",
			"Maxthon",
			"K-Meleon",
			"Camino",
			NULL
			};
	
	for(i=0; normal_agent[i]; i++)
	{
		if (strstr(request_agent, normal_agent[i]))
		{
			SC_CFPRINTF_FORCE("normal agent:%s match %s\n", request_agent, normal_agent[i]);
			is_detecting_agent = 0;
			break;
		}
	}
	
	if ((access("/tmp/captive_agent", F_OK) == 0) && (is_detecting_agent == 0))
	{
		SC_CFPRINTF_FORCE("but force it detecting agent for debug\n");
		is_detecting_agent = 1;
	}
	
	return is_detecting_agent;
}

int is_captive_detecting(char *request_host, char *request_agent)
{
	int captive_detecting = 0;
	if (request_host && request_agent && request_host[0] && request_agent[0])
	{
		if (captive_detecting_host(request_host) && captive_detecting_agent(request_agent))
		{
			captive_detecting = 1;
		}
	}
	SC_CFPRINTF_FORCE("request_host:%s, request_agent:%.30s..., is %s captive_detecting\n", request_host, request_agent, captive_detecting?"":"not");
	return captive_detecting;
}

int is_apple_captive()
{
	return captive_is_apple;	
}

