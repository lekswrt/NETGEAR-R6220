#ifndef _LIBHAL_WD_SOCKET_H_
#define _LIBHAL_WD_SOCKET_H_
#define CRASH_LOG_PATH "/tmp/crash_log.txt"

/********************************************
	Function:get crash log
	Parameter:
		crash_log_file:		name of file that save crash log(size: >=128bytes)
	Return:
		HAL_COM_RET_SUCCESS
		HAL_COM_RET_INTERNAL_ERROR
********************************************/
int hal_wd_get_crash_log(char *crash_log_file);

typedef enum
{
	WD_GET_CRASH_LOG_IOCTL = 0,  
}WD_IOCTL_E;

typedef struct 
{
    char crash_log_file[128];	
} hal_wd_trigger_t;
#endif
