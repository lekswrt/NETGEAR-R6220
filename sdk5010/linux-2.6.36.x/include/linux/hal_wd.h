#ifndef __SC_KERNEL_H__
#define __SC_KERNEL_H__

#define MEM_RESERVED_SIZE 0x8000 //32k

//#define BOOT_FREE_ADDRESS       ( 0x0FFF8000 | 0xA0000000)  //0x0FFF8000=256*1024*1024-32*1024(256m-32k)
#define BOOT_FREE_ADDRESS       (0x07C00000 | 0xA0000000) //128m-4m for R6260 128M RAM
#define BOOT_LOG_ADDRESS        (BOOT_FREE_ADDRESS  +  (1 << 11))  
#define SC_DMESG_LOG_SIZE		8192  //16k
#define BOOT_STACK_ADDRESS      (BOOT_LOG_ADDRESS + (1 << 13))
#define SC_STACK_LOG_SIZE       6144 //6k
#define __LOG_BUF_LEN (1 << CONFIG_LOG_BUF_SHIFT)

extern char stack_log_buff[SC_STACK_LOG_SIZE];
extern unsigned stack_buff_len;
#define SC_LOG_MSG_TO_BUFF(fmt, args...) do{				\
											if(stack_buff_len <= (SC_STACK_LOG_SIZE-256)){			\
												stack_buff_len += sprintf(stack_log_buff+stack_buff_len,fmt,##args);	\
											}				\
								}while(0)
#endif
