#include <taskLib.h>
#include <msgQLib.h>
#include <ip/socket.h>
#include <ip/msg.h>
#include <libsys/timer.h>
#include "libsys/vos/vos_task.h"
#include "libsys/vos/vos_msgq.h"
#include "ip/inet.h"
#include "ip/in.h"
#include "ip/netdb.h"
#include <libfile/file_sys.h>
#include <libsys/timer.h>
#include <libsys/verctl.h>
#include <libsys/vos/vos_semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libsys/misc.h>
#include <libcmd/cmdparse.h>
#include <libcmd/argparse.h>
#include <libcmd/cmderror.h>

#define MAX_RETRANSMISSION 4
#define BUFFER_SIZE 6000

#define RRQ   01 
#define WRQ   02 
#define DATA  03 
#define ACK   04 
#define ERR   05
#define OACK  06

#define FILE_NOT_EXIST         1
#define ACCESS_VIOLATION       2
#define ILLEGAL_TFTP_OPERATION 4
#define FILE_ALREADY_HAS       6


#define TIMER_MESSAGE     8
#define ENABLE_MESSAGE    11
#define DISABLE_MESSAGE   12
#define PORT_REQUEST      13


#define MAX_TFTP_SESSIONS  3
#define FILE_BUFFER        81920
#define OPTION_BUFFER      600
#define ERROR_BUFFER       100
#define DEFAULT_BLOCK_SIZE 512
#define OACK_SEND_BUFFER   10000

#define TIMEOUTT          3
#define RETRANSMITT       3
#define UDP_PORT          69
#define SESSION_PORT      1011

#define STR_BLK_NAME      30
#define STR_ERR_BUFF      20
#define STR_FILENAME      30

extern unsigned long Print(char *format, ...);

typedef struct 
{
	uint16 opcode;
	char filename[0];
}__attribute__((packed)) read_write_packet;

typedef struct 
{
	uint16 opcode;
	uint16 block_number;
    char data[0];	
}__attribute__((packed)) data_packet;

typedef struct 
{
	uint16 opcode;
	uint16 block_number;
}__attribute__((packed)) ack_packet;

typedef struct 
{
	uint16 opcode;
	uint16 error_code;
    char error_msg[STR_ERR_BUFF];
}__attribute__((packed)) error_packet;

typedef struct 
{
	uint16 opcode;
	char blkname[0];
}__attribute__((packed)) option_packet;

typedef struct  
{
	unsigned long msg_type;
	unsigned long count;
	unsigned long reserved1;
	unsigned long reserved2;
} demo_msg_t;

typedef struct
{
	int sock_fd;
	int status;
	char filename[STR_FILENAME];
	char block_name[STR_BLK_NAME];
	int block_size;
	int option_flag;
    struct sockaddr_in client_add;
} __attribute__((packed)) tftp_session_t;

tftp_session_t tftp_sessions[MAX_TFTP_SESSIONS];
struct version_list list;

int enable_flag = 0;
int disable_flag = 0;
MSG_Q_ID msgq_id;
int timeout = TIMEOUTT;
int retrsmit_time = RETRANSMITT;
int port = UDP_PORT;
int read_write_check = 0;

void oack_send(char option_buffer[],option_packet *opt_byte, int index);
void option_negotiation(char pkt_buf[],read_write_packet *p_pkta,int index);
void rrq_packet(int s_id);
void wrq_packet(int s_id);
static int do_enable_tftp(int argc, char **argv, struct user *u);
static int set_tftp_port(int argc, char **argv, struct user *u);
static int set_tftp_retry(int argc, char **argv, struct user *u);
static int cmd_conf_tftp(int argc, char **argv, struct user *u);
static int do_show_tftp_statistics(int argc, char **argv, struct user *u);
int show_tftp(int argc, char **argv, struct user *u);
int32 tftp_show_running(DEVICE_ID diID);
