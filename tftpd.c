#include "tftpd.h"
#include "module.c"
#include "tftpd_task.c"

void oack_send(char option_buffer[],option_packet *opt_byte, int index)
{
	char *p;
	int size1,size2,t_size;
	char buffer[OPTION_BUFFER];
	int len = sizeof(tftp_sessions[index].client_add);
	opt_byte->opcode = htons(OACK);
	size1 = strlen(tftp_sessions[index].block_name)+1;
	memcpy(opt_byte->blkname,tftp_sessions[index].block_name,size1);
	p = (char *)&opt_byte->blkname;
	p= p + size1;
	sprintf(buffer,"%d",tftp_sessions[index].block_size);
	size2 = strlen(buffer)+1;
	memcpy(p,buffer,size2);
	t_size = 2+size1+size2;
	so_sendto(tftp_sessions[index].sock_fd,option_buffer,t_size,0,(struct soaddr *)&tftp_sessions[index].client_add,len);
	return;
}

void option_negotiation(char pkt_buf[],read_write_packet *p_pkta,int index)
{
	char *p;
	int blk_count = 0,size;
    char buffer[OACK_SEND_BUFFER];
    memset(buffer,0,sizeof(buffer));
    
	p = (char*) &p_pkta->filename;
	p = p + (strlen(p_pkta->filename) + 1) + (strlen("octet") + 1);
	strcpy(buffer,p);
	while((strcasecmp(buffer,"blksize")) != 0 && blk_count < 4)
	{
		p = p + strlen(buffer) + 1;
		strcpy(buffer,p);
		if((strcasecmp(buffer,"blksize")) == 0)
		{
			break;
		}
		blk_count++;
	}
	memcpy(tftp_sessions[index].block_name,buffer,strlen(buffer)+1);
	p = p + strlen(buffer) + 1;
	strcpy(buffer,p);
	size = atoi(buffer);
	if(blk_count == 4 || size == DEFAULT_BLOCK_SIZE || (size < 8 && size > 65526))
	{
		tftp_sessions[index].option_flag = 1;
		tftp_sessions[index].block_size = DEFAULT_BLOCK_SIZE;
	}
	else
	{
		tftp_sessions[index].option_flag = 0;
	    tftp_sessions[index].block_size = size;	
	}
	return;	
}

void rrq_packet(int s_id)
{
	FCB_POINT *fpp;
	char buf_rcv[BUFFER_SIZE],ack_ver[BUFFER_SIZE],buffer[FILE_BUFFER],option_buffer[OPTION_BUFFER],error_message[ERROR_BUFFER];
	UINT32 read;
	TIMER_USER_DATA timer_ud;
    unsigned long timer_id;
	MSG_Q_ID msgq_id1;
	int session_fd = -1;
	int count = 0,offset=0,read_count = 0;
	int timer_count = 0,buffer_increase = 0;
	int oack_flag = 0,timer_oack = 0,tic_count = 0;
	struct sockaddr_in s_addr;
	int rv;
	demo_msg_t msg;
	
    int len = sizeof(tftp_sessions[s_id].client_add);
    int len1= sizeof(s_addr);
    
    msgq_id1 = sys_msgq_create(256, Q_OP_FIFO);
	if (msgq_id1 == NULL)
	{
		read_write_check--;
		syslog(LOG_WARNING,"ERROR CREATING MESSAGE QUEUE\n");
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
		return;
	}
	
    session_fd = so_socket(AF_INET, SOCK_DGRAM, 0);
	if (session_fd < 0)
	{
		read_write_check--;
		syslog(LOG_WARNING,"ERROR CREATING SOCKET\n");
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
		return;
	}
	
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(SESSION_PORT + s_id);
	
	rv = so_bind(session_fd, (struct soaddr *)&s_addr, sizeof(s_addr));
	if ( rv < 0)
	{
		read_write_check--;
		syslog(LOG_WARNING,"BINDING\n");
		so_close(session_fd);
		sys_msgq_delete(msgq_id1);
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
		return;
	}

	if(socket_register(session_fd, (ULONG) msgq_id1, 0) != 0)
	{
		read_write_check--;
		syslog(LOG_WARNING,"REGISTER FAIL\n");
		so_close(session_fd);
		sys_msgq_delete(msgq_id1);
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
		return;
	}

	
	timer_ud.msg.qid = msgq_id1;
    timer_ud.msg.msg_buf[0] = TIMER_MESSAGE;
    
    sys_add_timer(TIMER_LOOP | TIMER_MSG_METHOD, &timer_ud, &timer_id); 
    
	data_packet *rcv_byte = (data_packet*) buf_rcv;
	ack_packet *ack_byte = (ack_packet*) ack_ver;
	option_packet *opt_byte = (option_packet *)option_buffer;
	
	while(1)
	{
		if(FILE_NOERROR == enter_filesys(OPEN_READ))
		{
			break;
		}
		else
		{
			sys_task_delay(20);
		}
	}
	
	rv = IsFileExist(tftp_sessions[s_id].filename);
	if(rv == 0)
	{
		read_write_check--;
		strcpy(error_message,"FILE_NOT_EXIST");
		send_error_message(session_fd,tftp_sessions[s_id].client_add,FILE_NOT_EXIST,error_message);
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
		exit_filesys(OPEN_READ);
		so_close(session_fd);
		sys_msgq_delete(msgq_id1);
		return;
	}
	
	fpp = file_open(tftp_sessions[s_id].filename,"r",NULL);					
	if(fpp == NULL)
	{
		read_write_check--;
		strcpy(error_message,"ACCESS_VIOLATION");
		send_error_message(session_fd,tftp_sessions[s_id].client_add,ACCESS_VIOLATION,error_message);
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
		exit_filesys(OPEN_READ);
		so_close(session_fd);
		sys_msgq_delete(msgq_id1);
		return;
	}
	
	memset(buffer,0,sizeof(buffer));
	read = file_read(fpp,(INT8 *)buffer,sizeof(buffer));
	
	if(tftp_sessions[s_id].option_flag == 0)
	{
		tftp_sessions[s_id].sock_fd = session_fd;
	    oack_send(option_buffer,opt_byte,s_id);
	    sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
	    tic_count++;
	}
	
	else if(tftp_sessions[s_id].option_flag == 1)
	{
		rcv_byte->opcode = htons(DATA);
	    if(read < tftp_sessions[s_id].block_size)
	    {
	    	read_count = read;
            rcv_byte->block_number = ++count;
	        memcpy(rcv_byte->data,buffer,read_count);
	        rv = so_sendto(session_fd,buf_rcv,sizeof(*rcv_byte)+read_count,0,(struct soaddr *)&tftp_sessions[s_id].client_add,len);
	        if(rv < 0)
	        {
		        syslog(LOG_WARNING,"FAIL TO SEND PACKET\n");
	        }
		}
		
		else
		{
			read_count = tftp_sessions[s_id].block_size;
            rcv_byte->block_number = ++count;
	        memcpy(rcv_byte->data,buffer,read_count);
	        buffer_increase = buffer_increase + read_count;
	        rv = so_sendto(session_fd,buf_rcv,sizeof(*rcv_byte)+tftp_sessions[s_id].block_size,0,(struct soaddr *)&tftp_sessions[s_id].client_add,len);
	        if(rv < 0)
	        {
		        syslog(LOG_WARNING,"FAIL TO SEND PACKET\n");
	        }
		}
		tic_count++;
	    sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
	}
	
	file_close(fpp);
	exit_filesys(OPEN_READ);
	sys_task_delay(1);
	
	while(1)
	{
		rv = sys_msgq_receive(msgq_id1, (unsigned long *)&msg, SYS_WAIT_FOREVER);
	    if (rv != SYS_OK)
		{
			syslog(LOG_WARNING,"FAIL TO RECEIVE MESSAGE\n");
			memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
			read_write_check--;
			continue;
		}
		
		switch(msg.msg_type)
		{
			case SOCKET_DATARCVD:
				
			    rv = so_recvfrom(session_fd, ack_ver, sizeof(ack_packet), 0, (struct soaddr *)&s_addr, &len1);
			    if(rv < 0)
			    {
			    	syslog(LOG_WARNING,"FAIL TO SEND ACK\n");
				    continue;
		        }
				
				if(ack_byte->block_number == 0)
				{
					sys_stop_timer(timer_id);
					rcv_byte->opcode = htons(DATA);
					read_count = read;
                    rcv_byte->block_number = ++count;
	                memcpy(rcv_byte->data,buffer,tftp_sessions[s_id].block_size);
	                buffer_increase = buffer_increase + tftp_sessions[s_id].block_size;
	                rv = so_sendto(session_fd,buf_rcv,sizeof(*rcv_byte)+tftp_sessions[s_id].block_size,0,(struct soaddr *)&tftp_sessions[s_id].client_add,len);
	                if(rv < 0)
	                {
		                syslog(LOG_WARNING,"FAIL TO SEND PACKET\n");
	                }
	                oack_flag = 1;
	                sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
	                continue;
				}
				
			    if(rcv_byte->block_number == ack_byte->block_number && ack_byte->opcode == ACK)
			    {
			    	sys_stop_timer(timer_id);
			    	timer_count = 0;		
			    }
		        else 
			    {
				    continue;
			    }
                
                
                if((read - buffer_increase) < tftp_sessions[s_id].block_size && (read - buffer_increase) != 0)
                {
                	read_count = read - buffer_increase;
                	rcv_byte->block_number = ++count;
			        memcpy(rcv_byte->data,buffer + buffer_increase,read_count);
			        so_sendto(session_fd,buf_rcv,sizeof(*rcv_byte)+read_count,0,(struct soaddr *)&tftp_sessions[s_id].client_add,len);
				}
				
				else if((read - buffer_increase) >= tftp_sessions[s_id].block_size)
				{
					read_count = tftp_sessions[s_id].block_size;
					rcv_byte->block_number = ++count;
					memcpy(rcv_byte->data,buffer + buffer_increase,read_count);
					buffer_increase = buffer_increase + read_count;
					so_sendto(session_fd,buf_rcv,sizeof(*rcv_byte)+read_count,0,(struct soaddr *)&tftp_sessions[s_id].client_add,len);
				}
			    sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
			    
			    if((read - buffer_increase) == 0)
			    {
			    	while(1)
			    	{
			    		if(FILE_NOERROR == enter_filesys(OPEN_READ))
			    		{
			    			break;
						}
						else
						{
							sys_task_delay(20);
						}
					}
					fpp = file_open(tftp_sessions[s_id].filename,"r",NULL);
	                if(fpp == NULL)
	                {
	            	    exit_filesys(OPEN_READ);
		                so_close(session_fd);
		                sys_msgq_delete(msgq_id1);
				    }
				    offset = offset + read;
				    file_seek(fpp,offset,FROM_HEAD);
				    memset(buffer,0,sizeof(buffer));
				    read = file_read(fpp,(INT8 *)buffer,sizeof(buffer));
				    buffer_increase = 0;
				    file_close(fpp);
	                exit_filesys(OPEN_READ);
				}
				tic_count++;
				if(tic_count == 10)
				{
					sys_task_delay(1);
					tic_count=0;
					
				}
				break;
				
			case TIMER_MESSAGE:
				if(oack_flag == 0)
				{
					if(timer_oack < retrsmit_time)
					{
						oack_send(option_buffer,opt_byte,s_id);
						sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
						timer_oack++;
					}
					else
					{
					    read_write_check--;
					    strcpy(error_message,"ILLEGAL_TFTP_OPERATION");
		                send_error_message(session_fd,tftp_sessions[s_id].client_add,ILLEGAL_TFTP_OPERATION,error_message);
		                memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
			            sys_delete_timer(timer_id);
			            so_close(session_fd);
			            sys_msgq_delete(msgq_id1);	
					    return;
					}
					
				}
				else 
				{
				    if(timer_count < retrsmit_time)
				    {
					    so_sendto(session_fd,buf_rcv,sizeof(*rcv_byte)+read_count,0,(struct soaddr *)&tftp_sessions[s_id].client_add,len);
					    sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
	                    Print("Resend Block no: %d %d\n",rcv_byte->block_number,read_count);
	                    timer_count++;
				    }
				    else
				    {
					    read_write_check--;
					    strcpy(error_message,"ILLEGAL_TFTP_OPERATION");
		                send_error_message(session_fd,tftp_sessions[s_id].client_add,ILLEGAL_TFTP_OPERATION,error_message);
		                memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
			            sys_delete_timer(timer_id);
			            so_close(session_fd);
			            sys_msgq_delete(msgq_id1);	
					    return;
				    }
				}
				
				break;
			default: 
			    break;
		}
			
		if(read_count < tftp_sessions[s_id].block_size && read_count != 0)
		{
			memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
			read_write_check--;
			sys_delete_timer(timer_id);
			so_close(session_fd);
			sys_msgq_delete(msgq_id1);
			return;
		}															
	}
	return;
}

void wrq_packet(int s_id)
{
	FCB_POINT *fpp;
	char buf_rcv[BUFFER_SIZE];
	char ack_ver[BUFFER_SIZE];
	char option_buffer[OPTION_BUFFER];
	char error_message[100];
	uint32 write;
	TIMER_USER_DATA timer_ud;
    unsigned long timer_id;
	MSG_Q_ID msgq_id1;
	int session_fd = -1;
	int count = 0,count_byte_write,timer_count = 0;
	struct sockaddr_in s_addr;
	int timer_oack=0,oack_check = 0;
	int rv;
	uint16 b_number=1;
	demo_msg_t msg;

	int len = sizeof(tftp_sessions[s_id].client_add);
    int len1= sizeof(s_addr);
    
    data_packet *rcv_byte = (data_packet*) buf_rcv;
	ack_packet *ack_byte = (ack_packet*) ack_ver;
	option_packet *opt_byte = (option_packet *)option_buffer;
    
    msgq_id1 = sys_msgq_create(256, Q_OP_FIFO);
	if (msgq_id1 == NULL)
	{
		tftp_sessions[s_id].status=0;
		read_write_check = 0;
		syslog(LOG_WARNING,"ERROR CREATING MESSAGE QUEUE\n");
		return;
	}
	
    session_fd = so_socket(AF_INET, SOCK_DGRAM, 0);
	if (session_fd < 0)
	{
		tftp_sessions[s_id].status=0;
		read_write_check = 0;
		syslog(LOG_WARNING,"ERROR CREATING SOCKET\n");
		return;
	}
	
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(SESSION_PORT);
	
	rv = so_bind(session_fd, (struct soaddr *)&s_addr, sizeof(s_addr));
	if ( rv < 0)
	{
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
		read_write_check = 0;
		syslog(LOG_WARNING,"BINDING NOT SUCCESSFUL\n");
		so_close(session_fd);
	    sys_msgq_delete(msgq_id1);
	    return;
	}

	if(socket_register(session_fd, (ULONG) msgq_id1, 0) != 0)
	{
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
		read_write_check = 0;
		syslog(LOG_WARNING,"REGISTER FAIL\n");
		so_close(session_fd);
		sys_msgq_delete(msgq_id1);
		return;
	}
	
	timer_ud.msg.qid = msgq_id1;
    timer_ud.msg.msg_buf[0] = TIMER_MESSAGE;
    
    sys_add_timer(TIMER_LOOP | TIMER_MSG_METHOD, &timer_ud, &timer_id);
	
	
	rv = enter_filesys(OPEN_WRITE);
	if(rv != 0)
	{
		exit_filesys(OPEN_WRITE);
		syslog(LOG_WARNING,"PERMISSION IS NOT SUCCESSFUL\n");
		return;
	}
	
	rv = IsFileExist(tftp_sessions[s_id].filename);
	if(rv != 0)
	{
		read_write_check = 0;
		strcpy(error_message,"FILE_ALREADY_HAS");
		send_error_message(session_fd,tftp_sessions[s_id].client_add,FILE_ALREADY_HAS,error_message);
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
	    exit_filesys(OPEN_WRITE);
		so_close(session_fd);
		sys_msgq_delete(msgq_id1);
		return;
	}
	
	fpp = file_open(tftp_sessions[s_id].filename,"w",NULL);					
	if(fpp == NULL)
	{
		read_write_check = 0;
		strcpy(error_message,"ACCESS_VIOLATION");
		send_error_message(session_fd,tftp_sessions[s_id].client_add,ACCESS_VIOLATION,error_message);
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
	    exit_filesys(OPEN_WRITE);
		so_close(session_fd);
		sys_msgq_delete(msgq_id1);
		return;
	}
	if(tftp_sessions[s_id].option_flag == 0)
	{
		tftp_sessions[s_id].sock_fd = session_fd;
		oack_send(option_buffer,opt_byte,s_id);
		timer_oack = 1;
		sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
	}
	else if(tftp_sessions[s_id].option_flag == 1)
	{
		ack_byte->opcode = htons(ACK);
	    ack_byte->block_number = count;
	    rv = so_sendto(session_fd,ack_ver,sizeof(*ack_byte)+sizeof(ack_packet),0,(struct soaddr *)&tftp_sessions[s_id].client_add,len);
	
	    if(rv < 0)
       	{
       		syslog(LOG_WARNING,"Failed to receive 1st ack\n");
	    }  
	    sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
	}
	while(1)
	{
		rv = sys_msgq_receive(msgq_id1, (unsigned long *)&msg, SYS_WAIT_FOREVER);
	    if (rv != SYS_OK)
		{
			syslog(LOG_WARNING,"Failed to receive message\n");
			continue;
		}
		
		switch(msg.msg_type)
		{
			case SOCKET_DATARCVD:
				count_byte_write = so_recvfrom(session_fd, buf_rcv, sizeof(buf_rcv), 0, (struct soaddr *)&s_addr,&len1);
			    if(count_byte_write < 0)
			    {
			    	syslog(LOG_WARNING,"Failed to receive PACKET\n");
				    continue;
		        }
		        
		        if(rcv_byte->opcode == DATA )
		        {
		        	sys_stop_timer(timer_id);
			    	timer_count = 0;
			    	timer_oack = 0;
				}
				else
				{
					continue;
				}
				
		        if(rcv_byte->block_number == b_number)
		        {
		        	write = file_write(fpp,(INT8 *)rcv_byte->data,(count_byte_write-4));
		            ack_byte->opcode = htons(ACK);
		            ack_byte->block_number = htons(b_number);
		            rv = so_sendto(session_fd,ack_ver,sizeof(*ack_byte)+sizeof(ack_packet),0,(struct soaddr *)&tftp_sessions[s_id].client_add,len);
	
	                if(rv < 0)
	                {
		                syslog(LOG_WARNING,"Failed to receive 1st ACK\n");
	                }
	                sys_start_timer(timer_id, TIMER_RESOLUTION_S | 5);
	                b_number++;
				}
				else continue;
		        
				break;
				
			case TIMER_MESSAGE:
				if(timer_oack == 1)
				{
					if(oack_check < retrsmit_time)
					{
						oack_send(option_buffer,opt_byte,s_id);
						sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
						oack_check ++;
					}
					else
					{
					    read_write_check = 0;
					    strcpy(error_message,"ILLEGAL_TFTP_OPERATION");
		                send_error_message(session_fd,tftp_sessions[s_id].client_add,ILLEGAL_TFTP_OPERATION,error_message);
		                memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
	                	sys_delete_timer(timer_id);
			            file_close(fpp);
			            exit_filesys(OPEN_WRITE);
			            so_close(session_fd);
			            sys_msgq_delete(msgq_id1);
			            return;
					}
					
				}
				else
				{
					if(timer_count < retrsmit_time)
					{
						so_sendto(session_fd,ack_ver,sizeof(*ack_byte)+sizeof(ack_packet),0,(struct soaddr *)&tftp_sessions[s_id].client_add,len);
						sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
		                Print("Resend This Block no: %d\n",ack_byte->block_number);
						
						timer_count++;
					}
					else
					{
					    read_write_check = 0;
					    strcpy(error_message,"ILLEGAL_TFTP_OPERATION");
		                send_error_message(session_fd,tftp_sessions[s_id].client_add,ILLEGAL_TFTP_OPERATION,error_message);
		                memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
	                	sys_delete_timer(timer_id);
			            file_close(fpp);
			            exit_filesys(OPEN_WRITE);
			            so_close(session_fd);
			            sys_msgq_delete(msgq_id1);
					    return;
					}
				}
				break;
			default:
				break;
		}
		if(write < tftp_sessions[s_id].block_size)
		{
			memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
			read_write_check = 0;
			sys_delete_timer(timer_id);
			file_close(fpp);
			exit_filesys(OPEN_WRITE);
			so_close(session_fd);
			sys_msgq_delete(msgq_id1);
			return;
		}
	}
	
}

void tftpd_init()
{
	list.module_type = MODULE_TYPE_TFTPD;
	strcpy(list.module_name,"tftpd_project");
	strcpy(list.module_description,"RFC1350_IMPLEMENTATION");
	list.version = 2;
	list.next = NULL;
	
	register_module_version(&list);
	
	tftp_register_cmds();
	
	interface_set_showrunning_service(MODULE_TYPE_TFTPD, tftp_show_running);
	
	TASK_ID task_id;
    
	task_id = sys_task_spawn("TSK3", 128, 0, 20096, (FUNCPTR)server_function, NULL, 0);
	if (task_id == ERROR)
		Print("Failed to create task\n");
	
	return;
}


