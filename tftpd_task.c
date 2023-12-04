void send_error_message(int sock_fd,struct sockaddr_in s_addr,int error_code,char error[])
{
	char err_buf[OPTION_BUFFER];
	int len = sizeof(s_addr),rv;
	error_packet *err_byte = (error_packet*)err_buf;
	err_byte->opcode = ERR;
	err_byte->error_code = error_code;
	strcpy(err_byte->error_msg,error);
	rv = so_sendto(sock_fd,err_buf,sizeof(*err_byte)+sizeof(error_packet),0,(struct soaddr *)&s_addr,len);
	syslog(LOG_ERR,"ERROR MESSAGE: %s\n",err_byte->error_msg);
}

void server_function()
{
	int rv;
	TASK_ID task_id;
	
	uint32 SEM_ID;
	char pkt_buf[OPTION_BUFFER];
	char err_buf[OPTION_BUFFER];
	char error_message[ERROR_BUFFER];
	
	struct sockaddr_in s_addr;
	int sock_fd = -1,enable_check =0,disable_check=0;
	int s_id = 0;
	demo_msg_t msg;
    int len = sizeof(s_addr);
    uint32 args[4]={-1,-1,-1,-1};
    
    read_write_packet *p_pkta = (read_write_packet *) pkt_buf;
	
	SEM_ID = sys_sm_create(SEM_Q_FIFO, SEM_FULL);
	
	msgq_id = sys_msgq_create(256, Q_OP_FIFO);
	if (msgq_id == NULL)
	{
		Print("ERROR CREATING MESSAGE QUEUE\n");
	}
	
    while(s_id < MAX_TFTP_SESSIONS)
	{
		memset(&tftp_sessions[s_id],0,sizeof(tftp_session_t));
		s_id++;
	}
	
	while(1)
	{
		int index = 0;
		memset(pkt_buf,0,sizeof(pkt_buf));
		
		rv = sys_msgq_receive(msgq_id, (unsigned long *)&msg, SYS_WAIT_FOREVER);
		if (rv != SYS_OK)
		{
			Print("Failed to receive message main\n");
			continue;
		}
		switch(msg.msg_type)
		{
			case SOCKET_DATARCVD:
				memset(&s_addr, 0, sizeof(s_addr));
				rv = so_recvfrom(sock_fd, pkt_buf, BUFFER_SIZE, 0, (struct soaddr *)&s_addr, &len);
				s_id = 0;
				while(s_id < MAX_TFTP_SESSIONS)
				{
					if((tftp_sessions[s_id].client_add.sin_port == s_addr.sin_port) && (tftp_sessions[s_id].client_add.sin_addr.s_addr == s_addr.sin_addr.s_addr)) 
					{
						strcpy(error_message,"ILLEGAL_TFTP_OPERATION");
						send_error_message(sock_fd,s_addr,ILLEGAL_TFTP_OPERATION,error_message);
						continue;
					}
					s_id++;
				}
				
				if(ntohs(p_pkta->opcode) == RRQ)
				{
					
					if(read_write_check < 3)
					{
						while(index < MAX_TFTP_SESSIONS)
						{
							if(tftp_sessions[index].status == 0)
							{
								read_write_check++;
								sys_sm_p(SEM_ID, WAIT_FOREVER);
								memset(&tftp_sessions[index],0,sizeof(tftp_session_t));
								strncpy(tftp_sessions[index].filename,p_pkta->filename,sizeof(tftp_sessions[index].filename));
							    tftp_sessions[index].status = 1;
							    tftp_sessions[index].client_add = s_addr;
							    option_negotiation(pkt_buf,p_pkta,index);
							    args[0]=index;
							    sys_sm_v(SEM_ID);
					            task_id = sys_task_spawn("TSK2", 128, 0, 336096, (FUNCPTR)rrq_packet, args, 0);
	                            if (task_id == (TASK_ID)SYS_ERROR)
		                             Print("Failed to create task\n");
		                        break;
							}
							index++;
					    }
					
					}
					else
					{
						strcpy(error_message,"ACCESS_VIOLATION");
						send_error_message(sock_fd,s_addr,ACCESS_VIOLATION,error_message);
					}
					 
				}
				else if(ntohs(p_pkta->opcode) == WRQ)
				{
					if(read_write_check == 0)
					{
					   	  read_write_check = 4;
					   	  args[0]=index;
					   	  memset(&tftp_sessions[index],0,sizeof(tftp_session_t));
						  strncpy(tftp_sessions[index].filename,p_pkta->filename,sizeof(tftp_sessions[index].filename));
						  tftp_sessions[index].client_add = s_addr;
						  tftp_sessions[index].status = 1;
						  option_negotiation(pkt_buf,p_pkta,index);
						  task_id = sys_task_spawn("TSK3", 128, 0, 336096, (FUNCPTR)wrq_packet, args, 0);
						  if (task_id == (TASK_ID)SYS_ERROR)
		                       Print("Failed to create task\n");
					}
					else
					{
						strcpy(error_message,"ACCESS_VIOLATION");
						send_error_message(sock_fd,s_addr,ACCESS_VIOLATION,error_message);
					}
					
				}
				break;
			case ENABLE_MESSAGE: 
			    if(enable_flag == 1)
			    {
			    	 disable_flag = 0;
			    	 disable_check = 0;
			    	 if(enable_check == 0)
			    	 {
			    	 	enable_check = 1;
			    	 	sock_fd = so_socket(AF_INET, SOCK_DGRAM, 0);
	                    if (sock_fd < 0)
	                    {
		                    Print("ERROR CREATING SOCKET\n");
	                    }
	
	                     memset(&s_addr, 0, sizeof(s_addr));
	                     s_addr.sin_family = AF_INET;
	                     s_addr.sin_port = htons(UDP_PORT);

                         rv = so_bind(sock_fd, (struct soaddr *)&s_addr, sizeof(s_addr));
	                     if ( rv < 0)
	                     {
		                      Print("BINDING FAILLLLLLLL\n");
	                     }
	
	                     if(socket_register(sock_fd, (ULONG) msgq_id, 0) != 0)
	                     {
		                      Print("REGISTER FAIL\n");
	                      }
	                      
					   }
					   else if(enable_check == 1)
					   {
					   	   vty_output("ALREADY_ENABLED\n");
					   	   continue;
					   }     
			    }
				break;
			case DISABLE_MESSAGE:
				if(disable_flag == 1)
				{
					if(disable_check == 0)
					{
						disable_check = 1;
						enable_flag = 0;
				        enable_check = 0;
				        so_close(sock_fd);
					}
					else
					{
						vty_output("ALREADY_DISABLED\n");
					   	continue;
					}
				}
				break;
			case PORT_REQUEST:
				so_close(sock_fd);
				sock_fd = so_socket(AF_INET, SOCK_DGRAM, 0);
	            if (sock_fd < 0)
	            {
		            Print("ERROR CREATING SOCKET\n");
	            }
	
	            memset(&s_addr, 0, sizeof(s_addr));
	            s_addr.sin_family = AF_INET;
	            s_addr.sin_port = htons(msg.count);

                rv = so_bind(sock_fd, (struct soaddr *)&s_addr, sizeof(s_addr));
	            if ( rv < 0)
	            {
		            Print("BINDING FAILLLLLLLL\n");
	            }
	
	            if(socket_register(sock_fd, (ULONG) msgq_id, 0) != 0)
	            {
		            Print("REGISTER FAIL\n");
	            }
				break;
			default:
				break;
		}
	}
	
}
