/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         A very simple Contiki application showing how Contiki programs look
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "contiki.h"
#include "net/ip/uip.h"
#include "net/ip/tcpip.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/rpl/rpl.h"
#include "sys/node-id.h"
#include "net/netstack.h"
#include "dev/button-sensor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>






#define DEBUG 0
#include "net/ip/uip-debug.h"



#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])


#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#ifndef SEND_INTERVAL
#define SEND_INTERVAL (20 * CLOCK_SECOND)


#endif

#define MAX_PAYLOAD_LEN 60



static uip_ipaddr_t prefix; 
/*---------------------------------------------------------------------------*/
void
set_prefix_64(uip_ipaddr_t *prefix_64)
{
  rpl_dag_t *dag;
  uip_ipaddr_t ipaddr;
  memcpy(&prefix, prefix_64, 16);
  memcpy(&ipaddr, prefix_64, 16);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  dag = rpl_set_root(RPL_DEFAULT_INSTANCE, &ipaddr);
  if(dag != NULL) {
    rpl_set_prefix(dag, &prefix, 64);
//    printf("created a new RPL dag\n");
  }
}

/*---------------------------------------------------------------------------*/


static uint8_t PREFIX[8] = {0x20, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00};

static struct uip_udp_conn *client_conn[5];
static uip_ipaddr_t server_ipaddr[5];

uint16_t backoff_time[] = {50, 150, 250, 350, 450};
uint8_t serverindex[] = {0, 1, 2, 3, 4};

static int seq_id = 0;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *str;
  
  if(uip_newdata()){
     str = uip_appdata;
     str[uip_datalen()] = '\0';
     PRINTF("DATA recv '%s'\n", str);
  }
}
/*---------------------------------------------------------------------------*/
static void
send_packet(void *ptr)
{
  
  char buf[MAX_PAYLOAD_LEN];

  uint8_t serverindex = *((uint8_t *)ptr);
  
  PRINTF("DATA send to %d 'Hello %d'\n",
	 server_ipaddr[serverindex].u8[sizeof(server_ipaddr[serverindex].u8) - 1], seq_id);
  sprintf(buf, "Hello %d from the client %u", seq_id, node_id);
  uip_udp_packet_sendto(client_conn[serverindex], buf, strlen(buf),
	                &server_ipaddr[serverindex], UIP_HTONS(UDP_SERVER_PORT));

}
/*---------------------------------------------------------------------------*/
static void
set_global_address(void)
{
  
  #if 0
  /* Mode 1 - 64 bits inline */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
  #elif 1
  /* Mode 2 - 16 bits inline */
  uip_ip6addr(server_ipaddr, 0x2001, 5, 0, 0, 0x200, 0, 0, 2);
  uip_ip6addr(server_ipaddr + 1, 0x2001, 5, 0, 0, 0x200, 0, 0, 3);
  uip_ip6addr(server_ipaddr + 2, 0x2001, 5, 0, 0, 0x200, 0, 0, 4);
  uip_ip6addr(server_ipaddr + 3, 0x2001, 5, 0, 0, 0x200, 0, 0, 5);
  uip_ip6addr(server_ipaddr + 4, 0x2001, 5, 0, 0, 0x200, 0, 0, 6);
  #else
  /* Mode 3 - derived from server link-local (MAC) address */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0250, 0xc2ff, 0xfea8, 0xcd1a); //redbee-econotag
  #endif

}

static uip_ipaddr_t prefix_64; 
static uint8_t conn_index;
uint8_t i;
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic;
  static struct ctimer backoff_timer[5];

  
  random_init(node_id);
  //powertrace_start(CLOCK_SECOND * 2); 
 
  memset(&prefix_64, 0, 16);
  memcpy(&prefix_64, PREFIX, 8);
  set_prefix_64(&prefix_64);
  
  set_global_address();
 
  /*create new connection with remote server*/
  for(conn_index = 0; conn_index < 5; conn_index++){
	  client_conn[conn_index] = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL);
	  if(client_conn[conn_index] == NULL) {
	    PRINTF("No UDP connection available, exiting the process!\n");
	    PROCESS_EXIT();
	  }
	  udp_bind(client_conn[conn_index], UIP_HTONS(UDP_CLIENT_PORT));
	  PRINTF("Created a connection with the server ");
	  PRINT6ADDR(&(client_conn[conn_index]->ripaddr));
	  PRINTF(" local/remote port %u/%u \n",
	  UIP_HTONS(client_conn[conn_index]->lport),UIP_HTONS(client_conn[conn_index]->rport));
}

   PROCESS_BEGIN(); 
    
  PRINTF("UDP client process started\n");

   etimer_set(&periodic, SEND_INTERVAL);
   while(1) {
	PROCESS_YIELD();
        if(ev == tcpip_event) {
           tcpip_handler();
         }
       
        if(etimer_expired(&periodic)){
	   etimer_reset(&periodic);
	   seq_id ++;
            for(i = 0; i < 5; i++){
                ctimer_set(&backoff_timer[i], backoff_time[i], send_packet, (void *)&serverindex[i]);
	    }
         }
   }
  
  PROCESS_END();
}

