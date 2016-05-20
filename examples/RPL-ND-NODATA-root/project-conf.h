/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
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
 */

#ifndef PROJECT_ROUTER_CONF_H_
#define PROJECT_ROUTER_CONF_H_

#ifndef UIP_FALLBACK_INTERFACE
#define UIP_FALLBACK_INTERFACE rpl_interface
#endif

#ifndef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM          4
#endif

#ifndef UIP_CONF_BUFFER_SIZE
#define UIP_CONF_BUFFER_SIZE    140
#endif

#ifndef UIP_CONF_RECEIVE_WINDOW
#define UIP_CONF_RECEIVE_WINDOW  60
#endif

#ifndef WEBSERVER_CONF_CFS_CONNS
#define WEBSERVER_CONF_CFS_CONNS 2
#endif

#define UIP_ND6_CONF_ENGINE	UIP_ND6_ENGINE_RPL
#define UIP_ND6_ENGINE UIP_ND6_CONF_ENGINE



#define NETSTACK_CONF_WITH_IPV6		1
#undef NETSTACK_CONF_WITH_IPV6_RPL
#define NETSTACK_CONF_WITH_IPV6_RPL               1
#define UIP_CONF_IPV6_RPL               1
#define UIP_CONF_ROUTER                 1
#define UIP_CONF_GW			1
#define UIP_CONF_ND6_SEND_RA		0
#define UIP_ND6_SEND_RA UIP_CONF_ND6_SEND_RA
#define UIP_CONF_ND6_SEND_RA_PERIODIC   0
#define UIP_ND6_SEND_RA_PERIODIC UIP_CONF_ND6_SEND_RA_PERIODIC 
#define UIP_CONF_ND6_SEND_NA		0
#define UIP_ND6_SEND_NA UIP_CONF_ND6_SEND_NA

#define UIP_CONF_DS6_LL_NUD 1
#undef UIP_DS6_LL_NUD
#define UIP_DS6_LL_NUD UIP_CONF_DS6_LL_NUD

#define UIP_CONF_IPV6_CHECKS	1


#undef UIP_CONF_TCP
#define UIP_CONF_TCP 0

#endif /* PROJECT_ROUTER_CONF_H_ */
