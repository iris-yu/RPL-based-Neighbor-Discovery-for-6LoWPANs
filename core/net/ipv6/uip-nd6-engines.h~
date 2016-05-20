/*
 * Copyright (c) 2011, Loughborough University - Computer Science
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
 */

/**
 * \file
 *         Header file with definition of multicast engine constants
 *
 *         When writing a new engine, add it here with a unique number and
 *         then modify uip-mcast6.h accordingly
 *
 * \author
 *         George Oikonomou - <oikonomou@users.sourceforge.net>
 */

#ifndef UIP_ND6_ENGINES_H_
#define UIP_ND6_ENGINES_H_


#define UIP_ND6_ENGINE_IPv6        0 
#define UIP_ND6_ENGINE_6Lo         1
#define UIP_ND6_ENGINE_RPL     	   2

#ifdef UIP_ND6_CONF_ENGINE
#define UIP_ND6_ENGINE UIP_ND6_CONF_ENGINE
#else
#define UIP_ND6_ENGINE UIP_ND6_ENGINE_IPv6
#endif



/** \Some common constants needed for all the three Neighbor Discovery Mechanism */
/** \name constant for RS or NS solicitations */
/** @{ */
#define UIP_ND6_MAX_RTR_SOLICITATION_DELAY 1
#define UIP_ND6_RTR_SOLICITATION_INTERVAL  5
#define UIP_ND6_MAX_RTR_SOLICITATION_INTERVAL  60
#define UIP_ND6_MAX_RTR_SOLICITATIONS	   5



#ifndef UIP_CONF_ND6_DEF_MAXDADNS
/** \brief Do not try DAD when using EUI-64 as allowed by draft-ietf-6lowpan-nd-15 section 8.2 */
#if UIP_CONF_LL_802154
#define UIP_ND6_DEF_MAXDADNS 0
#else /* UIP_CONF_LL_802154 */
#define UIP_ND6_DEF_MAXDADNS UIP_ND6_SEND_NA
#endif /* UIP_CONF_LL_802154 */
#else /* UIP_CONF_ND6_DEF_MAXDADNS */
#define UIP_ND6_DEF_MAXDADNS UIP_CONF_ND6_DEF_MAXDADNS
#endif /* UIP_CONF_ND6_DEF_MAXDADNS */




#undef UIP_ND6_REACHABLE_TIME
#define UIP_ND6_REACHABLE_TIME         30000

#undef UIP_ND6_RETRANS_TIMER
#define UIP_ND6_RETRANS_TIMER	       1000

#undef UIP_ND6_NS_REG_TIMER
#define UIP_ND6_NS_REG_TIMER	       5


#define UIP_ND6_DELAY_FIRST_PROBE_TIME 5
#define UIP_ND6_MIN_RANDOM_FACTOR(x)   (x / 2)
#define UIP_ND6_MAX_RANDOM_FACTOR(x)   ((x) + (x) / 2)


/** @} */


#endif /* UIP_ND6_ENGINES_H_ */
