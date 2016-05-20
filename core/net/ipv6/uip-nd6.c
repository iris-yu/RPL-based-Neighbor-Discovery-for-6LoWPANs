/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
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

/**
 * \addtogroup uip6
 * @{
 */

/**
 * \file
 *    Neighbor discovery (RFC 4861)
 * \author Mathilde Durvy <mdurvy@cisco.com>
 * \author Julien Abeille <jabeille@cisco.com>
 */

#include <string.h>
#include "net/ipv6/uip-icmp6.h"
#include "net/ipv6/uip-nd6.h"
#include "net/ipv6/uip-ds6.h"
#if UIP_ND6_RA_RDNSS
#include "net/ip/uip-nameserver.h"
#endif
#include "lib/random.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/ipv6/uip-ds6-route.h"

/*------------------------------------------------------------------*/
#define DEBUG 0
#include "net/ip/uip-debug.h"

#if UIP_LOGGING
#include <stdio.h>
void uip_log(char *msg);

#define UIP_LOG(m) uip_log(m)
#else
#define UIP_LOG(m)
#endif /* UIP_LOGGING == 1 */

#define PRINT6LLADDR(lladdr) PRINTF(" %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",lladdr->u8[0], lladdr->u8[1], lladdr->u8[2], lladdr->u8[3],lladdr->u8[4], lladdr->u8[5],lladdr->u8[6],lladdr->u8[7])

#define PRINT6UIPLLADDR(lladdr) PRINTF(" %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",lladdr.addr[0], lladdr.addr[1], lladdr.addr[2], lladdr.addr[3],lladdr.addr[4], lladdr.addr[5],lladdr.addr[6],lladdr.addr[7])

/*------------------------------------------------------------------*/
/** @{ */
/** \name Pointers to the header structures.
 *  All pointers except UIP_IP_BUF depend on uip_ext_len, which at
 *  packet reception, is the total length of the extension headers.
 *  
 *  The pointer to ND6 options header also depends on nd6_opt_offset,
 *  which we set in each function.
 *
 *  Care should be taken when manipulating these buffers about the
 *  value of these length variables
 */

#define UIP_IP_BUF                ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])  /**< Pointer to IP header */
#define UIP_ICMP_BUF            ((struct uip_icmp_hdr *)&uip_buf[uip_l2_l3_hdr_len])  /**< Pointer to ICMP header*/
/**@{  Pointers to messages just after icmp header */
#define UIP_ND6_RS_BUF            ((uip_nd6_rs *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_ND6_RA_BUF            ((uip_nd6_ra *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_ND6_NS_BUF            ((uip_nd6_ns *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_ND6_NA_BUF            ((uip_nd6_na *)&uip_buf[uip_l2_l3_icmp_hdr_len])
/** @} */
/** Pointer to ND option */
#define UIP_ND6_OPT_HDR_BUF  ((uip_nd6_opt_hdr *)&uip_buf[uip_l2_l3_icmp_hdr_len + nd6_opt_offset])
#define UIP_ND6_OPT_PREFIX_BUF ((uip_nd6_opt_prefix_info *)&uip_buf[uip_l2_l3_icmp_hdr_len + nd6_opt_offset])
#define UIP_ND6_OPT_MTU_BUF ((uip_nd6_opt_mtu *)&uip_buf[uip_l2_l3_icmp_hdr_len + nd6_opt_offset])
#define UIP_ND6_OPT_RDNSS_BUF ((uip_nd6_opt_dns *)&uip_buf[uip_l2_l3_icmp_hdr_len + nd6_opt_offset])
/** @} */

static uint8_t nd6_opt_offset;                     /** Offset from the end of the icmpv6 header to the option in uip_buf*/
static uint8_t *nd6_opt_llao;   /**  Pointer to llao option in uip_buf */
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
static uip_nd6_opt_aro *nd6_opt_aro;   /**  Pointer to aro option in uip_buf */
#endif

//#if !UIP_CONF_ROUTER            // TBD see if we move it to ra_input
static uip_nd6_opt_prefix_info *nd6_opt_prefix_info; /**  Pointer to prefix information option in uip_buf */
static uip_ipaddr_t ipaddr;
static uip_ds6_prefix_t *prefix; /**  Pointer to a prefix list entry */
//#endif
static uip_ds6_nbr_t *nbr; /**  Pointer to a nbr cache entry*/
static uip_ds6_defrt_t *defrt; /**  Pointer to a router list entry */
static uip_ds6_addr_t *addr; /**  Pointer to an interface address */
/*------------------------------------------------------------------*/

/*------------------------------------------------------------------*/
/* create a llao */ 
static void
create_llao(uint8_t *llao, uint8_t type) {
  llao[UIP_ND6_OPT_TYPE_OFFSET] = type;
  llao[UIP_ND6_OPT_LEN_OFFSET] = UIP_ND6_OPT_LLAO_LEN >> 3;
  memcpy(&llao[UIP_ND6_OPT_DATA_OFFSET], &uip_lladdr, UIP_LLADDR_LEN);
  /* padding on some */
  memset(&llao[UIP_ND6_OPT_DATA_OFFSET + UIP_LLADDR_LEN], 0,
         UIP_ND6_OPT_LLAO_LEN - 2 - UIP_LLADDR_LEN);
}

#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
/* create an aro */ 
static void
create_aro(uint8_t* aro, uint16_t lifetime) {
  ((uip_nd6_opt_aro*)aro)->type = UIP_ND6_OPT_ARO;
  ((uip_nd6_opt_aro*)aro)->len = UIP_ND6_OPT_ARO_LEN >> 3;
    ((uip_nd6_opt_aro*)aro)->status = (uint8_t)0; /* Status: must be set to 0 in NS */
    ((uip_nd6_opt_aro*)aro)->lifetime = uip_htons(lifetime);
  memcpy(&(((uip_nd6_opt_aro*)aro)->eui64), &uip_lladdr, UIP_LLADDR_LEN);
}
#endif


/*------------------------------------------------------------------*/

#if UIP_ND6_SEND_NA

static void
ns_input(void)
{
  uip_ds6_nbr_t *reg_neighbor;
  linkaddr_t *linkaddr;
  uint8_t flags;
  PRINTF("Received NS from ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" to ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" with target address");
  PRINT6ADDR((uip_ipaddr_t *) (&UIP_ND6_NS_BUF->tgtipaddr));
  PRINTF("\n");
  UIP_STAT(++uip_stat.nd6.recv);

#if UIP_CONF_IPV6_CHECKS
  if((UIP_IP_BUF->ttl != UIP_ND6_HOP_LIMIT) ||
     (uip_is_addr_mcast(&UIP_ND6_NS_BUF->tgtipaddr)) ||
     (UIP_ICMP_BUF->icode != 0)) {
    PRINTF("NS received is bad\n");
    goto discard;
  }
#endif /* UIP_CONF_IPV6_CHECKS */

  /* Options processing */
  nd6_opt_llao = NULL;
  #if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
  nd6_opt_aro = NULL;
  #endif 
  nd6_opt_offset = UIP_ND6_NS_LEN;
  while(uip_l3_icmp_hdr_len + nd6_opt_offset < uip_len) {
#if UIP_CONF_IPV6_CHECKS
    if(UIP_ND6_OPT_HDR_BUF->len == 0) {
      PRINTF("NS received is bad\n");
      goto discard;
    }
#endif /* UIP_CONF_IPV6_CHECKS */
    switch (UIP_ND6_OPT_HDR_BUF->type) {
    case UIP_ND6_OPT_SLLAO:
      nd6_opt_llao = &uip_buf[uip_l2_l3_icmp_hdr_len + nd6_opt_offset];
#if UIP_CONF_IPV6_CHECKS
      /* There must be NO option in a DAD NS */
      if(uip_is_addr_unspecified(&UIP_IP_BUF->srcipaddr)) {
        PRINTF("NS received is bad\n");
        goto discard;
      } 
	  else {
#endif /*UIP_CONF_IPV6_CHECKS */
        nbr = uip_ds6_nbr_lookup(&UIP_IP_BUF->srcipaddr);
        if(nbr == NULL) {
          uip_ds6_nbr_add(&UIP_IP_BUF->srcipaddr,
			  (uip_lladdr_t *)&nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET],
			  0, NBR_STALE);
        }
	#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_IPv6 
	else {
          uip_lladdr_t *lladdr = (uip_lladdr_t *)uip_ds6_nbr_get_ll(nbr);
          if(memcmp(&nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET],
		    lladdr, UIP_LLADDR_LEN) != 0) {
            memcpy(lladdr, &nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET],
		   UIP_LLADDR_LEN);
            nbr->state = NBR_STALE;
          } else {
            if(nbr->state == NBR_INCOMPLETE) {
              nbr->state = NBR_STALE;
            }
          }
        }
#endif
        //nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;
#if UIP_CONF_IPV6_CHECKS
      }
#endif /*UIP_CONF_IPV6_CHECKS */
      break;
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
	case UIP_ND6_OPT_ARO:
	
      	nd6_opt_aro = (uip_nd6_opt_aro*)&uip_buf[uip_l2_l3_icmp_hdr_len + nd6_opt_offset];
	PRINTF(" NS input with ARO address");
  	PRINT6UIPLLADDR(nd6_opt_aro->eui64);
 	PRINTF("\n");
	//nd6_opt_offset += UIP_ND6_OPT_ARO_LEN;
      break;
#endif	  
    default:
      PRINTF("ND option not supported in NS");
      break;
    }
    nd6_opt_offset += (UIP_ND6_OPT_HDR_BUF->len << 3);
  }
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_IPv6
  addr = uip_ds6_addr_lookup(&UIP_ND6_NS_BUF->tgtipaddr);
  if(addr != NULL) {
#if UIP_ND6_DEF_MAXDADNS > 0
    if(uip_is_addr_unspecified(&UIP_IP_BUF->srcipaddr)) {
      /* DAD CASE */
#if UIP_CONF_IPV6_CHECKS
      if(!uip_is_addr_solicited_node(&UIP_IP_BUF->destipaddr)) {
        PRINTF("NS received is bad\n");
        goto discard;
      }
#endif /* UIP_CONF_IPV6_CHECKS */
      if(addr->state != ADDR_TENTATIVE) {
        uip_create_linklocal_allnodes_mcast(&UIP_IP_BUF->destipaddr);
        uip_ds6_select_src(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr);
        flags = UIP_ND6_NA_FLAG_OVERRIDE;
        goto create_na;
      } else {
          /** \todo if I sent a NS before him, I win */
        uip_ds6_dad_failed(addr);
        goto discard;
      }
#else /* UIP_ND6_DEF_MAXDADNS > 0 */
    if(uip_is_addr_unspecified(&UIP_IP_BUF->srcipaddr)) {
      /* DAD CASE */
      goto discard;
#endif /* UIP_ND6_DEF_MAXDADNS > 0 */
    }
#if UIP_CONF_IPV6_CHECKS
    if(uip_ds6_is_my_addr(&UIP_IP_BUF->srcipaddr)) {
        /**
         * \NOTE do we do something here? we both are using the same address.
         * If we are doing dad, we could cancel it, though we should receive a
         * NA in response of DAD NS we sent, hence DAD will fail anyway. If we
         * were not doing DAD, it means there is a duplicate in the network!
         */
      PRINTF("NS received is bad\n");
      goto discard;
    }
#endif /*UIP_CONF_IPV6_CHECKS */

    /* Address resolution case */
    if(uip_is_addr_solicited_node(&UIP_IP_BUF->destipaddr)) {
      uip_ipaddr_copy(&UIP_IP_BUF->destipaddr, &UIP_IP_BUF->srcipaddr);
      uip_ipaddr_copy(&UIP_IP_BUF->srcipaddr, &UIP_ND6_NS_BUF->tgtipaddr);
      flags = UIP_ND6_NA_FLAG_SOLICITED | UIP_ND6_NA_FLAG_OVERRIDE;
      goto create_na;
    }

    /* NUD CASE */
    if(uip_ds6_addr_lookup(&UIP_IP_BUF->destipaddr) == addr) {
      uip_ipaddr_copy(&UIP_IP_BUF->destipaddr, &UIP_IP_BUF->srcipaddr);
      uip_ipaddr_copy(&UIP_IP_BUF->srcipaddr, &UIP_ND6_NS_BUF->tgtipaddr);
      flags = UIP_ND6_NA_FLAG_SOLICITED | UIP_ND6_NA_FLAG_OVERRIDE;
      goto create_na;
    } else {
#if UIP_CONF_IPV6_CHECKS
      PRINTF("NS received is bad\n");
      goto discard;
#endif /* UIP_CONF_IPV6_CHECKS */
    }
  } else {
    goto discard;
  }
#endif /* UIP_ND6_ENGINE_IPv6 */
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
  	if ((uip_is_addr_unspecified(&UIP_IP_BUF->srcipaddr)) || (nd6_opt_llao == NULL)) {
  		nd6_opt_aro = NULL;
  	}
  	if ((nd6_opt_aro != NULL) && ((nd6_opt_aro->len != 2) || (nd6_opt_aro->status != ARO_STATUS_SUCCESS))) {
  		/* BAD ARO */
  		goto discard;			
  	}
  	/* If there is no ARO option the packet has been sent for NUD and 
  	 * therefore it must be forwarded unchanged.
  	 */
  	if (nd6_opt_aro == NULL) {
		PRINTF("ARO received is NULL, forward this NA.\n");
  		goto forward;
  	}

	/* Check if the NCE exists */
	nbr = uip_ds6_nbr_lookup(&UIP_IP_BUF->srcipaddr);
    if(nbr == NULL) {
    	/* The NCE does not exist. Try to create it in TENTATIVE state. */
		reg_neighbor = uip_ds6_nbr_add(&UIP_IP_BUF->srcipaddr, (uip_lladdr_t *)&(nd6_opt_aro->eui64), 1, NBR_REACHABLE);
		if (reg_neighbor == NULL) {
				/* NC is full. We must respond a NA reporting the error */
		
       	uip_nd6_registration_error(ARO_STATUS_RTR_NC_FULL);
		} else {
				/* Registration succeeded. Set NCE's ARO-pending flag = 1 */
				//nbr->aro_pending = 1;
		stimer_set(&(reg_neighbor->reachable), uip_ntohs(nd6_opt_aro->lifetime)/1000); 
		reg_neighbor->state = NBR_REACHABLE;
		stimer_set(&reg_neighbor->sendns, UIP_ND6_NS_REG_TIMER);
		reg_neighbor->is_registered_with_state = REG_REGISTERED;	
		goto create_na;
		}
    } else { /* nbr != NULL */
     	/* 
       * The NCE exists. We have to check which case we are in:
       * - Duplicate
       * - Registration
       * - Re-registration (if NCE exists in REGISTERED state)
       */
	linkaddr = nbr_table_get_lladdr(ds6_neighbors, nbr);
	PRINTF(" Compare with the nbr lladdr in nbr cache:");
  	PRINT6LLADDR(linkaddr);
 	PRINTF("\n");
		
	if(memcmp(nd6_opt_aro->eui64.addr, linkaddr->u8, UIP_LLADDR_LEN) != 0) {
      	/* 
      	 * NCE exists with different EUI-64 (Duplicate). We must respond a NA 
      	 * reporting the error. In this case, we must not delete the NCE, since
      	 * it corresponds to another node. 
      	 */
			uip_nd6_registration_error(ARO_STATUS_DUPLICATE);
		} else { /* NCE exists with the same EUI-64 */
	    //nbr->aro_pending = 1;
			if(nbr->state != NBR_GARBAGE_COLLECTABLE) {
       		/* 
       		 * Re-registration. Refresh Lifetime, set ARO-pending flag = 1 and Forward NS to 
       		 * IEEE 802.3 segment to perform NUD of the router.
       		 * We set the timer now just in order to save the lifetime. However, we'll have 
	 	 * to restart it just before responding the NA in response 
	 	 */
				stimer_set(&(reg_neighbor->reachable), uip_ntohs(nd6_opt_aro->lifetime)/1000);        
				reg_neighbor->state = NBR_REACHABLE;
		                stimer_set(&reg_neighbor->sendns, UIP_ND6_NS_REG_TIMER);
				reg_neighbor->is_registered_with_state = REG_REGISTERED;	
				//nbr->aro_pending = 0;
				goto create_na;
			} else {
        	/* 
        	 * Either the NCE exists in GARBAGE-COLLECTIBLE state or there has been an 
        	 * error somewhere. Discard 
        	 */
				goto discard;
			}
      }
    }
#endif

return;

create_na:
#if UIP_ND6_ENGINE == UIP_UIP6_ENGINE_IPv6
    /* If the node is a router it should set R flag in NAs */
#if UIP_CONF_ROUTER
    flags = flags | UIP_ND6_NA_FLAG_ROUTER;
#endif
 PRINTF("Prepare to send NA from ");
 PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
 PRINTF(" to ");
 PRINT6ADDR(&UIP_IP_BUF->destipaddr);
 
   uip_nd6_create_na(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr, &UIP_IP_BUF->srcipaddr, flags);
	/* include TLLAO option */
  uip_nd6_append_icmp_opt(UIP_ND6_OPT_TLLAO, uip_lladdr.addr, 0, 0);
#endif
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
	uip_nd6_create_na(&UIP_IP_BUF->destipaddr, &UIP_IP_BUF->srcipaddr, NULL, UIP_ND6_NA_FLAG_ROUTER);
	/* include ARO option */
	uip_nd6_append_icmp_opt(UIP_ND6_OPT_ARO, &nd6_opt_aro->eui64, ARO_STATUS_SUCCESS, nd6_opt_aro->lifetime);
	/* Compute checksum */
#endif
  uip_nd6_update_icmp_checksum();
  UIP_STAT(++uip_stat.nd6.sent);
  PRINTF("Sending NA from ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" to ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF(" with target address ");
  PRINT6ADDR(&UIP_ND6_NA_BUF->tgtipaddr);
  PRINTF("\n");
  return;

discard:
  uip_len = 0;
  return;
forward:
  return;
}
#endif /* UIP_ND6_SEND_NA */


/*------------------------------------------------------------------*/
void
uip_nd6_ns_output(uip_ipaddr_t * src, uip_ipaddr_t * dest, uip_ipaddr_t * tgt)
{
  uip_ext_len = 0;
  UIP_IP_BUF->vtc = 0x60;
  UIP_IP_BUF->tcflow = 0;
  UIP_IP_BUF->flow = 0;
  UIP_IP_BUF->proto = UIP_PROTO_ICMP6;
  UIP_IP_BUF->ttl = UIP_ND6_HOP_LIMIT;
  
  UIP_ICMP_BUF->type = ICMP6_NS;
  UIP_ICMP_BUF->icode = 0;
  UIP_ND6_NS_BUF->reserved = 0;
  uip_ipaddr_copy((uip_ipaddr_t *) &UIP_ND6_NS_BUF->tgtipaddr, tgt);
  UIP_IP_BUF->len[0] = 0;       /* length will not be more than 255 */

  if(dest == NULL) {
    uip_create_solicited_node(tgt, &UIP_IP_BUF->destipaddr);
  } else {
    uip_ipaddr_copy(&UIP_IP_BUF->destipaddr, dest);
  }
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_IPv6  
   /*
   * check if we add a SLLAO option: for DAD, MUST NOT, for NUD, MAY
   * (here yes), for Address resolution , MUST 
   */
  if(!(uip_ds6_is_my_addr(tgt))) {
    if(src != NULL) {
      uip_ipaddr_copy(&UIP_IP_BUF->srcipaddr, src);
    } else {
      uip_ds6_select_src(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr);
    }
    if (uip_is_addr_unspecified(&UIP_IP_BUF->srcipaddr)) {
      PRINTF("Dropping NS due to no suitable source address\n");
      uip_len = 0;
      return;
    }
	UIP_IP_BUF->len[1] =
      UIP_ICMPH_LEN + UIP_ND6_NS_LEN + UIP_ND6_OPT_LLAO_LEN;
	  create_llao(&uip_buf[uip_l2_l3_icmp_hdr_len + UIP_ND6_NS_LEN], UIP_ND6_OPT_SLLAO);
	
    uip_len =
      UIP_IPH_LEN + UIP_ICMPH_LEN + UIP_ND6_NS_LEN + UIP_ND6_OPT_LLAO_LEN;
  } else {
    uip_create_unspecified(&UIP_IP_BUF->srcipaddr);
    UIP_IP_BUF->len[1] = UIP_ICMPH_LEN + UIP_ND6_NS_LEN;
    uip_len = UIP_IPH_LEN + UIP_ICMPH_LEN + UIP_ND6_NS_LEN;
  }
#endif   

#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
  if(src != NULL) {
      uip_ipaddr_copy(&UIP_IP_BUF->srcipaddr, src);
    } else {
      uip_ds6_select_src(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr);
    }
	create_llao(&uip_buf[uip_l2_l3_icmp_hdr_len + UIP_ND6_NS_LEN], UIP_ND6_OPT_SLLAO);
	create_aro(&uip_buf[uip_l2_l3_icmp_hdr_len + UIP_ND6_NS_LEN + UIP_ND6_OPT_LLAO_LEN],
                uip_ds6_if.reachable_time);
	nd6_opt_aro = (uip_nd6_opt_aro*)&uip_buf[uip_l2_l3_icmp_hdr_len + UIP_ND6_NS_LEN + UIP_ND6_OPT_LLAO_LEN];
	PRINTF(" NS output with ARO address");
  	PRINT6UIPLLADDR(nd6_opt_aro->eui64);
 	PRINTF("\n");
	
    UIP_IP_BUF->len[1] =
      UIP_ICMPH_LEN + UIP_ND6_NS_LEN + UIP_ND6_OPT_LLAO_LEN + UIP_ND6_OPT_ARO_LEN;
    uip_len =
          UIP_IPH_LEN + UIP_ICMPH_LEN + UIP_ND6_NS_LEN + UIP_ND6_OPT_LLAO_LEN + UIP_ND6_OPT_ARO_LEN;
#endif

	uip_nd6_update_icmp_checksum();

  UIP_STAT(++uip_stat.nd6.sent);
  PRINTF("Sending NS to");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("from");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("with target address");
  PRINT6ADDR(tgt);
  PRINTF("\n");
  return;
}
#if UIP_ND6_SEND_NA
/*------------------------------------------------------------------*/
/**
 * Neighbor Advertisement Processing
 *
 * we might have to send a pkt that had been buffered while address
 * resolution was performed (if we support buffering, see UIP_CONF_QUEUE_PKT)
 *
 * As per RFC 4861, on link layer that have addresses, TLLAO options MUST be
 * included when responding to multicast solicitations, SHOULD be included in
 * response to unicast (here we assume it is for now)
 *
 * NA can be received after sending NS for DAD, Address resolution or NUD. Can
 * be unsolicited as well.
 * It can trigger update of the state of the neighbor in the neighbor cache,
 * router in the router list.
 * If the NS was for DAD, it means DAD failed
 *
 */
static void
na_input(void)
{
  uint8_t is_llchange;
  uint8_t is_router;
  uint8_t is_solicited;
  uint8_t is_override;

  PRINTF("Received NA from");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("to");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("with target address");
  PRINT6ADDR((uip_ipaddr_t *) (&UIP_ND6_NA_BUF->tgtipaddr));
  PRINTF("\n");
  UIP_STAT(++uip_stat.nd6.recv);

  /* 
   * booleans. the three last one are not 0 or 1 but 0 or 0x80, 0x40, 0x20
   * but it works. Be careful though, do not use tests such as is_router == 1 
   */
  is_llchange = 0;
  is_router = ((UIP_ND6_NA_BUF->flagsreserved & UIP_ND6_NA_FLAG_ROUTER));
  is_solicited =
    ((UIP_ND6_NA_BUF->flagsreserved & UIP_ND6_NA_FLAG_SOLICITED));
  is_override =
    ((UIP_ND6_NA_BUF->flagsreserved & UIP_ND6_NA_FLAG_OVERRIDE));

#if UIP_CONF_IPV6_CHECKS
  if((UIP_IP_BUF->ttl != UIP_ND6_HOP_LIMIT) ||
     (UIP_ICMP_BUF->icode != 0) ||
     (uip_is_addr_mcast(&UIP_ND6_NA_BUF->tgtipaddr)) ||
     (is_solicited && uip_is_addr_mcast(&UIP_IP_BUF->destipaddr))) {
    PRINTF("NA received is bad\n");
    goto discard;
  }
#endif /*UIP_CONF_IPV6_CHECKS */

  /* Options processing: we handle TLLAO, and must ignore others */
  nd6_opt_offset = UIP_ND6_NA_LEN;
  nd6_opt_llao = NULL;
  while(uip_l3_icmp_hdr_len + nd6_opt_offset < uip_len) {
#if UIP_CONF_IPV6_CHECKS
    if(UIP_ND6_OPT_HDR_BUF->len == 0) {
      PRINTF("NA received is bad\n");
      goto discard;
    }
#endif /*UIP_CONF_IPV6_CHECKS */
    switch (UIP_ND6_OPT_HDR_BUF->type) {
    case UIP_ND6_OPT_TLLAO:
      nd6_opt_llao = (uint8_t *)UIP_ND6_OPT_HDR_BUF;
      break;
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
    case UIP_ND6_OPT_ARO:
      nd6_opt_aro = (uip_nd6_opt_aro *)UIP_ND6_OPT_HDR_BUF;
	PRINTF(" NA input with ARO address");
  	PRINT6UIPLLADDR(nd6_opt_aro->eui64);
 	PRINTF("\n");
#if UIP_CONF_IPV6_CHECKS
      if((nd6_opt_aro->len != 2) ||
          (memcmp(nd6_opt_aro->eui64.addr, uip_lladdr.addr, UIP_LLADDR_LEN) != 0)) {
        /* ignore this option */
        nd6_opt_aro = NULL;
      }
#endif /* UIP_CONF_IPV6_CHECKS */
      break;
#endif /* UIP_ND6_ENGINE_6Lo */
    default:
      PRINTF("ND option not supported in NA\n");
      break;
    }
    nd6_opt_offset += (UIP_ND6_OPT_HDR_BUF->len << 3);
  }
  addr = uip_ds6_addr_lookup(&UIP_ND6_NA_BUF->tgtipaddr);
  #if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo 
   nbr = uip_ds6_nbr_lookup(&UIP_IP_BUF->srcipaddr);
	if(nd6_opt_aro != NULL && nbr->state != NBR_GARBAGE_COLLECTABLE) {
          if ((nd6_opt_aro->lifetime == 0) && (nbr->is_register_to_state == REG_TO_BE_UNREGISTERED)) {
            /* If the lifetime is 0, this means that the unregistration was successful;
             * we can delete the registration entry safely */
            uip_ds6_nbr_rm(nbr); 
			nbr->is_register_to_state = 0;
			nbr->state = 0;/* Remove entry */
			nbr->nscount = 0;
          } else {
            switch(nd6_opt_aro->status) {
            case ARO_STATUS_SUCCESS:
              /* Make sure this is actually the address we are registerig */
              /* Clear the NS count */
                nbr->state = NBR_REACHABLE;
                nbr->is_register_to_state = REG_REGISTERED;
		PRINTF("Set nbr's state as REG_REGISTERED\n");
                nbr->nscount = 0;
                stimer_set(&nbr->reachable, uip_ntohs(nd6_opt_aro->lifetime) /1000);
		stimer_set(&nbr->sendns, UIP_ND6_NS_REG_TIMER);
		defrt = uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr);
    		if(defrt != NULL)
    			  stimer_reset(&(defrt->lifetime));          
	       break;
            case ARO_STATUS_DUPLICATE:
              /* Remove the address */
              uip_ds6_addr_rm(addr);
              /* Clear registration_in_progress so that other registrations can occur */
              break;
            case ARO_STATUS_RTR_NC_FULL:
               /* Remove entry. uip_periodic will try with other def. router
                * if possible */
			uip_ds6_nbr_rm(nbr); 
			nbr->is_register_to_state = 0;
			nbr->state = 0;/* Remove entry */
			nbr->nscount = 0;
              break;
            default:
              break;
            }
          }
      }
 
 #endif
 #if UIP_ND6_ENGINE == UIP_ND6_ENGINE_IPv6 
  /* Message processing, including TLLAO if any */
  if(addr != NULL) {
#if UIP_ND6_DEF_MAXDADNS > 0
    if(addr->state == ADDR_TENTATIVE) {
      uip_ds6_dad_failed(addr);
    }
#endif /*UIP_ND6_DEF_MAXDADNS > 0 */
    PRINTF("NA received is bad\n");
    goto discard;
 } else {
    uip_lladdr_t *lladdr;
    nbr = uip_ds6_nbr_lookup(&UIP_ND6_NA_BUF->tgtipaddr);
    lladdr = (uip_lladdr_t *)uip_ds6_nbr_get_ll(nbr);
    if(nbr == NULL) {
     PRINTF("NA received-discard 1 because we do not have such a neighbor.\n");
      goto discard;
    }

    if(nd6_opt_llao != 0) {
      is_llchange =
        memcmp(&nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET], (void *)lladdr,
               UIP_LLADDR_LEN);
    }
    if(nbr->state == NBR_INCOMPLETE) {
	PRINTF("NA received-if nbr's state is INCOMPLETE.\n");
      if(nd6_opt_llao == NULL) {
    PRINTF("NA received-discard 2 because the link layer address option is NULL.\n");
        goto discard;
      }
      memcpy(lladdr, &nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET],
	     UIP_LLADDR_LEN);
      if(is_solicited) {
       PRINTF("NA received is correct, we now set this neighbor's state as REACHABLE!\n");
        nbr->state = NBR_REACHABLE;
        nbr->nscount = 0;

        /* reachable time is stored in ms */
        stimer_set(&(nbr->reachable), uip_ds6_if.reachable_time / 1000);

      } else {
	PRINTF("This is not a solicitated NA!\n");
        nbr->state = NBR_STALE;
      }
      nbr->isrouter = is_router;
    } else {
	PRINTF("NA received-if nbr's state is not INCOMPLETE.\n");
      if(!is_override && is_llchange) {
        if(nbr->state == NBR_REACHABLE) {
          nbr->state = NBR_STALE;
        }
       PRINTF("NA received-discard 3:the nbr's lladdr changed so from REACHABLE to STALE.\n");
        goto discard;
      } else {
        if(is_override || (!is_override && nd6_opt_llao != 0 && !is_llchange)
           || nd6_opt_llao == 0) {
          if(nd6_opt_llao != 0) {
            memcpy(lladdr, &nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET],
		   UIP_LLADDR_LEN);
          }
          if(is_solicited) {
	PRINTF("NA received is correct, we now set this neighbor's state as REACHABLE!\n");
            nbr->state = NBR_REACHABLE;
            /* reachable time is stored in ms */
            stimer_set(&(nbr->reachable), uip_ds6_if.reachable_time / 1000);
          } else {
            if(nd6_opt_llao != 0 && is_llchange) {
              nbr->state = NBR_STALE;
            }
          }
        }
      }
      if(nbr->isrouter && !is_router) {
        defrt = uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr);
        if(defrt != NULL) {
          uip_ds6_defrt_rm(defrt);
        }
      }
      nbr->isrouter = is_router;
    }
  }
#endif
#if UIP_CONF_IPV6_QUEUE_PKT
  /* The nbr is now reachable, check if we had buffered a pkt for it */
  /*if(nbr->queue_buf_len != 0) {
    uip_len = nbr->queue_buf_len;
    memcpy(UIP_IP_BUF, nbr->queue_buf, uip_len);
    nbr->queue_buf_len = 0;
    return;
    }*/
  if(uip_packetqueue_buflen(&nbr->packethandle) != 0) {
    uip_len = uip_packetqueue_buflen(&nbr->packethandle);
    memcpy(UIP_IP_BUF, uip_packetqueue_buf(&nbr->packethandle), uip_len);
    uip_packetqueue_free(&nbr->packethandle);
    return;
  }
  
#endif /*UIP_CONF_IPV6_QUEUE_PKT */

discard:
  uip_len = 0;
  return;
}
#endif /* UIP_ND6_SEND_NA */

#if UIP_CONF_ROUTER
#if UIP_ND6_SEND_RA
/*---------------------------------------------------------------------------*/
static void
rs_input(void)
{

  PRINTF("Received RS from");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("to");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("\n");
  UIP_STAT(++uip_stat.nd6.recv);


#if UIP_CONF_IPV6_CHECKS
  /*
   * Check hop limit / icmp code 
   * target address must not be multicast
   * if the NA is solicited, dest must not be multicast
   */
  if((UIP_IP_BUF->ttl != UIP_ND6_HOP_LIMIT) || (UIP_ICMP_BUF->icode != 0)) {
    PRINTF("RS received is bad\n");
    goto discard;
  }
#endif /*UIP_CONF_IPV6_CHECKS */

  /* Only valid option is Source Link-Layer Address option any thing
     else is discarded */
  nd6_opt_offset = UIP_ND6_RS_LEN;
  nd6_opt_llao = NULL;

  while(uip_l3_icmp_hdr_len + nd6_opt_offset < uip_len) {
#if UIP_CONF_IPV6_CHECKS
    if(UIP_ND6_OPT_HDR_BUF->len == 0) {
      PRINTF("RS received is bad\n");
      goto discard;
    }
#endif /*UIP_CONF_IPV6_CHECKS */
    switch (UIP_ND6_OPT_HDR_BUF->type) {
    case UIP_ND6_OPT_SLLAO:
      nd6_opt_llao = (uint8_t *)UIP_ND6_OPT_HDR_BUF;
      break;
    default:
      PRINTF("ND option not supported in RS\n");
      break;
    }
    nd6_opt_offset += (UIP_ND6_OPT_HDR_BUF->len << 3);
  }
  /* Options processing: only SLLAO */
  if(nd6_opt_llao != NULL) {
#if UIP_CONF_IPV6_CHECKS
    if(uip_is_addr_unspecified(&UIP_IP_BUF->srcipaddr)) {
      PRINTF("RS received is bad\n");
      goto discard;
    } else {
#endif /*UIP_CONF_IPV6_CHECKS */
      if((nbr = uip_ds6_nbr_lookup(&UIP_IP_BUF->srcipaddr)) == NULL) {
        /* we need to add the neighbor */
        nbr = uip_ds6_nbr_add(&UIP_IP_BUF->srcipaddr,
                        (uip_lladdr_t *)&nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET], 0, NBR_STALE);
	#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
	stimer_set(&(nbr->reachable), 0); 
	stimer_set(&nbr->sendns, 0);
	nbr->is_register_to_state = 0;
	nbr->nscount = 0;
	#endif
      } else {
        /* If LL address changed, set neighbor state to stale */
        if(memcmp(&nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET],
            uip_ds6_nbr_get_ll(nbr), UIP_LLADDR_LEN) != 0) {
          //uip_ds6_nbr_t nbr_data = *nbr;
	uip_ds6_nbr_t nbr_data;
	memcpy(&nbr_data, nbr, sizeof(uip_ds6_nbr_t));
          uip_ds6_nbr_rm(nbr);
          nbr = uip_ds6_nbr_add(&UIP_IP_BUF->srcipaddr,
                                (uip_lladdr_t *)&nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET], 0, NBR_STALE);
        }
        nbr->isrouter = 0;
      }
#if UIP_CONF_IPV6_CHECKS
    }
#endif /*UIP_CONF_IPV6_CHECKS */
  }

  /* Schedule a sollicited RA */
    PRINTF("Sending Solicited RA right now.\n");
	#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_IPv6 || UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
	uip_ds6_send_ra_sollicited();
	#endif
return;

discard:
  uip_len = 0;
  return;
}

/*---------------------------------------------------------------------------*/
void
uip_nd6_ra_output(uip_ipaddr_t * dest)
{

  UIP_IP_BUF->vtc = 0x60;
  UIP_IP_BUF->tcflow = 0;
  UIP_IP_BUF->flow = 0;
  UIP_IP_BUF->proto = UIP_PROTO_ICMP6;
  UIP_IP_BUF->ttl = UIP_ND6_HOP_LIMIT;

  if(dest == NULL) {
    uip_create_linklocal_allnodes_mcast(&UIP_IP_BUF->destipaddr);
  } else {
    /* For sollicited RA */
    uip_ipaddr_copy(&UIP_IP_BUF->destipaddr, dest);
  }
  uip_ds6_select_src(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr);

  UIP_ICMP_BUF->type = ICMP6_RA;
  UIP_ICMP_BUF->icode = 0;

  UIP_ND6_RA_BUF->cur_ttl = uip_ds6_if.cur_hop_limit;

  UIP_ND6_RA_BUF->flags_reserved =
    (UIP_ND6_M_FLAG << 7) | (UIP_ND6_O_FLAG << 6);

  UIP_ND6_RA_BUF->router_lifetime = uip_htons(UIP_ND6_ROUTER_LIFETIME);
  UIP_ND6_RA_BUF->reachable_time = 0;
  UIP_ND6_RA_BUF->retrans_timer = 0;


  uip_len = UIP_IPH_LEN + UIP_ICMPH_LEN + UIP_ND6_RA_LEN;
  nd6_opt_offset = UIP_ND6_RA_LEN;


#if !UIP_CONF_ROUTER
  /* Prefix list */
  for(prefix = uip_ds6_prefix_list;
      prefix < uip_ds6_prefix_list + UIP_DS6_PREFIX_NB; prefix++) {
    if((prefix->isused) && (prefix->advertise)) {
      UIP_ND6_OPT_PREFIX_BUF->type = UIP_ND6_OPT_PREFIX_INFO;
      UIP_ND6_OPT_PREFIX_BUF->len = UIP_ND6_OPT_PREFIX_INFO_LEN / 8;
      UIP_ND6_OPT_PREFIX_BUF->preflen = prefix->length;
      UIP_ND6_OPT_PREFIX_BUF->flagsreserved1 = prefix->l_a_reserved;
      UIP_ND6_OPT_PREFIX_BUF->validlt = uip_htonl(prefix->vlifetime);
      UIP_ND6_OPT_PREFIX_BUF->preferredlt = uip_htonl(prefix->plifetime);
      UIP_ND6_OPT_PREFIX_BUF->reserved2 = 0;
      uip_ipaddr_copy(&(UIP_ND6_OPT_PREFIX_BUF->prefix), &(prefix->ipaddr));
      nd6_opt_offset += UIP_ND6_OPT_PREFIX_INFO_LEN;
      uip_len += UIP_ND6_OPT_PREFIX_INFO_LEN;
    }
  }
#endif /* !UIP_CONF_ROUTER */

  /* Source link-layer option */
  create_llao((uint8_t *)UIP_ND6_OPT_HDR_BUF, UIP_ND6_OPT_SLLAO);

  uip_len += UIP_ND6_OPT_LLAO_LEN;
  nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;

  /* MTU */
  UIP_ND6_OPT_MTU_BUF->type = UIP_ND6_OPT_MTU;
  UIP_ND6_OPT_MTU_BUF->len = UIP_ND6_OPT_MTU_LEN >> 3;
  UIP_ND6_OPT_MTU_BUF->reserved = 0;
  //UIP_ND6_OPT_MTU_BUF->mtu = uip_htonl(uip_ds6_if.link_mtu);
  UIP_ND6_OPT_MTU_BUF->mtu = uip_htonl(1500);

  uip_len += UIP_ND6_OPT_MTU_LEN;
  nd6_opt_offset += UIP_ND6_OPT_MTU_LEN;

#if UIP_ND6_RA_RDNSS
  if(uip_nameserver_count() > 0) {
    uint8_t i = 0;
    uip_ipaddr_t *ip = &UIP_ND6_OPT_RDNSS_BUF->ip;
    uip_ipaddr_t *dns = NULL;
    UIP_ND6_OPT_RDNSS_BUF->type = UIP_ND6_OPT_RDNSS;
    UIP_ND6_OPT_RDNSS_BUF->reserved = 0;
    UIP_ND6_OPT_RDNSS_BUF->lifetime = uip_nameserver_next_expiration();
    if(UIP_ND6_OPT_RDNSS_BUF->lifetime != UIP_NAMESERVER_INFINITE_LIFETIME) {
      UIP_ND6_OPT_RDNSS_BUF->lifetime -= clock_seconds();
    }
    while((dns = uip_nameserver_get(i)) != NULL) {
      uip_ipaddr_copy(ip++, dns);
      i++;
    }
    UIP_ND6_OPT_RDNSS_BUF->len = UIP_ND6_OPT_RDNSS_LEN + (i << 1);
    PRINTF("%d nameservers reported\n", i);
    uip_len += UIP_ND6_OPT_RDNSS_BUF->len << 3;
    nd6_opt_offset += UIP_ND6_OPT_RDNSS_BUF->len << 3;
  }
#endif /* UIP_ND6_RA_RDNSS */


  UIP_IP_BUF->len[0] = ((uip_len - UIP_IPH_LEN) >> 8);
  UIP_IP_BUF->len[1] = ((uip_len - UIP_IPH_LEN) & 0xff);

  /*ICMP checksum */
  UIP_ICMP_BUF->icmpchksum = 0;
  UIP_ICMP_BUF->icmpchksum = ~uip_icmp6chksum();

  UIP_STAT(++uip_stat.nd6.sent);
  PRINTF("Sending RA to");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("from");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("\n");
  return;
}
#endif /* UIP_ND6_SEND_RA */
#endif /* UIP_CONF_ROUTER */

#if (UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo && !UIP_CONF_ROUTER) || UIP_ND6_ENGINE == UIP_ND6_ENGINE_IPv6
/*---------------------------------------------------------------------------*/
void
uip_nd6_rs_output(void)
{
  UIP_IP_BUF->vtc = 0x60;
  UIP_IP_BUF->tcflow = 0;
  UIP_IP_BUF->flow = 0;
  UIP_IP_BUF->proto = UIP_PROTO_ICMP6;
  UIP_IP_BUF->ttl = UIP_ND6_HOP_LIMIT;
  uip_create_linklocal_allrouters_mcast(&UIP_IP_BUF->destipaddr);
  uip_ds6_select_src(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr);
  UIP_ICMP_BUF->type = ICMP6_RS;
  UIP_ICMP_BUF->icode = 0;
  UIP_IP_BUF->len[0] = 0;       /* length will not be more than 255 */

  if(uip_is_addr_unspecified(&UIP_IP_BUF->srcipaddr)) {
    UIP_IP_BUF->len[1] = UIP_ICMPH_LEN + UIP_ND6_RS_LEN;
    uip_len = uip_l3_icmp_hdr_len + UIP_ND6_RS_LEN;
  } else {
    uip_len = uip_l3_icmp_hdr_len + UIP_ND6_RS_LEN + UIP_ND6_OPT_LLAO_LEN;
    UIP_IP_BUF->len[1] =
      UIP_ICMPH_LEN + UIP_ND6_RS_LEN + UIP_ND6_OPT_LLAO_LEN;

    create_llao(&uip_buf[uip_l2_l3_icmp_hdr_len + UIP_ND6_RS_LEN],
		UIP_ND6_OPT_SLLAO);
  }

  UIP_ICMP_BUF->icmpchksum = 0;
  UIP_ICMP_BUF->icmpchksum = ~uip_icmp6chksum();

  UIP_STAT(++uip_stat.nd6.sent);
  PRINTF("Sendin RS to");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("from");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("\n");
  return;
}
#endif
/*---------------------------------------------------------------------------*/
/*
 * Process a Router Advertisement
 *
 * - Possible actions when receiving a RA: add router to router list,
 *   recalculate reachable time, update link hop limit, update retrans timer.
 * - If MTU option: update MTU.
 * - If SLLAO option: update entry in neighbor cache
 * - If prefix option: start autoconf, add prefix to prefix list
 */

static void
ra_input(void)
{
 PRINTF("Received RA from");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("to");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("\n");
  UIP_STAT(++uip_stat.nd6.recv);

#if UIP_CONF_IPV6_CHECKS
  if((UIP_IP_BUF->ttl != UIP_ND6_HOP_LIMIT) ||
     (!uip_is_addr_link_local(&UIP_IP_BUF->srcipaddr)) ||
     (UIP_ICMP_BUF->icode != 0)) {
    PRINTF("RA received is bad");
    goto discard;
  }
#endif /*UIP_CONF_IPV6_CHECKS */

  if(UIP_ND6_RA_BUF->cur_ttl != 0) {
    uip_ds6_if.cur_hop_limit = UIP_ND6_RA_BUF->cur_ttl;
    PRINTF("uip_ds6_if.cur_hop_limit %u\n", uip_ds6_if.cur_hop_limit);
  }
  

  if(UIP_ND6_RA_BUF->reachable_time != 0) {
    if(uip_ds6_if.base_reachable_time !=
       uip_ntohl(UIP_ND6_RA_BUF->reachable_time)) {
      uip_ds6_if.base_reachable_time = uip_ntohl(UIP_ND6_RA_BUF->reachable_time);
      uip_ds6_if.reachable_time = uip_ds6_compute_reachable_time();
    }
  }
  if(UIP_ND6_RA_BUF->retrans_timer != 0) {
    uip_ds6_if.retrans_timer = uip_ntohl(UIP_ND6_RA_BUF->retrans_timer);
  }

  /* Options processing */
  nd6_opt_offset = UIP_ND6_RA_LEN;
  while(uip_l3_icmp_hdr_len + nd6_opt_offset < uip_len) {
    if(UIP_ND6_OPT_HDR_BUF->len == 0) {
      PRINTF("RA received is bad");
      goto discard;
    }
    switch (UIP_ND6_OPT_HDR_BUF->type) {
    case UIP_ND6_OPT_SLLAO:
      PRINTF("Processing SLLAO option in RA\n");
      nd6_opt_llao = (uint8_t *) UIP_ND6_OPT_HDR_BUF;
      nbr = uip_ds6_nbr_lookup(&UIP_IP_BUF->srcipaddr);
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_IPv6
      if(nbr == NULL) {
        nbr = uip_ds6_nbr_add(&UIP_IP_BUF->srcipaddr,
                              (uip_lladdr_t *)&nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET],
			      1, NBR_REACHABLE);
        stimer_set(&(nbr->reachable), uip_ds6_if.reachable_time / 1000);
      } else {
        uip_lladdr_t *lladdr = uip_ds6_nbr_get_ll(nbr);
        if(nbr->state == NBR_INCOMPLETE) {
          nbr->state = NBR_REACHABLE;
          stimer_set(&(nbr->reachable), uip_ds6_if.reachable_time / 1000);
        }
        if(memcmp(&nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET],
		  lladdr, UIP_LLADDR_LEN) != 0) {
          memcpy(lladdr, &nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET],
		 UIP_LLADDR_LEN);
          nbr->state = NBR_STALE;
        }
        nbr->isrouter = 1;
      }
#endif
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
	if(nbr == NULL) {
        nbr = uip_ds6_nbr_add(&UIP_IP_BUF->srcipaddr,(uip_lladdr_t *)&nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET], 1, NBR_REACHABLE);
		stimer_set(&(nbr->reachable), uip_ds6_if.reachable_time/1000); 
		stimer_set(&nbr->sendns, UIP_ND6_NS_REG_TIMER);
		PRINTF("Set nbr's state as REG_TO_BE_REGISTERED\n");
		nbr->is_register_to_state = REG_TO_BE_REGISTERED;
		nbr->nscount = 0;
    } else {
        uip_lladdr_t *lladdr = uip_ds6_nbr_get_ll(nbr);
        if(nbr->state == NBR_STALE) {
          nbr->state = NBR_REACHABLE;
           stimer_set(&(nbr->reachable), uip_ds6_if.reachable_time / 1000);
        }
        if(memcmp(&nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET],
		  lladdr, UIP_LLADDR_LEN) != 0) {
          memcpy(lladdr, &nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET], UIP_LLADDR_LEN);
          nbr->state = NBR_REACHABLE;
           stimer_set(&(nbr->reachable), uip_ds6_if.reachable_time / 1000);
        }
        nbr->isrouter = 1;
      }
#endif
    case UIP_ND6_OPT_MTU:
      PRINTF("Processing MTU option in RA\n");
      uip_ds6_if.link_mtu =
        uip_ntohl(((uip_nd6_opt_mtu *) UIP_ND6_OPT_HDR_BUF)->mtu);
      break;
    case UIP_ND6_OPT_PREFIX_INFO:
      PRINTF("Processing PREFIX option in RA\n");
      nd6_opt_prefix_info = (uip_nd6_opt_prefix_info *) UIP_ND6_OPT_HDR_BUF;
      if((uip_ntohl(nd6_opt_prefix_info->validlt) >=
          uip_ntohl(nd6_opt_prefix_info->preferredlt))
         && (!uip_is_addr_link_local(&nd6_opt_prefix_info->prefix))) {
        /* on-link flag related processing */
        if(nd6_opt_prefix_info->flagsreserved1 & UIP_ND6_RA_FLAG_ONLINK) {
          prefix = uip_ds6_prefix_lookup(&nd6_opt_prefix_info->prefix,
                                  nd6_opt_prefix_info->preflen);
          if(prefix == NULL) {
            if(nd6_opt_prefix_info->validlt != 0) {
              if(nd6_opt_prefix_info->validlt != UIP_ND6_INFINITE_LIFETIME) {
		#if UIP_CONF_ROUTER
                prefix = uip_ds6_prefix_add(&nd6_opt_prefix_info->prefix,
                                            nd6_opt_prefix_info->preflen,1,
					    nd6_opt_prefix_info->flagsreserved1,
                                            uip_ntohl(nd6_opt_prefix_info->validlt),
					uip_ntohl(nd6_opt_prefix_info->preferredlt));			
		#else
                prefix = uip_ds6_prefix_add(&nd6_opt_prefix_info->prefix,
                                            nd6_opt_prefix_info->preflen,
                                            uip_ntohl(nd6_opt_prefix_info->
                                                  validlt));
		#endif
              } 
            }
          } 
#if !UIP_CONF_ROUTER
	else {
            switch (nd6_opt_prefix_info->validlt) {
            case 0:
              uip_ds6_prefix_rm(prefix);
              break;
            case UIP_ND6_INFINITE_LIFETIME:

              prefix->isinfinite = 1;
              break;
            default:
              PRINTF("Updating timer of prefix");
              PRINT6ADDR(&prefix->ipaddr);
              PRINTF("new value %lu\n", uip_ntohl(nd6_opt_prefix_info->validlt));
              stimer_set(&prefix->vlifetime,
                         uip_ntohl(nd6_opt_prefix_info->validlt));
              prefix->isinfinite = 0;
              break;
            }
          }
#endif
        }
        /* End of on-link flag related processing */
        /* autonomous flag related processing */
        if((nd6_opt_prefix_info->flagsreserved1 & UIP_ND6_RA_FLAG_AUTONOMOUS)
           && (nd6_opt_prefix_info->validlt != 0)
           && (nd6_opt_prefix_info->preflen == UIP_DEFAULT_PREFIX_LEN)) {
	  
          uip_ipaddr_copy(&ipaddr, &nd6_opt_prefix_info->prefix);
          uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
          addr = uip_ds6_addr_lookup(&ipaddr);
          if((addr != NULL) && (addr->type == ADDR_AUTOCONF)) {
            if(nd6_opt_prefix_info->validlt != UIP_ND6_INFINITE_LIFETIME) {
              /* The processing below is defined in RFC4862 section 5.5.3 e */
              if((uip_ntohl(nd6_opt_prefix_info->validlt) > 2 * 60 * 60) ||
                 (uip_ntohl(nd6_opt_prefix_info->validlt) >
                  stimer_remaining(&addr->vlifetime))) {
                PRINTF("Updating timer of address");
                PRINT6ADDR(&addr->ipaddr);
                PRINTF("new value %lu\n",
                       uip_ntohl(nd6_opt_prefix_info->validlt));
                stimer_set(&addr->vlifetime,
                           uip_ntohl(nd6_opt_prefix_info->validlt));
              } else {
                stimer_set(&addr->vlifetime, 2 * 60 * 60);
                PRINTF("Updating timer of address ");
                PRINT6ADDR(&addr->ipaddr);
                PRINTF("new value %lu\n", (unsigned long)(2 * 60 * 60));
              }
              addr->isinfinite = 0;
            } else {
              addr->isinfinite = 1;
            }
          } else {
            if(uip_ntohl(nd6_opt_prefix_info->validlt) ==
               UIP_ND6_INFINITE_LIFETIME) {
              uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
            } else {
              uip_ds6_addr_add(&ipaddr, uip_ntohl(nd6_opt_prefix_info->validlt),
                               ADDR_AUTOCONF);
            }
          }
        }
        /* End of autonomous flag related processing */
      }
      break;
#if UIP_ND6_RA_RDNSS
    case UIP_ND6_OPT_RDNSS:
      if(UIP_ND6_RA_BUF->flags_reserved & (UIP_ND6_O_FLAG << 6)) {
        PRINTF("Processing RDNSS option\n");
        uint8_t naddr = (UIP_ND6_OPT_RDNSS_BUF->len - 1) / 2;
        uip_ipaddr_t *ip = (uip_ipaddr_t *)(&UIP_ND6_OPT_RDNSS_BUF->ip);
        PRINTF("got %d nameservers\n", naddr);
        while(naddr-- > 0) {
          PRINTF(" nameserver: ");
          PRINT6ADDR(ip);
          PRINTF(" lifetime: %lx\n", uip_ntohl(UIP_ND6_OPT_RDNSS_BUF->lifetime));
          uip_nameserver_update(ip, uip_ntohl(UIP_ND6_OPT_RDNSS_BUF->lifetime));
          ip++;
        }
      }
      break;
#endif /* UIP_ND6_RA_RDNSS */
    default:
      PRINTF("ND option not supported in RA");
      break;
    }
    nd6_opt_offset += (UIP_ND6_OPT_HDR_BUF->len << 3);
  }

  if(UIP_ND6_RA_BUF->router_lifetime != 0) {
    if(nbr != NULL) {
      nbr->isrouter = 1;
    }
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
	defrt = uip_ds6_defrt_lookup(&UIP_IP_BUF->srcipaddr);
    if(defrt == NULL) {
      uip_ds6_defrt_add(&UIP_IP_BUF->srcipaddr,
                        (unsigned
                         long)(uip_ntohs(UIP_ND6_RA_BUF->router_lifetime)));
    } else {
      stimer_set(&(defrt->lifetime),
                 (unsigned long)(uip_ntohs(UIP_ND6_RA_BUF->router_lifetime)));
    }
#endif
  } else {
    if(defrt != NULL) {
      uip_ds6_defrt_rm(defrt);
    }

  }
  

#if UIP_CONF_IPV6_QUEUE_PKT
  /* If the nbr just became reachable (e.g. it was in NBR_INCOMPLETE state
   * and we got a SLLAO), check if we had buffered a pkt for it */
  /*  if((nbr != NULL) && (nbr->queue_buf_len != 0)) {
    uip_len = nbr->queue_buf_len;
    memcpy(UIP_IP_BUF, nbr->queue_buf, uip_len);
    nbr->queue_buf_len = 0;
    return;
    }*/
  if(nbr != NULL && uip_packetqueue_buflen(&nbr->packethandle) != 0) {
    uip_len = uip_packetqueue_buflen(&nbr->packethandle);
    memcpy(UIP_IP_BUF, uip_packetqueue_buf(&nbr->packethandle), uip_len);
    uip_packetqueue_free(&nbr->packethandle);
    return;
  }

#endif /*UIP_CONF_IPV6_QUEUE_PKT */

discard:
  uip_len = 0;
  return;
}
#define UIP_ICMP_OPTS_APPEND ((uip_nd6_opt_hdr *)&uip_buf[UIP_LLH_LEN + uip_len])
void
uip_nd6_append_icmp_opt(uint8_t type, void* data, uint8_t status, uint16_t lifetime)
{
	UIP_ICMP_OPTS_APPEND->type = type;
	/* Length depends on the specific type of option */
	switch (type) {
	case UIP_ND6_OPT_SLLAO:
	case UIP_ND6_OPT_TLLAO:
	UIP_ICMP_OPTS_APPEND->len = UIP_ND6_OPT_LLAO_LEN >> 3;
  	memcpy((uint8_t*)(UIP_ICMP_OPTS_APPEND) + UIP_ND6_OPT_DATA_OFFSET, data, UIP_802154_LONGADDR_LEN);
  	/* padding required */
  	memset((uint8_t*)(UIP_ICMP_OPTS_APPEND) + UIP_ND6_OPT_DATA_OFFSET + UIP_802154_LONGADDR_LEN, 0,
    				UIP_ND6_OPT_LLAO_LEN - 2 - UIP_802154_LONGADDR_LEN);
    UIP_IP_BUF->len[1] += UIP_ND6_OPT_LLAO_LEN;
    uip_len += UIP_ND6_OPT_LLAO_LEN;
	break;
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
	case UIP_ND6_OPT_ARO:
		UIP_ICMP_OPTS_APPEND->len = UIP_ND6_OPT_ARO_LEN >> 3;
		((uip_nd6_opt_aro*)UIP_ICMP_OPTS_APPEND)->status = status;
		/* The reserved field MUST be initialized to zero by the sender */		
		((uip_nd6_opt_aro*)UIP_ICMP_OPTS_APPEND)->reserved1 = (uint8_t)0;
 		((uip_nd6_opt_aro*)UIP_ICMP_OPTS_APPEND)->reserved2 = (uint16_t)0;
  	((uip_nd6_opt_aro*)UIP_ICMP_OPTS_APPEND)->lifetime = lifetime;
		memcpy(&(((uip_nd6_opt_aro*)UIP_ICMP_OPTS_APPEND)->eui64), data, UIP_LLADDR_LEN);
		/* No need for padding here */
		UIP_IP_BUF->len[1] += UIP_ND6_OPT_ARO_LEN;
		uip_len += UIP_ND6_OPT_ARO_LEN;
		break;
#endif
#if CONF_6LOWPAN_ND_6CO
#endif
	}
}

void
uip_nd6_create_na(uip_ipaddr_t* src, uip_ipaddr_t* dst, uip_ipaddr_t* tgt, uint8_t flags)
{
		
	uip_ipaddr_t aux;
	
	uip_ipaddr_copy(&aux, src);
  uip_ipaddr_copy(&UIP_IP_BUF->destipaddr, dst);
	uip_ipaddr_copy(&UIP_IP_BUF->srcipaddr, &aux);
        PRINTF("Create NA from ");
PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
PRINTF(" to "); 
PRINT6ADDR(&UIP_IP_BUF->destipaddr);
	
	uip_ext_len = 0;
	UIP_IP_BUF->vtc = 0x60;
	UIP_IP_BUF->tcflow = 0;
	UIP_IP_BUF->flow = 0;
	UIP_IP_BUF->len[0] = 0;       /* length will not be more than 255 */
	UIP_IP_BUF->len[1] = UIP_ICMPH_LEN + UIP_ND6_NA_LEN;
	UIP_IP_BUF->proto = UIP_PROTO_ICMP6;
	UIP_IP_BUF->ttl = UIP_ND6_HOP_LIMIT;

	UIP_ICMP_BUF->type = ICMP6_NA;
	UIP_ICMP_BUF->icode = 0;

	UIP_ND6_NA_BUF->flagsreserved = flags;
	
	uip_ipaddr_copy((uip_ipaddr_t *)&UIP_ND6_NA_BUF->tgtipaddr, tgt);

	uip_len =
    	UIP_IPH_LEN + UIP_ICMPH_LEN + UIP_ND6_NA_LEN;
}


/* Updates the ICMPv6 checksum */
void
uip_nd6_update_icmp_checksum(){
	UIP_ICMP_BUF->icmpchksum = 0;
	UIP_ICMP_BUF->icmpchksum = ~uip_icmp6chksum();
}

/* This function expects a NS with ARO to be in uip_buf and generates
 * the NA with ARO in response depending on the value of status. */

void
uip_nd6_registration_error(uint8_t status) {
	PRINTF("This is an error na with status number %u!\n",status);
	uip_nd6_create_na(&UIP_IP_BUF->destipaddr, &UIP_IP_BUF->srcipaddr, NULL, UIP_ND6_NA_FLAG_ROUTER);
	
	/* include TLLAO option */
	uip_nd6_append_icmp_opt(UIP_ND6_OPT_TLLAO, (uip_lladdr_t *)&(nd6_opt_llao[UIP_ND6_OPT_DATA_OFFSET]), 0, 0);
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_6Lo
	/* include ARO option */
	uip_nd6_append_icmp_opt(UIP_ND6_OPT_ARO, (uip_lladdr_t *)&(nd6_opt_aro->eui64), status, nd6_opt_aro->lifetime);
	/* Compute checksum */
#endif
	uip_nd6_update_icmp_checksum();
}




/*------------------------------------------------------------------*/
/* ICMPv6 input handlers */
#if UIP_ND6_SEND_NA
UIP_ICMP6_HANDLER(ns_input_handler, ICMP6_NS, UIP_ICMP6_HANDLER_CODE_ANY,
                  ns_input);
UIP_ICMP6_HANDLER(na_input_handler, ICMP6_NA, UIP_ICMP6_HANDLER_CODE_ANY,
                  na_input);
#endif

#if UIP_CONF_ROUTER && UIP_ND6_SEND_RA
UIP_ICMP6_HANDLER(rs_input_handler, ICMP6_RS, UIP_ICMP6_HANDLER_CODE_ANY,
                  rs_input);
#endif


UIP_ICMP6_HANDLER(ra_input_handler, ICMP6_RA, UIP_ICMP6_HANDLER_CODE_ANY,
                  ra_input);


/*---------------------------------------------------------------------------*/
void
uip_nd6_init()
{
#if UIP_ND6_SEND_NA
  /* Only handle NSs if we are prepared to send out NAs */
  uip_icmp6_register_input_handler(&ns_input_handler);

  /*
   * Only handle NAs if we are prepared to send out NAs.
   * This is perhaps logically incorrect, but this condition was present in
   * uip_process and we keep it until proven wrong
   */
  uip_icmp6_register_input_handler(&na_input_handler);
#endif


#if UIP_CONF_ROUTER && UIP_ND6_SEND_RA
  /* Only accept RS if we are a router and happy to send out RAs */
  uip_icmp6_register_input_handler(&rs_input_handler);
#endif

  uip_icmp6_register_input_handler(&ra_input_handler);
}
/*---------------------------------------------------------------------------*/
 /** @} */
