/*
 * Copyright (c) 2009, Swedish Institute of Computer Science.
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
 *         ContikiRPL, an implementation of RPL: IPv6 Routing Protocol
 *         for Low-Power and Lossy Networks (IETF RFC 6550)
 *
 * \author Joakim Eriksson <joakime@sics.se>, Nicolas Tsiftes <nvt@sics.se>
 */

/**
 * \addtogroup uip6
 * @{
 */

//#include "net/ip/uip.h"
#include "net/ip/tcpip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/rpl/rpl.h"
#include "net/rpl/rpl-private.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/linkaddr.h"

#if UIP_ND6_CONF_ENGINE == UIP_ND6_ENGINE_RPL
#include "lib/list.h"
#include "lib/memb.h"
#endif 


#include "net/ipv6/uip-ds6-route.h"


#define DEBUG 0
#include "net/ip/uip-debug.h"

#include <limits.h>
#include <string.h>

#if RPL_CONF_STATS
rpl_stats_t rpl_stats;
#endif

static enum rpl_mode mode = RPL_MODE_MESH;

/*---------------------------------------------------------------------------*/
#if UIP_ND6_ENGINE == UIP_ND6_ENGINE_RPL

LIST(rpl_sourceinfo_list);
//MEMB(rpl_sourceinfo_mem, rpl_sourceinfo, 5);
static char rpl_sourceinfo_mem_memb_count[5];
static struct rpl_sourceinfo rpl_sourceinfo_mem_memb_mem[5];
static struct memb rpl_sourceinfo_mem = {sizeof(rpl_sourceinfo_t), 5, rpl_sourceinfo_mem_memb_count, (void *)rpl_sourceinfo_mem_memb_mem};


void
rpl_sourceinfo_init(void)
{
  memb_init(&rpl_sourceinfo_mem);
  list_init(rpl_sourceinfo_list);
}


struct rpl_sourceinfo *
rpl_sourceinfo_list_head(void){
    void *currentitem;
    currentitem = list_head(rpl_sourceinfo_list);
    return (struct rpl_sourceinfo *)currentitem;
} 


struct rpl_sourceinfo *
rpl_sourceinfo_list_next(struct rpl_sourceinfo *rpl_sourceinfo_item){
    void *currentitem;
    currentitem = list_item_next(rpl_sourceinfo_item);
    return (struct rpl_sourceinfo *)currentitem;
} 




struct rpl_sourceinfo *
rpl_sourceinfo_list_add(unsigned short nodeid){
   struct rpl_sourceinfo *s, *sourceinfonew;
   for(s = rpl_sourceinfo_list_head(); s != NULL; s = rpl_sourceinfo_list_next(s)){
    	if(s->nodeID == nodeid)
		return NULL;
    }		  
    sourceinfonew = memb_alloc(&rpl_sourceinfo_mem);
    sourceinfonew->nodeID = nodeid;
    list_add(rpl_sourceinfo_list, sourceinfonew);
		  
}



void
rpl_sourceinfo_list_purge(void){
    struct rpl_sourceinfo *s;
    for(s = rpl_sourceinfo_list_head(); s != NULL; s = rpl_sourceinfo_list_next(s)){
    list_remove(rpl_sourceinfo_list, s);
    memb_free(&rpl_sourceinfo_mem, (struct rpl_sourceinfo *)s);
    }		  
}

#endif
/*---------------------------------------------------------------------------*/
enum rpl_mode
rpl_get_mode(void)
{
  return mode;
}
/*---------------------------------------------------------------------------*/
enum rpl_mode
rpl_set_mode(enum rpl_mode m)
{
  enum rpl_mode oldmode = mode;

  /* We need to do different things depending on what mode we are
     switching to. */
  if(m == RPL_MODE_MESH) {

    /* If we switch to mesh mode, we should send out a DAO message to
       inform our parent that we now are reachable. Before we do this,
       we must set the mode variable, since DAOs will not be sent if
       we are in feather mode. */
    PRINTF("RPL: switching to mesh mode\n");
    mode = m;

    if(default_instance != NULL) {
      rpl_schedule_dao_immediately(default_instance);
    }
  } else if(m == RPL_MODE_FEATHER) {

    PRINTF("RPL: switching to feather mode\n");
    mode = m;
    if(default_instance != NULL) {
      rpl_cancel_dao(default_instance);
    }

  } else {
    mode = m;
  }

  return oldmode;
}
/*---------------------------------------------------------------------------*/
void
rpl_purge_routes(void)
{
  uip_ds6_route_t *r;
  uip_ipaddr_t prefix;
  rpl_dag_t *dag;
#if RPL_CONF_MULTICAST
  uip_mcast6_route_t *mcast_route;
#endif

  /* First pass, decrement lifetime */
  r = uip_ds6_route_head();

  while(r != NULL) {
    if(r->state.lifetime >= 1) {
      /*
       * If a route is at lifetime == 1, set it to 0, scheduling it for
       * immediate removal below. This achieves the same as the original code,
       * which would delete lifetime <= 1
       */
      r->state.lifetime--;
    }
    r = uip_ds6_route_next(r);
  }

  /* Second pass, remove dead routes */
  r = uip_ds6_route_head();

  while(r != NULL) {
    if(r->state.lifetime < 1) {
      /* Routes with lifetime == 1 have only just been decremented from 2 to 1,
       * thus we want to keep them. Hence < and not <= */
      uip_ipaddr_copy(&prefix, &r->ipaddr);
      uip_ds6_route_rm(r);
      r = uip_ds6_route_head();
      PRINTF("No more routes to ");
      PRINT6ADDR(&prefix);
      dag = default_instance->current_dag;
      /* Propagate this information with a No-Path DAO to preferred parent if we are not a RPL Root */
      if(dag->rank != ROOT_RANK(default_instance)) {
        PRINTF(" -> generate No-Path DAO\n");
        dao_output_target(dag->preferred_parent, &prefix, RPL_ZERO_LIFETIME);
        /* Don't schedule more than 1 No-Path DAO, let next iteration handle that */
        return;
      }
      PRINTF("\n");
    } else {
      r = uip_ds6_route_next(r);
    }
  }

#if RPL_CONF_MULTICAST
  mcast_route = uip_mcast6_route_list_head();

  while(mcast_route != NULL) {
    if(mcast_route->lifetime <= 1) {
      uip_mcast6_route_rm(mcast_route);
      mcast_route = uip_mcast6_route_list_head();
    } else {
      mcast_route->lifetime--;
      mcast_route = list_item_next(mcast_route);
    }
  }
#endif
}
/*---------------------------------------------------------------------------*/
void
rpl_remove_routes(rpl_dag_t *dag)
{
  uip_ds6_route_t *r;
#if RPL_CONF_MULTICAST
  uip_mcast6_route_t *mcast_route;
#endif

  r = uip_ds6_route_head();

  while(r != NULL) {
    if(r->state.dag == dag) {
      uip_ds6_route_rm(r);
      r = uip_ds6_route_head();
    } else {
      r = uip_ds6_route_next(r);
    }
  }

#if RPL_CONF_MULTICAST
  mcast_route = uip_mcast6_route_list_head();

  while(mcast_route != NULL) {
    if(mcast_route->dag == dag) {
      uip_mcast6_route_rm(mcast_route);
      mcast_route = uip_mcast6_route_list_head();
    } else {
      mcast_route = list_item_next(mcast_route);
    }
  }
#endif
}
/*---------------------------------------------------------------------------*/
void
rpl_remove_routes_by_nexthop(uip_ipaddr_t *nexthop, rpl_dag_t *dag)
{
  uip_ds6_route_t *r;

  r = uip_ds6_route_head();

  while(r != NULL) {
    if(uip_ipaddr_cmp(uip_ds6_route_nexthop(r), nexthop) &&
       r->state.dag == dag) {
      uip_ds6_route_rm(r);
      r = uip_ds6_route_head();
    } else {
      r = uip_ds6_route_next(r);
    }
  }
  ANNOTATE("#L %u 0\n", nexthop->u8[sizeof(uip_ipaddr_t) - 1]);
}
/*---------------------------------------------------------------------------*/
uip_ds6_route_t *
rpl_add_route(rpl_dag_t *dag, uip_ipaddr_t *prefix, int prefix_len,
              uip_ipaddr_t *next_hop)
{
  uip_ds6_route_t *rep;

  if((rep = uip_ds6_route_add(prefix, prefix_len, next_hop)) == NULL) {
    PRINTF("RPL: No space for more route entries\n");
    return NULL;
  }

  rep->state.dag = dag;
  rep->state.lifetime = RPL_LIFETIME(dag->instance, dag->instance->default_lifetime);
  rep->state.learned_from = RPL_ROUTE_FROM_INTERNAL;

  PRINTF("RPL: Added a route to ");
  PRINT6ADDR(prefix);
  PRINTF("/%d via ", prefix_len);
  PRINT6ADDR(next_hop);
  PRINTF("\n");

  return rep;
}
/*---------------------------------------------------------------------------*/
void
rpl_link_neighbor_callback(const linkaddr_t *addr, int status, int numtx)
{
  uip_ipaddr_t ipaddr;
  rpl_parent_t *parent;
  rpl_instance_t *instance;
  rpl_instance_t *end;

  uip_ip6addr(&ipaddr, 0xfe80, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, (uip_lladdr_t *)addr);

  for(instance = &instance_table[0], end = instance + RPL_MAX_INSTANCES; instance < end; ++instance) {
    if(instance->used == 1 ) {
      parent = rpl_find_parent_any_dag(instance, &ipaddr);
      if(parent != NULL) {
        /* Trigger DAG rank recalculation. */
        PRINTF("RPL: rpl_link_neighbor_callback triggering update\n");
        parent->flags |= RPL_PARENT_FLAG_UPDATED;
        if(instance->of->neighbor_link_callback != NULL) {
          instance->of->neighbor_link_callback(parent, status, numtx);
          parent->last_tx_time = clock_time();
        }
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
void
rpl_ipv6_neighbor_callback(uip_ds6_nbr_t *nbr)
{
  rpl_parent_t *p;
  rpl_instance_t *instance;
  rpl_instance_t *end;

  uip_ds6_route_neighbor_route_t *neighbor_route;
  struct uip_ds6_route_neighbor_routes *item;
  
  int index;

  PRINTF("RPL: Removing neighbor ");
  PRINT6ADDR(&nbr->ipaddr);
  PRINTF("\n");
  for(instance = &instance_table[0], end = instance + RPL_MAX_INSTANCES; instance < end; ++instance) {
    if(instance->used == 1 ) {
      p = rpl_find_parent_any_dag(instance, &nbr->ipaddr);
      if(p != NULL) {
        p->rank = INFINITE_RANK;
        /* Trigger DAG rank recalculation. */
        PRINTF("RPL: rpl_ipv6_neighbor_callback infinite rank\n");
        p->flags |= RPL_PARENT_FLAG_UPDATED;
      }
	  #if UIP_ND6_CONF_ENGINE == UIP_ND6_ENGINE_RPL
	  index = index_from_item(ds6_neighbors, nbr);

	  item = item_from_index(nbr_routes, index);
	  for(neighbor_route = list_head(item->route_list);
       		 neighbor_route != NULL;
        	neighbor_route = list_item_next(neighbor_route)){
		list_remove(item->route_list, neighbor_route);
		#if UIP_CONF_GW != 1
		PRINTF("RPL: rpl send DAO-NOPATH to GW because of neighbor unreachability.\n");
		dao_output_target(default_instance->current_dag->preferred_parent,&(neighbor_route->route->ipaddr), RPL_ZERO_LIFETIME);
		#endif
		#if UIP_CONF_GW == 1
		PRINTF("RPL: GW initiated neighbor deletion.\n");
		gw_nbr_delete(&nbr->ipaddr);
		#endif
		uip_ds6_route_rm(neighbor_route->route);
	}
	  if((struct uip_ds6_route_neighbor_routes *)item->route_list == NULL) {
      /* If this was the only route using this neighbor, remove the
         neibhor from the table */
      PRINTF("uip_ds6_route_rm: removing neighbor too\n");
      nbr_table_remove(nbr_routes, item);
    }
	#endif
    }
  }
}
/*---------------------------------------------------------------------------*/
void
rpl_init(void)
{
  uip_ipaddr_t rplmaddr;
  PRINTF("RPL started\n");
  default_instance = NULL;

  #if UIP_ND6_ENGINE == UIP_ND6_ENGINE_RPL
  rpl_sourceinfo_init();
  #endif

  rpl_dag_init();
  rpl_reset_periodic_timer();
  rpl_icmp6_register_handlers();

  /* add rpl multicast address */
  uip_create_linklocal_rplnodes_mcast(&rplmaddr);
  uip_ds6_maddr_add(&rplmaddr);

#if RPL_CONF_STATS
  memset(&rpl_stats, 0, sizeof(rpl_stats));
#endif

  RPL_OF.reset(NULL);
}
/*---------------------------------------------------------------------------*/

/** @}*/
