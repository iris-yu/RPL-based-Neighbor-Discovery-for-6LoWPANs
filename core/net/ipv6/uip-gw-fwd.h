/**
 * \file		pgw_fwd.h
 *
 * \brief		Forwarding/bridging-related definitions for the 6LoWPAN-ND proxy-gateway 
 *
 * \author		Luis Maqueda <luis@sen.se>
 */


#ifndef UIP_GW_FWD_H_
#define UIP_GW_FWD_H_


#include "net/ip/uip.h"




/* Number of entries in the bridge */
#define MAX_GW_NBR_ENTRIES	30

#define GW_ND6_NA_FLAG_SOLICITED       0x40
#define GW_ND6_NA_FLAG_OVERRIDE        0x20


#define UIP_CONF_TAP 1
#define UIP_CONF_TUN 0

/* 
 * Interface types 
 */
typedef enum {
	UNDEFINED = 0,
	IEEE_802_3,
	IEEE_802_15_4,
	LOCAL
} interface_t;

/* 
 * An entry in the bridge cache 
 */
typedef struct {
	uip_ipaddr_t addr;
	uint8_t state;
} gw_nbr_entry_t;


typedef struct {
	gw_nbr_entry_t table[MAX_GW_NBR_ENTRIES];
	uint8_t elems;
} gw_nbr_table_t;

#define  GW_NBR_GARBAGE_COLLECTABLE 0
#define  GW_NBR_REACHABLE 1


/** \brief Incoming and outgoing interfaces */
extern interface_t incoming_if, outgoing_if;

extern uint8_t if_send_to_slip;
/** \brief Source and destination MAC addresses */



/** \name ND6 option types */
/** @{ */
#define GW_ND6_OPT_TYPE_OFFSET         0
#define GW_ND6_OPT_LEN_OFFSET          1
#define GW_ND6_OPT_DATA_OFFSET         2



/* If the interface is ethernet or 802.15.4 */
#define UIP_ND6_OPT_ETH_LLAO_LEN     8
#define UIP_ND6_OPT_LONG_LLAO_LEN      16
#define UIP_ETH_LLH_LEN 14
#define ETH_LLADDR_SIZE		6
//#define 802154_LLADDR_SIZE		8
//#define IEEE_8023_MAC_ADDRESS	{0x00,0x50,0x56,0xc0,0x00,0x01 00:50:56:34:26:7F}
#define IEEE_8023_MAC_ADDRESS	{0,80,86,52,38,127}
extern uint8_t eth_lladdr_id[ETH_LLADDR_SIZE];

//#define IEEE_8023_ROUTER_MAC_ADDRESS	{202,1,14,129,0,28}

#define ETH_IPV6_TYPE {134,221}
extern uint8_t eth_router_lladdr_id[ETH_LLADDR_SIZE];

extern uint8_t eth_llheader[UIP_ETH_LLH_LEN];

extern uip_ipaddr_t routeripaddr;	

//uint8_t ieee[] = IEEE_8023_MAC_ADDRESS;
//memcpy(ds2411_id, ieee, sizeof(uip_lladdr.addr));
//ds2411_id[7] = node_id & 0xff;

gw_nbr_entry_t* gw_nbr_lookup(uip_ipaddr_t *addr);
void gw_nbr_add(uip_ipaddr_t *addr); 
void gw_nbr_delete(uip_ipaddr_t *addr);

void uip_gw_fwd_init();
void gw_create_ethheader();

void gw_icmp6_input();
void uip_gw_create_na(uip_ipaddr_t* src, uip_ipaddr_t* dst, uip_ipaddr_t* tgt, uint8_t flags);
void uip_gw_append_icmp_opt(uint8_t type, void* data, uint8_t status, uint16_t lifetime);


#endif /*UIP_GW_FWD_H_*/
