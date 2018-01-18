/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Check if target IP address is one of the router's IP addresses and returns the interface. Otherwise return NULL.*/
struct sr_if *ip_in_router(struct sr_if *interface, uint32_t ip_addr) {
     struct sr_if *curr_interface = interface;
     while (curr_interface !=  NULL) {
        if (curr_interface->ip == ip_addr) {
            return curr_interface;
        } 
        curr_interface = curr_interface->next;
    }
    return NULL;
}

/* Return interface name corresponding to destination ip. */
char *name_by_dest(struct sr_instance *sr, uint32_t dest_ip) {
    struct sr_rt *routing_table;
    for (routing_table = sr->routing_table; routing_table != NULL; routing_table = routing_table->next) {
        if (((uint32_t) routing_table->dest.s_addr) == dest_ip) {
            return routing_table->interface; 
        }
    }
    return NULL;
}

/*cksum function for ip addresses*/
uint16_t ip_cksum (sr_ip_hdr_t *ip_hdr, int len) {
    uint16_t temp, result;

    temp = ip_hdr->ip_sum; 
    ip_hdr->ip_sum = 0;
    result = cksum(ip_hdr, len);
    ip_hdr->ip_sum = temp;    

    return result;
}

/*cksum function for icmp*/
uint16_t icmp_cksum (sr_icmp_hdr_t *icmp_hdr, int len) {
    uint16_t temp, result;

    temp = icmp_hdr->icmp_sum; 
    icmp_hdr->icmp_sum = 0;
    result = cksum(icmp_hdr, len);
    icmp_hdr->icmp_sum = temp;

    return result;
}

/*cksum function for icmp type 3*/
uint16_t icmp3_cksum(sr_icmp_t3_hdr_t *icmp3_hdr, int len) {
    uint16_t temp, result;

    temp = icmp3_hdr->icmp_sum;
    icmp3_hdr->icmp_sum = 0;
    result = cksum(icmp3_hdr, len);
    icmp3_hdr->icmp_sum = temp;
    
    return result;
}

/*LPM function */
struct sr_rt *find_lpm(struct sr_rt *rt, uint32_t dest_ip) {
  long int currLongestMatch = 0;
  struct sr_rt *found = NULL;

  while (rt != NULL) {  	
     if ((rt->mask.s_addr & dest_ip) ==  rt->dest.s_addr) {
        if ((rt->mask.s_addr) > currLongestMatch) {
           currLongestMatch = rt->mask.s_addr;
           found = rt;
        }
     }
     rt = rt->next;
  }
  return found;
}


uint8_t *create_ethernet_header(int type, unsigned char *src_addr, unsigned char *dest_addr, int data_len) {
    unsigned int len = sizeof(sr_ethernet_hdr_t);   
    sr_ethernet_hdr_t *ethernet_header = NULL;
    
    /* If packet is an ARP */
    if (type == 1 || type == 2) {
        len += sizeof(sr_arp_hdr_t);
        ethernet_header = (sr_ethernet_hdr_t *) malloc(len);
        /* If packet is a ARP request, set destination MAC address to FF:FF:FF:FF:FF:FF */
        if (type == 1) {
            int i;
            for (i = 0; i < ETHER_ADDR_LEN; i++) {
                ethernet_header->ether_dhost[i] = 255;
            }
            memcpy(ethernet_header->ether_shost, src_addr, ETHER_ADDR_LEN);
        } else {
            memcpy(ethernet_header->ether_shost, src_addr, ETHER_ADDR_LEN);
            memcpy(ethernet_header->ether_dhost, dest_addr, ETHER_ADDR_LEN);
        }
        ethernet_header->ether_type = htons(ethertype_arp);
    /* If packet is an IP */
    } else if (type == 3 || type == 4) {
        if (type == 3) {
            len += sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + data_len;
        } else {
            len += sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        }
        ethernet_header = (sr_ethernet_hdr_t *) malloc(len);
        if (dest_addr == NULL) {
            int i;
            for (i = 0; i < ETHER_ADDR_LEN; i++) {
                ethernet_header->ether_dhost[i] = 255;
            }
        } else {
            memcpy(ethernet_header->ether_dhost, dest_addr, ETHER_ADDR_LEN);
        }
        memcpy(ethernet_header->ether_shost, src_addr, ETHER_ADDR_LEN);   
        ethernet_header->ether_type = htons(ethertype_ip); 
    }
    
    return (uint8_t *) ethernet_header;
}

void add_arp_request(uint8_t *ethernet_header, uint32_t src_ip, uint32_t tar_ip) {
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (ethernet_header + sizeof(sr_ethernet_hdr_t));
    arp_header->ar_hrd = htons(arp_hrd_ethernet);
    arp_header->ar_pro = htons(ethertype_ip);
    arp_header->ar_hln = 0x0006;
    arp_header->ar_pln = 0x0004;
    arp_header->ar_op = htons(arp_op_request);
    memcpy(arp_header->ar_sha, ((sr_ethernet_hdr_t *) ethernet_header)->ether_shost, ETHER_ADDR_LEN);
    arp_header->ar_sip = src_ip;
    arp_header->ar_tip = tar_ip;
}

void add_arp_reply(uint8_t *ethernet_header, unsigned char *src_addr, uint32_t src_ip, uint32_t tar_ip) {
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (ethernet_header + sizeof(sr_ethernet_hdr_t));
    arp_header->ar_hrd = htons(arp_hrd_ethernet);
    arp_header->ar_pro = htons(ethertype_ip);
    arp_header->ar_hln = 0x0006;
    arp_header->ar_pln = 0x0004;
    arp_header->ar_op = htons(arp_op_reply);
    memcpy(arp_header->ar_sha, src_addr, ETHER_ADDR_LEN);
    arp_header->ar_sip = src_ip;
    memcpy(arp_header->ar_tha, ((sr_ethernet_hdr_t *) ethernet_header)->ether_dhost, ETHER_ADDR_LEN);
    arp_header->ar_tip = tar_ip;
}

void add_ip_header(uint8_t *ethernet_header, uint32_t src_ip, uint32_t tar_ip, uint16_t len) {
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (ethernet_header + sizeof(sr_ethernet_hdr_t));
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(len);
    ip_header->ip_id = 0;
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = ip_protocol_icmp;
    ip_header->ip_sum = 0;
    ip_header->ip_src = src_ip;
    ip_header->ip_dst = tar_ip;

    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
}

void add_icmp_hdr(uint8_t *ethernet_header, uint8_t type, uint8_t icmp_code, uint8_t *ip_packet) {
    sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *) (ethernet_header + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_t3_hdr->icmp_type = type;
    icmp_t3_hdr->icmp_code = icmp_code;
    icmp_t3_hdr->icmp_sum = 0;

    /* Header is 20 bytes */
    memcpy(icmp_t3_hdr->data, ip_packet, 20);
    /* Shift 20 bytes over */
    uint8_t *data;
    data = icmp_t3_hdr->data + 20; 
    /* Shift IHL bytes over ip header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) ip_packet;
    ip_packet = ip_packet + 20;
    /*((ip_header->ip_hl * 32) / 8);*/
    /* Copy over 8 bytes of data */
    memcpy(data, ip_packet, 8);

    /* Calculate checksum */
    icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
}

void add_icmp_echo_header(uint8_t *eth_icmp_reply, uint8_t *packet, unsigned int len) {
    int offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);

    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (eth_icmp_reply + offset); 
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_type = 0; 
    icmp_hdr->icmp_sum = 0;
    memcpy(((uint8_t *) icmp_hdr) + 4, packet, len);
    icmp_hdr->icmp_sum = icmp_cksum(icmp_hdr, len + sizeof(sr_icmp_hdr_t));
}


void send_icmp_packet(struct sr_instance *sr, uint8_t type, uint8_t icmp_code, struct sr_if *interface, uint8_t *packet) {
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
    uint8_t *eth_icmp_pkt = create_ethernet_header(4, interface->addr, ethernet_header->ether_shost, 0);
    
    uint16_t ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);  

    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    if ((type == 11 && icmp_code == 0) || (type == 3 && (icmp_code == 1 || icmp_code == 0))) {
        add_ip_header(eth_icmp_pkt, interface->ip, ip_header->ip_src, ip_len);
    } else {
        add_ip_header(eth_icmp_pkt, ip_header->ip_dst, ip_header->ip_src, ip_len);
    }
    add_icmp_hdr(eth_icmp_pkt, type, icmp_code, (uint8_t *) ip_header);
    
    print_hdrs(eth_icmp_pkt, sizeof(sr_ethernet_hdr_t) + ip_len); 
    sr_send_packet(sr, eth_icmp_pkt, sizeof(sr_ethernet_hdr_t) + ip_len, interface->name);
    /*free(eth_icmp_pkt);*/
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request) {
    time_t curtime = time(0);
    if (difftime(curtime, request->sent) >= 1.0) {
        if (request->times_sent >= 5) {
            /* Send ICMP host unreachable to all waiting packets. */
            struct sr_packet *waiting_pkt;
            for (waiting_pkt = request->packets; waiting_pkt != NULL; waiting_pkt = waiting_pkt->next) {
                sr_ip_hdr_t *origin_ip = (sr_ip_hdr_t *) (waiting_pkt->buf + sizeof(sr_ethernet_hdr_t));
                struct sr_rt *route = find_lpm(sr->routing_table, origin_ip->ip_src);
                struct sr_if *incoming_pkt_if = sr_get_interface(sr, route->interface);
                send_icmp_packet(sr, 3, 1, incoming_pkt_if, waiting_pkt->buf); 
            };           
            /* Destroy request from cache */
            sr_arpreq_destroy(&sr->cache, request);
        } else {
            /* Create and send ARP request packet. */
            struct sr_if *if_to_origin = sr_get_interface(sr, request->packets->iface);
            uint8_t *eth_arp_request = create_ethernet_header(1, if_to_origin->addr, NULL, 0);
            add_arp_request(eth_arp_request, if_to_origin->ip, request->ip);                    
            
            print_hdrs(eth_arp_request, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            sr_send_packet(sr, eth_arp_request, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), request->packets->iface);
            free(eth_arp_request);

            request->sent = curtime;
            request->times_sent++;
        }
    }
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*
Function that is called when the IP packet is for me.
*/
void send_icmp_echo(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {	
	int offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    printf("Print ICMP request packet\n");
    print_hdrs(packet, len); 
    
    /* Info from request */
    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /* Get size of data from packet.*/
    int data_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);
    
    /* Shift packet to data */
    packet = packet + offset; 
	
    /*Setting up headers for sending echo reply*/
    struct sr_if *ckinterface = sr_get_interface(sr, interface);
    uint8_t *eth_icmp_reply = create_ethernet_header(3, ckinterface->addr, NULL, data_len);
    add_ip_header(eth_icmp_reply, ip_hdr->ip_dst, ip_hdr->ip_src, len - sizeof(sr_ethernet_hdr_t));
    add_icmp_echo_header(eth_icmp_reply, packet, data_len);
    
    printf("ICMP Packet to replay.\n");
    print_hdrs(eth_icmp_reply, len);
    struct sr_arpentry *arpentry;
    if ((arpentry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_src)) != NULL) {
        /*arp cache hit*/
        printf("ARP cache is hit\n");
        memcpy(((sr_ethernet_hdr_t *) eth_icmp_reply)->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, eth_icmp_reply, len, interface);
    } else {
        /*arp cache miss*/
        printf("ARP cache miss\n");
        struct sr_arpreq *newarpreq = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_src, eth_icmp_reply, len, interface);
        handle_arpreq(sr,newarpreq);
    }
}
/*end ip_packet_for_me*/


/*
Handles an IP packet when called by sr_handlepacket when an IP packet is dectected.
Determines if the packet is for me or not. Decrements TTL and recompute checksum if not,
then tries to figure out where to forward it.  
*/
void sr_handle_ip_packet(struct sr_instance* sr,
		uint8_t * packet,
		unsigned int len,
		char* interface)
{
	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *) packet;
	
	if (len < 20){
		fprintf(stderr, "IP Packet too small!");
		return;
	} 
	
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    if (ip_hdr->ip_sum != ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t))) { 
		fprintf(stderr, "IP Checksum is invalid!");
        return;
    }    

	uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
	
	struct sr_if *fetch_interface = ip_in_router(sr->if_list, ip_hdr->ip_dst); 
	struct sr_if *incoming_interface = sr_get_interface(sr, interface);
	
	if (fetch_interface == NULL) {
		printf("IP Packet is not for me.\n");
		/*TODO: ADD TTL handling: ip_hdr->ip_ttl--. then*/
		/*TTL Handling when forwarding the IP packet*/
        ip_hdr->ip_ttl -= 1;
		if (ip_hdr->ip_ttl <= 0) {
	        printf("TTL <=0, send type 11 icmp error.\n");
            send_icmp_packet(sr, 11, 0, incoming_interface, packet);            
        } else {
			/*Checking routing table*/
			/*Recompute check sum after decrementing TTL*/ 
			ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            struct sr_rt *rt_entry = find_lpm(sr->routing_table, ip_hdr->ip_dst);
			
			/*Found a rt entry*/
            if (rt_entry!= NULL) {		
				/*Checking arp cache*/
                print_addr_ip_int(ip_hdr->ip_dst);
                struct sr_arpentry *arpentry;
				if ((arpentry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst)) != NULL) {
					/*arp cache hit*/
                    printf("ARP cache is hit\n");
                    struct sr_if *pkt_iface = sr_get_interface(sr, rt_entry->interface);
                    memcpy(ether_hdr->ether_shost, pkt_iface->addr, ETHER_ADDR_LEN);
					memcpy(ether_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
					
                    print_hdrs(packet, len);
                    sr_send_packet(sr, packet, len, rt_entry->interface);
				} else {
					/*arp cache miss*/
                    printf("ARP cache miss\n");
					struct sr_arpreq *newarpreq = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, rt_entry->interface);
					handle_arpreq(sr,newarpreq);
				}								
			} else {
			    /*No entry in rt matches the destination address*/ 
				printf("---No matching in rt---\n");
                send_icmp_packet(sr, 3, 0, incoming_interface, packet);
            }
		}
	} else {
		printf("IP Packet is for me\n");
		if(ip_proto == ip_protocol_icmp){
            /*Case ICMP Echo*/
            sr_icmp_hdr_t *echo_request = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            printf("ICMP Packet?\n");
            print_hdrs(packet, len);
            printf("type: %d\n", echo_request->icmp_type);
            int total_pkt_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t); 
            if (echo_request->icmp_type == 8 && echo_request->icmp_sum == icmp_cksum(echo_request, total_pkt_len)) {
                printf("Packet is ICMP Echo request\n");
                
                send_icmp_echo(sr, packet, len, interface);
            }    
		} else if (ip_proto == 0x6 || ip_proto == 0x11) {
			printf("Packet is TCP or UDP\n");
            /*send icmp error packet here*/
            send_icmp_packet(sr, 3, 3, incoming_interface, packet);
        }
	}
	
	printf("**********************************************Done IP packet processing\n");
	
}/*end sr_handle_ip_packet*/


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /* fill in code here */
  	
  sr_ethernet_hdr_t *ethernet_packet = (sr_ethernet_hdr_t *) packet;
  struct sr_if *sr_interface = sr_get_interface(sr, interface);

  /*Check whether it is an IP or ARP here*/
  uint16_t ethrtype = ethertype(packet);
  printf("Starting to check packet: \n");
  if (ethrtype == ethertype_ip){
  	/*IP Forwarding and Handling IP packet*/
  	printf("---IP Forwarding---\n");
  	sr_handle_ip_packet(sr, packet, len, interface);
  } else if (ethrtype == ethertype_arp){
  	/*ARP Handling*/
	 printf("---ARP Handling---\n");
	/*Determine if it is a request or reply call*/
    sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    print_hdrs(packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    struct sr_if *search_interface;
    if ((search_interface = ip_in_router(sr->if_list, arp_packet->ar_tip)) != NULL) {        
        printf("ARP FOR US\n");
        /* Arp packet is a request */
        if (ntohs(arp_packet->ar_op) == arp_op_request) {
            printf("ARP request\n");
            uint8_t *eth_arp_reply = create_ethernet_header(2, sr_interface->addr, ethernet_packet->ether_shost, 0);  
            add_arp_reply(eth_arp_reply, search_interface->addr, arp_packet->ar_tip, arp_packet->ar_sip);    
                      
            print_addr_ip_int(arp_packet->ar_sip);
            sr_arpcache_insert(&sr->cache, ethernet_packet->ether_shost, arp_packet->ar_sip);
            sr_arpcache_dump(&sr->cache);
            
            printf("Printing ARP to reply\n");    
            print_hdrs(eth_arp_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            sr_send_packet(sr, eth_arp_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
            free(eth_arp_reply); 
        /* Arp packet is a reply */
        } else if (ntohs(arp_packet->ar_op) == arp_op_reply) {
            printf("ARP reply\n");
            printf("IP Adress to insert to cache.\n");
            print_addr_ip_int(arp_packet->ar_sip);
            struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, arp_packet->ar_sha, arp_packet->ar_sip);
            if (request != NULL) {
                struct sr_packet *packet;
                for (packet = request->packets; packet != NULL; packet = packet->next) {
                    struct sr_if *pkt_iface = sr_get_interface(sr, packet->iface);

                    memcpy(((sr_ethernet_hdr_t *) packet->buf)->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);
                    memcpy(((sr_ethernet_hdr_t *) packet->buf)->ether_shost, pkt_iface->addr, ETHER_ADDR_LEN);
                    
                    printf("Sending Packet since we got correct address now: \n");
                    print_hdrs(packet->buf, len);
                    sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                }
                sr_arpreq_destroy(&sr->cache, request);
            }
            sr_arpcache_dump(&sr->cache);
        }
    }  	
  } else {
  	/*No matching.*/
  	printf("---No matching---\n");
  }
}
/* end sr_ForwardPacket */

