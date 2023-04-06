#include <iostream>
#include <string.h>

// #include "include/queue.h"
#include "include/lib.h"
#include "include/protocols.h"
#include <arpa/inet.h>
#include <vector>
#include <queue>

class arp
{
private:
	std::vector<arp_entry> atable;

public:
	std::vector<arp_entry> *get_atable()
	{
		return &atable;
	}

	arp_entry *get_arp_entry(uint32_t __ip_dest__)
	{
		for (auto &e : atable)
		{
			if (__ip_dest__ == e.ip)
				return &e;
		}
		return nullptr;
	}

	void add_entry(arp_entry e)
	{
		atable.push_back(e);
	}
};

struct node {
	route_table_entry* data;
	node* __children__[2];
	node(route_table_entry* __data) {
		__children__[0] = nullptr;
		__children__[1] = nullptr;
		data = __data;
	}
};

class trie
{
private:
	node* root;
public:
	trie() {
		root = new node(nullptr);
	}

	/**
	 * The function adds a new route table entry to a tree data structure.
	 * 
	 * @param e The parameter "e" is a pointer to a route_table_entry struct.
	 */
	void add(route_table_entry* e)
	{
		uint32_t prefix = ntohl(e->prefix);
		uint32_t mask = ntohl(e->mask);

		node* cur = root;
		for (int i = 0; (i < 30) && (mask & (1 << 31)); i++)
		{
			if (!cur->__children__[(prefix & (1 << 31)) >> 31])
				cur->__children__[(prefix & (1 << 31)) >> 31] = new node(nullptr);
			cur = cur->__children__[(prefix & (1 << 31)) >> 31];
			prefix = prefix << 1;
			mask = mask << 1;
		}

		if (!cur->__children__[(prefix & (1 << 31)) >> 31])
			cur->__children__[(prefix & (1 << 31)) >> 31] = new node(e);
	}

	/**
	 * The function returns the best route for a given IP address by traversing a binary tree.
	 * 
	 * @param ip The parameter "ip" is a 32-bit unsigned integer representing an IP address.
	 * 
	 * @return The function `get_best_route` returns a pointer to a `route_table_entry` object, which
	 * represents the best matching route for the given IP address. If no matching route is found, it
	 * returns a null pointer.
	 */
	route_table_entry* get_best_route(uint32_t ip) {
		node* cur = root;
		while (cur)
		{
			if (!cur->__children__[(ip & (1 << 31)) >> 31])
				return cur->data;

			cur = cur->__children__[(ip & (1 << 31)) >> 31];
			ip = ip << 1;
		}
		return nullptr;
	}
};

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	route_table_entry *rtable = new route_table_entry[100000];
	int rtable_len = read_rtable(argv[1], rtable);

	arp *arp_table = new arp;

	trie* route_table = new trie;

	for (int i = 0; i < rtable_len; i++)
	{
		route_table->add(&rtable[i]);
	}

	std::queue<data> queue;

	while (1)
	{

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		ether_header *eth_hdr = (struct ether_header *)buf;

		if (ntohs(eth_hdr->ether_type) == 0x0806)
		{
			arp_header *arp_hdr = (arp_header *)(buf + sizeof(ether_header));

			uint32_t target_ip = 0;
			inet_aton(get_interface_ip(interface), (in_addr *)&(target_ip));

			uint8_t *aux = new uint8_t[6];
			get_interface_mac(interface, aux);

			/* This code block is handling the case where an ARP reply message is received. The condition checks
			if the target IP address in the ARP header matches the IP address of the interface on which the
			message was received and if the operation code is equal to 2 (ARP reply). If this condition is
			true, the ARP entry for the sender IP address and MAC address is added to the ARP table. If there
			are packets waiting in the queue to be sent, the first packet is retrieved and the MAC address of
			the sender is obtained from the ARP table. The MAC address of the sender is then used to update
			the destination MAC address in the Ethernet header of the packet, and the packet is sent to the
			interface on which the ARP reply was received. */
			if (target_ip == arp_hdr->tpa && ntohs(arp_hdr->op) == 2)
			{
				arp_table->add_entry(arp_entry(arp_hdr->spa, arp_hdr->sha));
				if (!queue.empty())
				{
					data __data = queue.front();
					queue.pop();
					arp_entry *a = arp_table->get_arp_entry(arp_hdr->spa);

					ether_header *eth_hdr = (ether_header *)__data.payload;

					memcpy(eth_hdr->ether_dhost, a->mac, 6);

					get_interface_mac(interface, eth_hdr->ether_shost);

					send_to_link(interface, __data.payload, __data.length);
					std::cout << "Packet sent to the next node\n";
				}
				continue;
			}

			/* This code block is handling the case where an ARP request message is received. The condition
			checks if the target IP address in the ARP header matches the IP address of the interface on
			which the message was received and if the operation code is equal to 1 (ARP request). If this
			condition is true, the ARP header is modified to create an ARP reply message, the destination MAC
			address in the Ethernet header is set to the source MAC address, the source MAC address in the
			Ethernet header is set to the MAC address of the interface on which the message was received, and
			the packet is sent back to the sender using the `send_to_link` function. */
			if (target_ip == arp_hdr->tpa && ntohs(arp_hdr->op) == 1)
			{
				arp_hdr->set_arp_header(2, eth_hdr->ether_shost, arp_hdr->tpa, arp_hdr->sha, arp_hdr->spa);
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				get_interface_mac(interface, eth_hdr->ether_shost);
				memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);
			}

			send_to_link(interface, buf, len);
			std::cout << "ARP reply sent\n";
			continue;
		}

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if (ntohs(eth_hdr->ether_type) == 0x0800)
		{
			iphdr *ip_hdr = (iphdr *)(buf + sizeof(ether_header));

			icmphdr *icmp_hdr = (icmphdr *)(buf + sizeof(ether_header) + sizeof(iphdr));

			uint16_t check_sum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			uint16_t sum_ok = (check_sum == checksum((uint16_t *)ip_hdr, sizeof(iphdr)));
			if (!sum_ok)
			{
				std::cout << "Wrong checksum\n";
				continue;
			}

			in_addr *aux = new in_addr;
			inet_aton(get_interface_ip(interface), aux);

			/* This code block is handling the case where the received packet is an ICMP Echo Request (ping)
			message sent to the router itself. It creates a new packet with an Ethernet header, an IP header,
			and an ICMP header, sets the appropriate fields in these headers to create an ICMP Echo Reply
			message, calculates the checksums, and sends the packet back to the source interface using the
			`send_to_link` function. The `delete aux` statement is freeing the memory allocated for the
			`in_addr` structure used to store the IP address of the interface. */
			if (ip_hdr->daddr == aux->s_addr && icmp_hdr->type == 0x8 && icmp_hdr->code == 0x0)
			{

				icmp_hdr->type = 0x0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, htons(ip_hdr->tot_len) - sizeof(iphdr)));

				eth_hdr->set_ether_header(eth_hdr->ether_shost, eth_hdr->ether_dhost, eth_hdr->ether_type);

				ip_hdr->daddr = ip_hdr->saddr;
				inet_aton(get_interface_ip(interface), (in_addr *)&(ip_hdr->saddr));
				ip_hdr->ttl = 255;
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(iphdr)));

				send_to_link(interface, buf, len);
				std::cout << "Echo ping reply sent\n";
				delete aux;
				continue;
			}
			delete aux;

			route_table_entry *route = route_table->get_best_route(ntohl(ip_hdr->daddr));

			/* This code block is handling the case where there is no route in the routing table for the
			destination IP address of the received packet. In this case, an ICMP Destination Unreachable
			message needs to be sent back to the source of the packet. The code creates a new packet with an
			Ethernet header, an IP header, and an ICMP header, sets the appropriate fields in these headers,
			calculates the checksums, and sends the packet back to the source interface using the
			`send_to_link` function. */
			if (route == nullptr)
			{

				ip_hdr->check = htons(check_sum);

				char *dest_unreachable = new char[MAX_PACKET_LEN];

				ether_header *to_eth_hdr = (ether_header *)dest_unreachable;
				iphdr *to_ip_hdr = (iphdr *)(dest_unreachable + sizeof(ether_header));
				icmphdr *to_icmp_hdr = (icmphdr *)(dest_unreachable + sizeof(iphdr) + sizeof(ether_header));

				to_eth_hdr->set_ether_header(eth_hdr->ether_shost, eth_hdr->ether_dhost, eth_hdr->ether_type);

				to_ip_hdr->set_iphdr(ip_hdr->saddr);

				inet_aton(get_interface_ip(interface), (in_addr *)&(to_ip_hdr->saddr));
				to_ip_hdr->check = htons(checksum((uint16_t *)to_ip_hdr, sizeof(iphdr)));

				to_icmp_hdr->set_icmphdr(0x3, ip_hdr);
				to_icmp_hdr->checksum = htons(checksum((uint16_t *)to_icmp_hdr, sizeof(icmphdr) + 8 + sizeof(iphdr)));

				send_to_link(interface, dest_unreachable, sizeof(ether_header) + 2 * sizeof(iphdr) + sizeof(icmphdr) + 8);
				std::cout << "Destination unreachable sent\n";
				delete[] dest_unreachable;
				continue;
			}

			/* This code block is handling the case where the time-to-live (TTL) field in the IP header of a
			received packet has reached 1 or less. In this case, the packet cannot be forwarded any further
			and an ICMP Time Exceeded message needs to be sent back to the source of the packet. */
			if (ip_hdr->ttl <= 1)
			{

				ip_hdr->check = htons(check_sum);

				char *icmp_timeout = new char[MAX_PACKET_LEN];

				ether_header *to_eth_hdr = (ether_header *)icmp_timeout;
				iphdr *to_ip_hdr = (iphdr *)(icmp_timeout + sizeof(ether_header));
				icmphdr *to_icmp_hdr = (icmphdr *)(icmp_timeout + sizeof(iphdr) + sizeof(ether_header));

				to_eth_hdr->set_ether_header(eth_hdr->ether_shost, eth_hdr->ether_dhost, eth_hdr->ether_type);

				to_ip_hdr->set_iphdr(ip_hdr->saddr);

				inet_aton(get_interface_ip(interface), (in_addr *)&(to_ip_hdr->saddr));
				to_ip_hdr->check = htons(checksum((uint16_t *)to_ip_hdr, sizeof(iphdr)));

				to_icmp_hdr->set_icmphdr(0xb, ip_hdr);
				to_icmp_hdr->checksum = htons(checksum((uint16_t *)to_icmp_hdr, sizeof(icmphdr) + 8 + sizeof(iphdr)));

				send_to_link(interface, icmp_timeout, sizeof(ether_header) + 2 * sizeof(iphdr) + sizeof(icmphdr) + 8);
				std::cout << "ICMP_Timeout sent\n";
				delete[] icmp_timeout;
				continue;
			}

			/* These lines of code are decrementing the time-to-live (TTL) field in the IP header of a received
			packet by 1, recalculating the IP header checksum, and updating the checksum field in the IP
			header with the new value. The TTL field is used to limit the lifetime of a packet in the network
			and prevent it from circulating indefinitely. When the TTL field reaches 0, the packet is
			discarded and an ICMP Time Exceeded message is sent back to the source of the packet. */
			ip_hdr->ttl -= 1;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(iphdr)));


			arp_entry *a = arp_table->get_arp_entry(route->next_hop);

			/* This code block is handling the case where the ARP entry for the next hop of a received packet is
			not present in the ARP table. In this case, an ARP request needs to be sent to the network to
			obtain the MAC address of the next hop. The code creates a new packet with an Ethernet header and
			an ARP header, sets the appropriate fields in these headers to create an ARP request message, and
			sends the packet to the interface corresponding to the route. The original packet is saved in a
			queue to be sent later, after the ARP reply is received. */
			if (a == nullptr)
			{
				char *keep = new char[len];
				memcpy(keep, buf, len);
				queue.push(data(keep, len));

				char *arp_request = new char[sizeof(ether_header) + sizeof(arp_header)];
				ether_header *a_eth_hdr = (ether_header *)arp_request;
				memset(a_eth_hdr->ether_dhost, 0xff, 6);
				get_interface_mac(route->interface, a_eth_hdr->ether_shost);
				a_eth_hdr->ether_type = htons(0x0806);

				arp_header *a_arp_hdr = (arp_header *)(arp_request + sizeof(ether_header));

				uint32_t interface_ip = 0;
				inet_aton(get_interface_ip(route->interface), (in_addr *)&(interface_ip));

				a_arp_hdr->set_arp_header(1, a_eth_hdr->ether_shost, interface_ip, a_eth_hdr->ether_shost, route->next_hop);
				memset(a_arp_hdr->tha, 0xff, 6);

				send_to_link(route->interface, arp_request, sizeof(ether_header) + sizeof(arp_header));
				std::cout << "ARP request sent\n";
				continue;
			}

			memcpy(eth_hdr->ether_dhost, a->mac, 6);

			get_interface_mac(interface, eth_hdr->ether_shost);
			send_to_link(route->interface, buf, len);
			std::cout << "Packet sent to next node\n";
		}
	}
}