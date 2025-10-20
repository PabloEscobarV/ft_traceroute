/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp_msg_base.hpp                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Pablo Escobar <sataniv.rider@gmail.com>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/20 22:54:12 by Pablo Escob       #+#    #+#             */
/*   Updated: 2025/10/20 23:45:07 by Pablo Escob      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <cstdint>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


using iphdr_t = struct iphdr;
using icmphdr_t = struct icmphdr;

class Icmp_msg_base
{
	int _ip_hdr_size;

protected:
	const int ICMP_HEADER_SIZE = sizeof(icmphdr_t);

	iphdr_t*		_ip_router;
	icmphdr_t*	_icmp_hdr;
	int 				calculate_ip_hdr_size(iphdr_t* ip_header);
	
public:
	Icmp_msg_base(iphdr_t* ip_router = nullptr, icmphdr_t* icmp_header = nullptr);
	Icmp_msg_base(uint8_t* raw_data, size_t data_size);
	virtual ~Icmp_msg_base();
	
	inline iphdr_t*		get_ip_router_hdr() const { return _ip_router; }
	inline icmphdr_t*	get_icmp_hdr() const { return _icmp_hdr; }
	inline int				get_ip_header_size() const { return _ip_hdr_size; }
	inline int				get_icmp_header_size() const { return ICMP_HEADER_SIZE; }
	inline int				get_base_hdr_size() const { return _ip_hdr_size + ICMP_HEADER_SIZE; }
};
