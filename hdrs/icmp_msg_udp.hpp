/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp_msg_udp.hpp                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Pablo Escobar <sataniv.rider@gmail.com>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/20 23:18:34 by Pablo Escob       #+#    #+#             */
/*   Updated: 2025/10/20 23:40:05 by Pablo Escob      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include "icmp_msg_base.hpp"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

using udphdr_t = struct udphdr;

class Icmp_msg_udp : public Icmp_msg_base
{
	int _ip_hdr_size;
	
protected:
	static const int UDP_HEADER_SIZE = sizeof(udphdr_t);

	iphdr_t*	_ip_original;
	udphdr_t*	_udp_original;

public:
	Icmp_msg_udp(iphdr_t* ip_router = nullptr,
							icmphdr_t* icmp_header = nullptr,
							iphdr_t* ip_original = nullptr,
							udphdr_t* udp_original = nullptr);
	Icmp_msg_udp(uint8_t* raw_data, size_t data_size);
	virtual ~Icmp_msg_udp();
	inline iphdr_t*		get_ip_original_hdr() const { return _ip_original; }
	inline udphdr_t*	get_udp_original_hdr() const { return _udp_original; }
	inline int				get_udp_header_size() const { return UDP_HEADER_SIZE; }
};
