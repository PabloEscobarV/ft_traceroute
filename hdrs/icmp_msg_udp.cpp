/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp_msg_udp.cpp                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Pablo Escobar <sataniv.rider@gmail.com>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/20 23:31:34 by Pablo Escob       #+#    #+#             */
/*   Updated: 2025/10/20 23:45:23 by Pablo Escob      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "icmp_msg_udp.hpp"

Icmp_msg_udp::Icmp_msg_udp(iphdr_t* ip_router,
														icmphdr_t* icmp_header,
														iphdr_t* ip_original,
														udphdr_t* udp_original) :
	Icmp_msg_base(ip_router, icmp_header),
	_ip_original(ip_original),
	_udp_original(udp_original)
{
	if (_ip_original)
		_ip_hdr_size = calculate_ip_hdr_size(_ip_original);
}

Icmp_msg_udp::Icmp_msg_udp(uint8_t* raw_data, size_t data_size) :
	Icmp_msg_base(raw_data, data_size),
	_ip_original(nullptr),
	_udp_original(nullptr)
{
	int base_hdr_size = get_base_hdr_size();

	if (raw_data && data_size >= (base_hdr_size + _ip_hdr_size + UDP_HEADER_SIZE))
	{
		_ip_original = reinterpret_cast<iphdr_t *>(raw_data + base_hdr_size);
		_ip_hdr_size = calculate_ip_hdr_size(_ip_original);
		_udp_original = reinterpret_cast<udphdr_t *>(raw_data + base_hdr_size + _ip_hdr_size);
	}
	else
	{
		_ip_original = nullptr;
		_udp_original = nullptr;
		_ip_hdr_size = 0;
	}
}
