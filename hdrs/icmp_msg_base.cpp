/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp_msg_base.cpp                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Pablo Escobar <sataniv.rider@gmail.com>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/20 23:16:52 by Pablo Escob       #+#    #+#             */
/*   Updated: 2025/10/20 23:45:10 by Pablo Escob      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "icmp_msg_base.hpp"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

Icmp_msg_base::Icmp_msg_base(iphdr_t* ip_router, icmphdr_t* icmp_header) :
	_ip_router(ip_router),
	_icmp_hdr(icmp_header),
	_ip_hdr_size(0)
{
	if (_ip_router)
		_ip_hdr_size = calculate_ip_hdr_size(_ip_router);
}

Icmp_msg_base::Icmp_msg_base(uint8_t* raw_data, size_t data_size)
{
	if (raw_data && data_size >= (_ip_hdr_size + ICMP_HEADER_SIZE))
	{
		_ip_router = reinterpret_cast<iphdr_t *>(raw_data);
		_ip_hdr_size = calculate_ip_hdr_size(_ip_router);
		_icmp_hdr = reinterpret_cast<icmphdr_t *>(raw_data + _ip_hdr_size);
	}
	else
	{
		_ip_router = nullptr;
		_icmp_hdr = nullptr;
		_ip_hdr_size = 0;
	}
}

int Icmp_msg_base::calculate_ip_hdr_size(iphdr_t* ip_header)
{
	if (!ip_header)
		return -1;
	return ip_header->ihl * 4;
}
