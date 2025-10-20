/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_traceroute.cpp                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Pablo Escobar <sataniv.rider@gmail.com>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 21:15:11 by Pablo Escob       #+#    #+#             */
/*   Updated: 2025/10/20 22:52:58 by Pablo Escob      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <chrono>

#define BUFFER_SIZE 64
#define BASE_PORT 33434

using namespace std;
using sockaddr_in_t = struct sockaddr_in;
using addrinfo_t = struct addrinfo;
using iphdr_t = struct iphdr;
using icmphdr_t = struct icmphdr;
using udphdr_t = struct udphdr;

enum e_icmp_t
{
	E_ICMP_ERR = -1,
	E_ICMP_TTL,
	E_ICMP_REACHED,
};

struct socket_fd_t
{
	int udp_send_fd;
	int icmp_recv_fd;
	socket_fd_t(int send_fd = 0, int receive_fd = 0) : udp_send_fd(send_fd), icmp_recv_fd(receive_fd) {}
};

struct payload_t
{
	int ttl;
	payload_t(int t = 0) : ttl(t) {}
};

struct icmp_te_t
{
	iphdr_t *ip_router_hdr;
	iphdr_t *ip_original_hdr;
	udphdr_t *udp_original_hdr;
	icmphdr_t *icmp_header;
	payload_t payload;
	icmp_te_t() : ip_router_hdr(nullptr),
								ip_original_hdr(nullptr),
								udp_original_hdr(nullptr),
								icmp_header(nullptr) {}
};

void send_udp(sockaddr_in_t& addr, int send_fd, int base_port, int ttl)
{
	payload_t payload(ttl);

	if (send_fd < 0 || ttl < 1)
	{
		perror("socket");
		return ;
	}
	addr.sin_port = htons(base_port + ttl);
	setsockopt(send_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	sendto(send_fd, &payload, sizeof(payload), 0, (struct sockaddr *)&addr, sizeof(addr));
	// cout << "Debug: sndt: TTL: " << ttl << endl;
}

bool	wait_icmp(int icmp_fd, int timeout_sec, int timeout_usec)
{
	fd_set icmp_fds;
	struct timeval timeout;

	FD_ZERO(&icmp_fds);
	FD_SET(icmp_fd, &icmp_fds);
	timeout.tv_sec = timeout_sec;
	timeout.tv_usec = timeout_usec;
	return select(icmp_fd + 1, &icmp_fds, nullptr, nullptr, &timeout) > 0;
}

int recieve_icmp(sockaddr_in_t& addr, int icmp_fd, char *buffer, int size = BUFFER_SIZE)
{
	sockaddr_in_t recv_addr;
	socklen_t addr_len = sizeof(recv_addr);
	int received_size = 0;

	if (icmp_fd < 0)
	{
		perror("socket");
		return -1;
	}
	if (wait_icmp(icmp_fd, 1, 0))
	{
		received_size = recvfrom(icmp_fd, buffer, size, 0, (struct sockaddr *)&recv_addr, &addr_len);
	}
	return received_size;
}

void print_bits(char* buffer, int size)
{
	for (int i = 0; i < size; ++i)
	{
		for (int j = 0; j < 8; ++j)
			if (buffer[i] & (1 << j))
				cout << "1";
			else
				cout << "0";
			cout << " ";
		if ((i + 1) % 4 == 0)
			cout << "\t";
		if ((i + 1) % 8 == 0)
			cout << endl;
	}
	cout << endl;
}

payload_t get_payload(char* buffer)
{
	payload_t data;

	data.ttl = 0;
	memcpy(&data, buffer, sizeof(data));
	return data;
}

icmp_te_t* parse_icmp_message(char* buffer, int data_size)
{
	icmp_te_t* icmp_msg = new icmp_te_t();
	int icmp_hdr_offset = 0;
	int ip_orig_hdr_offset = 0;
	int udp_orig_hdr_offset = 0;
	int payload_offset = 0;

	if (!buffer)
		return nullptr;
	icmp_msg->ip_router_hdr = reinterpret_cast<iphdr_t *>(buffer);
	icmp_hdr_offset = icmp_msg->ip_router_hdr->ihl * 4;
	icmp_msg->icmp_header = reinterpret_cast<icmphdr_t *>(buffer + icmp_hdr_offset);
	ip_orig_hdr_offset = icmp_hdr_offset + sizeof(icmphdr_t);
	icmp_msg->ip_original_hdr = reinterpret_cast<iphdr_t *>(buffer + ip_orig_hdr_offset);
	udp_orig_hdr_offset = ip_orig_hdr_offset + icmp_msg->ip_original_hdr->ihl * 4;
	icmp_msg->udp_original_hdr = reinterpret_cast<udphdr_t *>(buffer + udp_orig_hdr_offset);
	payload_offset = udp_orig_hdr_offset + sizeof(udphdr_t);
	if (payload_offset < data_size)
		icmp_msg->payload = get_payload(buffer + payload_offset);
	return icmp_msg;
}

e_icmp_t check_icmp_answer(icmp_te_t& icmp_msg, sockaddr_in_t& addr, int base_port, int ttl)
{
	if (icmp_msg.ip_original_hdr->daddr == addr.sin_addr.s_addr
			&& icmp_msg.udp_original_hdr->dest == htons(base_port + ttl))
	{
		if (icmp_msg.icmp_header->type == ICMP_TIME_EXCEEDED && icmp_msg.icmp_header->code == ICMP_EXC_TTL)
			return E_ICMP_TTL;
		if (icmp_msg.icmp_header->type == ICMP_DEST_UNREACH && icmp_msg.icmp_header->code == ICMP_PORT_UNREACH)
			return E_ICMP_REACHED;
	}
	return E_ICMP_ERR;
}

string get_ip_to_str(addrinfo& addr_info)
{
	string ip_address;
	void *addr;

	addr = &reinterpret_cast<sockaddr_in_t *>(addr_info.ai_addr)->sin_addr;
	ip_address = inet_ntoa(*reinterpret_cast<struct in_addr *>(addr));
	return ip_address;
}

addrinfo_t* get_addrinfo(string hostname, string service)
{
	struct addrinfo hints;
	struct addrinfo *addr_info;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if (getaddrinfo(hostname.c_str(), service.c_str(), &hints, &addr_info) != 0)
	{
		perror("getaddrinfo");
		return nullptr;
	}
	return addr_info;
}

socket_fd_t create_sockets()
{
	return socket_fd_t(socket(AF_INET, SOCK_DGRAM, 0), socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
}

char* ip_to_hostname(uint32_t ip_addr)
{
	sockaddr_in_t addr;
	char* buffer = new char[NI_MAXHOST];

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip_addr;
	addr.sin_port = 0;
	if (getnameinfo(reinterpret_cast<struct sockaddr *>(&addr),
			sizeof(addr), buffer, NI_MAXHOST, nullptr, 0, 0) == 0)
		return buffer;
	delete[] buffer;
	return nullptr;
}

void print_icmp_info(icmp_te_t& icmp_msg, int ttl)
{
	char* hostname = ip_to_hostname(icmp_msg.ip_router_hdr->saddr);
	in_addr ip_addr {};
	
	ip_addr.s_addr= icmp_msg.ip_router_hdr->saddr;
	cout << "HOP IP[" << ttl << "]: " << inet_ntoa(ip_addr);
	if (hostname)
		cout << " [" << hostname << "]";
	cout << endl;
	delete[] hostname;
}

void handle_icmp_data(icmp_te_t icmp_msg, char* buffer, const int msg_len)
{
	icmp_msg = parse_icmp_message(buffer, msg_len);
	icmp_status = check_icmp_answer(*icmp_msg, addr, base_port, ttl);
	if (icmp_status == E_ICMP_REACHED)
		break;
	if (icmp_status == E_ICMP_TTL)
		print_icmp_info(*icmp_msg, ttl);
}

void proccess_icmp_msg(socket_fd_t& sockets, sockaddr_in_t& addr, int base_port, int max_ttl = 30)
{
	const int buffer_size = BUFFER_SIZE;
	icmp_te_t* icmp_msg = nullptr;
	char *buffer = new char[buffer_size];
	e_icmp_t icmp_status;
	int msg_len = 0;

	for (int ttl = 1; ttl < max_ttl; ++ttl)
	{
		send_udp(addr, sockets.udp_send_fd, base_port, ttl);
		msg_len = recieve_icmp(addr, sockets.icmp_recv_fd, buffer, buffer_size);
		if (msg_len > 0)
		{
			icmp_msg = parse_icmp_message(buffer, msg_len);
			icmp_status = check_icmp_answer(*icmp_msg, addr, base_port, ttl);
			if (icmp_status == E_ICMP_REACHED)
				break;
			if (icmp_status == E_ICMP_TTL)
				print_icmp_info(*icmp_msg, ttl);
		}
		delete icmp_msg;
		memset(buffer, 0, buffer_size);
	}
	delete[] buffer;
}

void get_ttl_answer(string hostname, string service, int base_port, int max_ttl = 30)
{
	socket_fd_t sockets = create_sockets();
	addrinfo_t *addrinfo = get_addrinfo(hostname, service);
	sockaddr_in_t *addr = nullptr;
	char *buffer = nullptr;

	if (!addrinfo)
		return ;
	addr = reinterpret_cast<sockaddr_in_t *>(addrinfo->ai_addr);
	proccess_icmp_msg(sockets, *addr, base_port, max_ttl);
	freeaddrinfo(addrinfo);
}

string get_ip(string hostname, string service)
{
	addrinfo_t* addrinfo = get_addrinfo(hostname, service);
	if (!addrinfo)
		return "";
	string ip = get_ip_to_str(*addrinfo);
	freeaddrinfo(addrinfo);
	return ip;
}

int main()
{
	const int max_ttl = 30;
	string hostname = "www.example.com";
	string service = "http";
	string ip;

	cout << "Enter hostname: ";
	getline(cin, hostname);
	cout << "Enter service (port): ";
	getline(cin, service);
	ip = get_ip(hostname, service);
	if (!ip.empty())
		cout << "IP address of " << hostname << ": " << ip << endl;
	else
		cout << "Could not resolve hostname." << endl;
	get_ttl_answer(hostname, service, BASE_PORT, max_ttl);
	return 0;
}