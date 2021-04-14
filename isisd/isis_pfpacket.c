/*
 * IS-IS Rout(e)ing protocol - isis_pfpacket.c
 *
 * Copyright (C) 2001,2002    Sampo Saaristo
 *                            Tampere University of Technology
 *                            Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#if ISIS_METHOD == ISIS_METHOD_PFPACKET
#include <net/ethernet.h> /* the L2 protocols */
#include <netpacket/packet.h>

#include <linux/filter.h>

#include "log.h"
#include "network.h"
#include "stream.h"
#include "if.h"
#include "lib_errors.h"
#include "vrf.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isisd.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_network.h"
#include "isisd/isis_tlvs.h"

#include "privs.h"

#define PORT 8080

/* tcpdump -i eth0 'isis' -dd */
static const struct sock_filter isisfilter[] = {
	/* NB: we're in SOCK_DGRAM, so src/dst mac + length are stripped
	 * off!
	 * (OTOH it's a bit more lower-layer agnostic and might work
	 * over GRE?) */
	/*	{ 0x28, 0, 0, 0x0000000c - 14 }, */
	/*	{ 0x25, 5, 0, 0x000005dc }, */
	{0x28, 0, 0, 0x0000000e - 14}, {0x15, 0, 3, 0x0000fefe},
	{0x30, 0, 0, 0x00000011 - 14}, {0x15, 0, 1, 0x00000083},
	{0x6, 0, 0, 0x00040000},       {0x6, 0, 0, 0x00000000},
};

static const struct sock_fprog bpf = {
	.len = array_size(isisfilter),
	.filter = (struct sock_filter *)isisfilter,
};

/*
 * Table 9 - Architectural constants for use with ISO 8802 subnetworks
 * ISO 10589 - 8.4.8
 */

static const uint8_t ALL_L1_ISS[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x14};
static const uint8_t ALL_L2_ISS[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x15};
static const uint8_t ALL_ISS[6] = {0x09, 0x00, 0x2B, 0x00, 0x00, 0x05};
static const uint8_t ALL_ESS[6] = {0x09, 0x00, 0x2B, 0x00, 0x00, 0x04};

static uint8_t discard_buff[8192];

/*
 * if level is 0 we are joining p2p multicast
 * FIXME: and the p2p multicast being ???
 */
static int isis_multicast_join(int fd, int registerto, int if_num)
{
	struct packet_mreq mreq;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = if_num;
	if (registerto) {
		mreq.mr_type = PACKET_MR_MULTICAST;
		mreq.mr_alen = ETH_ALEN;
		if (registerto == 1)
			memcpy(&mreq.mr_address, ALL_L1_ISS, ETH_ALEN);
		else if (registerto == 2)
			memcpy(&mreq.mr_address, ALL_L2_ISS, ETH_ALEN);
		else if (registerto == 3)
			memcpy(&mreq.mr_address, ALL_ISS, ETH_ALEN);
		else
			memcpy(&mreq.mr_address, ALL_ESS, ETH_ALEN);

	} else {
		mreq.mr_type = PACKET_MR_ALLMULTI;
	}
#ifdef EXTREME_DEBUG
	zlog_debug(
		"isis_multicast_join(): fd=%d, reg_to=%d, if_num=%d, address = %02x:%02x:%02x:%02x:%02x:%02x",
		fd, registerto, if_num, mreq.mr_address[0], mreq.mr_address[1],
		mreq.mr_address[2], mreq.mr_address[3], mreq.mr_address[4],
		mreq.mr_address[5]);
#endif /* EXTREME_DEBUG */
	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
		       sizeof(struct packet_mreq))) {
		zlog_warn("isis_multicast_join(): setsockopt(): %s",
			  safe_strerror(errno));
		return ISIS_WARNING;
	}

	return ISIS_OK;
}

static int open_packet_socket(struct isis_circuit *circuit)
{
	struct sockaddr_ll s_addr;
	int fd, retval = ISIS_OK;
	struct vrf *vrf = NULL;

	vrf = vrf_lookup_by_id(circuit->interface->vrf_id);

	if (vrf == NULL) {
		zlog_warn("open_packet_socket(): failed to find vrf node");
		return ISIS_WARNING;
	}

	fd = vrf_socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL),
			circuit->interface->vrf_id, vrf->name);

	if (fd < 0) {
		zlog_warn("open_packet_socket(): socket() failed %s",
			  safe_strerror(errno));
		return ISIS_WARNING;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) {
		zlog_warn("open_packet_socket(): SO_ATTACH_FILTER failed: %s",
			  safe_strerror(errno));
	}

	/*
	 * Bind to the physical interface
	 */
	memset(&s_addr, 0, sizeof(struct sockaddr_ll));
	s_addr.sll_family = AF_PACKET;
	s_addr.sll_protocol = htons(ETH_P_ALL);
	s_addr.sll_ifindex = circuit->interface->ifindex;

	if (bind(fd, (struct sockaddr *)(&s_addr), sizeof(struct sockaddr_ll))
	    < 0) {
		zlog_warn("open_packet_socket(): bind() failed: %s",
			  safe_strerror(errno));
		close(fd);
		return ISIS_WARNING;
	}

	circuit->fd = fd;

	if (if_is_broadcast(circuit->interface)) {
		/*
		 * Join to multicast groups
		 * according to
		 * 8.4.2 - Broadcast subnetwork IIH PDUs
		 * FIXME: is there a case only one will fail??
		 */
		/* joining ALL_L1_ISS */
		retval |= isis_multicast_join(circuit->fd, 1,
					      circuit->interface->ifindex);
		/* joining ALL_L2_ISS */
		retval |= isis_multicast_join(circuit->fd, 2,
					      circuit->interface->ifindex);
		/* joining ALL_ISS (used in RFC 5309 p2p-over-lan as well) */
		retval |= isis_multicast_join(circuit->fd, 3,
					      circuit->interface->ifindex);
	} else {
		retval = isis_multicast_join(circuit->fd, 0,
					     circuit->interface->ifindex);
	}

	return retval;
}

/*
* fonction called by the thread to 
* open the connection
*/
int open_connection(struct thread *thread)
{
	struct isis_circuit *circuit;
	struct sockaddr_in address;
	int addrlen = sizeof(address);
	int connected_tcp_socket;

	//getting the circuit
	printf("GETTING INPUT ON TCP SOCKET \n");
	circuit = THREAD_ARG(thread);
	assert(circuit);
	if((connected_tcp_socket = accept(circuit->tcp_fd, (struct sockaddr *)&address, 
									  (socklen_t*)&addrlen)) < 0){
		zlog_debug("ERROR with connect\n");
		return ISIS_WARNING;
	}
	/*if(fcntl(connected_tcp_socket, F_SETFL, O_NONBLOCK) == -1){
		zlog_debug("EROOR fcntl %s", safe_strerror(errno));
		return ISIS_WARNING;
	}*/
	circuit->tcp_fd = connected_tcp_socket;
	circuit->tcp_connected = true;
	thread_add_read(master, isis_tcp_receive, circuit, circuit->tcp_fd, NULL);
	circuit->not_listening = false;
	return ISIS_OK;
}

/*
* function used to open the tcp socket
*/
static int open_tcp_socket(struct isis_circuit *circuit)
{
	//TODO better to do a check of the validity of the ip
	if(strcmp(circuit->interface->name, "enp0s10") != 0){
		printf("pas enp0s10\n");
		return ISIS_OK;
	}
	struct sockaddr_in servaddr;
	int tcp_sock, retval = ISIS_OK;
	struct vrf *vrf = NULL;
	int opt = TRUE;

	vrf = vrf_lookup_by_id(circuit->interface->vrf_id);

	if (vrf == NULL) {
		zlog_warn("open_packet_socket(): failed to find vrf node");
		return ISIS_WARNING;
	}

	tcp_sock = vrf_socket(AF_INET, SOCK_STREAM, 0, 
						 circuit->interface->vrf_id, vrf->name);

	if( tcp_sock < 0){
		zlog_warn("open_tcp_socket failed: %s", safe_strerror(errno));
		return ISIS_WARNING;
	}

	if( setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt))){
		zlog_warn("open_tcp_socket(): setsockopt failed: %s",
			  safe_strerror(errno));
		return ISIS_WARNING;
	}

	/*getting the ip address of the interface */
	//TODO faire socket non bloquant
	char ip_address[15];
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
	printf("getting ip for %s\n", circuit->interface->name);
	strncpy(ifr.ifr_name, circuit->interface->name, IFNAMSIZ-1);
	ioctl(tcp_sock, SIOCGIFADDR, &ifr);
	strcpy(ip_address,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	printf("IP address is : %s\n", ip_address);

	/* bind to physical address */
	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(ip_address);
	servaddr.sin_port = 0;//htons(PORT);
	if( bind(tcp_sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0){
		zlog_warn("open_tcp_socket(): bind() failed: %s",
			  safe_strerror(errno));
		close(tcp_sock);
		return ISIS_WARNING;		
	}
	unsigned int len = sizeof(servaddr);
	if( getsockname(tcp_sock,(struct sockaddr*)&servaddr, &len) != 0){
		zlog_warn("error getsockname : %s\n", safe_strerror(errno));
		return ISIS_WARNING;
	}
	circuit->tcp_port = ntohs(servaddr.sin_port);
	printf("port : %u \n",circuit->tcp_port);

	// 5 is the max queue for pending connection
	if(listen(tcp_sock, 5) != 0){
		zlog_warn("error listen... \n");
		return ISIS_WARNING;
	}

	circuit->tcp_fd = tcp_sock;
	thread_add_read(master, open_connection, circuit, tcp_sock, NULL);

	return retval;

}

/*
* open a tcp connection
*/
void open_tcp_connection(struct isis_item_list *addresse, struct isis_circuit *circuit)
{
	struct sockaddr_in servaddr;
	struct isis_ipv4_address *address = (struct isis_ipv4_address *)addresse;

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd == -1){
		zlog_warn("socket creation failed in open_tcp_connection...\n");
		return;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("10.10.10.3");// TODO address->addr;
	servaddr.sin_port = htons(circuit->tcp_port);

	if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0){
		zlog_warn("Connection with the server failed... \n");
		return;
	}

	circuit->tcp_fd = sockfd;
	circuit->tcp_connected = true;
	thread_add_read(master, isis_tcp_receive, circuit, circuit->tcp_fd, &circuit->t_read);
	circuit->not_listening = false;
}

/*
 * Create the socket and set the tx/rx funcs
 */
int isis_sock_init(struct isis_circuit *circuit)
{
	int retval = ISIS_OK;

	frr_with_privs(&isisd_privs) {

		retval = open_packet_socket(circuit);

		if (retval != ISIS_OK) {
			zlog_warn("%s: could not initialize the socket",
				  __func__);
			break;
		}

	/* Assign Rx and Tx callbacks are based on real if type */
		if (if_is_broadcast(circuit->interface)) {
			circuit->tx = isis_send_pdu_bcast;
			circuit->rx = isis_recv_pdu_bcast;
		} else if (if_is_pointopoint(circuit->interface)) {
			circuit->tx = isis_send_pdu_p2p;
			circuit->rx = isis_recv_pdu_p2p;
		} else {
			zlog_warn("isis_sock_init(): unknown circuit type");
			retval = ISIS_WARNING;
			break;
		}
	}

	return retval;
}

/*
* create the TCP socket to send lsp (and psnp) through
*/
int isis_tcp_sock_init(struct isis_circuit *circuit)
{
	int retval = ISIS_OK;

	frr_with_privs(&isisd_privs) {

		retval = open_tcp_socket(circuit);

		if(retval != ISIS_OK){
			zlog_warn("%s: could not open tcp socket", __func__);
			break;
		}
	}

	return retval;
}

static inline int llc_check(uint8_t *llc)
{
	if (*llc != ISO_SAP || *(llc + 1) != ISO_SAP || *(llc + 2) != 3)
		return 0;

	return 1;
}

int isis_recv_pdu_bcast(struct isis_circuit *circuit, uint8_t *ssnpa, bool is_lsp)
{
	int bytesread, addr_len;
		struct sockaddr_ll s_addr;
		uint8_t llc[LLC_LEN];

		addr_len = sizeof(s_addr);

		memset(&s_addr, 0, sizeof(struct sockaddr_ll));

	if(is_lsp){
		//DO ONE THING TO READ ON TCP SOCKET
		size_t length = 0;
		if(circuit->is_partial_packet){
			length = stream_get_endp(circuit->tcp_buffer);
			stream_write(circuit->rcv_stream, circuit->tcp_buffer->data, length);
			circuit->is_partial_packet = false;
		}
		unsigned int max_size =
			circuit->interface->mtu > circuit->interface->mtu6
				? circuit->interface->mtu
				: circuit->interface->mtu6;
		uint8_t temp_buff[max_size - LLC_LEN - length];
		bytesread =
			recvfrom(circuit->tcp_fd, temp_buff, max_size - LLC_LEN - length, MSG_DONTWAIT,
				NULL, 0);
		if (bytesread < 0) {
			zlog_warn("%s: recvfrom() failed", __func__);
			return ISIS_WARNING;
		}
		/* then we lose the LLC */
		zlog_debug("BYTERAED : %u",bytesread);
		stream_write(circuit->rcv_stream, temp_buff  ,bytesread );
		//stream_hexdump(circuit->rcv_stream);
		memcpy(ssnpa, &s_addr.sll_addr, s_addr.sll_halen);

		return ISIS_OK;
	} else {
		bytesread =
			recvfrom(circuit->fd, (void *)&llc, LLC_LEN, MSG_PEEK,
				(struct sockaddr *)&s_addr, (socklen_t *)&addr_len);

		if ((bytesread < 0)
			|| (s_addr.sll_ifindex != (int)circuit->interface->ifindex)) {
			if (bytesread < 0) {
				zlog_warn(
					"isis_recv_packet_bcast(): ifname %s, fd %d, bytesread %d, recvfrom(): %s",
					circuit->interface->name, circuit->fd,
					bytesread, safe_strerror(errno));
			}
			if (s_addr.sll_ifindex != (int)circuit->interface->ifindex) {
				zlog_warn(
					"packet is received on multiple interfaces: socket interface %d, circuit interface %d, packet type %u",
					s_addr.sll_ifindex, circuit->interface->ifindex,
					s_addr.sll_pkttype);
			}

			/* get rid of the packet */
			bytesread = recvfrom(circuit->fd, discard_buff,
						sizeof(discard_buff), MSG_DONTWAIT,
						(struct sockaddr *)&s_addr,
						(socklen_t *)&addr_len);

			if (bytesread < 0)
				zlog_warn("isis_recv_pdu_bcast(): recvfrom() failed");

			return ISIS_WARNING;
		}
		/*
		* Filtering by llc field, discard packets sent by this host (other
		* circuit)
		*/ 
		if (!llc_check(llc) || s_addr.sll_pkttype == PACKET_OUTGOING) {
			/*  Read the packet into discard buff */
			bytesread = recvfrom(circuit->fd, discard_buff,
						sizeof(discard_buff), MSG_DONTWAIT,
						(struct sockaddr *)&s_addr,
						(socklen_t *)&addr_len);
			if (bytesread < 0)
				zlog_warn("isis_recv_pdu_bcast(): recvfrom() failed");
			return ISIS_WARNING;
		}

		/* Ensure that we have enough space for a pdu padded to fill the mtu */
		unsigned int max_size =
			circuit->interface->mtu > circuit->interface->mtu6
				? circuit->interface->mtu
				: circuit->interface->mtu6;
		uint8_t temp_buff[max_size];
		bytesread =
			recvfrom(circuit->fd, temp_buff, max_size, MSG_DONTWAIT,
				(struct sockaddr *)&s_addr, (socklen_t *)&addr_len);
		if (bytesread < 0) {
			zlog_warn("%s: recvfrom() failed", __func__);
			return ISIS_WARNING;
		}
		/* then we lose the LLC */
		stream_write(circuit->rcv_stream, temp_buff + LLC_LEN,
				bytesread - LLC_LEN);
		memcpy(ssnpa, &s_addr.sll_addr, s_addr.sll_halen);

		return ISIS_OK;
	}
}

int isis_recv_pdu_p2p(struct isis_circuit *circuit, uint8_t *ssnpa)
{
	int bytesread, addr_len;
	struct sockaddr_ll s_addr;

	memset(&s_addr, 0, sizeof(struct sockaddr_ll));
	addr_len = sizeof(s_addr);

	/* we can read directly to the stream */
	(void)stream_recvfrom(
		circuit->rcv_stream, circuit->fd, circuit->interface->mtu, 0,
		(struct sockaddr *)&s_addr, (socklen_t *)&addr_len);

	if (s_addr.sll_pkttype == PACKET_OUTGOING) {
		/*  Read the packet into discard buff */
		bytesread = recvfrom(circuit->fd, discard_buff,
				     sizeof(discard_buff), MSG_DONTWAIT,
				     (struct sockaddr *)&s_addr,
				     (socklen_t *)&addr_len);
		if (bytesread < 0)
			zlog_warn("isis_recv_pdu_p2p(): recvfrom() failed");
		return ISIS_WARNING;
	}

	/* If we don't have protocol type 0x00FE which is
	 * ISO over GRE we exit with pain :)
	 */
	if (ntohs(s_addr.sll_protocol) != 0x00FE) {
		zlog_warn("isis_recv_pdu_p2p(): protocol mismatch(): %X",
			  ntohs(s_addr.sll_protocol));
		return ISIS_WARNING;
	}

	memcpy(ssnpa, &s_addr.sll_addr, s_addr.sll_halen);

	return ISIS_OK;
}

int isis_send_pdu_bcast(struct isis_circuit *circuit, int level, bool is_lsp)
{
	struct msghdr msg;
	struct iovec iov[2];
	char temp_buff[LLC_LEN];

	/* we need to do the LLC in here because of P2P circuits, which will
	 * not need it
	 */
	struct sockaddr_ll sa;

	stream_set_getp(circuit->snd_stream, 0);
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	sa.sll_family = AF_PACKET;

	size_t frame_size = stream_get_endp(circuit->snd_stream) + LLC_LEN;
	sa.sll_protocol = htons(isis_ethertype(frame_size));
	sa.sll_ifindex = circuit->interface->ifindex;
	sa.sll_halen = ETH_ALEN;
	/* RFC5309 section 4.1 recommends ALL_ISS */
	if (circuit->circ_type == CIRCUIT_T_P2P)
		memcpy(&sa.sll_addr, ALL_ISS, ETH_ALEN);
	else if (level == 1)
		memcpy(&sa.sll_addr, ALL_L1_ISS, ETH_ALEN);
	else
		memcpy(&sa.sll_addr, ALL_L2_ISS, ETH_ALEN);

	/* on a broadcast circuit */
	/* first we put the LLC in */
	temp_buff[0] = 0xFE;
	temp_buff[1] = 0xFE;
	temp_buff[2] = 0x03;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(struct sockaddr_ll);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	iov[0].iov_base = temp_buff;
	iov[0].iov_len = LLC_LEN;
	iov[1].iov_base = circuit->snd_stream->data;
	iov[1].iov_len = stream_get_endp(circuit->snd_stream);

	//TODO not sure only lsp in the buffer
	if(is_lsp){
		zlog_debug("send buffer length %lu", stream_get_endp(circuit->snd_stream));
		if (send(circuit->tcp_fd, circuit->snd_stream->data, stream_get_endp (circuit->snd_stream), 0) < 0) {
			zlog_warn("IS-IS pfpacket: could not transmit packet on TCP socket %s: %s",
			  circuit->interface->name, safe_strerror(errno));
			if (ERRNO_IO_RETRY(errno))
				return ISIS_WARNING;
			return ISIS_ERROR;
		}

	} else {
		if (sendmsg(circuit->fd, &msg, 0) < 0) {
			zlog_warn("IS-IS pfpacket: could not transmit packet on %s: %s",
			  circuit->interface->name, safe_strerror(errno));
			if (ERRNO_IO_RETRY(errno))
				return ISIS_WARNING;
			return ISIS_ERROR;
		}
	}
	return ISIS_OK;
}

int isis_send_pdu_p2p(struct isis_circuit *circuit, int level)
{
	struct sockaddr_ll sa;
	ssize_t rv;

	stream_set_getp(circuit->snd_stream, 0);
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = circuit->interface->ifindex;
	sa.sll_halen = ETH_ALEN;
	if (level == 1)
		memcpy(&sa.sll_addr, ALL_L1_ISS, ETH_ALEN);
	else
		memcpy(&sa.sll_addr, ALL_L2_ISS, ETH_ALEN);


	/* lets try correcting the protocol */
	sa.sll_protocol = htons(0x00FE);
	rv = sendto(circuit->fd, circuit->snd_stream->data,
		    stream_get_endp(circuit->snd_stream), 0,
		    (struct sockaddr *)&sa, sizeof(struct sockaddr_ll));
	if (rv < 0) {
		zlog_warn("IS-IS pfpacket: could not transmit packet on %s: %s",
			  circuit->interface->name, safe_strerror(errno));
		if (ERRNO_IO_RETRY(errno))
			return ISIS_WARNING;
		return ISIS_ERROR;
	}
	return ISIS_OK;
}

#endif /* ISIS_METHOD == ISIS_METHOD_PFPACKET */
