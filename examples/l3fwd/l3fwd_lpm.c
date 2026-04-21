/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netinet/in.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>

#include "l3fwd.h"
#include "l3fwd_common.h"
#include "l3fwd_event.h"
#include "l3fwd_pcm.h"

#include "lpm_route_parse.c"

/*
 * L3FWD_DROP_MODE: When defined, L3FWD receives packets but drops them
 * instead of forwarding. Useful for testing RX-only performance.
 * Comment out this line to restore normal forwarding behavior.
 */
// #define L3FWD_DROP_MODE 1

#define IPV4_L3FWD_LPM_MAX_RULES         1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)
#define IPV6_L3FWD_LPM_MAX_RULES         1024
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)

static struct rte_lpm *ipv4_l3fwd_lpm_lookup_struct[NB_SOCKETS];
static struct rte_lpm6 *ipv6_l3fwd_lpm_lookup_struct[NB_SOCKETS];

/* Global array of packet statistics per lcore */
struct lcore_packet_stats lcore_stats[RTE_MAX_LCORE];

/* Check if a packet is a DHCP packet (UDP ports 67/68) */
int
is_dhcp_packet(struct rte_mbuf *pkt)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_udp_hdr *udp_hdr;
    uint16_t src_port, dst_port;

    /* Check if packet is large enough and is IPv4 */
    if (rte_pktmbuf_data_len(pkt) < sizeof(*eth_hdr) + sizeof(*ipv4_hdr) + sizeof(*udp_hdr))
        return 0;

    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4)
        return 0;

    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    if (ipv4_hdr->next_proto_id != IPPROTO_UDP)
        return 0;

    udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + sizeof(*ipv4_hdr));
    src_port = rte_be_to_cpu_16(udp_hdr->src_port);
    dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);

    /* DHCP uses ports 67 (server) and 68 (client) */
    return (src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68);
}

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
/* Analyze and log packet details */
void
analyze_packet(struct rte_mbuf *pkt, unsigned int lcore_id, const char *direction, uint16_t queue_id)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint32_t src_ip, dst_ip;
	uint16_t src_port = 0, dst_port = 0;
	uint8_t proto;
	char src_ip_str[INET_ADDRSTRLEN];
	char dst_ip_str[INET_ADDRSTRLEN];
	char src_mac_str[18];
	char dst_mac_str[18];

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

	/* Convert MAC addresses to string format */
	snprintf(src_mac_str, sizeof(src_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
		 eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
		 eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
		 eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
	snprintf(dst_mac_str, sizeof(dst_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
		 eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
		 eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
		 eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		proto = ipv4_hdr->next_proto_id;

		/* Convert IPs to string format */
		struct in_addr addr;
		addr.s_addr = rte_cpu_to_be_32(src_ip);
		inet_ntop(AF_INET, &addr, src_ip_str, INET_ADDRSTRLEN);
		addr.s_addr = rte_cpu_to_be_32(dst_ip);
		inet_ntop(AF_INET, &addr, dst_ip_str, INET_ADDRSTRLEN);

		/* Extract port numbers for TCP/UDP */
		if (proto == IPPROTO_TCP && rte_pktmbuf_data_len(pkt) >= sizeof(*eth_hdr) + sizeof(*ipv4_hdr) + sizeof(*tcp_hdr)) {
			tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + sizeof(*ipv4_hdr));
			src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
			dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
			AK_DEBUG_LOG_L3FWD("[%s] lcore=%u queue=%u TCP %s:%u -> %s:%u (MAC %s -> %s) (RSS=0x%08x)",
				direction, lcore_id, queue_id, src_ip_str, src_port, dst_ip_str, dst_port, src_mac_str, dst_mac_str, pkt->hash.rss);
		} else if (proto == IPPROTO_UDP && rte_pktmbuf_data_len(pkt) >= sizeof(*eth_hdr) + sizeof(*ipv4_hdr) + sizeof(*udp_hdr)) {
			udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + sizeof(*ipv4_hdr));
			src_port = rte_be_to_cpu_16(udp_hdr->src_port);
			dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
			AK_DEBUG_LOG_L3FWD("[%s] lcore=%u queue=%u UDP %s:%u -> %s:%u (MAC %s -> %s) (RSS=0x%08x)",
				direction, lcore_id, queue_id, src_ip_str, src_port, dst_ip_str, dst_port, src_mac_str, dst_mac_str, pkt->hash.rss);
		} else {
			AK_DEBUG_LOG_L3FWD("[%s] lcore=%u queue=%u IP proto=%u %s -> %s (MAC %s -> %s) (RSS=0x%08x)",
				direction, lcore_id, queue_id, proto, src_ip_str, dst_ip_str, src_mac_str, dst_mac_str, pkt->hash.rss);
		}
	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {
		AK_DEBUG_LOG_L3FWD("[%s] lcore=%u queue=%u IPv6 packet (MAC %s -> %s)", direction, lcore_id, queue_id, src_mac_str, dst_mac_str);
	} else {
		AK_DEBUG_LOG_L3FWD("[%s] lcore=%u queue=%u Non-IP packet (type=0x%04x) (MAC %s -> %s)",
			direction, lcore_id, queue_id, rte_be_to_cpu_16(eth_hdr->ether_type), src_mac_str, dst_mac_str);
	}
}
#endif

/* Print packet statistics when exiting */
static void
print_packet_stats(void)
{
	unsigned int lcore_id;
	uint64_t total_rx = 0, total_tx = 0;
	uint64_t tsc_hz = rte_get_tsc_hz();

	/* Find global earliest first_rx_time and latest last_rx_time for total duration */
	uint64_t global_first_rx = UINT64_MAX, global_last_rx = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_stats[lcore_id].first_rx_time > 0 && lcore_stats[lcore_id].first_rx_time < global_first_rx) {
			global_first_rx = lcore_stats[lcore_id].first_rx_time;
		}
		if (lcore_stats[lcore_id].last_rx_time > global_last_rx) {
			global_last_rx = lcore_stats[lcore_id].last_rx_time;
		}
	}
	double total_elapsed_sec = 0;
	if (global_first_rx != UINT64_MAX && global_last_rx > global_first_rx) {
		total_elapsed_sec = (double)(global_last_rx - global_first_rx) / tsc_hz;
	}

	printf("\n");
	printf("=====================================\n");
	printf("L3FWD Packet Statistics Summary (Duration: %.2f sec)\n", total_elapsed_sec);
	printf("=====================================\n");
	printf("%-8s %-12s %-12s %-10s %-10s %-8s\n",
		"Lcore", "RX Packets", "TX Packets", "RX Mpps", "TX Mpps", "Loss%");
	printf("%-8s %-12s %-12s %-10s %-10s %-8s\n",
		"-----", "----------", "----------", "--------", "--------", "------");

	uint64_t total_dropped_invalid_ipv4 = 0, total_dropped_no_route = 0;
	uint64_t total_dropped_tx_failed = 0, total_dropped_non_ip = 0, total_dropped_unknown = 0;

	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_stats[lcore_id].start_time > 0) {
			/* Use first/last packet timestamps for accurate rate calculation */
			double elapsed_sec = 0;
			if (lcore_stats[lcore_id].first_rx_time > 0 && lcore_stats[lcore_id].last_rx_time > 0) {
				uint64_t duration = lcore_stats[lcore_id].last_rx_time - lcore_stats[lcore_id].first_rx_time;
				elapsed_sec = (double)duration / tsc_hz;
			}
			double rx_rate = elapsed_sec > 0 ? lcore_stats[lcore_id].filtered_rx_packets / elapsed_sec : 0;
			double tx_rate = elapsed_sec > 0 ? lcore_stats[lcore_id].filtered_tx_packets / elapsed_sec : 0;
			double loss_rate = lcore_stats[lcore_id].filtered_rx_packets > 0 ?
				(double)(lcore_stats[lcore_id].filtered_rx_packets - lcore_stats[lcore_id].filtered_tx_packets) * 100.0 / lcore_stats[lcore_id].filtered_rx_packets : 0.0;

			printf("%-8u %-12" PRIu64 " %-12" PRIu64 " %-10.1f %-10.1f %-8.1f\n",
				lcore_id,
				lcore_stats[lcore_id].filtered_rx_packets,
				lcore_stats[lcore_id].filtered_tx_packets,
				rx_rate / 1000000.0,  /* Convert to Mpps */
				tx_rate / 1000000.0,
				loss_rate);

			total_rx += lcore_stats[lcore_id].filtered_rx_packets;
			total_tx += lcore_stats[lcore_id].filtered_tx_packets;
			total_dropped_invalid_ipv4 += lcore_stats[lcore_id].dropped_invalid_ipv4;
			total_dropped_no_route += lcore_stats[lcore_id].dropped_no_route;
			total_dropped_tx_failed += lcore_stats[lcore_id].dropped_tx_failed;
			total_dropped_non_ip += lcore_stats[lcore_id].dropped_non_ip;
			total_dropped_unknown += lcore_stats[lcore_id].dropped_unknown;
		}
	}

	/* Calculate total excluded packets (unwanted traffic like DHCP) */
	uint64_t total_raw_rx = 0, total_raw_tx = 0, total_excluded_rx = 0, total_excluded_tx = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_stats[lcore_id].start_time > 0) {
			total_raw_rx += lcore_stats[lcore_id].rx_packets;
			total_raw_tx += lcore_stats[lcore_id].tx_packets;
		}
	}
	total_excluded_rx = total_raw_rx - total_rx;
	total_excluded_tx = total_raw_tx - total_tx;

	double total_loss_rate = total_rx > 0 ? (double)(total_rx - total_tx) * 100.0 / total_rx : 0.0;
	double total_rx_mpps = total_elapsed_sec > 0 ? (double)total_rx / total_elapsed_sec / 1000000.0 : 0;
	double total_tx_mpps = total_elapsed_sec > 0 ? (double)total_tx / total_elapsed_sec / 1000000.0 : 0;

	printf("%-8s %-12s %-12s %-10s %-10s %-8s\n",
		"-----", "----------", "----------", "--------", "--------", "------");
	printf("%-8s %-12" PRIu64 " %-12" PRIu64 " %-10.1f %-10.1f %-8.1f\n",
		"Total", total_rx, total_tx, total_rx_mpps, total_tx_mpps, total_loss_rate);
	printf("=====================================\n");
	printf("ANALYSIS: RX/TX difference = %" PRIu64 " packets (%.1f%% loss)\n",
		total_rx - total_tx, total_loss_rate);

	printf("FILTERING: %" PRIu64 " RX + %" PRIu64 " TX unwanted packets excluded from counting\n\n\n",
		total_excluded_rx, total_excluded_tx);
	// if (total_raw_rx > 0 && total_raw_tx > 0) {
	// 	printf("           (%.1f%% of total RX, %.1f%% of total TX)\n",
	// 		(double)total_excluded_rx * 100.0 / total_raw_rx,
	// 		(double)total_excluded_tx * 100.0 / total_raw_tx);
	// }


	/* Print detailed drop analysis */
	if (total_rx - total_tx > 0) {
		printf("DROP ANALYSIS:\n");
		printf("  Invalid IPv4 packets: %" PRIu64 "\n", total_dropped_invalid_ipv4);
		printf("  No route found: %" PRIu64 "\n", total_dropped_no_route);
		printf("  TX failed (queue full): %" PRIu64 " (%.1f%% of RX)\n",
			total_dropped_tx_failed, total_rx > 0 ? (double)total_dropped_tx_failed * 100.0 / total_rx : 0.0);
		printf("  Non-IP packets: %" PRIu64 "\n", total_dropped_non_ip);
		printf("  Unknown drops: %" PRIu64 "\n", total_dropped_unknown);

		if (total_dropped_tx_failed > 0) {
			printf("\nTX CONGESTION ANALYSIS:\n");
			printf("  - TX queue is overloaded (receiving faster than transmitting)\n");
			printf("  - Consider: reducing RX rate, increasing TX queue size, or checking network bottleneck\n");
		}
	}

	/* Always show CURRENT CONFIGURATION when stats are enabled */
	if (stats_enabled) {
		printf("\nCURRENT CONFIGURATION:\n");
		printf("  RX_DESC_DEFAULT (nb_rxd): %u \n", nb_rxd);
		printf("  TX_DESC_DEFAULT (nb_txd): %u \n", nb_txd);
		printf("  MAX_PKT_BURST: %u\n", MAX_PKT_BURST);
		printf("  DEFAULT_PKT_BURST: %u (actual nb_pkt_per_burst: %u)\n", DEFAULT_PKT_BURST, nb_pkt_per_burst);
		printf("  BURST_TX_DRAIN_US: %u us\n", BURST_TX_DRAIN_US);
		printf("  MAX_TX_BURST: %u\n", MAX_TX_BURST);
		printf("  enabled_port_mask: 0x%x\n", enabled_port_mask);

		/* Get port info for first enabled port */
		uint16_t portid;
		for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
			if ((enabled_port_mask & (1 << portid)) != 0) {
				struct rte_eth_dev_info dev_info;
				struct rte_eth_link link;
				if (rte_eth_dev_info_get(portid, &dev_info) == 0) {
					printf("  Port %u driver_name: %s\n", portid, dev_info.driver_name);
					printf("  Port %u max_tx_queues: %u\n", portid, dev_info.max_tx_queues);
					printf("  Port %u max_rx_queues: %u\n", portid, dev_info.max_rx_queues);
				}
				if (rte_eth_link_get_nowait(portid, &link) == 0) {
					printf("  Port %u link_speed: %u Mbps, %s\n", portid, link.link_speed,
						link.link_status ? "UP" : "DOWN");
				}
				break; /* Only show first enabled port */
			}
		}
	}
	printf("=====================================\n");

	print_all_nic_hw_stats();

	/* Print PCM performance statistics if available */
	if (stats_enabled && pcm_monitoring_is_available()) {
		/* Stop measurement period FIRST to capture final state */
		pcm_monitoring_stop_all();

		/* Then collect and calculate statistics immediately */
		pcm_monitoring_measure_all();

		/* Print comprehensive PCM statistics */
		pcm_print_core_statistics();
		pcm_print_memory_statistics();
		pcm_print_io_statistics();
		pcm_print_system_statistics();
	}
}

/* Signal handler for graceful shutdown */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\nReceived signal %d, shutting down...\n", signum);
		if (stats_enabled) {
			stats_enabled = false;  /* Set false FIRST to prevent double printing from main loop */
			print_packet_stats();
		}
		force_quit = true;
	}
}

/* Performing LPM-based lookups. 8< */
static inline uint16_t
lpm_get_ipv4_dst_port(const struct rte_ipv4_hdr *ipv4_hdr,
		      uint16_t portid,
		      struct rte_lpm *ipv4_l3fwd_lookup_struct)
{
	uint32_t dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	uint32_t next_hop;

	if (rte_lpm_lookup(ipv4_l3fwd_lookup_struct, dst_ip, &next_hop) == 0)
		return next_hop;
	else
		return portid;
}
/* >8 End of performing LPM-based lookups. */

static inline uint16_t
lpm_get_ipv6_dst_port(const struct rte_ipv6_hdr *ipv6_hdr,
		      uint16_t portid,
		      struct rte_lpm6 *ipv6_l3fwd_lookup_struct)
{
	const struct rte_ipv6_addr *dst_ip = &ipv6_hdr->dst_addr;
	uint32_t next_hop;

	if (rte_lpm6_lookup(ipv6_l3fwd_lookup_struct, dst_ip, &next_hop) == 0)
		return next_hop;
	else
		return portid;
}

static __rte_always_inline uint16_t
lpm_get_dst_port(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
		uint16_t portid)
{
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

		return lpm_get_ipv4_dst_port(ipv4_hdr, portid,
					     qconf->ipv4_lookup_struct);
	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);

		return lpm_get_ipv6_dst_port(ipv6_hdr, portid,
					     qconf->ipv6_lookup_struct);
	}

	return portid;
}

/*
 * lpm_get_dst_port optimized routine for packets where dst_ipv4 is already
 * precalculated. If packet is ipv6 dst_addr is taken directly from packet
 * header and dst_ipv4 value is not used.
 */
static __rte_always_inline uint16_t
lpm_get_dst_port_with_ipv4(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
	uint32_t dst_ipv4, uint16_t portid)
{
	uint32_t next_hop;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		return (uint16_t) ((rte_lpm_lookup(qconf->ipv4_lookup_struct,
						   dst_ipv4, &next_hop) == 0)
				   ? next_hop : portid);

	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);

		return (uint16_t) ((rte_lpm6_lookup(qconf->ipv6_lookup_struct,
				&ipv6_hdr->dst_addr, &next_hop) == 0)
				? next_hop : portid);

	}

	return portid;
}

#if defined(RTE_ARCH_X86)
#include "l3fwd_lpm_sse.h"
#elif defined __ARM_NEON
#include "l3fwd_lpm_neon.h"
#elif defined(RTE_ARCH_PPC_64)
#include "l3fwd_lpm_altivec.h"
#else
#include "l3fwd_lpm.h"
#endif

/* main processing loop */
int
lpm_main_loop(__rte_unused void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, nb_rx;
	uint16_t portid, queueid;
	struct lcore_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];

	/* Initialize packet statistics for this lcore */
	lcore_stats[lcore_id].rx_packets = 0;
	lcore_stats[lcore_id].tx_packets = 0;
	lcore_stats[lcore_id].filtered_rx_packets = 0;
	lcore_stats[lcore_id].filtered_tx_packets = 0;
	lcore_stats[lcore_id].start_time = rte_rdtsc();

	/* Install signal handlers only on master lcore */
	if (rte_lcore_id() == rte_get_main_lcore()) {
		signal(SIGINT, signal_handler);
		signal(SIGTERM, signal_handler);
	}

	const uint16_t n_rx_q = qconf->n_rx_queue;
	const uint16_t n_tx_p = qconf->n_tx_port;
	if (n_rx_q == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, L3FWD, "[lpm] entering main loop on lcore %u\n", lcore_id);
#ifdef L3FWD_DROP_MODE
	RTE_LOG(WARNING, L3FWD, "*** DROP MODE: lcore %u will DROP all received packets ***\n", lcore_id);
#endif
	for (i = 0; i < n_rx_q; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
			" [RX] lcoreid=%u, port=%u rxq=%hhu\n",
			lcore_id, portid, queueid);
	}

	for (i = 0; i < n_tx_p; i++) {
		portid = qconf->tx_port_id[i];
		RTE_LOG(INFO, L3FWD,
			" [TX] lcoreid=%u, port=%u, txq=%hhu\n",
			lcore_id, portid, qconf->tx_queue_id[portid]);
	}

	for (i = 0; i < n_rx_q; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		uint16_t tx_queueid = qconf->tx_queue_id[portid];
		RTE_LOG(INFO, L3FWD,
			" -- lcoreid=%u portid=%u rxqueueid=%" PRIu16 " txqueueid=%" PRIu16 "\n",
			lcore_id, portid, queueid, tx_queueid);
	}

	cur_tsc = rte_rdtsc();
	prev_tsc = cur_tsc;

	while (!force_quit) {

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < n_tx_p; ++i) {
				portid = qconf->tx_port_id[i];
				if (qconf->tx_mbufs[portid].len == 0)
					continue;

				AK_DEBUG_LOG_L3FWD("lcore %u sending %u packets to port %u queue %u",
					lcore_id, qconf->tx_mbufs[portid].len, portid, qconf->tx_queue_id[portid]);
				send_burst(qconf,
					qconf->tx_mbufs[portid].len,
					portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < n_rx_q; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				nb_pkt_per_burst);
			if (nb_rx == 0)
				continue;

			/* Update RX packet statistics with filtering */
			if (stats_enabled) {
				uint64_t filtered_count = 0;

				/* Single iteration through all received packets */
				for (int j = 0; j < nb_rx; j++) {
					/* Filter out unwanted packets (DHCP etc.) for statistics */
					if (!is_dhcp_packet(pkts_burst[j])) {
						filtered_count++;
					}
#ifdef RTE_LIBRTE_ETHDEV_DEBUG
					/* Analyze packet for debugging */
					analyze_packet(pkts_burst[j], lcore_id, "RX", queueid);
#endif
				}

				lcore_stats[lcore_id].rx_packets += nb_rx;
				lcore_stats[lcore_id].filtered_rx_packets += filtered_count;

				/* Update timestamps only for filtered (benchmark) packets */
				if (filtered_count > 0) {
					uint64_t now = rte_rdtsc();
					if (lcore_stats[lcore_id].first_rx_time == 0)
						lcore_stats[lcore_id].first_rx_time = now;
					lcore_stats[lcore_id].last_rx_time = now;
				}
			} else {
#ifdef RTE_LIBRTE_ETHDEV_DEBUG
				/* Analyze packets for debugging even when stats disabled */
				for (int j = 0; j < nb_rx; j++) {
					analyze_packet(pkts_burst[j], lcore_id, "RX", queueid);
				}
#endif
			}

			AK_DEBUG_LOG_L3FWD("lcore %u received %d packets from port %u queue %u", lcore_id, nb_rx, portid, queueid);

#ifdef L3FWD_DROP_MODE
			/* DROP MODE: Free packets without forwarding */
			for (int j = 0; j < nb_rx; j++) {
				rte_pktmbuf_free(pkts_burst[j]);
			}
#else
#if defined RTE_ARCH_X86 || defined __ARM_NEON \
			 || defined RTE_ARCH_PPC_64
			l3fwd_lpm_send_packets(nb_rx, pkts_burst,
						portid, qconf);
#else
			l3fwd_lpm_no_opt_send_packets(nb_rx, pkts_burst,
							portid, qconf);
#endif /* X86 */
#endif /* L3FWD_DROP_MODE */
		}

		cur_tsc = rte_rdtsc();
	}

	/* Print statistics when main loop exits */
	if (rte_lcore_id() == rte_get_main_lcore() && stats_enabled) {
		print_packet_stats();
	}

	return 0;
}

#ifdef RTE_LIB_EVENTDEV
static __rte_always_inline uint16_t
lpm_process_event_pkt(const struct lcore_conf *lconf, struct rte_mbuf *mbuf)
{
	mbuf->port = lpm_get_dst_port(lconf, mbuf, mbuf->port);

#if defined RTE_ARCH_X86 || defined __ARM_NEON \
	|| defined RTE_ARCH_PPC_64
	process_packet(mbuf, &mbuf->port);
#else

	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf,
			struct rte_ether_hdr *);

	/* dst addr */
	*(uint64_t *)&eth_hdr->dst_addr = dest_eth_addr[mbuf->port];

	/* src addr */
	rte_ether_addr_copy(&ports_eth_addr[mbuf->port],
			&eth_hdr->src_addr);

	rfc1812_process(rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *,
						sizeof(struct rte_ether_hdr)),
			&mbuf->port, mbuf->packet_type);
#endif
	return mbuf->port;
}

static __rte_always_inline void
lpm_event_loop_single(struct l3fwd_event_resources *evt_rsrc,
		const uint8_t flags)
{
	const int event_p_id = l3fwd_get_free_event_port(evt_rsrc);
	const uint8_t tx_q_id = evt_rsrc->evq.event_q_id[
		evt_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	uint8_t enq = 0, deq = 0;
	struct lcore_conf *lconf;
	unsigned int lcore_id;
	struct rte_event ev;

	if (event_p_id < 0)
		return;

	lcore_id = rte_lcore_id();
	lconf = &lcore_conf[lcore_id];

	RTE_LOG(INFO, L3FWD, "entering %s on lcore %u\n", __func__, lcore_id);
	while (!force_quit) {
		deq = rte_event_dequeue_burst(event_d_id, event_p_id, &ev, 1,
					      0);
		if (!deq)
			continue;

		if (lpm_process_event_pkt(lconf, ev.mbuf) == BAD_PORT) {
			rte_pktmbuf_free(ev.mbuf);
			continue;
		}

		if (flags & L3FWD_EVENT_TX_ENQ) {
			ev.queue_id = tx_q_id;
			ev.op = RTE_EVENT_OP_FORWARD;
			do {
				enq = rte_event_enqueue_burst(
					event_d_id, event_p_id, &ev, 1);
			} while (!enq && !force_quit);
		}

		if (flags & L3FWD_EVENT_TX_DIRECT) {
			rte_event_eth_tx_adapter_txq_set(ev.mbuf, 0);
			do {
				enq = rte_event_eth_tx_adapter_enqueue(
					event_d_id, event_p_id, &ev, 1, 0);
			} while (!enq && !force_quit);
		}
	}

	l3fwd_event_worker_cleanup(event_d_id, event_p_id, &ev, enq, deq, 0);
}

static __rte_always_inline void
lpm_event_loop_burst(struct l3fwd_event_resources *evt_rsrc,
		const uint8_t flags)
{
	const int event_p_id = l3fwd_get_free_event_port(evt_rsrc);
	const uint8_t tx_q_id = evt_rsrc->evq.event_q_id[
		evt_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	const uint16_t deq_len = evt_rsrc->deq_depth;
	struct rte_event events[MAX_PKT_BURST];
	int i, nb_enq = 0, nb_deq = 0;
	struct lcore_conf *lconf;
	unsigned int lcore_id;

	if (event_p_id < 0)
		return;

	lcore_id = rte_lcore_id();

	lconf = &lcore_conf[lcore_id];

	RTE_LOG(INFO, L3FWD, "entering %s on lcore %u\n", __func__, lcore_id);

	while (!force_quit) {
		/* Read events from RX queues */
		nb_deq = rte_event_dequeue_burst(event_d_id, event_p_id,
				events, deq_len, 0);
		if (nb_deq == 0) {
			rte_pause();
			continue;
		}

		for (i = 0; i < nb_deq; i++) {
			if (flags & L3FWD_EVENT_TX_ENQ) {
				events[i].queue_id = tx_q_id;
				events[i].op = RTE_EVENT_OP_FORWARD;
			}

			if (flags & L3FWD_EVENT_TX_DIRECT)
				rte_event_eth_tx_adapter_txq_set(events[i].mbuf,
								 0);

			lpm_process_event_pkt(lconf, events[i].mbuf);
		}

		if (flags & L3FWD_EVENT_TX_ENQ) {
			nb_enq = rte_event_enqueue_burst(event_d_id, event_p_id,
					events, nb_deq);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_enqueue_burst(event_d_id,
						event_p_id, events + nb_enq,
						nb_deq - nb_enq);
		}

		if (flags & L3FWD_EVENT_TX_DIRECT) {
			nb_enq = rte_event_eth_tx_adapter_enqueue(event_d_id,
					event_p_id, events, nb_deq, 0);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_eth_tx_adapter_enqueue(
						event_d_id, event_p_id,
						events + nb_enq,
						nb_deq - nb_enq, 0);
		}
	}

	l3fwd_event_worker_cleanup(event_d_id, event_p_id, events, nb_enq,
				   nb_deq, 0);
}

static __rte_always_inline void
lpm_event_loop(struct l3fwd_event_resources *evt_rsrc,
		 const uint8_t flags)
{
	if (flags & L3FWD_EVENT_SINGLE)
		lpm_event_loop_single(evt_rsrc, flags);
	if (flags & L3FWD_EVENT_BURST)
		lpm_event_loop_burst(evt_rsrc, flags);
}

int __rte_noinline
lpm_event_main_loop_tx_d(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_DIRECT | L3FWD_EVENT_SINGLE);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_d_burst(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_DIRECT | L3FWD_EVENT_BURST);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_q(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_ENQ | L3FWD_EVENT_SINGLE);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_q_burst(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_ENQ | L3FWD_EVENT_BURST);
	return 0;
}

static __rte_always_inline void
lpm_process_event_vector(struct rte_event_vector *vec, struct lcore_conf *lconf,
			 uint16_t *dst_port)
{
	struct rte_mbuf **mbufs = vec->mbufs;
	int i;

#if defined RTE_ARCH_X86 || defined __ARM_NEON || defined RTE_ARCH_PPC_64
	if (vec->attr_valid) {
		l3fwd_lpm_process_packets(vec->nb_elem, mbufs, vec->port,
					  dst_port, lconf, 1);
	} else {
		for (i = 0; i < vec->nb_elem; i++)
			l3fwd_lpm_process_packets(1, &mbufs[i], mbufs[i]->port,
						  &dst_port[i], lconf, 1);
	}
#else
	for (i = 0; i < vec->nb_elem; i++)
		dst_port[i] = lpm_process_event_pkt(lconf, mbufs[i]);
#endif

	process_event_vector(vec, dst_port);
}

/* Same eventdev loop for single and burst of vector */
static __rte_always_inline void
lpm_event_loop_vector(struct l3fwd_event_resources *evt_rsrc,
		      const uint8_t flags)
{
	const int event_p_id = l3fwd_get_free_event_port(evt_rsrc);
	const uint8_t tx_q_id =
		evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	const uint16_t deq_len = evt_rsrc->deq_depth;
	struct rte_event events[MAX_PKT_BURST];
	int i, nb_enq = 0, nb_deq = 0;
	struct lcore_conf *lconf;
	uint16_t *dst_port_list;
	unsigned int lcore_id;

	if (event_p_id < 0)
		return;

	lcore_id = rte_lcore_id();
	lconf = &lcore_conf[lcore_id];
	dst_port_list =
		rte_zmalloc("", sizeof(uint16_t) * evt_rsrc->vector_size,
			    RTE_CACHE_LINE_SIZE);
	if (dst_port_list == NULL)
		return;
	RTE_LOG(INFO, L3FWD, "entering %s on lcore %u\n", __func__, lcore_id);

	while (!force_quit) {
		/* Read events from RX queues */
		nb_deq = rte_event_dequeue_burst(event_d_id, event_p_id, events,
						 deq_len, 0);
		if (nb_deq == 0) {
			rte_pause();
			continue;
		}

		for (i = 0; i < nb_deq; i++) {
			if (flags & L3FWD_EVENT_TX_ENQ) {
				events[i].queue_id = tx_q_id;
				events[i].op = RTE_EVENT_OP_FORWARD;
			}

			lpm_process_event_vector(events[i].vec, lconf,
						 dst_port_list);
		}

		if (flags & L3FWD_EVENT_TX_ENQ) {
			nb_enq = rte_event_enqueue_burst(event_d_id, event_p_id,
							 events, nb_deq);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_enqueue_burst(
					event_d_id, event_p_id, events + nb_enq,
					nb_deq - nb_enq);
		}

		if (flags & L3FWD_EVENT_TX_DIRECT) {
			nb_enq = rte_event_eth_tx_adapter_enqueue(
				event_d_id, event_p_id, events, nb_deq, 0);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_eth_tx_adapter_enqueue(
					event_d_id, event_p_id, events + nb_enq,
					nb_deq - nb_enq, 0);
		}
	}

	l3fwd_event_worker_cleanup(event_d_id, event_p_id, events, nb_enq,
				   nb_deq, 1);
	rte_free(dst_port_list);
}

int __rte_noinline
lpm_event_main_loop_tx_d_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	lpm_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_DIRECT);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_d_burst_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	lpm_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_DIRECT);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_q_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	lpm_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_ENQ);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_q_burst_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	lpm_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_ENQ);
	return 0;
}
#endif

void
setup_lpm(const int socketid)
{
	struct rte_eth_dev_info dev_info;
	struct rte_lpm6_config config;
	struct rte_lpm_config config_ipv4;
	int i;
	int ret;
	char s[64];
	char abuf[INET6_ADDRSTRLEN];

	/* create the LPM table */
	config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	config_ipv4.flags = 0;
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);
	ipv4_l3fwd_lpm_lookup_struct[socketid] =
			rte_lpm_create(s, socketid, &config_ipv4);
	if (ipv4_l3fwd_lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);

	/* populate the LPM table */
	for (i = 0; i < route_num_v4; i++) {
		struct in_addr in;

		/* skip unused ports */
		if ((1 << route_base_v4[i].if_out &
				enabled_port_mask) == 0)
			continue;

		ret = rte_eth_dev_info_get(route_base_v4[i].if_out, &dev_info);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Unable to get device info for port %u\n",
				 route_base_v4[i].if_out);

		ret = rte_lpm_add(ipv4_l3fwd_lpm_lookup_struct[socketid],
			route_base_v4[i].ip,
			route_base_v4[i].depth,
			route_base_v4[i].if_out);

		if (ret < 0) {
			lpm_free_routes();
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the l3fwd LPM table on socket %d\n",
				i, socketid);
		}

		in.s_addr = htonl(route_base_v4[i].ip);
		printf("LPM: Adding route %s / %d (%d) [%s]\n",
		       inet_ntop(AF_INET, &in, abuf, sizeof(abuf)),
		       route_base_v4[i].depth,
		       route_base_v4[i].if_out, rte_dev_name(dev_info.device));
	}

	/* create the LPM6 table */
	snprintf(s, sizeof(s), "IPV6_L3FWD_LPM_%d", socketid);

	config.max_rules = IPV6_L3FWD_LPM_MAX_RULES;
	config.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S;
	config.flags = 0;
	ipv6_l3fwd_lpm_lookup_struct[socketid] = rte_lpm6_create(s, socketid,
				&config);
	if (ipv6_l3fwd_lpm_lookup_struct[socketid] == NULL) {
		lpm_free_routes();
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);
	}

	/* populate the LPM table */
	for (i = 0; i < route_num_v6; i++) {

		/* skip unused ports */
		if ((1 << route_base_v6[i].if_out &
				enabled_port_mask) == 0)
			continue;

		ret = rte_eth_dev_info_get(route_base_v6[i].if_out, &dev_info);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Unable to get device info for port %u\n",
				 route_base_v6[i].if_out);

		ret = rte_lpm6_add(ipv6_l3fwd_lpm_lookup_struct[socketid],
			&route_base_v6[i].ip6,
			route_base_v6[i].depth,
			route_base_v6[i].if_out);

		if (ret < 0) {
			lpm_free_routes();
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the l3fwd LPM table on socket %d\n",
				i, socketid);
		}

		printf("LPM: Adding route %s / %d (%d) [%s]\n",
		       inet_ntop(AF_INET6, &route_base_v6[i].ip6, abuf,
				 sizeof(abuf)),
		       route_base_v6[i].depth,
		       route_base_v6[i].if_out, rte_dev_name(dev_info.device));
	}
}

int
lpm_check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4 = 0, ptype_l3_ipv6 = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		if (ptypes[i] & RTE_PTYPE_L3_IPV4)
			ptype_l3_ipv4 = 1;
		if (ptypes[i] & RTE_PTYPE_L3_IPV6)
			ptype_l3_ipv6 = 1;
	}

	if (!ipv6 && !ptype_l3_ipv4) {
		printf("port %d cannot parse RTE_PTYPE_L3_IPV4\n", portid);
		return 0;
	}

	if (ipv6 && !ptype_l3_ipv6) {
		printf("port %d cannot parse RTE_PTYPE_L3_IPV6\n", portid);
		return 0;
	}

	return 1;

}

static inline void
lpm_parse_ptype(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = eth_hdr->ether_type;
	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
	else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;

	m->packet_type = packet_type;
}

uint16_t
lpm_cb_parse_ptype(uint16_t port __rte_unused, uint16_t queue __rte_unused,
		   struct rte_mbuf *pkts[], uint16_t nb_pkts,
		   uint16_t max_pkts __rte_unused,
		   void *user_param __rte_unused)
{
	unsigned int i;

	if (unlikely(nb_pkts == 0))
		return nb_pkts;
	rte_prefetch0(rte_pktmbuf_mtod(pkts[0], struct ether_hdr *));
	for (i = 0; i < (unsigned int) (nb_pkts - 1); ++i) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts[i+1],
			struct ether_hdr *));
		lpm_parse_ptype(pkts[i]);
	}
	lpm_parse_ptype(pkts[i]);

	return nb_pkts;
}

/* Return ipv4/ipv6 lpm fwd lookup struct. */
void *
lpm_get_ipv4_l3fwd_lookup_struct(const int socketid)
{
	return ipv4_l3fwd_lpm_lookup_struct[socketid];
}

void *
lpm_get_ipv6_l3fwd_lookup_struct(const int socketid)
{
	return ipv6_l3fwd_lpm_lookup_struct[socketid];
}
