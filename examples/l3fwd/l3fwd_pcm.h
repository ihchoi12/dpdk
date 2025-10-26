/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2025 Intel Corporation
 */

#ifndef __L3FWD_PCM_H__
#define __L3FWD_PCM_H__

#include <stdint.h>
#include <stdbool.h>
#include <rte_common.h>
#include <rte_lcore.h>
#include "common_pcm_wrapper.h"

/* Maximum number of performance events to track */
#define PCM_MAX_EVENTS 16
#define PCM_MAX_LCORES RTE_MAX_LCORE
#define PCM_MAX_SOCKETS 8

/* Enhanced performance metrics structure */
struct pcm_core_metrics {
    uint64_t instructions;          /* Instructions retired */
    uint64_t cycles;                /* CPU cycles */
    uint64_t l2_cache_hits;        /* L2 cache hits */
    uint64_t l2_cache_misses;      /* L2 cache misses */
    uint64_t l3_cache_hits;        /* L3 cache hits */
    uint64_t l3_cache_misses;      /* L3 cache misses (LLC) */
    double ipc;                    /* Instructions per cycle */
    double l2_cache_hit_ratio;     /* L2 cache hit ratio */
    double l3_cache_hit_ratio;     /* L3 cache hit ratio */
    double frequency_ghz;          /* Core frequency in GHz */
    double cpu_utilization;        /* CPU utilization percentage */
    double energy_joules;          /* Energy consumption in Joules */
    uint64_t timestamp;            /* Timestamp of measurement */
};

/* Memory performance metrics structure */
struct pcm_memory_metrics {
    uint64_t dram_read_bytes;      /* DRAM read bytes */
    uint64_t dram_write_bytes;     /* DRAM write bytes */
    double memory_controller_read_bw_mbps;  /* Memory controller read bandwidth MB/s */
    double memory_controller_write_bw_mbps; /* Memory controller write bandwidth MB/s */
    double memory_controller_bw_mbps;       /* Memory controller total bandwidth MB/s */
    uint64_t timestamp;
};

/* I/O and uncore performance metrics structure */
struct pcm_io_metrics {
    uint64_t pcie_read_bytes;      /* PCIe read bytes */
    uint64_t pcie_write_bytes;     /* PCIe write bytes */
    double pcie_read_bandwidth_mbps;    /* PCIe read bandwidth MB/s */
    double pcie_write_bandwidth_mbps;   /* PCIe write bandwidth MB/s */
    uint64_t qpi_upi_data_bytes;       /* QPI/UPI data bytes */
    double qpi_upi_utilization;        /* QPI/UPI utilization percentage */
    uint64_t uncore_freq_ghz;          /* Uncore frequency GHz */
    double imc_reads_gbps;             /* IMC reads GB/s */
    double imc_writes_gbps;            /* IMC writes GB/s */
    uint64_t timestamp;
};

/* System-wide PCM metrics */
struct pcm_system_metrics {
    uint32_t active_cores;              /* Number of active cores */
    double total_energy_joules;         /* Total energy consumption */
    double package_energy_joules;       /* Package energy consumption */
    double dram_energy_joules;          /* DRAM energy consumption */
    double total_ipc;                   /* System-wide IPC */
    double memory_bandwidth_utilization; /* Memory bandwidth utilization % */
    double thermal_throttle_ratio;      /* Thermal throttling ratio */
    uint64_t timestamp;
};

/* Per-lcore PCM state */
struct pcm_lcore_state {
    uint32_t lcore_id;
    uint32_t socket_id;
    bool initialized;
    bool monitoring_active;
};

/* Function declarations */

/**
 * Initialize PCM monitoring system
 * @return 0 on success, negative on error
 */
int pcm_monitoring_init(void);

/**
 * Cleanup PCM monitoring system
 */
void pcm_monitoring_cleanup(void);

/**
 * Start monitoring on a specific lcore
 * @param lcore_id: The lcore to start monitoring
 * @return 0 on success, negative on error
 */
int pcm_monitoring_start_lcore(uint32_t lcore_id);

/**
 * Stop monitoring on a specific lcore
 * @param lcore_id: The lcore to stop monitoring
 * @return 0 on success, negative on error
 */
int pcm_monitoring_stop_lcore(uint32_t lcore_id);

/**
 * Start monitoring on all active lcores
 * @return 0 on success, negative on error
 */
int pcm_monitoring_start_all(void);

/**
 * Stop monitoring on all active lcores
 * @return 0 on success, negative on error
 */
int pcm_monitoring_stop_all(void);

/**
 * Take measurements on all active lcores and collect comprehensive statistics
 * @return 0 on success, negative on error
 */
int pcm_monitoring_measure_all(void);

/**
 * Check if PCM monitoring is available and initialized
 * @return true if available, false otherwise
 */
bool pcm_monitoring_is_available(void);

/**
 * Get current core metrics for a specific lcore
 * @param lcore_id: The lcore to query
 * @param metrics: Pointer to store the core metrics
 * @return 0 on success, negative on error
 */
int pcm_monitoring_get_lcore_metrics(uint32_t lcore_id, struct pcm_core_metrics *metrics);

/**
 * Get memory metrics for a specific socket
 * @param socket_id: The socket to query
 * @param metrics: Pointer to store the memory metrics
 * @return 0 on success, negative on error
 */
int pcm_monitoring_get_memory_metrics(uint32_t socket_id, struct pcm_memory_metrics *metrics);

/**
 * Get I/O metrics for a specific socket
 * @param socket_id: The socket to query
 * @param metrics: Pointer to store the I/O metrics
 * @return 0 on success, negative on error
 */
int pcm_monitoring_get_io_metrics(uint32_t socket_id, struct pcm_io_metrics *metrics);

/**
 * Get system-wide metrics
 * @param metrics: Pointer to store the system metrics
 * @return 0 on success, negative on error
 */
int pcm_monitoring_get_system_metrics(struct pcm_system_metrics *metrics);

/**
 * Print core performance statistics for all lcores
 */
void pcm_print_core_statistics(void);

/**
 * Print memory performance statistics for all sockets
 */
void pcm_print_memory_statistics(void);

/**
 * Print I/O performance statistics for all sockets
 */
void pcm_print_io_statistics(void);

/**
 * Print system-wide performance statistics
 */
void pcm_print_system_statistics(void);

/**
 * Print comprehensive performance summary (all categories)
 */
void pcm_monitoring_print_summary(void);

/**
 * Get PCM system information
 * @param info_buffer: Buffer to store system info
 * @param buffer_size: Size of the buffer
 * @return 0 on success, negative on error
 */
int pcm_monitoring_get_info(char *info_buffer, size_t buffer_size);

#endif /* __L3FWD_PCM_H__ */
