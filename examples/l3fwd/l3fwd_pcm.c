/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2025 Intel Corporation
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "l3fwd_pcm.h"
#include "common_pcm_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <dlfcn.h>
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_log.h>

/* Global PCM state */
static struct pcm_global_state {
    bool pcm_initialized;
    bool monitoring_enabled;
    bool use_static_wrapper;
    uint32_t num_lcores;
    double sampling_interval;
    struct pcm_lcore_state lcore_states[PCM_MAX_LCORES];
    struct pcm_core_metrics core_metrics[PCM_MAX_LCORES];
    struct pcm_memory_metrics memory_metrics[PCM_MAX_SOCKETS];
    struct pcm_io_metrics io_metrics[PCM_MAX_SOCKETS];
    struct pcm_system_metrics system_metrics;
    uint64_t start_timestamp;
    uint64_t last_measurement_timestamp;
} g_pcm_state = {0};

/* Helper macros */
#define PCM_LOG(level, fmt, args...) \
    rte_log(RTE_LOG_ ## level, RTE_LOGTYPE_USER1, "[PCM] " fmt "\n", ##args)

#define NSEC_PER_SEC 1000000000ULL
#define USEC_PER_SEC 1000000ULL

/* Utility functions */
static uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

/* Core PCM monitoring functions */
int pcm_monitoring_init(void)
{
    if (g_pcm_state.pcm_initialized) {
        PCM_LOG(WARNING, "PCM monitoring already initialized");
        return 0;
    }

    /* Check if PCM is disabled via environment variable */
    if (getenv("PCM_DISABLED")) {
        printf("DEBUG: PCM monitoring disabled by PCM_DISABLED environment variable\n");
        return -1;
    }

    /* Try static PCM wrapper */
    if (pcm_wrapper_is_available()) {
        if (pcm_wrapper_init() == 0) {

            /* Initialize global state for static wrapper */
            memset(&g_pcm_state, 0, sizeof(g_pcm_state));
            g_pcm_state.pcm_initialized = true;
            g_pcm_state.monitoring_enabled = true;
            g_pcm_state.num_lcores = rte_lcore_count();
            g_pcm_state.sampling_interval = 1.0;
            g_pcm_state.use_static_wrapper = true; /* Flag to indicate static wrapper usage */

            /* Validate initialization parameters */
            if (g_pcm_state.num_lcores == 0 || g_pcm_state.num_lcores > RTE_MAX_LCORE) {
                printf("DEBUG: WARNING - Suspicious lcore count %u detected\n", g_pcm_state.num_lcores);
            }

            /* Initialize per-lcore states */
            uint32_t lcore_id;
            RTE_LCORE_FOREACH(lcore_id) {
                struct pcm_lcore_state *state = &g_pcm_state.lcore_states[lcore_id];
                state->lcore_id = lcore_id;
                state->socket_id = rte_lcore_to_socket_id(lcore_id);
                state->initialized = true;
                state->monitoring_active = false;
            }

            /* Get and display system information */
            char sys_info[1024];
            if (pcm_wrapper_get_system_info(sys_info, sizeof(sys_info)) == 0) {
                printf("=== PCM System Information ===\n%s=== End PCM System Info ===\n", sys_info);
            }

            PCM_LOG(INFO, "PCM monitoring initialized successfully with static wrapper for %u lcores",
                    g_pcm_state.num_lcores);
            return 0;
        } else {
            printf("ERROR: Static PCM wrapper initialization failed\n");
        }
    } else {
        printf("ERROR: Static PCM wrapper not available\n");
    }

    /* If static wrapper failed, return error (no fallback to dynamic loading to avoid GLIBCXX issues) */
    PCM_LOG(ERR, "Failed to initialize PCM monitoring (static wrapper not available or failed)");
    return -1;
}

void pcm_monitoring_cleanup(void)
{
    if (!g_pcm_state.pcm_initialized) {
        return;
    }

    /* Stop monitoring on all active lcores */
    uint32_t lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        if (g_pcm_state.lcore_states[lcore_id].monitoring_active) {
            pcm_monitoring_stop_lcore(lcore_id);
        }
    }

    /* Cleanup PCM */
    if (g_pcm_state.use_static_wrapper) {
        pcm_wrapper_cleanup();
    }

    /* Reset global state */
    memset(&g_pcm_state, 0, sizeof(g_pcm_state));

    PCM_LOG(INFO, "PCM monitoring cleanup completed");
}

int pcm_monitoring_start_all(void)
{
    if (!g_pcm_state.pcm_initialized) {
        PCM_LOG(ERR, "PCM not initialized");
        return -1;
    }

    /* Start measurement period in PCM wrapper */
    if (g_pcm_state.use_static_wrapper) {
        if (pcm_wrapper_start_measurement() != 0) {
            PCM_LOG(ERR, "Failed to start PCM measurement");
            return -1;
        }
    }

    g_pcm_state.start_timestamp = get_timestamp_ns();

    /* Start monitoring on all available lcores */
    uint32_t lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        pcm_monitoring_start_lcore(lcore_id);
    }

    printf("Starting PCM monitoring on all lcores...\n");
    return 0;
}

int pcm_monitoring_stop_all(void)
{
    if (!g_pcm_state.pcm_initialized) {
        return -1;
    }

    /* Stop measurement period in PCM wrapper */
    if (g_pcm_state.use_static_wrapper) {
        if (pcm_wrapper_stop_measurement() != 0) {
            PCM_LOG(ERR, "Failed to stop PCM measurement");
            return -1;
        }
    }

    /* Stop monitoring on all lcores */
    uint32_t lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        pcm_monitoring_stop_lcore(lcore_id);
    }

    printf("Stopped PCM monitoring on all lcores\n");
    return 0;
}

int pcm_monitoring_start_lcore(uint32_t lcore_id)
{
    if (!g_pcm_state.pcm_initialized) {
        return -1;
    }

    if (lcore_id >= RTE_MAX_LCORE) {
        PCM_LOG(ERR, "Invalid lcore ID: %u", lcore_id);
        return -1;
    }

    struct pcm_lcore_state *state = &g_pcm_state.lcore_states[lcore_id];

    if (!state->initialized) {
        PCM_LOG(ERR, "Lcore %u not initialized", lcore_id);
        return -1;
    }

    if (state->monitoring_active) {
        PCM_LOG(WARNING, "Monitoring already active on lcore %u", lcore_id);
        return 0;
    }

    state->monitoring_active = true;
    PCM_LOG(INFO, "Started monitoring on lcore %u", lcore_id);
    return 0;
}

int pcm_monitoring_stop_lcore(uint32_t lcore_id)
{
    if (!g_pcm_state.pcm_initialized) {
        return -1;
    }

    if (lcore_id >= RTE_MAX_LCORE) {
        return -1;
    }

    struct pcm_lcore_state *state = &g_pcm_state.lcore_states[lcore_id];

    if (!state->monitoring_active) {
        return 0;
    }

    state->monitoring_active = false;
    PCM_LOG(INFO, "Stopped monitoring on lcore %u", lcore_id);
    return 0;
}

int pcm_monitoring_measure_all(void)
{
    if (!g_pcm_state.pcm_initialized || !g_pcm_state.use_static_wrapper) {
        return -1;
    }

    uint64_t timestamp = get_timestamp_ns();
    uint32_t lcore_id;

    /* Collect core metrics for all active lcores */
    RTE_LCORE_FOREACH(lcore_id) {
        /* Always collect metrics for all lcores that were initialized,
         * regardless of monitoring_active flag since stop_all() resets it */
        if (g_pcm_state.lcore_states[lcore_id].initialized) {
            struct pcm_core_metrics *metrics = &g_pcm_state.core_metrics[lcore_id];
            pcm_core_counters_t counters;

            if (pcm_wrapper_get_core_counters(lcore_id, &counters) == 0) {
                metrics->cycles = counters.cycles;
                metrics->instructions = counters.instructions;
                metrics->l2_cache_hits = counters.l2_cache_hits;
                metrics->l2_cache_misses = counters.l2_cache_misses;
                metrics->l3_cache_hits = counters.l3_cache_hits;
                metrics->l3_cache_misses = counters.l3_cache_misses;
                metrics->ipc = counters.ipc;
                metrics->l2_cache_hit_ratio = counters.l2_cache_hit_ratio;
                metrics->l3_cache_hit_ratio = counters.l3_cache_hit_ratio;
                metrics->frequency_ghz = counters.frequency_ghz;
                metrics->cpu_utilization = counters.cpu_utilization;
                metrics->energy_joules = counters.energy_joules;
                metrics->timestamp = timestamp;

                /* Check for measurement anomalies */
                if (counters.ipc > 5.0) {
                    printf("DEBUG: WARNING - Very high IPC %.2f detected on lcore %u\n", counters.ipc, lcore_id);
                }
                if (counters.cycles > 0 && counters.instructions == 0) {
                    printf("DEBUG: WARNING - Zero instructions with non-zero cycles on lcore %u\n", lcore_id);
                }
            } else {
                printf("WARNING: Failed to get counters for lcore %u\n", lcore_id);
            }
        }
    }

    /* Collect memory metrics for all sockets */
    for (uint32_t socket = 0; socket < PCM_MAX_SOCKETS; socket++) {
        struct pcm_memory_metrics *metrics = &g_pcm_state.memory_metrics[socket];
        pcm_memory_counters_t counters;

        if (pcm_wrapper_get_memory_counters(socket, &counters) == 0) {
            metrics->dram_read_bytes = counters.dram_read_bytes;
            metrics->dram_write_bytes = counters.dram_write_bytes;
            metrics->memory_controller_read_bw_mbps = counters.memory_controller_read_bw_mbps;
            metrics->memory_controller_write_bw_mbps = counters.memory_controller_write_bw_mbps;
            metrics->memory_controller_bw_mbps = counters.memory_controller_bw_mbps;
            metrics->timestamp = timestamp;
        }
    }

    /* Collect I/O metrics for all sockets */
    for (uint32_t socket = 0; socket < PCM_MAX_SOCKETS; socket++) {
        struct pcm_io_metrics *metrics = &g_pcm_state.io_metrics[socket];
        pcm_io_counters_t counters;

        if (pcm_wrapper_get_io_counters(socket, &counters) == 0) {
            metrics->pcie_read_bytes = counters.pcie_read_bytes;
            metrics->pcie_write_bytes = counters.pcie_write_bytes;
            metrics->pcie_read_bandwidth_mbps = counters.pcie_read_bandwidth_mbps;
            metrics->pcie_write_bandwidth_mbps = counters.pcie_write_bandwidth_mbps;
            metrics->qpi_upi_data_bytes = counters.qpi_upi_data_bytes;
            metrics->qpi_upi_utilization = counters.qpi_upi_utilization;
            metrics->uncore_freq_ghz = counters.uncore_freq_ghz;
            metrics->imc_reads_gbps = counters.imc_reads_gbps;
            metrics->imc_writes_gbps = counters.imc_writes_gbps;
            metrics->timestamp = timestamp;
        }
    }

    /* Collect system-wide metrics */
    pcm_system_counters_t sys_counters;
    if (pcm_wrapper_get_system_counters(&sys_counters) == 0) {
        struct pcm_system_metrics *metrics = &g_pcm_state.system_metrics;
        metrics->active_cores = sys_counters.active_cores;
        metrics->total_energy_joules = sys_counters.total_energy_joules;
        metrics->package_energy_joules = sys_counters.package_energy_joules;
        metrics->dram_energy_joules = sys_counters.dram_energy_joules;
        metrics->total_ipc = sys_counters.total_ipc;
        metrics->memory_bandwidth_utilization = sys_counters.memory_bandwidth_utilization;
        metrics->thermal_throttle_ratio = sys_counters.thermal_throttle_ratio;
        metrics->timestamp = timestamp;
    }

    g_pcm_state.last_measurement_timestamp = timestamp;
    return 0;
}

/* Enhanced statistics display functions */
void pcm_print_core_statistics(void)
{
    if (!g_pcm_state.pcm_initialized) {
        return;
    }

    /* Calculate measurement duration in microseconds */
    uint64_t duration_us = 0;
    if (g_pcm_state.last_measurement_timestamp > g_pcm_state.start_timestamp) {
        duration_us = (g_pcm_state.last_measurement_timestamp - g_pcm_state.start_timestamp) / 1000;
    }

    printf("\n=====================================\n");
    printf("Intel PCM Core Performance Statistics (%lu us)\n", duration_us);
    printf("=====================================\n");
    printf("%-5s %-12s %-12s %-6s %-10s %-8s %-8s %-6s %-6s %-8s\n",
           "Core", "Cycles", "Instructions", "IPC", "L3 Misses", "L2 Hit%", "L3 Hit%", "Freq", "CPU%", "Energy");
    printf("%-5s %-12s %-12s %-6s %-10s %-8s %-8s %-6s %-6s %-8s\n",
           "----", "----------", "----------", "----", "---------", "------", "------", "----", "----", "------");

    uint64_t total_cycles = 0, total_instructions = 0, total_l3_misses = 0;
    double total_energy = 0.0;
    uint32_t active_cores = 0;

    uint32_t lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        /* Check if lcore was initialized and has valid metrics */
        if (g_pcm_state.lcore_states[lcore_id].initialized &&
            (g_pcm_state.core_metrics[lcore_id].cycles > 0 || g_pcm_state.core_metrics[lcore_id].instructions > 0)) {
            struct pcm_core_metrics *metrics = &g_pcm_state.core_metrics[lcore_id];

            printf("%-5u %-12lu %-12lu %-6.2f %-10lu %-8.1f %-8.1f %-6.2f %-6.1f %-8.2f\n",
                   lcore_id,
                   metrics->cycles,
                   metrics->instructions,
                   metrics->ipc,
                   metrics->l3_cache_misses,
                   metrics->l2_cache_hit_ratio * 100.0,
                   metrics->l3_cache_hit_ratio * 100.0,
                   metrics->frequency_ghz,
                   metrics->cpu_utilization * 100.0,
                   metrics->energy_joules);

            total_cycles += metrics->cycles;
            total_instructions += metrics->instructions;
            total_l3_misses += metrics->l3_cache_misses;
            total_energy += metrics->energy_joules;
            active_cores++;
        }
    }

    printf("%-5s %-12s %-12s %-6s %-10s %-8s %-8s %-6s %-6s %-8s\n",
           "----", "----------", "----------", "----", "---------", "------", "------", "----", "----", "------");

    double avg_ipc = total_cycles > 0 ? (double)total_instructions / total_cycles : 0.0;
    printf("%-5s %-12lu %-12lu %-6.2f %-10lu %-8s %-8s %-6s %-6s %-8.2f\n",
           "Total", total_cycles, total_instructions, avg_ipc, total_l3_misses,
           "-", "-", "-", "-", total_energy);

    printf("Active Cores: %u\n", active_cores);
    printf("=====================================\n");
}

void pcm_print_memory_statistics(void)
{
    if (!g_pcm_state.pcm_initialized) {
        return;
    }

    /* Calculate measurement duration in microseconds */
    uint64_t duration_us = 0;
    if (g_pcm_state.last_measurement_timestamp > g_pcm_state.start_timestamp) {
        duration_us = (g_pcm_state.last_measurement_timestamp - g_pcm_state.start_timestamp) / 1000;
    }

    printf("\n=====================================\n");
    printf("Intel PCM Memory Performance Statistics (%lu us)\n", duration_us);
    printf("=====================================\n");
    printf("%-6s %-12s %-12s %-12s %-12s %-12s\n",
           "Socket", "DRAM Read", "DRAM Write", "MC Read BW", "MC Write BW", "MC Total BW");
    printf("%-6s %-12s %-12s %-12s %-12s %-12s\n",
           "------", "----------", "-----------", "----------", "-----------", "-----------");

    for (uint32_t socket = 0; socket < PCM_MAX_SOCKETS; socket++) {
        struct pcm_memory_metrics *metrics = &g_pcm_state.memory_metrics[socket];

        if (metrics->timestamp > 0) {
            printf("%-6u %-12lu %-12lu %-12.1f %-12.1f %-12.1f\n",
                   socket,
                   metrics->dram_read_bytes,
                   metrics->dram_write_bytes,
                   metrics->memory_controller_read_bw_mbps,
                   metrics->memory_controller_write_bw_mbps,
                   metrics->memory_controller_bw_mbps);
        }
    }
    printf("=====================================\n");
}

void pcm_print_io_statistics(void)
{
    if (!g_pcm_state.pcm_initialized) {
        return;
    }

    /* Calculate measurement duration in microseconds */
    uint64_t duration_us = 0;
    if (g_pcm_state.last_measurement_timestamp > g_pcm_state.start_timestamp) {
        duration_us = (g_pcm_state.last_measurement_timestamp - g_pcm_state.start_timestamp) / 1000;
    }

    printf("\n=====================================\n");
    printf("Intel PCM I/O Performance Statistics (%lu us)\n", duration_us);
    printf("=====================================\n");
    printf("%-6s %-12s %-12s %-10s %-10s %-8s\n",
           "Socket", "PCIe Read", "PCIe Write", "PCIe R BW", "PCIe W BW", "UPI Util%");
    printf("%-6s %-12s %-12s %-10s %-10s %-8s\n",
           "------", "----------", "-----------", "---------", "---------", "---------");

    for (uint32_t socket = 0; socket < PCM_MAX_SOCKETS; socket++) {
        struct pcm_io_metrics *metrics = &g_pcm_state.io_metrics[socket];

        if (metrics->timestamp > 0) {
            printf("%-6u %-12lu %-12lu %-10.1f %-10.1f %-9.1f\n",
                   socket,
                   metrics->pcie_read_bytes,
                   metrics->pcie_write_bytes,
                   metrics->pcie_read_bandwidth_mbps,
                   metrics->pcie_write_bandwidth_mbps,
                   metrics->qpi_upi_utilization * 100.0);
        }
    }
    printf("=====================================\n");
}

void pcm_print_system_statistics(void)
{
    if (!g_pcm_state.pcm_initialized) {
        return;
    }

    struct pcm_system_metrics *metrics = &g_pcm_state.system_metrics;

    /* Calculate measurement duration in microseconds */
    uint64_t duration_us = 0;
    if (g_pcm_state.last_measurement_timestamp > g_pcm_state.start_timestamp) {
        duration_us = (g_pcm_state.last_measurement_timestamp - g_pcm_state.start_timestamp) / 1000;
    }

    printf("\n=====================================\n");
    printf("Intel PCM System-Wide Statistics (%lu us)\n", duration_us);
    printf("=====================================\n");
    printf("Active Cores: %u\n", metrics->active_cores);
    printf("Total IPC: %.2f\n", metrics->total_ipc);
    printf("Total Energy: %.2f J\n", metrics->total_energy_joules);
    printf("Package Energy: %.2f J\n", metrics->package_energy_joules);
    printf("DRAM Energy: %.2f J\n", metrics->dram_energy_joules);
    printf("Memory BW Utilization: %.1f%%\n", metrics->memory_bandwidth_utilization * 100.0);
    printf("Thermal Throttle Ratio: %.1f%%\n", metrics->thermal_throttle_ratio * 100.0);
    printf("=====================================\n");
}

/* Additional utility functions */

bool pcm_monitoring_is_available(void)
{
    return g_pcm_state.pcm_initialized;
}

int pcm_monitoring_get_lcore_metrics(uint32_t lcore_id, struct pcm_core_metrics *metrics)
{
    if (!g_pcm_state.pcm_initialized || !metrics || lcore_id >= RTE_MAX_LCORE) {
        return -1;
    }

    if (!g_pcm_state.lcore_states[lcore_id].monitoring_active) {
        return -1;
    }

    *metrics = g_pcm_state.core_metrics[lcore_id];
    return 0;
}

int pcm_monitoring_get_memory_metrics(uint32_t socket_id, struct pcm_memory_metrics *metrics)
{
    if (!g_pcm_state.pcm_initialized || !metrics || socket_id >= PCM_MAX_SOCKETS) {
        return -1;
    }

    *metrics = g_pcm_state.memory_metrics[socket_id];
    return 0;
}

int pcm_monitoring_get_io_metrics(uint32_t socket_id, struct pcm_io_metrics *metrics)
{
    if (!g_pcm_state.pcm_initialized || !metrics || socket_id >= PCM_MAX_SOCKETS) {
        return -1;
    }

    *metrics = g_pcm_state.io_metrics[socket_id];
    return 0;
}

int pcm_monitoring_get_system_metrics(struct pcm_system_metrics *metrics)
{
    if (!g_pcm_state.pcm_initialized || !metrics) {
        return -1;
    }

    *metrics = g_pcm_state.system_metrics;
    return 0;
}

void pcm_monitoring_print_summary(void)
{
    if (!g_pcm_state.pcm_initialized) {
        printf("PCM monitoring not available\n");
        return;
    }

    printf("\n=== COMPREHENSIVE PCM PERFORMANCE SUMMARY ===\n");
    pcm_print_core_statistics();
    pcm_print_memory_statistics();
    pcm_print_io_statistics();
    pcm_print_system_statistics();
    printf("=== END PCM PERFORMANCE SUMMARY ===\n");
}

int pcm_monitoring_get_info(char *info_buffer, size_t buffer_size)
{
    if (!info_buffer || buffer_size == 0) {
        return -1;
    }

    if (!g_pcm_state.pcm_initialized) {
        snprintf(info_buffer, buffer_size, "PCM monitoring not initialized");
        return -1;
    }

    if (g_pcm_state.use_static_wrapper) {
        return pcm_wrapper_get_system_info(info_buffer, buffer_size);
    } else {
        snprintf(info_buffer, buffer_size, "PCM monitoring active (fallback mode)");
        return 0;
    }
}
