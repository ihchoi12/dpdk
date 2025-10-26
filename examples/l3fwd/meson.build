# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

allow_experimental_apis = true

# Add C++ compiler support for PCM wrapper
add_languages('cpp', required: true)

deps += ['acl', 'hash', 'lpm', 'fib']

# PCM library configuration for static linking
pcm_base_path = meson.current_source_dir() / '..' / '..' / '..' / 'pcm'
pcm_lib_path = pcm_base_path / 'build' / 'src'
pcm_inc_path = pcm_base_path / 'src'
common_pcm_path = meson.current_source_dir() / '..' / '..' / '..' / 'common' / 'pcm'

# Check for PCM static library
pcm_static_lib = pcm_lib_path / 'libpcm.a'
pcm_found = false

if fs.is_file(pcm_static_lib)
    pcm_found = true
    message('Found PCM static library: ' + pcm_static_lib)
endif

sources = files(
        'l3fwd_acl.c',
        'l3fwd_em.c',
        'l3fwd_event.c',
        'l3fwd_event_internal_port.c',
        'l3fwd_event_generic.c',
        'l3fwd_fib.c',
        'l3fwd_lpm.c',
        'l3fwd_pcm.c',
        'main.c',
)

# Add common PCM wrapper if library found
if pcm_found
    sources += files('../../../common/pcm/common_pcm_wrapper.cpp')
    message('PCM integration enabled with static linking (using common wrapper)')
endif

if dpdk_conf.has('RTE_LIB_EVENTDEV')
    deps += 'eventdev'
endif
cflags += no_wvla_cflag

# Initialize ldflags
ldflags = []

# Add PCM support if available
if pcm_found
    includes += include_directories('../../../pcm/src', '../../../common/pcm')
    ldflags += [pcm_static_lib, '-static-libstdc++', '-static-libgcc', '-lpthread', '-ldl', '-lnuma']
endif
