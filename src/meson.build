project('sysprof', 'c')

# Dependencies
libbpf = dependency('libbpf', required: true)
ebpf_build = subdir('ebpf') # Include eBPF build system

# Source files
sources = ['sysprof.c', 'ebpf/sysprof-bpf.skel.h']

# Build executable
executable('sysprof', sources, dependencies: [libbpf])
