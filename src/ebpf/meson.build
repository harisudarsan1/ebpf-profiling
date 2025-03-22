project('ebpf', 'c')

fs = import('fs')
# Map uname output to our arch string.
arch_map = {
  'x86_64': 'x86',
  'armv7l': 'arm',
  'aarch64': 'arm64',
  'ppc64le': 'powerpc',
  'mips64': 'mips',
  'loongarch64': 'loongarch',
}
uname_m = run_command('uname', '-m').stdout().strip()
arch = arch_map.get(uname_m, 'unknown')

# Ensure architecture is supported
if arch == 'unknown'
  error('Unsupported architecture: ' + uname_m)
endif

# Path to vmlinux.h (assumed relative to this directory)
vmlinux_path = join_paths('..', '..', 'vmlinux.h', 'include', arch, 'vmlinux.h')

# Include directories for libbpf and the kernel header.
inc_dirs = include_directories(
  '..',
  join_paths('..', '..', 'libbpf', 'include', 'uapi'),
  fs.parent(vmlinux_path),
)

# Find the Clang compiler.
clang = find_program('clang', required: true)

# Retrieve Clang's default system include paths.
# clang_includes_cmd = "clang -v -E - < /dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \\(/.*\\)|-idirafter \\1|p }'"
# clang_includes_output = run_command('sh', '-c', clang_includes_cmd).stdout().strip()
# clang_bpf_sys_includes = clang_includes_output.split('\n')

# Compiler flags for BPF code
ebpf_cflags = [
  '-g',
  '-O2',
  '-target', 'bpf',
  '-D__TARGET_ARCH_' + arch,
  '-I../../libbpf/include/uapi',
  '-I' + fs.parent(vmlinux_path),
]

# List of eBPF source files.
ebpf_srcs = ['sysprof-bpf.c']
ebpf_objects = []

foreach src : ebpf_srcs
  base = src.split('.')[0]
  final_obj = base + '.bpf.o'

  comp_target = custom_target(
    final_obj,
    input: [src, vmlinux_path],
    output: final_obj,
    command: [clang, ebpf_cflags, '-c', '@INPUT0@', '-o', '@OUTPUT@'],
  )

  ebpf_objects += comp_target
endforeach

# Optionally install or use ebpf_objects as needed
