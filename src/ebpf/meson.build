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
vmlinux_path = join_paths('..', '..', '..', 'vmlinux.h', 'include', arch, 'vmlinux.h')

# Include directories for libbpf and the kernel header.
inc_dirs = include_directories(
  '..',
  join_paths('..', '..', 'libbpf', 'include', 'uapi'),
  fs.parent(vmlinux_path),
)

# Find the Clang compiler.
clang = find_program('clang', required: true)
bpftool = find_program('bpftool', required: true)

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
  '-I../../../libbpf/include/uapi',
  '-I' + fs.parent(vmlinux_path),
]

# List of eBPF source files.
ebpf_srcs = ['sysprof-bpf.c']
ebpf_objects = []

foreach src : ebpf_srcs
  base = src.split('.')[0]
  final_obj = base + '.bpf.o'
  skel_h = base + '.skel.h'
  ebpf_obj = custom_target(
    final_obj,
    input: src,
    output: final_obj,
    command: [clang, ebpf_cflags, '-c', '@INPUT0@', '-o', '@OUTPUT@'],
    build_by_default: true, # Ensure it's built by default
    install: false,
  )

  # ebpf_objects += comp_target

  # Print the full path (for debugging)
  message('Object file:', ebpf_obj.full_path())

  # 2. Generate skeleton header (to source directory)
  custom_target(
    'gen-skel-' + skel_h,
    input: ebpf_obj,
    output: skel_h, # Meson thinks this goes to builddir
    command: [
      'sh',
      '-c', # Redirect output directly to source directory
      bpftool.path()
      + ' gen skeleton @INPUT@ > '
      + meson.current_source_dir() / skel_h,
    ],
    build_by_default: true,
    install: false,
  )

endforeach

# Optionally install or use ebpf_objects as needed
