project('sysprof', 'c',
  version: '1.0',
  default_options: [
    'b_pie=true',          # Enable PIE globally
    'buildtype=debug',
    'warning_level=3',
    'c_std=gnu11'
  ])

# First process ebpf components
subdir('ebpf')



# Then build network executable
# In src/meson.build
# executable('sysprof',
#   sources: 'sysprof.c',
#   include_directories: includes,
#   dependencies: [
#     dependency('libbpf'),
#     dependency('libelf'),
#     dependency('zlib')
#   ],
#   c_args: [
#     '-fPIE',              # Explicit position-independent code
#     '-Wall'
#   ],
#   link_args: [
#     '-pie',               # Required for PIE linking
#     '-Wl,--build-id=sha1'
#   ],
#   install: true
# )
executable('sysprof',
  'sysprof.c',
  dependencies: [
    bpf_skel_dep,
    dependency('libbpf'),
    dependency('libelf'),
    dependency('zlib')
  ],
  
  c_args: [
    '-fPIE',              # Explicit position-independent code
    '-Wall'
  ],
  link_args: [
    '-pie',               # Required for PIE linking
    '-Wl,--build-id=sha1'
  ],
  install: true,
)
# Explicit dependency - critical!
# add_project_dependencies('network', 
#   declare_dependency(sources: 'ebpf/sysprof-bpf.skel.h'),
#   language: 'c'
# )
