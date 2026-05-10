project('dpdk-l3fwd', 'c',
  default_options: ['buildtype=release', 'c_std=c11'])

dpdk = dependency('libdpdk')

executable('l3fwd',
  ['src/main.c', 'src/mpls.c', 'src/vxlan.c', 'src/acl.c'],
  dependencies : dpdk,
  install       : false)