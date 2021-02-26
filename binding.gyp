{
  "variables": {
    "dependencies_libdir": "<(module_root_dir)/dependencies/lib",
    "cpu_cores": "<!(lscpu -b --parse=CPU | grep -v '^#' | wc -l)"
  },
  "targets": [
    {
      "target_name": "dtls",
      "dependencies": ["gnutls"],
      "sources": [
        "lib/dtls.c"
      ],
      "cflags": ["-fPIC", "-save-temps"],
      "include_dirs":["<(module_root_dir)/lib", "<(module_root_dir)/dependencies/include"],
      "link_settings": {
        "libraries": [
          "-Wl,-rpath,<(dependencies_libdir)/",
          '-ltasn1', '-lgmp', '-lhogweed', '-lnettle', '-lgnutls'
        ],
        "library_dirs": [
          '<(dependencies_libdir)'
        ]
      }
    },
    {
      "target_name": "gnutls",
      "type": "none",
      "actions": [
        {
          "action_name": "action_build_gnutls",
          "outputs": [
            '<(dependencies_libdir)/libgnutls.so',
            '<(dependencies_libdir)/libnettle.so',
            '<(dependencies_libdir)/libhogweed.so',
            '<(dependencies_libdir)/libgmp.so',
            '<(dependencies_libdir)/libtasn1.so'
          ],
          "inputs": [
            "<(module_root_dir)/Makefile"
          ],
          "action": ["make", "-j<(cpu_cores)"]
        }
      ]
    }
  ]
}
