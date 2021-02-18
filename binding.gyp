{
  "variables": {
    "dependencies_libdir": "<(module_root_dir)/dependencies/lib"
  },
  "targets": [{
    "target_name": "dtls",
    "sources": [
      "lib/dtls.c"
    ],
    "cflags": ["-fPIC"],
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
  }]
}
