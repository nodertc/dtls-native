{
  "targets": [{
    "target_name": "dtls",
    "sources": [
      "lib/dtls.c"
    ],
    "include_dirs":["lib", "dependencies/include"],
    "libraries": ['-L${PWD}/dependencies/lib', '-lgmp', '-lnettle', '-lhogweed', '-ltasn1']
  }]
}
