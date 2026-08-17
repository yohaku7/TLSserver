# TLSserver

A very simple TLS 1.3 server, implemented by Python.

# Try Server

Execute command below:
```commandline
openssl s_client -tls1_3 -tlsextdebug -debug -keylogfile /dev/stdout -state -trace -curves x25519 -ciphersuites TLS_AES_128_GCM_SHA256 -msg -connect localhost:4433
```
