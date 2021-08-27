#!/usr/bin/env bash

./ssl/ssl_server2 \
	force_version=tls1_3 \
	force_ciphersuite=TLS1-3-CHACHA20-POLY1305-SHA256 \
	key_exchange_modes=ecdhe_ecdsa \
	curves=secp256r1 \
	tickets=0 named_groups=secp256r1 \
	auth_mode=required \
	crt_file=./certs/server.crt \
	key_file=./certs/server.key \
	ca_file=./certs/ca.crt

