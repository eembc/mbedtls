#!/usr/bin/env bash

./ssl/ssl_client2 \
	server_name=localhost \
	server_addr=127.0.0.1 \
	force_version=tls1_3 \
	force_ciphersuite=TLS1-3-CHACHA20-POLY1305-SHA256 \
	key_exchange_modes=ecdhe_ecdsa \
	named_groups=secp256r1 \
	key_exchange_modes=ecdhe_ecdsa \
	curves=secp256r1 \
	ca_file=./certs/ca.crt \
	crt_file=./certs/client.crt \
	key_file=./certs/client.key

