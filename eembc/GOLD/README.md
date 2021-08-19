# Sample logs

`v1` logs are frome the `pule` + PERL days. There were some bugs, and this wasn't tls1.3 mode

`v2` logs are from the new attempt at macro instrumentation. Here we label SHA used in ECDSA and AES used in DRBG (also a bug in # of ECSA calls)

`v3` logs use Frida, the tls1.3 (now deprecated in 3.0.0) method, and we don't yet prune DRBG AES but we call out ECDSA/SHA. Also, one of the BLOCK'ed SHAs is 64 bytes smaller than the v2 log, not sure who made a mistake; will debug later (also one of the SHA larger contexts has been split up, i think it might be a clone bug)


