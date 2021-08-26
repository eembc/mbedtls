const log = new File('frida.log', 'w')

const hookup = {

    'mbedtls_aes_init': 1,
    'mbedtls_aes_free': 1,

    'mbedtls_internal_aes_encrypt': 1,
    'mbedtls_internal_aes_decrypt': 1,

    'mbedtls_ccm_init': 1,
    'mbedtls_ccm_free': 1,
    'mbedtls_ccm_star_encrypt_and_tag': 1,
    'mbedtls_ccm_star_auth_decrypt': 1,

    'mbedtls_ecdh_init': 1,
    'mbedtls_ecdh_free': 1,
    'mbedtls_ecdh_calc_secret': 1,

    'mbedtls_ecdsa_write_signature': 1,
    'mbedtls_ecdsa_write_signature_det': 1,
    'mbedtls_ecdsa_read_signature': 1,

    'mbedtls_ecdsa_init': 1,
    'mbedtls_ecdsa_free': 1,

    'mbedtls_gcm_init': 1,
    'mbedtls_gcm_free': 1,

    'mbedtls_sha256_init': 1,
    'mbedtls_sha256_free': 1,
    'mbedtls_sha256_clone': 1,
    'mbedtls_sha256_update_ret': 1,

    // These may require their own code since we need to extract
    // the AES context from an input parameter.
    'block_cipher_df': 1,
    'ctr_drbg_update_internal': 1,
    'mbedtls_ctr_drbg_random_with_add': 1,

    // This has its own function now
    //'mbedtls_ssl_handshake_client_step': 1,
}

let mods = Process.enumerateModules()
//console.log(JSON.stringify(mods[0], '', 4))
let imps = mods[0].enumerateSymbols()
let base = undefined
imps.forEach(x => {``
    if (hookup[x.name] == 1) {
        //console.log(JSON.stringify(x, '', 4))
        base = x.address
        //console.log("Connecting to", x.name, "base", base)
        Interceptor.attach(base, {
            onEnter(args) {
                let obj = {
                    dir: "enter",
                    prim: x.name,
                    arg0: args[0],
                    arg1: args[1],
                    arg2: args[2],
                }
                log.write(JSON.stringify(obj))
                log.write('\n')
            },
            onLeave(retval) {
                let obj = {
                    dir: "exit",
                    prim: x.name,
                    retval
                }
                log.write(JSON.stringify(obj))
                log.write('\n')
            }
        })
    }
    else if (x.name === 'mbedtls_ssl_handshake_client_step') {
        base = x.address
        Interceptor.attach(base, {
            onEnter(args) {
                // This is dicey: args[0] is a pointer to an 'mbedtls_ssl_context'
                // The first argument is a pointer to a config (assume 8 bytes on Linux)
                // The second argument is int state.
                // Clearly this can change, but for now, just shift 8 bytes and readInt()
                let state = args[0].add(8)
                let obj = {
                    dir: "enter",
                    prim: x.name,
                    arg0: state.readInt(),
                    arg1: args[1],
                    arg2: args[2],
                }
                log.write(JSON.stringify(obj))
                log.write('\n')
            },
            onLeave(retval) {
                let obj = {
                    dir: "exit",
                    prim: x.name,
                    retval
                }
                log.write(JSON.stringify(obj))
                log.write('\n')
            }
        })
    }
})
