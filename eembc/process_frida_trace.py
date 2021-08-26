#!/usr/bin/env python3

import sys
import re
import json

class CAliasTable:
    """ Provides context to alias mapping """
    def __init__ (self):
        self.current_alias = 0
        self.context_to_alias = {}
        self.alias_to_context = {}
        self.alias_description = {}
    def base_add (self, key):
        self.context_to_alias[key] = self.current_alias
        self.alias_to_context[self.current_alias] = key
        self.alias_description[self.current_alias] = "unknown"
        self.current_alias = self.current_alias + 1
    def add (self, pointer_string):
        if pointer_string in self.context_to_alias:
            raise Exception("Context already in use, cannot alias: %s" % pointer_string)
        self.base_add(pointer_string)
    def remove (self, pointer_string):
        if pointer_string in self.context_to_alias:
            del self.context_to_alias[pointer_string]
        else:
            print("Warning: freeing context without clone/init: %s" % pointer_string)
    def clone (self, dest_pointer, source_pointer):
        if dest_pointer in self.context_to_alias:
            print("Warning: cloning existing context: %s into %s" % (source_pointer, dest_pointer))
        self.base_add(dest_pointer)
    def get_alias (self, context):
        if context in self.context_to_alias:
            return self.context_to_alias[context]
        return None
    def get_context (self, alias):
        if alias in self.alias_to_context:
            return self.alias_to_context[alias]
        return None
    def description (self, alias, description=None):
        if description:
            self.alias_description[alias] = description
        elif alias in self.alias_description:
            return self.alias_description[alias]
        return None

# TODO: Need a "validate payload" function

class CParserLibrary:
    def __init__(self, trace_processor):
        self.trace_processor = trace_processor
        self.block_sha = False
        pass

    def parse(self, payload):
        function_name = payload['prim']
        function = getattr(self, function_name)
        # TODO: Handle when there IS NO function!
        function(payload)

    # Helper functions to make the code smaller

    def helper_add_ctx(self, payload):
        if payload['dir'] != 'enter':
            return
        ctx = payload['arg0']
        self.trace_processor.aliases.add(ctx)

    def helper_remove_ctx(self, payload):
        if payload['dir'] != 'enter':
            return
        ctx = payload['arg0']
        self.trace_processor.aliases.remove(ctx)

    # SSL State change probe

    def mbedtls_ssl_handshake_client_step(self, payload):
        if payload['dir'] != 'enter':
            return
        self.trace_processor.current_state = int(payload['arg0'])

    # AES ECB Functions

    def mbedtls_aes_init(self, payload):
        self.helper_add_ctx(payload)
    
    def mbedtls_aes_free(self, payload):
        self.helper_remove_ctx(payload)
    
    def mbedtls_internal_aes_encrypt(self, payload):
        if payload['dir'] != 'enter':
            return
        ctx = payload['arg0']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(alias, 16, "aes/E")
    
    def mbedtls_internal_aes_decrypt(self, payload):
        if payload['dir'] != 'enter':
            return
        ctx = payload['arg0']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(alias, 16, "aes/D")

    # AES/CCM functions

    def mbedtls_ccm_init(self, payload):
        self.helper_add_ctx(payload)

    def mbedtls_ccm_free(self, payload):
        self.helper_remove_ctx(payload)

    def mbedtls_ccm_star_encrypt_and_tag(self, payload):
        if payload['dir'] != 'enter':
            return
        ctx = payload['arg0']
        numbytes = int(payload['arg1'], 16)
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(alias, numbytes, "ccm/E")

    def mbedtls_ccm_star_auth_decrypt(self, payload):
        if payload['dir'] != 'enter':
            return
        ctx = payload['arg0']
        numbytes = int(payload['arg1'], 16)
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(alias, numbytes, "ccm/D")

    # ECDH Functions

    def mbedtls_ecdh_init(self, payload):
        self.helper_add_ctx(payload)

    def mbedtls_ecdh_free(self, payload):
        self.helper_remove_ctx(payload)

    def mbedtls_ecdh_calc_secret(self, payload):
        if payload['dir'] != 'enter':
            return
        ctx = payload['arg0']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(alias, 1, 'ecdh')

    # ECDSA functions

    def mbedtls_ecdsa_init(self, payload):
        self.helper_add_ctx(payload)

    def mbedtls_ecdsa_free(self, payload):
        self.helper_remove_ctx(payload)

    def mbedtls_ecdsa_write_signature(self, payload):
        # Ignore all SHAs that occur in read/write ECDSA
        if payload['dir'] == 'enter':
            self.block_sha = True
            ctx = payload['arg0']
            alias = self.trace_processor.aliases.get_alias(ctx)
            self.trace_processor.post_event(alias, 1, 'ecdsa/s')
        else:
            self.block_sha = False

    def mbedtls_ecdsa_write_signature_det(self, payload):
        # Ignore all SHAs that occur in read/write ECDSA
        if payload['dir'] == 'enter':
            self.block_sha = True
            ctx = payload['arg0']
            alias = self.trace_processor.aliases.get_alias(ctx)
            self.trace_processor.post_event(alias, 1, 'ecdsa/s')
        else:
            self.block_sha = False

    def mbedtls_ecdsa_read_signature(self, payload):
        # Ignore all SHAs that occur in read/write ECDSA
        if payload['dir'] == 'enter':
            self.block_sha = True
            ctx = payload['arg0']
            alias = self.trace_processor.aliases.get_alias(ctx)
            self.trace_processor.post_event(alias, 1, 'ecdsa/v')
        else:
            self.block_sha = False

    # GCM (WIP)

    def mbedtls_gcm_init(self, payload):
        self.helper_add_ctx(payload)

    def mbedtls_gcm_free(self, payload):
        self.helper_remove_ctx(payload)

    # SHA256

    def mbedtls_sha256_init(self, payload):
        self.helper_add_ctx(payload)

    def mbedtls_sha256_free(self, payload):
        self.helper_remove_ctx(payload)

    def mbedtls_sha256_clone(self, payload):
        if payload['dir'] != 'enter':
            return
        src = payload['arg0']
        dst = payload['arg1']
        self.trace_processor.aliases.clone(src, dst)

    def mbedtls_sha256_update_ret(self, payload):
        if payload['dir'] != 'enter':
            return
        ctx = payload['arg0']
        numbytes = int(payload['arg2'], 16)
        alias = self.trace_processor.aliases.get_alias(ctx)
        shortname = "sha"
        if self.block_sha is True:
            shortname += '/BLOCK'
        self.trace_processor.post_event(alias, numbytes, shortname)

    # MISC
    # TODO: We may decide to NOT ignore AES/ECB that occurs inside these

    def block_cipher_df(self, payload):
        pass

    def ctr_drbg_update_internal(self, payload):
        pass

    def mbedtls_ctr_drbg_random_with_add(self, payload):
        pass

class CTraceProcessor:
    """ Processes an mbedTLS TRACE file. """
    def __init__(self):
        self.aliases = CAliasTable()
        self.parsers = CParserLibrary(self)
        self.current_state = -1
        self.scoreboard = {}

    def process_file(self, file_name):
        with open(file_name, 'r') as file:
            for line in file:
                self.process_line(line.strip())

    def process_line(self, line):
        # Note: messages MIGHT appear in the middle of another line
        found = re.match(r"^.*message: {.*'(.*?)'.*$", line)
        if found:
            self.process_one_trace(found[1])

    def process_one_trace(self, text):
        """ Call the correct parse based on the type of trace """
        trace = json.loads(text)
        print(trace)
        self.parsers.parse(trace)

    def post_event (self, alias, n, tag):
        """ Add an event to the scoreboard, incrementing its 'n' value. """
        self.aliases.description(alias, tag)
        if alias not in self.scoreboard:
            self.scoreboard[alias] = {}
        slot = self.scoreboard[alias]
        if self.current_state in slot:
            slot[self.current_state] += n
        else:
            slot[self.current_state] = n

def main ():
    if len(sys.argv) < 2:
        raise Exception("Please specify the input file to process.")
    trace_processor = CTraceProcessor()
    trace_processor.process_file(sys.argv[1])

    print("% 5s,% 30s,% 15s:," % ("alias", "type", "context"), end="")
    for i in range (-1, 20):
        print("% 6d," % i, end="")
    print("")

    for alias in sorted(trace_processor.scoreboard):
        print("%05d,% 30s,% 16s," % (
            int(alias),
            trace_processor.aliases.description(alias),
            trace_processor.aliases.get_context(alias)),
            end="")
        for i in range(-1, 20):
            if i in trace_processor.scoreboard[alias]:
                print("% 6s," % str(
                    trace_processor.scoreboard[alias][i]), end="")
            else:
                print("% 6s," % " ", end="")
        print()

if __name__ == '__main__':
    main()
