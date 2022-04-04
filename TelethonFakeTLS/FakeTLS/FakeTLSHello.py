import base64
import re
from . import EncryptionHelper as Eh
import hmac
import hashlib
import time
import logging as log


def gen_sha256_digest(key: bytes, msg: bytes) -> bytes:
    return hmac.new(
        key=key, msg=msg, digestmod=hashlib.sha256).digest()


def decode_b64(s: str) -> bytes:
    s = re.sub(r'[^a-zA-Z0-9+/]+', '', s)
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


class MTProxyFakeTLSClientCodec:
    client_hello_dict: dict[str:bytes] = {
        'content_type': b'\x16',  # handshake (22)
        'version': b'\x03\x01',  # TLS 1.0
        'len': b'\x02\x00',  # 512
        'handshake_type': b'\x01',  # client hello
        'handshake_len': b'\x00\x01\xfc',  # 508
        'handshake_version': b'\x03\x03',  # TLS 1.2

        # Random
        'random': b'\00' * 32,  # = 32 random bytes digest
        # End Random

        'session_id_len': b'\x20',  # 32

        # Session ID
        'session_id': b'\x00' * 32,  # = 32 random bytes
        # End Session ID

        'cipher_suites_len': b'\x00\x20',  # 32
        'cipher_suites': b"\xfa\xfa\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30"
                         b"\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35",  # 16 suites
        'compression_methods_len': b'\x01',  # 1
        'compression_methods': b'\x00',  # no compression
        'extensions_len': b'\x01\x93',  # 403
        'ext_reserved_1': b"\x4a\x4a\x00\x00",  # GREASE

        # SNI
        'ext_server_name_type': b'\x00\x00',  # server_name (0)
        'ext_server_name_len': b'\x00\x00',  # = 2 + 1 + 2 + domain_len
        'ext_server_name_indication_list_len': b'\x00\x00',  # = 1 + 2 + domain_len
        'ext_server_name_indication_type': b'\x00',  # host_name (0)
        'ext_server_name_indication_len': b'\x00\x00',  # = domain_len
        'ext_server_name_indication': b'\x00',  # = domain
        # End SNI

        'ext_extended_master_secret': b"\x00\x17\x00\x00",
        'ext_renegotiation_info': b"\xff\x01\x00\x01\x00",
        'ext_supported_groups': b"\x00\x0a\x00\x0a\x00\x08\xba\xba\x00\x1d\x00\x17\x00\x18",
        'ext_ec_point_formats': b"\x00\x0b\x00\x02\x01\x00",
        'ext_session_ticket': b"\x00\x23\x00\x00",
        'ext_alpn': b"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31",
        'ext_status_request': b"\x00\x05\x00\x05\x01\x00\x00\x00\x00",
        'ext_signature_algorithms': b"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04"
                                    b"\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01",
        'ext_signature_cert_timestamp': b"\x00\x12\x00\x00",

        # Key Share x25519
        'ext_key_share_type': b'\x00\x33',  # key_share (51)
        'ext_key_share_len': b'\x00\x2b',  # 43
        'ext_key_share_client_key_len': b'\x00\x29',  # 41
        'ext_key_share_reserved': b"\xba\xba\x00\x01\x00",  # GREASE
        'ext_key_share_group': b"\x00\x1d",  # x25519 (29)
        'ext_key_share_exchange_len': b"\x00\x20",  # 32
        'ext_key_share_exchange': b"\x00",  # = x25519_public_key
        # End Key Share x25519

        'ext_psk_key_exchange_modes': b"\x00\x2d\x00\x02\x01\x01",
        'ext_supported_tls_versions': b"\x00\x2b\x00\x0b\x0a\x9a\x9a\x03\x04\x03\x03\x03\x02\x03\x01",
        'ext_compress_cert': b"\x00\x1b\x00\x03\x02\x00\x02",
        'ext_reserved_2': b"\x1a\x1a\x00\x01\x00",

        # Padding
        'ext_padding_type': b'\x00\x15',  # padding (21)
        'ext_padding_len': b'\x00\x00',  # = 517 - packet_len
        'ext_padding': b'',  # = b'\x00' * padding_len
        # End Padding
    }

    def __init__(self, secret: str):
        try:
            self.secret: bytes = bytes.fromhex(f'ee{secret}')
        except:
            self.secret: bytes = decode_b64(f'7{secret}')

        self.domain: bytes = self.secret[17:]
        self.secret: bytes = self.secret[1:17]
        self.is_pkt_changed: bool = True
        self.pkt: bytes = b''

    # set or get parameters from client hello dict
    def client_hello(self, key: str, value: bytes | int | str | None = None,
                     ret_type: type(bytes) | type(str) | type(int) = type(bytes)) -> bytes | int | str | None:
        if value is None:
            if ret_type is bytes:
                return self.client_hello_dict[key]
            if ret_type is str:
                return self.client_hello_dict[key].decode(encoding='utf8')
            if ret_type is int:
                return int.from_bytes(self.client_hello_dict[key], 'big')

        if type(value) is str:
            value = value.encode(encoding='utf8')
        elif type(value) is int:
            value = value.to_bytes(length=len(self.client_hello_dict[key]), byteorder='big')

        self.client_hello_dict[key] = value
        self.is_pkt_changed = True

    def gen_set_session_id(self):
        self.client_hello('session_id', Eh.myrandom.getrandbytes(32))

    def fix_padding(self):
        self.client_hello('ext_padding', b'')
        padding_len = 517 - len(self.glue_pkt())
        self.client_hello('ext_padding_len', padding_len)
        self.client_hello('ext_padding', b'\x00' * padding_len)

    def glue_pkt(self) -> bytes:
        if self.is_pkt_changed:
            self.pkt = b''.join(self.client_hello_dict.values())
            self.is_pkt_changed = False
        return self.pkt

    def gen_set_key_share(self):
        self.client_hello('ext_key_share_exchange', Eh.gen_x25519_public_key())

    def gen_set_random(self):
        self.client_hello('random', b'\x00' * 32)
        digest = gen_sha256_digest(self.secret, self.glue_pkt())
        current_time = int(time.time()).to_bytes(length=4, byteorder='little')
        xored_time = bytes(current_time[i] ^ digest[28 + i]
                           for i in range(4))
        digest = digest[:28] + xored_time
        self.client_hello('random', digest)

    def set_domain(self):
        domain_len = len(self.domain)
        self.client_hello('ext_server_name_len', 2 + 1 + 2 + domain_len)
        self.client_hello('ext_server_name_indication_list_len', 1 + 2 + domain_len)
        self.client_hello('ext_server_name_indication_len', domain_len)
        self.client_hello('ext_server_name_indication', self.domain)

    def build_new_client_hello_packet(self) -> bytes:
        self.gen_set_session_id()
        self.set_domain()
        self.gen_set_key_share()
        self.fix_padding()
        self.gen_set_random()
        return self.glue_pkt()

    def verify_server_hello(self, server_hello: bytes) -> bool:
        log_msg = 'ServerHello: '

        log.debug(f'{len(server_hello)=}')

        try:
            if len(server_hello) < 127 + 6:
                log_msg += 'invalid size.'
                raise Exception(log_msg)

            if not server_hello.startswith(b'\x16\x03\x03'):
                log_msg += 'invalid tls packet 1.'
                raise Exception(log_msg)

            if server_hello[127:127 + 9] != b'\x14\x03\x03\x00\x01\x01\x17\x03\x03':
                log_msg += 'invalid tls packet 2.'
                raise Exception(log_msg)

            if server_hello[11 + 32 + 1:11 + 32 + 1 + 32] != self.client_hello_dict['session_id']:
                log_msg += 'invalid tls session id.'
                raise Exception(log_msg)

            client_digest = self.client_hello_dict['random']
            log.debug(f'{client_digest.hex()=}')

            server_digest = server_hello[11:11 + 32]
            log.debug(f'{server_digest.hex()=}')
            # Log.info(f'{server_hello.hex()=}')

            server_hello = server_hello[:11] + (b'\x00' * 32) + server_hello[11 + 32:]
            # Log.info(f'{server_hello.hex()=}')

            computed_digest = gen_sha256_digest(self.secret, client_digest + server_hello)
            log.debug(f'{computed_digest.hex()=}')

            if server_digest != computed_digest:
                log_msg += 'invalid server digest.'
                raise Exception(log_msg)
            else:
                log_msg += 'tls auth completed.'
        except Exception as ex:
            log.error(ex)
            return False
        else:
            log.debug(log_msg)
            return True
