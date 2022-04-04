import logging as log
import asyncio
import socket

from . import FakeTLS as Ft

from telethon.network.connection.tcpmtproxy import ConnectionTcpMTProxyRandomizedIntermediate


class ConnectionTcpMTProxyFakeTLS(ConnectionTcpMTProxyRandomizedIntermediate):
    def __init__(self, ip, port, dc_id, *, loggers, proxy=None, local_addr=None):
        self.fake_tls_cdc = Ft.MTProxyFakeTLSClientCodec(proxy[2])

        proxy_host = proxy[0]
        if len(proxy_host) > 60:
            proxy_host = socket.gethostbyname(proxy[0])

        proxy = proxy_host, proxy[1], self.fake_tls_cdc.secret.hex()

        super().__init__(ip, port, dc_id, loggers=loggers, proxy=proxy, local_addr=local_addr)

    async def _connect(self, timeout=None, ssl=None):
        if self._local_addr is not None:
            # NOTE: If port is not specified, we use 0 port
            # to notify the OS that port should be chosen randomly
            # from the available ones.
            if isinstance(self._local_addr, tuple) and len(self._local_addr) == 2:
                local_addr = self._local_addr
            elif isinstance(self._local_addr, str):
                local_addr = (self._local_addr, 0)
            else:
                raise ValueError("Unknown local address format: {}".format(self._local_addr))
        else:
            local_addr = None

        if not self._proxy:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=self._ip,
                    port=self._port,
                    ssl=ssl,
                    local_addr=local_addr
                ), timeout=timeout)
        else:
            # Proxy setup, connection and negotiation is performed here.
            sock = await self._proxy_connect(
                timeout=timeout,
                local_addr=local_addr
            )

            # Wrap socket in SSL context (if provided)
            if ssl:
                sock = self._wrap_socket_ssl(sock)

            self._reader, self._writer = await asyncio.open_connection(sock=sock)

        await self._init_fake_tls_conn()

        self._codec = self.packet_codec(self)
        self._init_conn()
        await self._writer.drain()

    async def _init_fake_tls_conn(self):
        log.info('Sending FakeTLS headers...')
        self._writer.write(self.fake_tls_cdc.build_new_client_hello_packet())
        await self._writer.drain()
        log.info('FakeTLS headers sent.')
        self._writer = Ft.FakeTLSStreamWriter(self._writer)
        self._reader = Ft.FakeTLSStreamReader(self._reader)

        log.info('Receiving server hello and verifying it...')
        if not self.fake_tls_cdc.verify_server_hello(await self._reader.read_server_hello()):
            msg = 'FakeTLS server hello verification failed.'
            log.error('FakeTLS server hello verification failed.')
            raise Exception(msg)
        log.info('FakeTLS handshake completed.')
