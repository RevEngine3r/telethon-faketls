import socket

import logging as log


class LayeredStreamReaderBase:
    __slots__ = ("upstream",)

    def __init__(self, upstream):
        self.upstream = upstream

    async def read(self, n):
        return await self.upstream.read(n)

    async def readexactly(self, n):
        return await self.upstream.readexactly(n)


class LayeredStreamWriterBase:
    __slots__ = ("upstream",)

    def __init__(self, upstream):
        self.upstream = upstream

    def write(self, data, extra={}):
        return self.upstream.write(data)

    def write_eof(self):
        return self.upstream.write_eof()

    async def drain(self):
        return await self.upstream.drain()

    def close(self):
        return self.upstream.close()

    def abort(self):
        return self.upstream.transport.abort()

    def get_extra_info(self, name):
        return self.upstream.get_extra_info(name)

    @property
    def transport(self):
        return self.upstream.transport


class FakeTLSStreamReader(LayeredStreamReaderBase):
    __slots__ = ('buf',)

    def __init__(self, upstream):
        self.upstream = upstream
        self.buf = bytearray()

    async def read(self, n, ignore_buf=False):
        if self.buf and not ignore_buf:
            data = self.buf
            self.buf = bytearray()
            return bytes(data)

        while True:
            tls_rec_type = await self.upstream.readexactly(1)
            if not tls_rec_type:
                return b""

            if tls_rec_type not in [b"\x14", b"\x17"]:
                log.error("BUG: bad tls type %s in FakeTLSStreamReader" %
                          tls_rec_type)
                return b""

            version = await self.upstream.readexactly(2)
            if version != b"\x03\x03":
                log.error(
                    "BUG: unknown version %s in FakeTLSStreamReader" % version)
                return b""

            data_len = int.from_bytes(await self.upstream.readexactly(2), "big")
            data = await self.upstream.readexactly(data_len)
            if tls_rec_type == b"\x14":
                continue
            return data

    async def readexactly(self, n):
        while len(self.buf) < n:
            tls_data = await self.read(1, ignore_buf=True)
            if not tls_data:
                return b""
            self.buf += tls_data
        data, self.buf = self.buf[:n], self.buf[n:]
        return bytes(data)

    async def read_server_hello(self) -> bytes:
        server_hello = await super().readexactly(127 + 6 + 3 + 2)
        log.info(f'{len(server_hello)=}')
        http_data_len = int.from_bytes(server_hello[-2:], 'big')
        log.info(f'{http_data_len=}')
        return server_hello + await super().readexactly(http_data_len)


class FakeTLSStreamWriter(LayeredStreamWriterBase):
    __slots__ = ()

    def __init__(self, upstream):
        self.upstream = upstream

    def write(self, data, extra={}):
        max_chunk_size = 16384 + 24
        for start in range(0, len(data), max_chunk_size):
            end = min(start + max_chunk_size, len(data))
            self.upstream.write(
                b"\x17\x03\x03" + int.to_bytes(end - start, 2, "big"))
            self.upstream.write(data[start: end])
        return len(data)
