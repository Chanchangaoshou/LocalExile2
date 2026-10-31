"""PoE2 login-capture stub, server-speaks-first variant.

On connect: immediately sends a dummy S->C 0x0002 key-exchange message with
PoE1 framing (u16 id=2, u16 128, 128-byte dummy ephemeral public, u16 56,
56-byte dummy DSA-SHA1 signature), then hex-dumps everything the client sends
back. If PoE2 kept PoE1's flow (client speaks first after connecting) the
client's first message will arrive right after; if the server speaks first the
client will react to our dummy (accept/log it, or error out).
"""
import asyncio
import datetime
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 21262
OUT = sys.argv[2] if len(sys.argv) > 2 else 'data/login-capture.txt'

DUMMY_S_HELLO = (
    (2).to_bytes(2, 'big')          # msg id 0x0002
    + (128).to_bytes(2, 'big')      # u16 128
    + bytes(128)                    # dummy ephemeral public
    + (56).to_bytes(2, 'big')       # u16 56
    + bytes(56)                     # dummy DSA signature r||s
)


def ts():
    return datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]


def log(line):
    print(f'[{ts()}] {line}', flush=True)
    with open(OUT, 'a') as f:
        f.write(f'[{ts()}] {line}\n')


def hexs(data, limit=200):
    h = data.hex()
    return h[:limit] + ('...' if len(h) > limit else '')


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    log(f'connect from {peer}')
    writer.write(DUMMY_S_HELLO)
    await writer.drain()
    log(f'sent dummy S->C 0x0002 ({len(DUMMY_S_HELLO)} bytes); waiting for client...')
    msg = 0
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), timeout=90)
            if not data:
                log(f'{peer} closed')
                break
            msg += 1
            log(f'C->S msg#{msg} {len(data)} bytes: {hexs(data)}')
            if msg == 1:
                writer.write(DUMMY_S_HELLO)
                await writer.drain()
                log('re-sent dummy S->C 0x0002 after first client message')
    except asyncio.TimeoutError:
        log(f'{peer} idle timeout (90s) - client sent nothing')
    except ConnectionResetError:
        log(f'{peer} reset by client')
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle, '127.0.0.1', PORT)
    log(f'capture stub (server-speaks-first) listening on 127.0.0.1:{PORT}; logging to {OUT}')
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
