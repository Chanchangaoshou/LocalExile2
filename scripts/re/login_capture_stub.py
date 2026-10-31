"""PoE2 login-capture stub.

Listens on 127.0.0.1:21262, accepts the game client's login connection, and
hex-dumps every byte exchanged (the first C->S message 0x0002 is plaintext —
its length tells us whether the client sends its static public key).
Responds to the first C->S message with a plausible-but-wrong S->C 0x0002
(correct framing, dummy key+signature) so the client stays connected a little
longer, then closes.

Usage: python scripts/re/login_capture_stub.py [port=21262] [outfile]
"""
import asyncio
import datetime
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 21262
OUT = sys.argv[2] if len(sys.argv) > 2 else 'data/login-capture.txt'


def ts():
    return datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    print(f'[{ts()}] connect from {peer}', flush=True)
    msg = 0
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), timeout=60)
            if not data:
                print(f'[{ts()}] {peer} closed', flush=True)
                break
            msg += 1
            line = f'[{ts()}] C->S msg#{msg} {len(data)} bytes: {data.hex()}'
            print(line, flush=True)
            with open(OUT, 'a') as f:
                f.write(line + '\n')
            if msg == 1:
                # plausible S->C 0x0002: u16 id=2, u16 128, 128-byte dummy key,
                # u16 56, 56-byte dummy signature -> framing only, contents wrong.
                reply = (2).to_bytes(2, 'big') + (128).to_bytes(2, 'big') + bytes(128) \
                        + (56).to_bytes(2, 'big') + bytes(56)
                writer.write(reply)
                await writer.drain()
                print(f'[{ts()}] sent dummy S->C 0x0002 ({len(reply)} bytes)', flush=True)
            else:
                break  # after the first exchange, close: client will show a login error
    except asyncio.TimeoutError:
        print(f'[{ts()}] {peer} idle timeout', flush=True)
    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(handle, '127.0.0.1', PORT)
    print(f'[{ts()}] capture stub listening on 127.0.0.1:{PORT}; logging to {OUT}', flush=True)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
