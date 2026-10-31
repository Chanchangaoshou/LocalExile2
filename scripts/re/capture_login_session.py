"""One-command login-capture experiment for the PoE2 client.

1. backs up gateway_list.txt
2. redirects it to 127.0.0.1:<port> (ASCII, CRLF)
3. starts the capture stub as a subprocess
4. launches the game via Steam
5. waits for the login connection (or timeout)
6. restores gateway_list.txt, stops the stub, closes the game

Usage: python scripts/re/capture_login_session.py [game_exe] [port]
Expects Steam to be running and logged in.
"""
import asyncio
import os
import shutil
import subprocess
import sys
import time

GAME_EXE = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Administrator\poe2-server\client\PathOfExileSteam.exe"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 21262
GAME_DIR_REAL = r"C:\Program Files (x86)\Steam\steamapps\common\Path of Exile 2"  # the install Steam launches
GW = os.path.join(GAME_DIR_REAL, 'gateway_list.txt')
GW_BAK = GW + '.bak'
STUB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'login_capture_stub.py')
CAPTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'login-capture.txt')
REDIRECT = f'Local;Local;127.0.0.1:{PORT};;false\r\n'


def redirect_gateway():
    shutil.copy(GW, GW_BAK)
    with open(GW, 'w', encoding='ascii', newline='') as f:
        f.write(REDIRECT)


def restore_gateway():
    if os.path.exists(GW_BAK):
        shutil.copy(GW_BAK, GW)
        os.remove(GW_BAK)


async def stub_once(port):
    """Run the capture stub in-process until one connection completes or timeout."""
    import login_capture_stub as stub
    stub.PORT = port
    stub.OUT = CAPTURE
    server = await asyncio.start_server(stub.handle, '127.0.0.1', port)
    print(f'stub listening on 127.0.0.1:{port}', flush=True)
    async with server:
        # single-connection mode: wait for one handler to finish
        handler_done = asyncio.Event()

        async def handle_wrapper(reader, writer):
            await stub.handle(reader, writer)
            handler_done.set()

        server2 = await asyncio.start_server(handle_wrapper, '127.0.0.1', port)
        server.close()
        await server.wait_closed()
        async with server2:
            try:
                await asyncio.wait_for(handler_done.wait(), timeout=240)
            except asyncio.TimeoutError:
                print('no connection within 240s', flush=True)
            server2.close()
            await server2.wait_closed()


def launch_game():
    # Steam must be running; fall back to launching the exe directly.
    steam = os.path.expandvars(r'C:\Program Files (x86)\Steam\steam.exe')
    if os.path.exists(steam):
        subprocess.run([steam, 'steam://run/2694490'], timeout=15)
    else:
        subprocess.Popen([GAME_EXE], cwd=GAME_DIR)


def main():
    os.makedirs(os.path.dirname(CAPTURE), exist_ok=True)
    if os.path.exists(CAPTURE):
        os.remove(CAPTURE)

    print('== redirecting gateway ==', flush=True)
    redirect_gateway()

    print('== starting capture stub ==', flush=True)
    stub_proc = subprocess.Popen([sys.executable, STUB, str(PORT), CAPTURE],
                                 cwd=os.path.dirname(STUB))
    time.sleep(2)

    print('== launching game ==', flush=True)
    launch_game()

    try:
        # wait while the stub captures (game startup ~1-2 min)
        deadline = time.time() + 300
        while time.time() < deadline:
            time.sleep(5)
            if os.path.exists(CAPTURE):
                size = os.path.getsize(CAPTURE)
                if size > 0 and time.time() - os.path.getmtime(CAPTURE) > 30:
                    break  # capture complete and quiet for 30s
        # extra grace period for the login attempt
        time.sleep(60)
    finally:
        print('== restoring gateway ==', flush=True)
        restore_gateway()

    print('== capture results ==', flush=True)
    if os.path.exists(CAPTURE):
        with open(CAPTURE) as f:
            print(f.read(), flush=True)
    # close the game (it cannot log in through the stub)
    subprocess.run(['taskkill', '/IM', 'PathOfExileSteam.exe', '/F'],
                   capture_output=True)
    print('DONE', flush=True)


if __name__ == '__main__':
    main()
