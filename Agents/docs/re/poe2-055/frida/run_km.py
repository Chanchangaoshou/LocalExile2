import frida, sys, time, os

LOG = r'C:\Users\13276\AppData\Local\Temp\km_capture.log'
def load_js():
    return open(r'C:\Users\13276\AppData\Local\Temp\km_capture.js', 'r', encoding='utf-8').read()

_fh = open(LOG, 'a', encoding='utf-8', buffering=1)
def log(msg):
    _fh.write(time.strftime('%H:%M:%S ') + str(msg) + '\n')

def on_message(message, data):
    log('MSG ' + str(message.get('payload') if message.get('type') == 'send' else message))

log('runner started, polling for PathOfExile.exe')
device = frida.get_local_device()
attached = set()
while True:
    try:
        alive = {pr.pid for pr in device.enumerate_processes()}
        attached.intersection_update(alive)
    except Exception:
        pass
    try:
        for proc in device.enumerate_processes():
            if proc.name.lower() == 'pathofexile.exe' and proc.pid not in attached:
                try:
                    session = device.attach(proc.pid)
                    script = session.create_script(load_js())
                    script.on('message', on_message)
                    script.load()
                    attached.add(proc.pid)
                    log(f'attached to pid {proc.pid}')
                except Exception as e:
                    log(f'attach failed pid {proc.pid}: {e}')
    except Exception as e:
        log('poll error: ' + str(e))
    time.sleep(2)
