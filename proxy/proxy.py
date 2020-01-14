#!/usr/bin/env python3

import afl
afl.init(remote_trace=True)
import argparse
import sys
import os
import signal
from time import sleep
try:
    from proxy.env import env
except:
    try:
        from env import env
    except:
        env = None
import frida


DESCR = """Frida AFL
"""

pid = None
session = None
device = None
script = None
args = None

TRACE_BITS = "trace_bits"

try:
    stdin = sys.stdin.buffer
except:
    stdin = sys.stdin

def on_message(message, data):
    global args, device, script, session, pid, stdin
    msg = message['payload']
    if msg['event'] == 'input':
        if os.path.exists(TRACE_BITS):
            os.remove(TRACE_BITS)
        buf = stdin.read()
        if len(buf) == 0:
            return
        script.post({
            "type": "input",
            "buf": buf.hex(),
        })
    elif msg['event'] == 'trace_bits':
        with open(TRACE_BITS, "wb") as f:
            f.write(data)
    elif msg['event'] == 'done':
        os._exit(0)

def signal_handler(sig, frame):
    global args, device, script, session, pid
    print('>Catch SIGINT, exiting...')
    if args.s and not args.U:
        print('>Killing', pid)
        os.kill(pid, signal.SIGKILL)
    elif args.s and args.U:
        try:
            device.kill(pid)
        except frida.ProcessNotFoundError:
            print('>Unable to find process :%s' % pid)
            pass
    try:
        script.unload()
        session.detach()
    except:
        pass
    os._exit(0)


def main():
    global args, device, script, session, pid
    opt = argparse.ArgumentParser(description=DESCR, formatter_class=argparse.RawTextHelpFormatter)
    opt.add_argument('-l', action='store', default='proxy/proxy.js', help='Script filename')
    opt.add_argument('-U', action='store_true', default=True, help='Connect to USB')
    opt.add_argument('-s', action='store_true', default=True, help='Spawn instead of attach')
    opt.add_argument('-t', action='store', help='file to store target program/pid (and arguments if spwaning)')
    opt.add_argument('input', nargs=argparse.REMAINDER, help='Input corpus file')
    args = opt.parse_args()

    app_name = args.t
    try:
        app_name = int(app_name)
        pid = app_name
    except:
        pass

    with open(args.l) as f:
        code = f.read()

    try:
        if args.U:
            device = frida.get_usb_device()
            if args.s:
                pid = device.spawn(args.t, env=env)
                session = device.attach(pid)
            else:
                session = device.attach(app_name)
        else:
            if args.s:
                pid = frida.spawn(args.t, stdio='pipe', env=env)
                session = frida.attach(pid)
            else:
                session = frida.attach(app_name)
    except Exception as e:
        print(e)
        os._exit(0)

    script = session.create_script(code, runtime='v8')
    script.on('message', on_message)
    script.load()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        script.exports.fuzzer()
    except frida.InvalidOperationError as e:
        raise e

#    sys.stdin.read()


if __name__ == '__main__':
    main()

