#!/usr/bin/env python3

import afl
import argparse
import sys
import os
import signal
import socket

try:
    from env import env
except:
    env = None


DESCR = """fridaAFL
"""

MAP_SIZE = 64 * 1024

pid = None
session = None
device = None
script = None
args = None

try:
    stdin = sys.stdin.buffer
except:
    stdin = sys.stdin

def on_message(message, data):
    global args, device, script, session, pid, stdin, sock
    if message['type'] == 'error':
        print(message)
        raise
    try:
        msg = message['payload']
    except:
        print(message)
        raise
    if msg['event'] == 'input':
        if len(args.input) > 0:
            with open(args.input[0], 'rb') as f:
                buf = f.read()
        else:
            buf = stdin.read()
        if len(buf) == 0:
            return
        script.post({
            "type": "input",
            "buf": buf.hex(),
        })
    elif msg['event'] == 'trace_bits':
        try:
            sock.sendall(data)
            sock.close()
        except Exception as e:
            print("Sock send error for trace_bits: ", e)
            pass
    elif msg['event'] == 'done':
        os._exit(0)
    elif msg['event'] in ['crash', 'exception', 'other']:
        if msg['err']['type'] == 'abort':
          os._exit(6)
        else:
          print(msg)
          os._exit(11)

def signal_handler(sig, frame):
    global args, device, script, session, pid, server_address, sock
    print('>Catch signal %s, exiting...' % sig)
    if args.s and not args.U:
        os.kill(pid, signal.SIGKILL)
    elif args.s and args.U:
        try:
            device.kill(pid)
        except:
            pass
    try:
        script.unload()
        session.detach()
    except:
        pass
    os._exit(sig)

def establish_sock():
    global sock, server_address
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_address = str(os.getppid())
    try:
        sock.connect(server_address)
    except FileNotFoundError:
        print("Instrument won't be sent to AFL")
        pass

def fuzz():
    global args, device, script, session, pid, sock, code, app_name, server_address
    afl.init(remote_trace=True)
    import frida
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
    signal.signal(signal.SIGALRM, signal_handler)

    establish_sock()

    try:
        script.exports.fuzzer()
    except (frida.core.RPCException, frida.InvalidOperationError) as e:
        print(e)
        os._exit(1)


def main():
    global args, device, script, session, pid, sock, code, app_name
    opt = argparse.ArgumentParser(description=DESCR, formatter_class=argparse.RawTextHelpFormatter)
    opt.add_argument('-l', action='store', default='proxy/proxy.js', help='Script filename')
    opt.add_argument('-U', action='store_true', default=False, help='Connect to USB')
    opt.add_argument('-s', action='store_true', default=False, help='Spawn instead of attach')
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

    fuzz()

    sys.stdin.read()
#    while afl.loop(1000, remote_trace=True):
#        fuzz()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(e)
        raise

