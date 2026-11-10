'use strict';

// Read-only socket telemetry. This agent observes socket API buffers and never
// changes arguments, return values, packet contents, or application behavior.
const MAX_CAPTURE = 4096;
const socketTypes = Object.create(null); // fd -> SOCK_STREAM / SOCK_DGRAM
const peers = Object.create(null);       // fd -> remote endpoint
let hookCount = 0;

function emitError(where, error) {
  send({ kind: 'agent_error', where: where, error: String(error) });
}

function readSockaddr(address) {
  try {
    if (address.isNull()) return null;
    const family = address.readU16();
    const port = (address.add(2).readU8() << 8) | address.add(3).readU8();
    if (family === 2) { // AF_INET
      const b = address.add(4).readByteArray(4);
      const a = new Uint8Array(b);
      return a[0] + '.' + a[1] + '.' + a[2] + '.' + a[3] + ':' + port;
    }
    if (family === 10) { // AF_INET6
      const b = new Uint8Array(address.add(8).readByteArray(16));
      const groups = [];
      for (let i = 0; i < 16; i += 2) groups.push(((b[i] << 8) | b[i + 1]).toString(16));
      return '[' + groups.join(':') + ']:' + port;
    }
    return 'family=' + family + ':' + port;
  } catch (_) {
    return null;
  }
}

function socketProtocol(fd, fallback) {
  const kind = socketTypes[fd];
  if (kind === 2) return 'UDP';
  if (kind === 1) return 'TCP';
  return fallback || 'TCP';
}

function report(direction, protocol, fd, buffer, byteCount, remote) {
  try {
    if (byteCount <= 0 || buffer.isNull()) return;
    const captured = Math.min(byteCount, MAX_CAPTURE);
    const bytes = buffer.readByteArray(captured);
    send({
      kind: 'network',
      direction: direction,
      protocol: protocol,
      fd: fd,
      remote: remote || peers[fd] || 'unknown',
      size: byteCount,
      captured: captured,
      truncated: byteCount > captured
    }, bytes);
  } catch (error) {
    emitError('read-buffer', error);
  }
}

function hookExport(libc, name, callbacks) {
  try {
    const address = libc.getExportByName(name);
    Interceptor.attach(address, callbacks);
    hookCount++;
  } catch (_) {
    // Android releases do not necessarily export every socket wrapper.
  }
}

try {
  const libc = Process.getModuleByName('libc.so');

  hookExport(libc, 'socket', {
    onEnter(args) {
      this.socketKind = args[1].toInt32() & 0xf;
    },
    onLeave(retval) {
      const fd = retval.toInt32();
      if (fd >= 0) socketTypes[fd] = this.socketKind;
    }
  });

  hookExport(libc, 'connect', {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.remote = readSockaddr(args[1]);
    },
    onLeave(retval) {
      if (this.remote) peers[this.fd] = this.remote;
      send({ kind: 'connection', fd: this.fd, remote: this.remote || 'unknown', result: retval.toInt32() });
    }
  });

  hookExport(libc, 'send', {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buffer = args[1];
      this.protocol = socketProtocol(this.fd, 'TCP');
    },
    onLeave(retval) {
      const n = retval.toInt32();
      if (n > 0) report('OUT', this.protocol, this.fd, this.buffer, n, null);
    }
  });

  hookExport(libc, 'recv', {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buffer = args[1];
      this.protocol = socketProtocol(this.fd, 'TCP');
    },
    onLeave(retval) {
      const n = retval.toInt32();
      if (n > 0) report('IN', this.protocol, this.fd, this.buffer, n, null);
    }
  });

  hookExport(libc, 'sendto', {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buffer = args[1];
      this.remote = readSockaddr(args[4]);
      this.protocol = this.remote ? 'UDP' : socketProtocol(this.fd, 'TCP');
    },
    onLeave(retval) {
      const n = retval.toInt32();
      if (n > 0) report('OUT', this.protocol, this.fd, this.buffer, n, this.remote);
    }
  });

  hookExport(libc, 'recvfrom', {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buffer = args[1];
      this.address = args[4];
      this.protocol = this.address.isNull() ? socketProtocol(this.fd, 'TCP') : 'UDP';
    },
    onLeave(retval) {
      const n = retval.toInt32();
      if (n > 0) {
        const remote = this.address.isNull() ? null : readSockaddr(this.address);
        report('IN', this.protocol, this.fd, this.buffer, n, remote);
      }
    }
  });

  // Some Android networking stacks use read/write on socket file descriptors.
  hookExport(libc, 'write', {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buffer = args[1];
      this.protocol = socketTypes[this.fd] ? socketProtocol(this.fd, 'TCP') : null;
    },
    onLeave(retval) {
      const n = retval.toInt32();
      if (this.protocol && n > 0) report('OUT', this.protocol, this.fd, this.buffer, n, null);
    }
  });

  hookExport(libc, 'read', {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buffer = args[1];
      this.protocol = socketTypes[this.fd] ? socketProtocol(this.fd, 'TCP') : null;
    },
    onLeave(retval) {
      const n = retval.toInt32();
      if (this.protocol && n > 0) report('IN', this.protocol, this.fd, this.buffer, n, null);
    }
  });

  send({ kind: 'ready', hooks: hookCount, maxCapture: MAX_CAPTURE, note: 'Socket API buffer monitor; TLS/QUIC payloads remain encrypted.' });
} catch (error) {
  emitError('initialize', error);
}
