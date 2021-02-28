'use strict';

/* eslint-disable require-jsdoc */
const dgram = require('dgram');
const Emitter = require('events');
const { dtls, constants } = require('.');

const { GNUTLS_CLIENT, GNUTLS_DATAGRAM } = constants;

dtls.set_debug_mode(true);

const socket = dgram.createSocket('udp4');
const sync = new Emitter();
const queue = [];
let ready = true;

socket.connect(4444, 'localhost', () => {
  console.log('connected to dtls server');

  const session = dtls.create_session(GNUTLS_CLIENT | GNUTLS_DATAGRAM);
  dtls.set_priority(session, 'NORMAL:+AEAD:+ECDHE-ECDSA:+ECDHE-RSA:+RSA:+PSK:+ECDHE-PSK:+VERS-DTLS1.2');
  dtls.set_mtu(session, 1200);

  dtls.send(session, (data) => {
    console.log('send %s bytes', data.length);
    socket.send(data, () => console.log('send successful'));
  });

  socket.on('message', buf => {
    queue.push(buf);

    if (ready) {
      setImmediate(() => sync.emit('ready'));
    }
  });

  dtls.handshake(session, (error) => {
    if (error) {
      console.log('handshake error', error);
    } else {
      console.log('handshake successful')
    }
    socket.disconnect();
    socket.close();
  });

  sync.on('ready', () => {
    if (!ready) {
      return;
    }

    ready = false;
    const buf = queue.shift();
    console.log('recv %s bytes', buf.length);

    dtls.recv(session, buf, (error) => {
      ready = true;

      if (error) {
        console.error('fail to recv data');
        socket.close();
        return;
      }

      console.error('recv successful');

      if (queue.length) {
        setImmediate(() => sync.emit('ready'));
      }
    });
  });
});

