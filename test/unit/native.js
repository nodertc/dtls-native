'use strict';

const { dtls, constants } = require('../../src');

const { GNUTLS_CLIENT, GNUTLS_DATAGRAM, GNUTLS_NONBLOCK } = constants;

test('check handle', () => {
  expect(dtls).not.toBeNull();
});

test('check version', () => {
  expect(dtls.gnutls_version).toEqual('3.6.15');
});

test('check create session', () => {
  expect(dtls.create_session(GNUTLS_CLIENT | GNUTLS_DATAGRAM)).toEqual({});
});

test('should check session flags', () => {
  expect(() => dtls.create_session()).toThrowError('Expected GnuTLS session init flags');
  expect(() => dtls.create_session(-1)).toThrowError('Invalid GnuTLS session init flags');
});

describe('test mtu', () => {
  let session;
  const mtu = 1420;

  beforeAll(() => {
    session = dtls.create_session(GNUTLS_CLIENT | GNUTLS_DATAGRAM);
    expect(session).toEqual({});
  });

  it('should set mtu', () => {
    expect(dtls.set_mtu(session, mtu)).not.toBeNull();
  });

  it('should get mtu', () => {
    expect(dtls.get_mtu(session)).toEqual(mtu);
  });

  it('should check arguments on set mtu', () => {
    expect(() => dtls.set_mtu()).toThrowError('Missing arguments');
    expect(() => dtls.set_mtu({}, mtu)).toThrowError('Invalid session handle');
    expect(() => dtls.set_mtu(session, -1)).toThrowError('Invalid mtu value');
  });

  it('should check arguments on get mtu', () => {
    expect(() => dtls.get_mtu()).toThrowError('Missing arguments');
    expect(() => dtls.get_mtu({})).toThrowError('Invalid session handle');
  });
});

test('should call handshake', (done) => {
  const session = dtls.create_session(GNUTLS_CLIENT | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK);
  dtls.handshake(session, (errno) => {
    expect(errno).toBeLessThan(0);
    done();
  });
});
