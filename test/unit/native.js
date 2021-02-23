'use strict';

const { dtls, constants } = require('../../src');

const { GNUTLS_CLIENT, GNUTLS_DATAGRAM } = constants;

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
