'use strict';

const dtls = require('../../src');

test('check handle', () => {
  expect(dtls).not.toBeNull();
});

test('check version', () => {
  expect(dtls.gnutls_version).toEqual('3.6.15');
});

test('check create session', () => {
  expect(dtls.create_session()).toEqual({});
});
