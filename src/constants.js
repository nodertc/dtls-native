'use strict';

/**
 * gnutls_init_flags_t:
 *
 * @GNUTLS_SERVER: Connection end is a server.
 * @GNUTLS_CLIENT: Connection end is a client.
 * @GNUTLS_DATAGRAM: Connection is datagram oriented (DTLS). Since 3.0.0.
 * @GNUTLS_NONBLOCK: Connection should not block. Since 3.0.0.
 * @GNUTLS_NO_SIGNAL: In systems where SIGPIPE is delivered on send, it will be disabled. That flag has effect in systems which support the MSG_NOSIGNAL sockets flag (since 3.4.2).
 * @GNUTLS_NO_EXTENSIONS: Do not enable any TLS extensions by default (since 3.1.2). As TLS 1.2 and later require extensions this option is considered obsolete and should not be used.
 * @GNUTLS_NO_REPLAY_PROTECTION: Disable any replay protection in DTLS. This must only be used if  replay protection is achieved using other means. Since 3.2.2.
 * @GNUTLS_ALLOW_ID_CHANGE: Allow the peer to replace its certificate, or change its ID during a rehandshake. This change is often used in attacks and thus prohibited by default. Since 3.5.0.
 * @GNUTLS_ENABLE_FALSE_START: Enable the TLS false start on client side if the negotiated ciphersuites allow it. This will enable sending data prior to the handshake being complete, and may introduce a risk of crypto failure when combined with certain key exchanged; for that GnuTLS may not enable that option in ciphersuites that are known to be not safe for false start. Since 3.5.0.
 * @GNUTLS_ENABLE_EARLY_START: Under TLS1.3 allow the server to return earlier than the full handshake
 *   finish; similarly to false start the handshake will be completed once data are received by the
 *   client, while the server is able to transmit sooner. This is not enabled by default as it could
 *   break certain existing server assumptions and use-cases. Since 3.6.4.
 * @GNUTLS_ENABLE_EARLY_DATA: Under TLS1.3 allow the server to receive early data sent as part of the initial ClientHello (0-RTT). This is not enabled by default as early data has weaker security properties than other data. Since 3.6.5.
 * @GNUTLS_FORCE_CLIENT_CERT: When in client side and only a single cert is specified, send that certificate irrespective of the issuers expected by the server. Since 3.5.0.
 * @GNUTLS_NO_TICKETS: Flag to indicate that the session should not use resumption with session tickets.
 * @GNUTLS_KEY_SHARE_TOP3: Generate key shares for the top-3 different groups which are enabled.
 *   That is, as each group is associated with a key type (EC, finite field, x25519), generate
 *   three keys using %GNUTLS_PK_DH, %GNUTLS_PK_EC, %GNUTLS_PK_ECDH_X25519 if all of them are enabled.
 * @GNUTLS_KEY_SHARE_TOP2: Generate key shares for the top-2 different groups which are enabled.
 *   For example (ECDH + x25519). This is the default.
 * @GNUTLS_KEY_SHARE_TOP: Generate key share for the first group which is enabled.
 *   For example x25519. This option is the most performant for client (less CPU spent
 *   generating keys), but if the server doesn't support the advertized option it may
 *   result to more roundtrips needed to discover the server's choice.
 * @GNUTLS_NO_AUTO_REKEY: Disable auto-rekeying under TLS1.3. If this option is not specified
 *   gnutls will force a rekey after 2^24 records have been sent.
 * @GNUTLS_POST_HANDSHAKE_AUTH: Enable post handshake authentication for server and client. When set and
 *   a server requests authentication after handshake %GNUTLS_E_REAUTH_REQUEST will be returned
 *   by gnutls_record_recv(). A client should then call gnutls_reauth() to re-authenticate.
 * @GNUTLS_SAFE_PADDING_CHECK: Flag to indicate that the TLS 1.3 padding check will be done in a
 *   safe way which doesn't leak the pad size based on GnuTLS processing time. This is of use to
 *   applications which hide the length of transferred data via the TLS1.3 padding mechanism and
 *   are already taking steps to hide the data processing time. This comes at a performance
 *   penalty.
 * @GNUTLS_AUTO_REAUTH: Enable transparent re-authentication in client side when the server
 *    requests to. That is, reauthentication is handled within gnutls_record_recv(), and
 *    the %GNUTLS_E_REHANDSHAKE or %GNUTLS_E_REAUTH_REQUEST are not returned. This must be
 *    enabled with %GNUTLS_POST_HANDSHAKE_AUTH for TLS1.3. Enabling this flag requires to restore
 *    interrupted calls to gnutls_record_recv() based on the output of gnutls_record_get_direction(),
 *    since gnutls_record_recv() could be interrupted when sending when this flag is enabled.
 *    Note this flag may not be used if you are using the same session for sending and receiving
 *    in different threads.
 * @GNUTLS_ENABLE_EARLY_DATA: Under TLS1.3 allow the server to receive early data sent as part of the initial ClientHello (0-RTT).
 *    This is not enabled by default as early data has weaker security properties than other data. Since 3.6.5.
 * @GNUTLS_ENABLE_RAWPK: Allows raw public-keys to be negotiated during the handshake. Since 3.6.6.
 * @GNUTLS_NO_AUTO_SEND_TICKET: Under TLS1.3 disable auto-sending of
 *    session tickets during the handshake.
 *
 * Enumeration of different flags for gnutls_init() function. All the flags
 * can be combined except @GNUTLS_SERVER and @GNUTLS_CLIENT which are mutually
 * exclusive.
 *
 * The key share options relate to the TLS 1.3 key share extension
 * which is a speculative key generation expecting that the server
 * would support the generated key.
 */

const GNUTLS_SERVER = 1;
const GNUTLS_CLIENT = 1 << 1;
const GNUTLS_DATAGRAM = 1 << 2;
const GNUTLS_NONBLOCK = 1 << 3;
const GNUTLS_NO_EXTENSIONS = 1 << 4;
const GNUTLS_NO_REPLAY_PROTECTION = 1 << 5;
const GNUTLS_NO_SIGNAL = 1 << 6;
const GNUTLS_ALLOW_ID_CHANGE = 1 << 7;
const GNUTLS_ENABLE_FALSE_START = 1 << 8;
const GNUTLS_FORCE_CLIENT_CERT = 1 << 9;
const GNUTLS_NO_TICKETS = 1 << 10;
const GNUTLS_KEY_SHARE_TOP = 1 << 11;
const GNUTLS_KEY_SHARE_TOP2 = 1 << 12;
const GNUTLS_KEY_SHARE_TOP3 = 1 << 13;
const GNUTLS_POST_HANDSHAKE_AUTH = 1 << 14;
const GNUTLS_NO_AUTO_REKEY = 1 << 15;
const GNUTLS_SAFE_PADDING_CHECK = 1 << 16;
const GNUTLS_ENABLE_EARLY_START = 1 << 17;
const GNUTLS_ENABLE_RAWPK = 1 << 18;
const GNUTLS_AUTO_REAUTH = 1 << 19;
const GNUTLS_ENABLE_EARLY_DATA = 1 << 20;
const GNUTLS_NO_AUTO_SEND_TICKET = 1 << 21;

module.exports = {
  GNUTLS_SERVER,
  GNUTLS_CLIENT,
  GNUTLS_DATAGRAM,
  GNUTLS_NONBLOCK,
  GNUTLS_NO_EXTENSIONS,
  GNUTLS_NO_REPLAY_PROTECTION,
  GNUTLS_NO_SIGNAL,
  GNUTLS_ALLOW_ID_CHANGE,
  GNUTLS_ENABLE_FALSE_START,
  GNUTLS_FORCE_CLIENT_CERT,
  GNUTLS_NO_TICKETS,
  GNUTLS_KEY_SHARE_TOP,
  GNUTLS_KEY_SHARE_TOP2,
  GNUTLS_KEY_SHARE_TOP3,
  GNUTLS_POST_HANDSHAKE_AUTH,
  GNUTLS_NO_AUTO_REKEY,
  GNUTLS_SAFE_PADDING_CHECK,
  GNUTLS_ENABLE_EARLY_START,
  GNUTLS_ENABLE_RAWPK,
  GNUTLS_AUTO_REAUTH,
  GNUTLS_ENABLE_EARLY_DATA,
  GNUTLS_NO_AUTO_SEND_TICKET,
};
