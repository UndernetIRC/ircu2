/*
 * IRC - Internet Relay Chat, ircd/tls_openssl.c
 * Copyright (C) 2019 Michael Poole
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief ircd TLS functions using OpenSSL.
 */

#include "config.h"
#include "client.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_tls.h"
#include "tls_io.h"
#include "ircd.h"
#include "listener.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_auth.h"
#include "send.h"
#include "s_bsd.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdarg.h>
#include <string.h> /* strerror() */
#include <sys/uio.h> /* IOV_MAX */
#include <unistd.h> /* write() on failure of ssl_accept() */

/** Fill \a reason (if non-NULL) with a formatted TLS failure description. */
static void tls_reason(char *reason, size_t reasonlen, const char *fmt, ...)
{
  va_list vl;

  if (!reason || reasonlen == 0)
    return;
  va_start(vl, fmt);
  ircd_vsnprintf(0, reason, reasonlen, fmt, vl);
  va_end(vl);
}

const char *ircd_tls_version = OPENSSL_VERSION_TEXT;

static SSL_CTX *server_ctx; /* For incoming connections */
static SSL_CTX *client_ctx; /* For outgoing connections */
static const EVP_MD *fp_digest;

static void ssl_log_error(const char *msg)
{
  unsigned long err;
  char buf[BUFSIZE];

  err = ERR_get_error();
  if (err)
  {
    ERR_error_string_n(err, buf, sizeof(buf));
    log_write(LS_SYSTEM, L_ERROR, 0, "OpenSSL %s: %s", msg, buf);

    while ((err = ERR_get_error()) != 0)
    {
      ERR_error_string_n(err, buf, sizeof(buf));
      log_write(LS_SYSTEM, L_ERROR, 0, " ... %s", buf);
    }
  }
  else
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "Unknown OpenSSL failure: %s", msg);
  }
}

static void ssl_set_ciphers(SSL_CTX *ctx, SSL *tls, const char *text)
{
  const char *sep;

  if (!text)
    return;

  sep = strchr(text, ' ');
  if (sep != NULL)
  {
    char *tmp;
#if HAVE_SSL_SET_CIPHERSUITES
    if (ctx)
      SSL_CTX_set_ciphersuites(ctx, sep + 1);
    if (tls)
      SSL_set_ciphersuites(tls, sep + 1);
#endif

    tmp = MyMalloc(sep + 1 - text);
    ircd_strncpy(tmp, text, sep - text);
    if (ctx)
      SSL_CTX_set_cipher_list(ctx, tmp);
    if (tls)
      SSL_set_cipher_list(tls, tmp);
    MyFree(tmp);
  }
  else if (*text != '\0')
  {
    if (ctx)
      SSL_CTX_set_cipher_list(ctx, text);
    if (tls)
      SSL_set_cipher_list(tls, text);
  }
  else
  {
    if (ctx)
      SSL_CTX_set_cipher_list(ctx, SSL_DEFAULT_CIPHER_LIST);
    if (tls)
      SSL_set_cipher_list(tls, SSL_DEFAULT_CIPHER_LIST);
#if HAVE_SSL_SET_CIPHERSUITES
    if (ctx)
      SSL_CTX_set_ciphersuites(ctx, TLS_DEFAULT_CIPHERSUITES);
    if (tls)
      SSL_set_ciphersuites(tls, TLS_DEFAULT_CIPHERSUITES);
#endif
  }
}

static int openssl_load_ca(SSL_CTX *ctx, const char *cacertfile,
                           const char *cacertdir, int systemca)
{
  int use_system = ircd_tls_use_system_ca(systemca, cacertfile, cacertdir);

  if (use_system)
  {
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
    {
      ssl_log_error("unable to load default CA certificates");
      return 0;
    }
  }

  if (!EmptyString(cacertdir))
  {
    if (SSL_CTX_load_verify_locations(ctx, NULL, cacertdir) != 1)
    {
      ssl_log_error("unable to load CA certificates from directory");
      return 0;
    }
  }

  if (!EmptyString(cacertfile))
  {
    if (SSL_CTX_load_verify_locations(ctx, cacertfile, NULL) != 1)
    {
      ssl_log_error("unable to load CA certificates from file");
      return 0;
    }
  }

  return 1;
}

static int openssl_fingerprint_verify_callback(int preverify_ok,
                                               X509_STORE_CTX *x509_ctx)
{
  /* Used only when verify_ca is unset: trust is decided by fingerprint pin
   * (or nothing).  Accept every presented cert so PKIX errors such as
   * missing clientAuth EKU or weak CA digests do not abort the handshake.
   */
  (void)preverify_ok;
  (void)x509_ctx;
  return 1;
}

/**
 * Apply OpenSSL verify mode for \a policy.
 * Soft policies use the accept-all fingerprint callback so PKIX is advisory.
 */
static void openssl_set_verify_policy(SSL_CTX *ctx, ircd_tls_trust_policy policy)
{
  int mode = SSL_VERIFY_NONE;
  int verify_ca = ircd_tls_trust_verifies_ca(policy);

  switch (policy)
  {
  case TLS_TRUST_REQUIRE_CA:
  case TLS_TRUST_REQUIRE_SOFT:
    mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    break;
  case TLS_TRUST_REQUEST_SOFT:
    mode = SSL_VERIFY_PEER;
    break;
  }

  mode |= SSL_VERIFY_CLIENT_ONCE;
  SSL_CTX_set_verify(ctx, mode, verify_ca ? NULL : openssl_fingerprint_verify_callback);
}

static void openssl_apply_verify_policy(SSL *tls, ircd_tls_trust_policy policy)
{
  int mode = SSL_VERIFY_NONE;
  int verify_ca = ircd_tls_trust_verifies_ca(policy);

  switch (policy)
  {
  case TLS_TRUST_REQUIRE_CA:
  case TLS_TRUST_REQUIRE_SOFT:
    mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    break;
  case TLS_TRUST_REQUEST_SOFT:
    mode = SSL_VERIFY_PEER;
    break;
  }

  mode |= SSL_VERIFY_CLIENT_ONCE;
  SSL_set_verify(tls, mode, verify_ca ? NULL : openssl_fingerprint_verify_callback);
}

/** Apply the I/O mode and hardening options every ircd SSL_CTX needs.
 * SSL_OP_NO_RENEGOTIATION removes the only way a peer can drive a post-
 * handshake SSL_write into SSL_ERROR_WANT_READ on TLS 1.2 (a CPU-spin
 * trigger); SSL_OP_NO_COMPRESSION disables CRIME-style record compression. */
static void openssl_harden_ctx(SSL_CTX *ctx)
{
  SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE
                   | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#ifdef SSL_OP_NO_RENEGOTIATION
  SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
#endif
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
}

static int openssl_configure_server_ctx(SSL_CTX *ctx, const char *ciphers,
                                        const char *cacertfile,
                                        const char *cacertdir,
                                        ircd_tls_trust_policy policy,
                                        int systemca)
{
  const char *str;

  if (!(SSL_CTX_use_certificate_chain_file(ctx, ircd_tls_certfile) == 1))
  {
    ssl_log_error("unable to load certificate file");
    return 0;
  }

  if (!(SSL_CTX_use_PrivateKey_file(ctx, ircd_tls_keyfile, SSL_FILETYPE_PEM) == 1))
  {
    ssl_log_error("unable to load private key");
    return 0;
  }

  if (!(SSL_CTX_check_private_key(ctx) == 1))
  {
    ssl_log_error("certificate and private key do not match");
    return 0;
  }

  if (!openssl_load_ca(ctx, cacertfile, cacertdir, systemca))
    return 0;

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  openssl_set_verify_policy(ctx, policy);
  openssl_harden_ctx(ctx);

  str = ciphers;
  if (EmptyString(str))
    str = feature_str(FEAT_TLS_CIPHERS);
  ssl_set_ciphers(ctx, NULL, str);

  return 1;
}

static int openssl_configure_client_ctx(SSL_CTX *ctx, const char *ciphers,
                                      const char *cacertfile,
                                      const char *cacertdir,
                                      ircd_tls_trust_policy policy,
                                      int systemca)
{
  const char *str;

  if (!(SSL_CTX_use_certificate_chain_file(ctx, ircd_tls_certfile) == 1))
  {
    ssl_log_error("unable to load certificate file");
    return 0;
  }

  if (!(SSL_CTX_use_PrivateKey_file(ctx, ircd_tls_keyfile, SSL_FILETYPE_PEM) == 1))
  {
    ssl_log_error("unable to load private key");
    return 0;
  }

  if (!(SSL_CTX_check_private_key(ctx) == 1))
  {
    ssl_log_error("certificate and private key do not match");
    return 0;
  }

  if (!openssl_load_ca(ctx, cacertfile, cacertdir, systemca))
    return 0;

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  openssl_set_verify_policy(ctx, policy);
  openssl_harden_ctx(ctx);

  str = ciphers;
  if (EmptyString(str))
    str = feature_str(FEAT_TLS_CIPHERS);
  ssl_set_ciphers(ctx, NULL, str);

  return 1;
}

static int listener_needs_custom_ctx(const struct Listener *listener)
{
  return listener && (
    listener_server(listener) ||
    !EmptyString(listener->tls_ciphers) ||
    !EmptyString(listener->tls_cacertfile) ||
    !EmptyString(listener->tls_cacertdir) ||
    listener->tls_verifypeer == 1 ||
    listener->tls_systemca != LISTENER_TLS_SYSTEMCA_DEFAULT);
}

static SSL_CTX *openssl_create_server_ctx(const char *ciphers,
                                          const char *cacertfile,
                                          const char *cacertdir,
                                          ircd_tls_trust_policy policy,
                                          int systemca)
{
  SSL_CTX *ctx;

  ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx)
  {
    ssl_log_error("SSL_CTX_new failed for server");
    return NULL;
  }

  if (!openssl_configure_server_ctx(ctx, ciphers, cacertfile, cacertdir,
                                    policy, systemca))
  {
    SSL_CTX_free(ctx);
    return NULL;
  }

  return ctx;
}

static SSL_CTX *openssl_create_client_ctx(const char *ciphers,
                                         const char *cacertfile,
                                         const char *cacertdir,
                                         ircd_tls_trust_policy policy,
                                         int systemca)
{
  SSL_CTX *ctx;

  ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx)
  {
    ssl_log_error("SSL_CTX_new failed for client");
    return NULL;
  }

  if (!openssl_configure_client_ctx(ctx, ciphers, cacertfile, cacertdir,
                                  policy, systemca))
  {
    SSL_CTX_free(ctx);
    return NULL;
  }

  return ctx;
}

static void ensure_conf_tls(struct ConfItem *aconf)
{
  if (!aconf || aconf->tls_ctx || !conf_tls_needs_custom_ctx(aconf))
    return;

  aconf->tls_ctx = openssl_create_client_ctx(aconf->tls_ciphers,
                                             aconf->tls_cacertfile,
                                             aconf->tls_cacertdir,
                                             ircd_tls_connect_trust_policy(aconf),
                                             aconf->tls_systemca);
}

int ircd_tls_init(void)
{
  static int openssl_init;
  SSL_CTX *new_server_ctx = NULL;
  SSL_CTX *new_client_ctx = NULL;
  const char *str;

  /* Early out if no private key or certificate file was given. */
  if (EmptyString(ircd_tls_keyfile) || EmptyString(ircd_tls_certfile))
    goto done;

  if (!openssl_init)
  {
    openssl_init = 1;
    SSL_library_init();
    SSL_load_error_strings();

    if (!RAND_poll())
    {
      ssl_log_error("RAND_poll failed");
      return 1;
    }

    fp_digest = EVP_sha256();
  }

  /* Create server context */
  new_server_ctx = SSL_CTX_new(TLS_server_method());
  if (!new_server_ctx)
  {
    ssl_log_error("SSL_CTX_new failed for server");
    return 2;
  }

  /* Create client context */
  new_client_ctx = SSL_CTX_new(TLS_client_method());
  if (!new_client_ctx)
  {
    ssl_log_error("SSL_CTX_new failed for client");
    SSL_CTX_free(new_server_ctx);
    return 2;
  }

  /* Configure certificates and keys for both contexts */
  if (!(SSL_CTX_use_certificate_chain_file(new_server_ctx, ircd_tls_certfile) == 1 &&
        SSL_CTX_use_certificate_chain_file(new_client_ctx, ircd_tls_certfile) == 1))
  {
    ssl_log_error("unable to load certificate file");
    goto fail;
  }

  if (!(SSL_CTX_use_PrivateKey_file(new_server_ctx, ircd_tls_keyfile, SSL_FILETYPE_PEM) == 1 &&
        SSL_CTX_use_PrivateKey_file(new_client_ctx, ircd_tls_keyfile, SSL_FILETYPE_PEM) == 1))
  {
    ssl_log_error("unable to load private key");
    goto fail;
  }

  if (!(SSL_CTX_check_private_key(new_server_ctx) == 1 &&
        SSL_CTX_check_private_key(new_client_ctx) == 1))
  {
    ssl_log_error("certificate and private key do not match");
    goto fail;
  }

  if (!openssl_load_ca(new_server_ctx, NULL, NULL,
                      LISTENER_TLS_SYSTEMCA_DEFAULT) ||
      !openssl_load_ca(new_client_ctx, NULL, NULL,
                       LISTENER_TLS_SYSTEMCA_DEFAULT))
    goto fail;

  /* Set protocol versions. */
  SSL_CTX_set_min_proto_version(new_server_ctx, TLS1_2_VERSION);
  SSL_CTX_set_min_proto_version(new_client_ctx, TLS1_2_VERSION);

  /* Default accept context: user TLS ports (REQUEST_SOFT). */
  openssl_set_verify_policy(new_server_ctx, TLS_TRUST_REQUEST_SOFT);
  /* Default connect context: outbound S2S without verifypeer (REQUIRE_SOFT). */
  openssl_set_verify_policy(new_client_ctx, TLS_TRUST_REQUIRE_SOFT);

  openssl_harden_ctx(new_server_ctx);
  openssl_harden_ctx(new_client_ctx);

  /* Configure ciphers */
  str = feature_str(FEAT_TLS_CIPHERS);
  ssl_set_ciphers(new_server_ctx, NULL, str);
  ssl_set_ciphers(new_client_ctx, NULL, str);

done:
  if (server_ctx)
    SSL_CTX_free(server_ctx);
  if (client_ctx)
    SSL_CTX_free(client_ctx);
  server_ctx = new_server_ctx;
  client_ctx = new_client_ctx;
  return 0;

fail:
  if (new_server_ctx)
    SSL_CTX_free(new_server_ctx);
  if (new_client_ctx)
    SSL_CTX_free(new_client_ctx);
  return 6;
}

void ircd_tls_close(void *ctx, const char *message)
{
  SSL *ssl = ctx;
  assert(ssl != NULL);

  if (!ssl)
    return;

  /* Only attempt graceful shutdown if the SSL handshake completed */
  if (SSL_is_init_finished(ssl)) {
    SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    if (SSL_shutdown(ssl) == 0)
      SSL_shutdown(ssl);
  }

  SSL_free(ssl);
}

static void ssl_set_fd(SSL *tls, int fd)
{
  SSL_set_fd(tls, fd);

  BIO_set_nbio(SSL_get_rbio(tls), 1);

  BIO_set_nbio(SSL_get_wbio(tls), 1);
}

void *ircd_tls_accept(struct Listener *listener, int fd)
{
  SSL *tls;
  SSL_CTX *ctx = server_ctx;

  if (listener && listener->tls_ctx)
    ctx = (SSL_CTX *)listener->tls_ctx;

  if (!ctx)
  {
    ssl_log_error("no TLS server context");
    return NULL;
  }

  tls = SSL_new(ctx);
  if (!tls)
  {
    ssl_log_error("unable to create SSL session");
    return NULL;
  }

  if (listener && listener->tls_ciphers && !listener->tls_ctx)
    ssl_set_ciphers(NULL, tls, listener->tls_ciphers);

  ssl_set_fd(tls, fd);

  SSL_set_accept_state(tls);

  if (listener)
    openssl_apply_verify_policy(tls, ircd_tls_listener_trust_policy(listener));

  return tls;
}

void *ircd_tls_connect(struct ConfItem *aconf, int fd)
{
  SSL *tls;
  SSL_CTX *ctx;

  ensure_conf_tls(aconf);
  ctx = (aconf && aconf->tls_ctx) ? (SSL_CTX *)aconf->tls_ctx : client_ctx;

  tls = SSL_new(ctx);
  if (!tls)
  {
    ssl_log_error("unable to create SSL session");
    return NULL;
  }

  if (aconf && aconf->tls_ciphers && !aconf->tls_ctx)
    ssl_set_ciphers(NULL, tls, aconf->tls_ciphers);

  ssl_set_fd(tls, fd);

  SSL_set_connect_state(tls);

  if (aconf)
  {
    openssl_apply_verify_policy(tls, ircd_tls_connect_trust_policy(aconf));

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (ircd_tls_connect_verify_hostname(aconf) && !EmptyString(aconf->name))
    {
      if (SSL_set1_host(tls, aconf->name) != 1)
      {
        ssl_log_error("unable to set TLS peer hostname");
        SSL_free(tls);
        return NULL;
      }
    }
#endif
  }

  return tls;
}

int ircd_tls_check_peer_hostname(struct Client *cptr, const char *name)
{
  SSL *tls;
  X509 *cert;
  int res;

  if (!cptr || EmptyString(name))
    return 0;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return 1;

  cert = SSL_get_peer_certificate(tls);
  if (!cert)
    return 1;

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  res = X509_check_host(cert, name, 0, 0, NULL);
  X509_free(cert);
  return res == 1 ? 0 : 1;
#else
  X509_free(cert);
  return 1;
#endif
}

void ircd_tls_conf_free(struct ConfItem *aconf)
{
  if (aconf && aconf->tls_ctx)
  {
    SSL_CTX_free((SSL_CTX *)aconf->tls_ctx);
    aconf->tls_ctx = NULL;
  }
}

int ircd_tls_conf_reload(struct ConfItem *aconf)
{
  SSL_CTX *new_ctx;

  if (!aconf || !conf_tls_needs_custom_ctx(aconf))
    return 0;

  new_ctx = openssl_create_client_ctx(aconf->tls_ciphers,
                                      aconf->tls_cacertfile,
                                      aconf->tls_cacertdir,
                                      ircd_tls_connect_trust_policy(aconf),
                                      aconf->tls_systemca);
  if (!new_ctx)
    return 1;

  ircd_tls_conf_free(aconf);
  aconf->tls_ctx = new_ctx;
  return 0;
}

int ircd_tls_listen(struct Listener *listener)
{
  SSL_CTX *new_ctx;

  if (!listener)
    return 1;

  if (!listener_needs_custom_ctx(listener))
    return 0;

  new_ctx = openssl_create_server_ctx(listener->tls_ciphers,
                                    listener->tls_cacertfile,
                                    listener->tls_cacertdir,
                                    ircd_tls_listener_trust_policy(listener),
                                    listener->tls_systemca);
  if (!new_ctx)
    return 1;

  ircd_tls_listen_free(listener);
  listener->tls_ctx = new_ctx;
  return 0;
}

int ircd_tls_listener_ready(const struct Listener *listener)
{
  return server_ctx != NULL
    || (listener && listener->tls_ctx != NULL);
}

void ircd_tls_listen_free(struct Listener *listener)
{
  if (listener && listener->tls_ctx)
  {
    SSL_CTX_free((SSL_CTX *)listener->tls_ctx);
    listener->tls_ctx = NULL;
  }
}

/** Classify a failed SSL_write() from the send path and record the socket
 * direction it is blocked on.  A write blocked on SSL_ERROR_WANT_READ must NOT
 * keep writable interest asserted (update_write() drops it), or the level-
 * triggered writable event spins; the always-on readable event drives the
 * retry.  Any other block is an ordinary "wants write". */
IOResult tls_backend_handshake(struct Client *cptr, struct tls_peer *peer,
                               char *reason, size_t reasonlen,
                               enum ircd_tls_want *want)
{
  SSL *tls;
  X509 *cert;
  int res, orig_errno, sslerr;
  long vr;
  unsigned long queued;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return IO_FAILURE;

  ERR_clear_error();
  res = SSL_is_server(tls) ? SSL_accept(tls) : SSL_connect(tls);

  if (res == 1)
  {
    cert = SSL_get_peer_certificate(tls);
    peer->have_cert = (cert != NULL);
    peer->verified = (SSL_get_verify_result(tls) == X509_V_OK);
    if (!peer->verified)
      tls_reason(peer->verify_err, sizeof(peer->verify_err),
                 "certificate verification failed: %s",
                 X509_verify_cert_error_string(SSL_get_verify_result(tls)));
    if (cert)
    {
      unsigned char buf[EVP_MAX_MD_SIZE];
      unsigned int len = sizeof(buf);
      if (X509_digest(cert, fp_digest, buf, &len) == 1
          && len <= sizeof(peer->digest))
      {
        memcpy(peer->digest, buf, len);
        peer->digest_len = len;
      }
      else
        log_write(LS_SYSTEM, L_ERROR, 0, "X509_digest failed for %C", cptr);
      X509_free(cert);
    }
    return IO_SUCCESS;
  }

  orig_errno = errno;
  sslerr = SSL_get_error(tls, res);
  vr = SSL_get_verify_result(tls);
  queued = ERR_peek_last_error();

  if (sslerr == SSL_ERROR_WANT_READ)
  {
    *want = IRCD_TLS_WANT_READ;
    return IO_BLOCKED;
  }
  if (sslerr == SSL_ERROR_WANT_WRITE
      || (sslerr == SSL_ERROR_SYSCALL
          && (orig_errno == EINTR || orig_errno == EAGAIN
              || orig_errno == EWOULDBLOCK)))
  {
    /* Anything other than WANT_READ is reported as a write: a wrong "write"
     * costs one loop pass, a wrong "read" would cost the whole deadline. */
    *want = IRCD_TLS_WANT_WRITE;
    return IO_BLOCKED;
  }

  /* Fatal.  Report the most specific reason available; the caller drops the
   * session. */
  if (vr != X509_V_OK)
    tls_reason(reason, reasonlen, "%s", X509_verify_cert_error_string(vr));
  else if (queued)
    tls_reason(reason, reasonlen, "%s", ERR_reason_error_string(queued));
  else if (sslerr == SSL_ERROR_ZERO_RETURN)
    tls_reason(reason, reasonlen, "peer closed connection");
  else if (sslerr == SSL_ERROR_SYSCALL && orig_errno)
    tls_reason(reason, reasonlen, "%s", strerror(orig_errno));
  else
    tls_reason(reason, reasonlen, "handshake error");
  return IO_FAILURE;
}

void tls_backend_drop(struct Client *cptr)
{
  SSL *tls = s_tls(&cli_socket(cptr));

  if (tls)
  {
    s_tls(&cli_socket(cptr)) = NULL;
    /* Do not SSL_shutdown() after a fatal error. */
    SSL_free(tls);
  }
}

/** Classify a non-WANT SSL error for the read/write paths, without tearing the
 * session down (the core owns teardown via tls_io_fatal()/tls_backend_drop()).
 * SYSCALL EINTR/EAGAIN is a normal block; ZERO_RETURN and everything else are
 * fatal. */
static IOResult ssl_io_result(SSL *tls, int err, int orig_errno)
{
  if (err == SSL_ERROR_SYSCALL &&
      (orig_errno == EINTR || orig_errno == EAGAIN || orig_errno == EWOULDBLOCK))
    return IO_BLOCKED;
  if (err == SSL_ERROR_ZERO_RETURN)
  {
    if (SSL_shutdown(tls) == 0)
      SSL_shutdown(tls);
  }
  return IO_FAILURE;
}

IOResult tls_backend_read(struct Client *cptr, char *buf, unsigned int length,
                          unsigned int *count_out, enum ircd_tls_want *want)
{
  SSL *tls;
  int res, orig_errno, err;

  *count_out = 0;
  *want = IRCD_TLS_WANT_NONE;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return IO_FAILURE;

  ERR_clear_error();
  res = SSL_read(tls, buf, length);
  if (res > 0)
  {
    *count_out = (unsigned int)res;
    return IO_SUCCESS;
  }

  orig_errno = errno;
  err = SSL_get_error(tls, res);
  if (err == SSL_ERROR_WANT_WRITE)
  {
    *want = IRCD_TLS_WANT_WRITE;
    return IO_BLOCKED;
  }
  if (err == SSL_ERROR_WANT_READ)
  {
    *want = IRCD_TLS_WANT_READ;
    return IO_BLOCKED;
  }
  return ssl_io_result(tls, err, orig_errno);
}

IOResult tls_backend_write(struct Client *cptr, const char *buf,
                           unsigned int len, unsigned int *written,
                           enum ircd_tls_want *want)
{
  SSL *tls;
  int res, orig_errno, err;

  *written = 0;
  *want = IRCD_TLS_WANT_NONE;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return IO_FAILURE;

  ERR_clear_error();
  res = SSL_write(tls, buf, (int)len);
  if (res > 0)
  {
    *written = (unsigned int)res;
    return IO_SUCCESS;
  }

  orig_errno = errno;
  err = SSL_get_error(tls, res);
  if (err == SSL_ERROR_WANT_READ)
  {
    *want = IRCD_TLS_WANT_READ;
    return IO_BLOCKED;
  }
  if (err == SSL_ERROR_WANT_WRITE)
  {
    *want = IRCD_TLS_WANT_WRITE;
    return IO_BLOCKED;
  }
  return ssl_io_result(tls, err, orig_errno);
}


int ircd_tls_sha1_base64(const void *data, size_t len, char *out, size_t outlen)
{
  unsigned char digest[SHA_DIGEST_LENGTH];
  BIO *b64;
  BIO *bmem;
  BUF_MEM *bptr;

  if (!data || !out || len == 0 || outlen == 0)
    return -1;

  SHA1(data, len, digest);

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  if (BIO_write(b64, digest, SHA_DIGEST_LENGTH) != SHA_DIGEST_LENGTH) {
    BIO_free_all(b64);
    return -1;
  }
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  if (!bptr || bptr->length >= outlen) {
    BIO_free_all(b64);
    return -1;
  }
  memcpy(out, bptr->data, bptr->length);
  out[bptr->length] = '\0';
  BIO_free_all(b64);
  return 0;
}
