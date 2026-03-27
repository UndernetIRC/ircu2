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
#include "ircd_string.h"
#include "ircd_tls.h"
#include "ircd.h"
#include "listener.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_auth.h"
#include "send.h"
#include "s_bsd.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <sys/uio.h> /* IOV_MAX */
#include <unistd.h> /* write() on failure of ssl_accept() */

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

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  if (!preverify_ok && feature_bool(FEAT_TLS_ALLOW_SELFSIGNED))
  {
    int err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
        err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
      return 1;
  }
  return preverify_ok;
}

int ircd_tls_init(void)
{
  static int openssl_init;
  SSL_CTX *new_server_ctx = NULL;
  SSL_CTX *new_client_ctx = NULL;
  const char *str, *s_2;
  int res;

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

  /* Configure CA certificates */
  str = feature_str(FEAT_TLS_CACERTFILE);
  s_2 = feature_str(FEAT_TLS_CACERTDIR);
  if (!EmptyString(str) || !EmptyString(s_2))
  {
    if (!EmptyString(s_2))
    {
      if (!(SSL_CTX_load_verify_locations(new_server_ctx, NULL, s_2) == 1 &&
            SSL_CTX_load_verify_locations(new_client_ctx, NULL, s_2) == 1))
      {
        ssl_log_error("unable to load CA certificates from directory");
        goto fail;
      }
    }

    if (!EmptyString(str))
    {
      if (!(SSL_CTX_load_verify_locations(new_server_ctx, str, NULL) == 1 &&
            SSL_CTX_load_verify_locations(new_client_ctx, str, NULL) == 1))
      {
        ssl_log_error("unable to load CA certificates from file");
        goto fail;
      }
    }
  }
  else
  {
    if (!(SSL_CTX_set_default_verify_paths(new_server_ctx) == 1 &&
          SSL_CTX_set_default_verify_paths(new_client_ctx) == 1))
    {
      ssl_log_error("unable to load default CA certificates");
      goto fail;
    }
  }

  /* Set protocol versions. */
  SSL_CTX_set_min_proto_version(new_server_ctx, TLS1_2_VERSION);
  SSL_CTX_set_min_proto_version(new_client_ctx, TLS1_2_VERSION);

  /* Configure verification */
  SSL_CTX_set_verify(new_server_ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, verify_callback);
  SSL_CTX_set_verify(new_client_ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, verify_callback);

  SSL_CTX_set_mode(new_server_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  SSL_CTX_set_mode(new_client_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

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

  tls = SSL_new(server_ctx);
  if (!tls)
  {
    ssl_log_error("unable to create SSL session");
    return NULL;
  }

  if (listener && listener->tls_ciphers)
    ssl_set_ciphers(NULL, tls, listener->tls_ciphers);

  ssl_set_fd(tls, fd);

  SSL_set_accept_state(tls);

  return tls;
}

void *ircd_tls_connect(struct ConfItem *aconf, int fd)
{
  SSL *tls;

  tls = SSL_new(client_ctx);
  if (!tls)
  {
    ssl_log_error("unable to create SSL session");
    return NULL;
  }

  if (aconf->tls_ciphers)
    ssl_set_ciphers(NULL, tls, aconf->tls_ciphers);

  ssl_set_fd(tls, fd);

  SSL_set_connect_state(tls);

  return tls;
}

int ircd_tls_listen(struct Listener *listener)
{
  /* noop for OpenSSL */
  return 0;
}

static void clear_tls_rexmit(struct Connection *con)
{
  if (con && con->con_rexmit) {
    con->con_rexmit = NULL;
    con->con_rexmit_len = 0;
  }
}

static IOResult ssl_handle_error(struct Client *cptr, SSL *tls, int res, int orig_errno)
{
  int err = SSL_get_error(tls, res);

  Debug((DEBUG_DEBUG, "ssl_handle_error: SSL_get_error=%d, res=%d, orig_errno=%d for %C",
         err, res, orig_errno, cptr));

  switch (err)
  {
  case SSL_ERROR_WANT_READ:
    return IO_BLOCKED;

  case SSL_ERROR_WANT_WRITE:
    return IO_BLOCKED;

  case SSL_ERROR_SYSCALL:
    if (orig_errno == EINTR || orig_errno == EAGAIN || orig_errno == EWOULDBLOCK)
      return IO_BLOCKED;
    break;
  case SSL_ERROR_ZERO_RETURN:
    Debug((DEBUG_DEBUG, "SSL_ERROR_ZERO_RETURN: peer closed connection for %C", cptr));
    if (SSL_shutdown(tls) == 0)
      SSL_shutdown(tls);
    break;

  default:
    /* Fatal SSL error */
    Debug((DEBUG_ERROR, "SSL fatal error %d for %C", err, cptr));
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        Debug((DEBUG_ERROR, "SSL ERROR: %s", ERR_error_string(e, NULL)));
    }
    break;
  }

  /* Fatal error - clean up SSL context */
  if (tls && s_tls(&cli_socket(cptr)) == tls) {
    Debug((DEBUG_ERROR, "SSL fall-through fatal error %d for %C", err, cptr));
    s_tls(&cli_socket(cptr)) = NULL;
    /* Do not call SSL_shutdown() after fatal errors */
    SSL_free(tls);
  }

  return IO_FAILURE;
}

int ircd_tls_negotiate(struct Client *cptr)
{
  SSL *tls;
  X509 *cert;
  unsigned int len;
  int res;
  unsigned char buf[EVP_MAX_MD_SIZE];
  const char* const error_ssl = "ERROR :SSL connection error\r\n";

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return 1;

  /* Check for handshake timeout */
  if (CurrentTime - cli_firsttime(cptr) > TLS_HANDSHAKE_TIMEOUT) {
    Debug((DEBUG_DEBUG, "SSL handshake timeout for fd=%d", cli_fd(cptr)));
    return -1;
  }

  /* For client connections, use SSL_connect */
  if (SSL_get_SSL_CTX(tls) == client_ctx)
    res = SSL_connect(tls);
  /* For server connections, use SSL_accept */
  else
    res = SSL_accept(tls);

  if (res == 1)
  {
    Debug((DEBUG_DEBUG, "SSL handshake success for fd=%d", cli_fd(cptr)));
    cert = SSL_get_peer_certificate(tls);
    if (cert)
    {
      Debug((DEBUG_DEBUG, "SSL_get_peer_certificate success for fd=%d", cli_fd(cptr)));
      len = sizeof(buf);
      res = X509_digest(cert, fp_digest, buf, &len);
      X509_free(cert);
      if (res)
      {
        log_write(LS_SYSTEM, L_ERROR, 0, "X509_digest failed for %C: %d",
          cptr, res);
      }
      if (len == 32) {
        /* Convert fingerprint to lowercase hex */
        char *p = cli_tls_fingerprint(cptr);
        for (unsigned int i = 0; i < len; i++) {
          sprintf(p + (i * 2), "%02x", buf[i]);
        }
        p[len * 2] = '\0';
        Debug((DEBUG_DEBUG, "Fingerprint for %C: %s", cptr, cli_tls_fingerprint(cptr)));
      }
      else {
        memset(cli_tls_fingerprint(cptr), 0, 65);
        Debug((DEBUG_DEBUG, "Invalid length"));
      }
    }
    ClearNegotiatingTLS(cptr);
  }
  else
  {
    int orig_errno = errno;
    /* Handshake in progress. */
    IOResult ssl_result = ssl_handle_error(cptr, tls, res, orig_errno);
    if (ssl_result == IO_FAILURE) {
      Debug((DEBUG_DEBUG, "SSL handshake failed for fd=%d", cli_fd(cptr)));
      write(cli_fd(cptr), error_ssl, strlen(error_ssl));
      return -1;
    }
    /* ssl_result == IO_BLOCKED - handshake still in progress */
    return 0;
  }

  return res;
}

IOResult ircd_tls_recv(struct Client *cptr, char *buf,
                       unsigned int length, unsigned int *count_out)
{
  SSL *tls;
  int res, orig_errno;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return IO_FAILURE;

  res = SSL_read(tls, buf, length);
  if (res > 0)
  {
    *count_out = res;
    return IO_SUCCESS;
  }

  orig_errno = errno;
  *count_out = 0;

  return ssl_handle_error(cptr, tls, res, orig_errno);
}

IOResult ircd_tls_sendv(struct Client *cptr, struct MsgQ *buf,
                        unsigned int *count_in,
                        unsigned int *count_out)
{
  struct iovec iov[512];
  SSL *tls;
  struct Connection *con;
  IOResult result = IO_BLOCKED;
  int ii, count, res, orig_errno;

  con = cli_connect(cptr);
  tls = s_tls(&con_socket(con));
  if (!tls)
    return IO_FAILURE;
  *count_out = 0;
  if (con->con_rexmit)
  {
    ERR_clear_error();
    res = SSL_write(tls, con->con_rexmit, con->con_rexmit_len);
    if (res <= 0) {
      orig_errno = errno;
      return ssl_handle_error(cptr, tls, res, orig_errno);
    }

    // Only excise the message if the full message was sent
    if (res == (int)con->con_rexmit_len) {
      msgq_excise(buf, con->con_rexmit, con->con_rexmit_len);
      con->con_rexmit_len = 0;
      con->con_rexmit = NULL;
      result = IO_SUCCESS;
    } else {
      // Partial send, update pointer and length for next retry
      con->con_rexmit = (char *)con->con_rexmit + res;
      con->con_rexmit_len -= res;
      return IO_BLOCKED;
    }
  }

  // Process remaining messages in the queue
  count = msgq_mapiov(buf, iov, sizeof(iov) / sizeof(iov[0]), count_in);
  for (ii = 0; ii < count; ++ii)
  {
    ERR_clear_error();
    res = SSL_write(tls, iov[ii].iov_base, iov[ii].iov_len);
    if (res > 0)
    {
      *count_out += res;
      result = IO_SUCCESS;
      if (res < (int)iov[ii].iov_len) {
        // Partial send, store for retransmission
        cli_connect(cptr)->con_rexmit = (char *)iov[ii].iov_base + res;
        cli_connect(cptr)->con_rexmit_len = iov[ii].iov_len - res;
        return IO_BLOCKED;
      }
      // else, full message sent, continue to next
      continue;
    }

    /* We only reach this if the SSL_write failed. */
    orig_errno = errno;
    cli_connect(cptr)->con_rexmit = iov[ii].iov_base;
    cli_connect(cptr)->con_rexmit_len = iov[ii].iov_len;
    return ssl_handle_error(cptr, tls, res, orig_errno);
  }

  return result;
}
