/*
 * IRC - Internet Relay Chat, ircd/tls_gnutls.c
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
 * @brief ircd TLS functions using gnutls.
 *
 * This relies on gnutls_session_t being (a typedef to) a pointer type.
 */

#include "ircd_tls.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "client.h"
#include "s_auth.h"
#include "send.h"
#include "s_conf.h"
#include "s_debug.h"
#include "listener.h"
#include "ircd_features.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#if defined(GNUTLS_AUTO_REAUTH) /* 3.6.4 */
# define TLS_SESSION_FLAGS GNUTLS_NONBLOCK | GNUTLS_NO_SIGNAL \
  | GNUTLS_POST_HANDSHAKE_AUTH | GNUTLS_AUTH_REAUTH \
  | GNUTLS_ENABLE_EARLY_START
#elif defined(GNUTLS_ENABLE_EARLY_START) /* earlier in 3.6.4 */
# define TLS_SESSION_FLAGS GNUTLS_NONBLOCK | GNUTLS_NO_SIGNAL \
  | GNUTLS_ENABLE_EARLY_START
#else
# define TLS_SESSION_FLAGS GNUTLS_NONBLOCK | GNUTLS_NO_SIGNAL
#endif

const char *ircd_tls_version = "gnutls " GNUTLS_VERSION;

static gnutls_priority_t tls_priority;
static gnutls_certificate_credentials_t tls_cert;

static int gnutls_load_ca(gnutls_certificate_credentials_t cred,
                          const char *cacertfile, const char *cacertdir,
                          int systemca)
{
  int use_system = ircd_tls_use_system_ca(systemca, cacertfile, cacertdir);
  int res;

  if (use_system)
  {
    res = gnutls_certificate_set_x509_system_trust(cred);
    if (res < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "Unable to load system CA certs: %s",
                gnutls_strerror(res));
      return 0;
    }
  }

  if (!EmptyString(cacertdir))
  {
    res = gnutls_certificate_set_x509_trust_dir(cred, cacertdir,
                                                GNUTLS_X509_FMT_PEM);
    if (res < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "Unable to read CA certs from"
                " %s: %s", cacertdir, gnutls_strerror(res));
      return 0;
    }
  }

  if (!EmptyString(cacertfile))
  {
    res = gnutls_certificate_set_x509_trust_file(cred, cacertfile,
                                                 GNUTLS_X509_FMT_PEM);
    if (res < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "Unable to read CA certs from"
                " %s: %s", cacertfile, gnutls_strerror(res));
      return 0;
    }
  }

  return 1;
}

static gnutls_certificate_credentials_t gnutls_create_credentials(
    const char *cacertfile, const char *cacertdir, int verifypeer,
    int systemca)
{
  gnutls_certificate_credentials_t cred;
  int res;

  gnutls_certificate_allocate_credentials(&cred);
  res = gnutls_certificate_set_x509_key_file2(cred,
    ircd_tls_certfile, ircd_tls_keyfile, GNUTLS_X509_FMT_PEM, "",
    GNUTLS_PKCS_PLAIN | GNUTLS_PKCS_NULL_PASSWORD);
  if (res < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "Unable to load TLS keyfile and/or"
      " certificate: %s", gnutls_strerror(res));
    gnutls_certificate_free_credentials(cred);
    return NULL;
  }

  if (!gnutls_load_ca(cred, cacertfile, cacertdir, systemca))
  {
    gnutls_certificate_free_credentials(cred);
    return NULL;
  }

  (void)verifypeer;
  return cred;
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

static void ensure_conf_tls(struct ConfItem *aconf)
{
  if (!aconf || aconf->tls_ctx || !conf_tls_needs_custom_ctx(aconf))
    return;

  aconf->tls_ctx = gnutls_create_credentials(aconf->tls_cacertfile,
                                             aconf->tls_cacertdir,
                                             aconf->tls_verifypeer,
                                             aconf->tls_systemca);
}

int ircd_tls_init(void)
{
  static int once;
  const char *str;
  int res;

  /* Early out? */
  if (EmptyString(ircd_tls_keyfile) || EmptyString(ircd_tls_certfile))
    return 0;

  if (!once)
  {
    once = 1;

    /* Global initialization is automatic for 3.3.0 and later. */
#if GNUTLS_VERSION_NUMBER < 0x030300
    if (gnutls_global_init() != GNUTLS_E_SUCCESS)
      return 1;
#endif
  }

  str = feature_str(FEAT_TLS_CIPHERS);
  if (str)
  {
    gnutls_priority_t new_priority;
    res = gnutls_priority_init2(&new_priority, str, &str,
                                GNUTLS_PRIORITY_INIT_DEF_APPEND);
    if (res == GNUTLS_E_SUCCESS)
    {
      if (tls_priority)
        gnutls_priority_deinit(tls_priority);
      tls_priority = new_priority;
    }
    else if (res == GNUTLS_E_INVALID_REQUEST)
      log_write(LS_SYSTEM, L_ERROR, 0, "Invalid TLS_CIPHERS near '%s'", str);
    else
      log_write(LS_SYSTEM, L_ERROR, 0, "Unable to use TLS_CIPHERS: %s",
        gnutls_strerror(res));
    /* But continue on failures. */
  }
  else
  {
    if (tls_priority)
      gnutls_priority_deinit(tls_priority);
    tls_priority = NULL;
  }

  if (1)
  {
    gnutls_certificate_credentials_t new_cert;

    new_cert = gnutls_create_credentials(NULL, NULL, 0,
                                         LISTENER_TLS_SYSTEMCA_DEFAULT);
    if (!new_cert)
      return 2;

    if (tls_cert)
      gnutls_certificate_free_credentials(tls_cert);
    tls_cert = new_cert;
  }

  return 0;
}

static void *tls_create(int flag, int fd, const char *name, const char *tls_ciphers,
                        gnutls_certificate_credentials_t cred,
                        int require_peer, int verify_ca)
{
  gnutls_session_t tls;
  gnutls_certificate_credentials_t use_cred = cred ? cred : tls_cert;
  int res;

  res = gnutls_init(&tls, flag | TLS_SESSION_FLAGS);
  if (res != GNUTLS_E_SUCCESS)
    return NULL;

  res = gnutls_credentials_set(tls, GNUTLS_CRD_CERTIFICATE, use_cred);
  if (res != GNUTLS_E_SUCCESS)
  {
    gnutls_deinit(tls);
    return NULL;
  }

  /* gnutls does not appear to allow an application to select which
   * SSL/TLS protocol versions to support, except indirectly through
   * priority strings.
   */

  if (tls_ciphers)
  {
    const char *sep;
    res = gnutls_set_default_priority_append(tls, tls_ciphers, &sep, 0);
    if (!name || res == GNUTLS_E_SUCCESS)
    {
      /* do not report error */
    }
    else if (res == GNUTLS_E_INVALID_REQUEST)
      log_write(LS_SYSTEM, L_ERROR, 0, "Invalid tls ciphers for %s near '%s'",
                name, sep);
    else
      log_write(LS_SYSTEM, L_ERROR, 0, "Unable to set TLS ciphers for %s: %s",
                name, gnutls_strerror(res));
  }
  else if (tls_priority)
  {
    res = gnutls_priority_set(tls, tls_priority);
    if (name && (res != GNUTLS_E_SUCCESS))
      log_write(LS_SYSTEM, L_ERROR, 0, "Unable to use default TLS ciphers"
                " for %s: %s", name, gnutls_strerror(res));
  }
  else
  {
    gnutls_set_default_priority(tls);
  }

  if (flag & GNUTLS_SERVER)
  {
    gnutls_certificate_server_set_request(tls,
      require_peer ? GNUTLS_CERT_REQUIRE : GNUTLS_CERT_IGNORE);
  }
  else if (verify_ca && name)
    gnutls_session_set_verify_cert(tls, name, 0);

  gnutls_handshake_set_timeout(tls, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  gnutls_transport_set_int(tls, fd);

  return tls;
}

void *ircd_tls_accept(struct Listener *listener, int fd)
{
  gnutls_certificate_credentials_t cred = NULL;

  if (listener && listener->tls_ctx)
    cred = (gnutls_certificate_credentials_t)listener->tls_ctx;
  else if (!tls_cert)
    return NULL;
  return tls_create(GNUTLS_SERVER, fd, NULL,
                    listener ? listener->tls_ciphers : NULL, cred,
                    listener && ircd_tls_listener_peer_cert_required(listener),
                    listener && ircd_tls_listener_verify_ca(listener));
}

void *ircd_tls_connect(struct ConfItem *aconf, int fd)
{
  gnutls_certificate_credentials_t cred = NULL;

  ensure_conf_tls(aconf);
  if (aconf && aconf->tls_ctx)
    cred = (gnutls_certificate_credentials_t)aconf->tls_ctx;
  return tls_create(GNUTLS_CLIENT, fd, aconf ? aconf->name : NULL,
                    aconf ? aconf->tls_ciphers : NULL, cred,
                    aconf && ircd_tls_connect_peer_cert_required(aconf),
                    aconf && ircd_tls_connect_verify_ca(aconf));
}

void ircd_tls_conf_free(struct ConfItem *aconf)
{
  if (aconf && aconf->tls_ctx)
  {
    gnutls_certificate_free_credentials(
      (gnutls_certificate_credentials_t)aconf->tls_ctx);
    aconf->tls_ctx = NULL;
  }
}

int ircd_tls_conf_reload(struct ConfItem *aconf)
{
  gnutls_certificate_credentials_t new_cred;

  if (!aconf || !conf_tls_needs_custom_ctx(aconf))
    return 0;

  new_cred = gnutls_create_credentials(aconf->tls_cacertfile,
                                       aconf->tls_cacertdir,
                                       aconf->tls_verifypeer,
                                       aconf->tls_systemca);
  if (!new_cred)
    return 1;

  ircd_tls_conf_free(aconf);
  aconf->tls_ctx = new_cred;
  return 0;
}

int ircd_tls_check_peer_hostname(struct Client *cptr, const char *name)
{
  gnutls_session_t tls;
  const gnutls_datum_t *datum;
  gnutls_x509_crt_t crt;
  int res;

  if (!cptr || EmptyString(name))
    return 0;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return 1;

  datum = gnutls_certificate_get_peers(tls, NULL);
  if (!datum || datum->size == 0)
    return 1;

  res = gnutls_x509_crt_init(&crt);
  if (res != GNUTLS_E_SUCCESS)
    return 1;

  res = gnutls_x509_crt_import(crt, datum, GNUTLS_X509_FMT_DER);
  if (res != GNUTLS_E_SUCCESS)
  {
    gnutls_x509_crt_deinit(crt);
    return 1;
  }

  res = gnutls_x509_crt_check_hostname(crt, name);
  gnutls_x509_crt_deinit(crt);
  return res ? 0 : 1;
}

void ircd_tls_close(void *ctx, const char *message)
{
  gnutls_bye(ctx, GNUTLS_SHUT_RDWR);
  gnutls_deinit(ctx);
}

int ircd_tls_listen(struct Listener *listener)
{
  gnutls_certificate_credentials_t new_cred;

  if (!listener)
    return 1;

  if (!listener_needs_custom_ctx(listener))
    return 0;

  new_cred = gnutls_create_credentials(listener->tls_cacertfile,
                                       listener->tls_cacertdir,
                                       listener->tls_verifypeer,
                                       listener->tls_systemca);
  if (!new_cred)
    return 1;

  ircd_tls_listen_free(listener);
  listener->tls_ctx = new_cred;
  return 0;
}

int ircd_tls_listener_ready(const struct Listener *listener)
{
  return tls_cert != NULL
    || (listener && listener->tls_ctx != NULL);
}

void ircd_tls_listen_free(struct Listener *listener)
{
  if (listener && listener->tls_ctx)
  {
    gnutls_certificate_free_credentials(
      (gnutls_certificate_credentials_t)listener->tls_ctx);
    listener->tls_ctx = NULL;
  }
}

int ircd_tls_negotiate(struct Client *cptr)
{
  gnutls_session_t tls;
  gnutls_x509_crt_t crt;
  const gnutls_datum_t *datum;
  size_t len;
  int res;
  unsigned char buf[32];

  tls = s_tls(&cli_socket(cptr));

  if (!tls)
    return 1;

  /* Check for handshake timeout - use the constant from header */
  if (CurrentTime - cli_firsttime(cptr) > TLS_HANDSHAKE_TIMEOUT) {
    Debug((DEBUG_DEBUG, "GnuTLS handshake timeout for %s", cli_name(cptr)));
    return -1;
  }

  res = gnutls_handshake(tls);
  switch (res)
  {
  case GNUTLS_E_INTERRUPTED:
  case GNUTLS_E_AGAIN:
  case GNUTLS_E_WARNING_ALERT_RECEIVED:
  case GNUTLS_E_GOT_APPLICATION_DATA:
    return 0;

  case GNUTLS_E_SUCCESS:
    datum = gnutls_certificate_get_peers(tls, NULL);
    if (ircd_tls_peer_cert_required(cptr) && (!datum || datum->size == 0))
    {
      Debug((DEBUG_DEBUG,
             "TLS peer certificate required but not presented for %s",
             cli_name(cptr)));
      return -1;
    }

    if (ircd_tls_verifypeer_enabled(cptr) && gnutls_auth_get_type(tls) == GNUTLS_CRT_X509)
    {
      unsigned int vstatus = 0;
      const char *hostname = NULL;
      struct ConfItem *aconf;

      if (IsConnecting(cptr)
          && (aconf = find_conf_byname(cli_confs(cptr), cli_name(cptr), CONF_SERVER))
          && ircd_tls_connect_verify_hostname(aconf))
        hostname = aconf->name;

      res = gnutls_certificate_verify_peers3(tls, hostname, &vstatus);
      if (res < 0)
      {
        Debug((DEBUG_DEBUG,
               "TLS peer certificate verification failed for %s: %s",
               cli_name(cptr), gnutls_strerror(res)));
        return -1;
      }
      if (vstatus != 0)
      {
        Debug((DEBUG_DEBUG,
               "TLS peer certificate verification failed for %s (0x%x)",
               cli_name(cptr), vstatus));
        return -1;
      }
    }

    if (!datum)
    {
      ClearNegotiatingTLS(cptr);
      return 1;
    }

    res = gnutls_x509_crt_init(&crt);
    if (res)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "gnutls_x509_crt_init failed for %s: %d",
        cli_name(cptr), res);
        return -1;
    }

    /* Complete the fingerprint extraction - convert buf to hex */
    res = gnutls_x509_crt_import(crt, datum, GNUTLS_X509_FMT_DER);
    if (res)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "gnutls_x509_crt_import failed for %s: %d",
        cli_name(cptr), res);
      gnutls_x509_crt_deinit(crt);
      return 1;
    }

    len = sizeof(buf);
    res = gnutls_x509_crt_get_fingerprint(crt, GNUTLS_DIG_SHA256, buf, &len);
    gnutls_x509_crt_deinit(crt);
    if (res)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "gnutls_x509_crt_get_fingerprint failed for %s: %d",
        cli_name(cptr), res);
      return 1;
    }
    
    /* Convert buf to hex like OpenSSL version */
    if (len == 32) {
      char *p = cli_tls_fingerprint(cptr);
      for (unsigned int i = 0; i < len; i++) {
        sprintf(p + (i * 2), "%02x", buf[i]);
      }
      p[len * 2] = '\0';
      Debug((DEBUG_DEBUG, "Fingerprint for %s: %s", cli_name(cptr), cli_tls_fingerprint(cptr)));
    }
    else {
      memset(cli_tls_fingerprint(cptr), 0, 65);
      Debug((DEBUG_DEBUG, "Invalid fingerprint length: %zu", len));
    }

    ClearNegotiatingTLS(cptr);
    return 1;

  default:
    Debug((DEBUG_DEBUG, " ... gnutls_handshake() failed -> %s (%d)",
           gnutls_strerror(res), res));
    if (gnutls_error_is_fatal(res)) {
      const char* const error_tls = "ERROR :TLS connection error\r\n";
      Debug((DEBUG_DEBUG, "GnuTLS handshake failed for %s: %s", cli_name(cptr), gnutls_strerror(res)));
      write(cli_fd(cptr), error_tls, strlen(error_tls));
      return -1;
    }
    return 0;
  }
}

IOResult ircd_tls_recv(struct Client *cptr, char *buf,
                       unsigned int length, unsigned int *count_out)
{
  gnutls_session_t tls;
  int res;

  *count_out = 0;
  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return IO_FAILURE;

  res = gnutls_record_recv(tls, buf, length);
  if (res > 0)
  {
    *count_out = res;
    return IO_SUCCESS;
  }
  if (res == GNUTLS_E_REHANDSHAKE)
  {
    res = gnutls_handshake(tls);
    if (res >= 0)
      return IO_SUCCESS;
  }
  if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN)
    return IO_BLOCKED;
  return gnutls_error_is_fatal(res) ? IO_FAILURE : IO_BLOCKED;
}

IOResult ircd_tls_sendv(struct Client *cptr, struct MsgQ *buf,
                        unsigned int *count_in, unsigned int *count_out)
{
  struct iovec iov[512];
  gnutls_session_t tls;
  struct Connection *con;
  IOResult result = IO_BLOCKED;
  ssize_t res;
  int ii, count;

  con = cli_connect(cptr);
  tls = s_tls(&con_socket(con));
  if (!tls)
    return IO_FAILURE;

  /* TODO: Try to use gnutls_record_cork()/_uncork()/_check_corked().
   * The exact semantics of check_corked()'s return value are not clear:
   * What does "the size of the corked data" signify relative to what
   * has been accepted or must be provided to a future call to
   * gnutls_record_send()?
   */
  *count_out = 0;
  if (con->con_rexmit)
  {
    res = gnutls_record_send(tls, con->con_rexmit, con->con_rexmit_len);
    if (res <= 0) {
      if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN)
        return IO_BLOCKED;
      return gnutls_error_is_fatal(res) ? IO_FAILURE : IO_BLOCKED;
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
    res = gnutls_record_send(tls, iov[ii].iov_base, iov[ii].iov_len);
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

    /* We only reach this if the gnutls_record_send failed. */
    if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
      cli_connect(cptr)->con_rexmit = iov[ii].iov_base;
      cli_connect(cptr)->con_rexmit_len = iov[ii].iov_len;
    }
    result = gnutls_error_is_fatal(res) ? IO_FAILURE : IO_BLOCKED;
    break;
  }

  return result;
}

int ircd_tls_sha1_base64(const void *data, size_t len, char *out, size_t outlen)
{
  unsigned char digest[20];
  gnutls_datum_t in;
  gnutls_datum_t encoded = { NULL, 0 };
  int rc;

  if (!data || !out || len == 0 || outlen == 0)
    return -1;

  rc = gnutls_hash_fast(GNUTLS_DIG_SHA1, data, len, digest);
  if (rc != 0)
    return -1;

  in.data = digest;
  in.size = sizeof(digest);

  rc = gnutls_base64_encode2(&in, &encoded);
  if (rc != 0)
    return -1;

  if (encoded.size >= outlen) {
    gnutls_free(encoded.data);
    return -1;
  }

  memcpy(out, encoded.data, encoded.size);
  out[encoded.size] = '\0';
  gnutls_free(encoded.data);
  return 0;
}
