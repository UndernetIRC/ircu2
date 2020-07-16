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

#include "config.h"
#include "client.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "ircd_tls.h"
#include "listener.h"
#include "s_conf.h"
#include "s_debug.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stddef.h>
#include <string.h>

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

int ircd_tls_init(void)
{
  static int once;
  const char *str, *s_2;
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

    gnutls_certificate_allocate_credentials(&new_cert);
    res = gnutls_certificate_set_x509_key_file2(new_cert,
      ircd_tls_certfile, ircd_tls_keyfile, GNUTLS_X509_FMT_PEM, "",
      GNUTLS_PKCS_PLAIN | GNUTLS_PKCS_NULL_PASSWORD);
    if (res < 0) /* may return a positive index */
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "Unable to load TLS keyfile and/or"
        " certificate: %s", gnutls_strerror(res));
      gnutls_certificate_free_credentials(new_cert);
      return 2;
    }

    str = feature_str(FEAT_TLS_CACERTFILE);
    s_2 = feature_str(FEAT_TLS_CACERTDIR);
    if (!EmptyString(str) || !EmptyString(s_2))
    {
      if (!EmptyString(s_2))
      {
        res = gnutls_certificate_set_x509_trust_dir(new_cert, s_2,
                                                    GNUTLS_X509_FMT_PEM);
        if (res < 0)
        {
          log_write(LS_SYSTEM, L_ERROR, 0, "Unable to read CA certs from"
                    " %s: %s", s_2, gnutls_strerror(res));
        }
      }

      if (!EmptyString(str))
      {
        res = gnutls_certificate_set_x509_trust_file(new_cert, str,
                                                     GNUTLS_X509_FMT_PEM);
        if (res < 0)
        {
          log_write(LS_SYSTEM, L_ERROR, 0, "Unable to read CA certs from"
                    " %s: %s", str, gnutls_strerror(res));
        }
      }
    }
    else
      (void)gnutls_certificate_set_x509_system_trust(new_cert);

    if (tls_cert)
      gnutls_certificate_free_credentials(tls_cert);
    tls_cert = new_cert;
  }

  return 0;
}

static void *tls_create(int flag, int fd, const char *name, const char *tls_ciphers)
{
  gnutls_session_t tls;
  int res;

  res = gnutls_init(&tls, flag | TLS_SESSION_FLAGS);
  if (res != GNUTLS_E_SUCCESS)
    return NULL;

  res = gnutls_credentials_set(tls, GNUTLS_CRD_CERTIFICATE, tls_cert);
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
    gnutls_certificate_server_set_request(tls, GNUTLS_CERT_REQUEST);

  gnutls_handshake_set_timeout(tls, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  gnutls_transport_set_int(tls, fd);

  return tls;
}

void *ircd_tls_accept(struct Listener *listener, int fd)
{
  return tls_create(GNUTLS_SERVER, fd, NULL, listener->tls_ciphers);
}

void *ircd_tls_connect(struct ConfItem *aconf, int fd)
{
  return tls_create(GNUTLS_CLIENT, fd, aconf->name, aconf->tls_ciphers);
}

void ircd_tls_close(void *ctx, const char *message)
{
  gnutls_bye(ctx, GNUTLS_SHUT_RDWR);
  gnutls_deinit(ctx);
}

void ircd_tls_fingerprint(void *ctx, char *fingerprint)
{
  memset(fingerprint, 0, 32);
}

static void handle_blocked(struct Client *cptr, gnutls_session_t tls)
{
  if (gnutls_record_get_direction(tls))
    socket_events(&cli_socket(cptr), SOCK_EVENT_WRITABLE);
  else
    socket_events(&cli_socket(cptr), SOCK_EVENT_READABLE);
}

int ircd_tls_negotiate(struct Client *cptr)
{
  gnutls_session_t tls;
  int res;

  tls = s_tls(&cli_socket(cptr));

  if (!tls)
    return 1;

  res = gnutls_handshake(tls);
  switch (res)
  {
  case GNUTLS_E_SUCCESS:
    return 1;
  case GNUTLS_E_INTERRUPTED:
  case GNUTLS_E_AGAIN:
    handle_blocked(cptr, tls);
    /* and fall through */
  case GNUTLS_E_WARNING_ALERT_RECEIVED:
  case GNUTLS_E_GOT_APPLICATION_DATA:
    return 0;
  default:
    Debug((DEBUG_DEBUG, " ... gnutls_handshake() failed -> %s (%d)",
           gnutls_strerror(res), res));
    return gnutls_error_is_fatal(res) ? -1 : 0;
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
  if (IsNegotiatingTLS(cptr))
  {
    res = gnutls_handshake(tls);
    if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN)
    {
      handle_blocked(cptr, tls);
      return IO_BLOCKED;
    }
    if (res != GNUTLS_E_SUCCESS)
      return gnutls_error_is_fatal(res) ? IO_FAILURE : IO_BLOCKED;
  }

  res = gnutls_record_recv(tls, buf, length);
  if (res >= 0)
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
    handle_blocked(cptr, tls);
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
  if (IsNegotiatingTLS(cptr))
  {
    res = gnutls_handshake(tls);
    if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN)
    {
      handle_blocked(cptr, tls);
      return IO_BLOCKED;
    }
    if (res != GNUTLS_E_SUCCESS)
      return gnutls_error_is_fatal(res) ? IO_FAILURE : IO_BLOCKED;
  }

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
    if (res <= 0)
    {
      if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN)
        handle_blocked(cptr, tls);
      return gnutls_error_is_fatal(res) ? IO_FAILURE : IO_BLOCKED;
    }
    msgq_excise(buf, con->con_rexmit, con->con_rexmit_len);
    con->con_rexmit_len = 0;
    con->con_rexmit = NULL;
    result = IO_SUCCESS;
  }

  count = msgq_mapiov(buf, iov, sizeof(iov) / sizeof(iov[0]), count_in);
  for (ii = 0; ii < count; ++ii)
  {
    res = gnutls_record_send(tls, iov[ii].iov_base, iov[ii].iov_len);
    if (res > 0)
    {
      *count_out += res;
      result = IO_SUCCESS;
      continue;
    }

    if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN)
    {
      handle_blocked(cptr, tls);
      cli_connect(cptr)->con_rexmit = iov[ii].iov_base;
      cli_connect(cptr)->con_rexmit_len = iov[ii].iov_len;
    }
    result = gnutls_error_is_fatal(res) ? IO_FAILURE : IO_BLOCKED;
    break;
  }

  return result;
}
