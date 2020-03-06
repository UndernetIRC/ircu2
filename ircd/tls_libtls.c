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
 * @brief ircd TLS functions using OpenBSD's libtls.
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

#include <stddef.h>
#include <string.h>
#include <tls.h>

#define CONCAT(A, B) A # B
const char *ircd_tls_version = CONCAT("libtls ", TLS_API);
static struct tls_config *tls_cfg;
static struct tls *tls_srv;

int ircd_tls_init(void)
{
  static int libtls_init;
  struct tls_config *new_cfg = NULL;
  struct tls *new_srv = NULL;
  uint32_t protos;
  const char *str;
  int res;

  if (EmptyString(ircd_tls_keyfile) || EmptyString(ircd_tls_certfile))
    goto done;

  if (!libtls_init)
  {
    libtls_init = 1;
    if (tls_init() < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "tls_init() failed");
      return 1;
    }
  }

  new_cfg = tls_config_new();
  if (!new_cfg)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "tls_config_new() failed");
    return 2;
  }

  new_srv = tls_server();
  if (!new_srv)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "unable to create new TLS server context");
    tls_config_free(new_cfg);
    return 3;
  }

  res = tls_config_add_keypair_file(new_cfg, ircd_tls_certfile, ircd_tls_keyfile);
  if (res < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "unable to load certificate and key: %s",
              tls_config_error(new_cfg));
    tls_config_free(new_cfg);
    tls_free(new_srv);
    return 4;
  }

  str = feature_str(FEAT_TLS_CACERTDIR);
  if (!EmptyString(str))
  {
    if (tls_config_set_ca_path(new_cfg, str) < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "unable to set CA path to %s: %s",
                str, tls_config_error(new_cfg));
    }
  }

  str = feature_str(FEAT_TLS_CACERTFILE);
  if (!EmptyString(str))
  {
    if (tls_config_set_ca_file(new_cfg, str) < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "unable to set CA file to %s: %s",
                str, tls_config_error(new_cfg));
    }
  }

  protos = 0;
  /* libtls does not support SSLv2 or SSLv3. */
  if (feature_bool(FEAT_TLS_V1P0))
    protos |= TLS_PROTOCOL_TLSv1_0;
  if (feature_bool(FEAT_TLS_V1P1))
    protos |= TLS_PROTOCOL_TLSv1_1;
  if (feature_bool(FEAT_TLS_V1P2))
    protos |= TLS_PROTOCOL_TLSv1_2;
#ifdef TLS_PROTOCOL_TLSv1_3
  if (feature_bool(FEAT_TLS_V1P3))
    protos |= TLS_PROTOCOL_TLSv1_3;
#endif
  if (tls_config_set_protocols(new_cfg, protos) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "unable to select TLS versions: %s",
              tls_config_error(new_cfg));
  }

  str = feature_str(FEAT_TLS_CIPHERS);
  if (!EmptyString(str))
  {
    if (tls_config_set_ciphers(new_cfg, str) < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "unable to select TLS ciphers: %s",
                tls_config_error(new_cfg));
    }
  }

  tls_config_verify_client_optional(new_cfg);

  if (tls_configure(new_srv, new_cfg) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "unable to configure TLS server context: %s",
              tls_error(new_srv));
    tls_config_free(new_cfg);
    tls_free(new_srv);
    return 5;
  }

done:
  tls_config_free(tls_cfg);
  tls_cfg = new_cfg;
  tls_free(tls_srv);
  tls_srv = new_srv;
  return 0;
}

void *ircd_tls_accept(struct Listener *listener, int fd)
{
  struct tls *tls;

  /* TODO: adjust acceptable ciphers list */

  if (tls_accept_socket(tls_srv, &tls, fd) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "TLS accept failed: %s",
              tls_error(tls_srv));
    return NULL;
  }

  return tls;
}

void *ircd_tls_connect(struct ConfItem *aconf, int fd)
{
  struct tls *tls;

  tls = tls_client();
  if (!tls)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "tls_client() failed");
    return NULL;
  }

  /* TODO: adjust acceptable ciphers list */

  if (tls_configure(tls, tls_cfg) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "tls_configure failed for client: %s",
              tls_error(tls));
    tls_free(tls);
    return NULL;
  }

  if (tls_connect_socket(tls, fd, aconf->name) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "tls_connect_socket failed for %s: %s",
              aconf->name, tls_error(tls));
    tls_free(tls);
    return NULL;
  }

  return tls;
}

void ircd_tls_close(void *ctx, const char *message)
{
  /* TODO: handle TLS_WANT_POLL{IN,OUT} from tls_close() */
  tls_close(ctx);
  tls_free(ctx);
}

void ircd_tls_fingerprint(void *ctx, char *fingerprint)
{
  const char *text;

  text = tls_peer_cert_hash(ctx);
  if (text && !ircd_strncmp(text, "SHA256:", 7))
  {
    /* TODO: convert from ASCII hex to binary */
    return;
  }
  memset(fingerprint, 0, 32);
}

static int tls_handle_error(struct Client *cptr, struct tls *tls, int err)
{
  if (err == TLS_WANT_POLLIN)
  {
    socket_events(&cli_socket(cptr), SOCK_EVENT_READABLE);
    return 0;
  }
  if (err == TLS_WANT_POLLOUT)
  {
    socket_events(&cli_socket(cptr), SOCK_EVENT_WRITABLE);
    return 0;
  }
  Debug((DEBUG_DEBUG, "tls fatal error for %s: %s", cli_name(cptr), tls_error(tls)));
  tls_free(tls);
  s_tls(&cli_socket(cptr)) = NULL;
  return -1;
}

int ircd_tls_negotiate(struct Client *cptr)
{
  struct tls *tls;
  int res;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return 1;

  res = tls_handshake(tls);
  if (res == 1)
    return 1;
  return tls_handle_error(cptr, tls, res);
}

IOResult ircd_tls_recv(struct Client *cptr, char *buf,
                       unsigned int length, unsigned int *count_out)
{
  struct tls *tls;
  int res;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return IO_FAILURE;

  res = tls_read(tls, buf, length);
  if (res >= 0)
  {
    *count_out = res;
    return IO_SUCCESS;
  }
  return (tls_handle_error(cptr, tls, res) < 0) ? IO_FAILURE : IO_BLOCKED;
}

IOResult ircd_tls_sendv(struct Client *cptr, struct MsgQ *buf,
                        unsigned int *count_in, unsigned int *count_out)
{
  struct iovec iov[512];
  struct tls *tls;
  struct Connection *con;
  int ii, count, res, orig_errno;

  con = cli_connect(cptr);
  tls = s_tls(&con_socket(con));
  if (!tls)
    return IO_FAILURE;

  /* tls_write() does not document any restriction on retries. */
  *count_out = 0;
  count = msgq_mapiov(buf, iov, sizeof(iov) / sizeof(iov[0]), count_in);
  for (ii = 0; ii < count; ++ii)
  {
    res = tls_write(tls, iov[ii].iov_base, iov[ii].iov_len);
    if (res > 0)
    {
      *count_out += res;
      break;
    }

    return (tls_handle_error(cptr, tls, res) < 0) ? IO_FAILURE : IO_BLOCKED;
  }

  return IO_SUCCESS;
}
