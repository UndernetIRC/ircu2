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
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "ircd_tls.h"
#include "listener.h"
#include "s_auth.h"
#include "send.h"
#include "s_conf.h"
#include "s_debug.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
const char *ircd_tls_version = "libtls " TOSTRING(TLS_API);

int ircd_tls_init(void)
{
  static int libtls_init;

  if (EmptyString(ircd_tls_keyfile) || EmptyString(ircd_tls_certfile))
    return 0;

  if (!libtls_init)
  {
    libtls_init = 1;
    if (tls_init() < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "tls_init() failed");
      return 1;
    }
  }

  return 0;
}

static struct tls_config *make_tls_config(const char *ciphers)
{
  struct tls_config *new_cfg;
  uint32_t protos;
  const char *str;

  new_cfg = tls_config_new();
  if (!new_cfg)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "tls_config_new() failed");
    return NULL;
  }

  if (tls_config_set_keypair_file(new_cfg, ircd_tls_certfile, ircd_tls_keyfile) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "unable to load certificate and key: %s",
              tls_config_error(new_cfg));
    goto fail;
  }

  str = feature_str(FEAT_TLS_CACERTDIR);
  if (!EmptyString(str))
  {
    if (tls_config_set_ca_path(new_cfg, str) < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "unable to set CA path to %s: %s",
                str, tls_config_error(new_cfg));
      goto fail;
    }
  }

  str = feature_str(FEAT_TLS_CACERTFILE);
  if (!EmptyString(str))
  {
    if (tls_config_set_ca_file(new_cfg, str) < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "unable to set CA file to %s: %s",
                str, tls_config_error(new_cfg));
      goto fail;
    }
  }

  /* Configure verification based on self-signed certificate feature */
  if (feature_bool(FEAT_TLS_ALLOW_SELFSIGNED)) {
    tls_config_verify_client_optional(new_cfg);
    tls_config_insecure_noverifycert(new_cfg);
  }

  protos = 0;
  /* Set minimum TLS version to 1.2 (like OpenSSL) and support 1.3 */
  protos |= TLS_PROTOCOL_TLSv1_2;
#ifdef TLS_PROTOCOL_TLSv1_3
  protos |= TLS_PROTOCOL_TLSv1_3;
#endif
  if (tls_config_set_protocols(new_cfg, protos) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "unable to select TLS versions: %s",
              tls_config_error(new_cfg));
    goto fail;
  }

  str = ciphers;
  if (EmptyString(str))
    str = feature_str(FEAT_TLS_CIPHERS);
  if (!EmptyString(str))
  {
    if (tls_config_set_ciphers(new_cfg, str) < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "unable to select TLS ciphers: %s",
                tls_config_error(new_cfg));
      goto fail;
    }
  }

  return new_cfg;

fail:
  tls_config_free(new_cfg);
  return NULL;
}

void *ircd_tls_accept(struct Listener *listener, int fd)
{
  struct tls *tls;

  if (!listener) {
    log_write(LS_SYSTEM, L_ERROR, 0, "TLS accept called with NULL listener");
    return NULL;
  }

  if (!listener->tls_ctx) {
    log_write(LS_SYSTEM, L_ERROR, 0, "TLS accept called with NULL tls_ctx");
    return NULL;
  }

  if (tls_accept_socket((struct tls *)listener->tls_ctx, &tls, fd) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "TLS accept failed: %s",
              tls_error((struct tls *)listener->tls_ctx));
    return NULL;
  }

  return tls;
}

void *ircd_tls_connect(struct ConfItem *aconf, int fd)
{
  struct tls_config *cfg;
  struct tls *tls;

  cfg = make_tls_config(aconf->tls_ciphers);
  if (!cfg)
  {
    return NULL;
  }

  tls = tls_client();
  if (!tls)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "tls_client() failed");
    return NULL;
  }

  if (tls_configure(tls, cfg) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "tls_configure failed for client: %s",
              tls_error(tls));
  fail:
    tls_free(tls);
    return NULL;
  }

  if (tls_connect_socket(tls, fd, aconf->name) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "tls_connect_socket failed for %s: %s",
              aconf->name, tls_error(tls));
    goto fail;
  }

  return tls;
}

void ircd_tls_close(void *ctx, const char *message)
{
  /* TODO: handle TLS_WANT_POLL{IN,OUT} from tls_close() */
  tls_close(ctx);
  tls_free(ctx);
}

static IOResult tls_handle_error(struct Client *cptr, struct tls *tls, int err)
{
  switch (err) {
    case TLS_WANT_POLLIN:
    case TLS_WANT_POLLOUT:
      return IO_BLOCKED;
    
    default:
      /* Fatal error */
      Debug((DEBUG_DEBUG, "tls fatal error for %s: %s", cli_name(cptr), tls_error(tls)));
      break;
  }
  tls_free(tls);
  s_tls(&cli_socket(cptr)) = NULL;
  return IO_FAILURE;
}

int ircd_tls_listen(struct Listener *listener)
{
  struct tls_config *cfg;
  struct tls *server_ctx;

  cfg = make_tls_config(listener->tls_ciphers);
  if (!cfg)
    return 1;

  if (listener->tls_ctx)
    server_ctx = (struct tls *)listener->tls_ctx;
  else
  {
    server_ctx = tls_server();
    if (!server_ctx)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "tls_server failed");
      tls_config_free(cfg);
      return 2;
    }
    listener->tls_ctx = (void *)server_ctx;
  }

  if (tls_configure(server_ctx, cfg) < 0)
  {
    const char *error = tls_error(server_ctx);
    fprintf(stderr, "TLS configure failed: %s\n", error ? error : "unknown error");
    log_write(LS_SYSTEM, L_ERROR, 0, "unable to configure TLS server context: %s",
              error ? error : "unknown error");
    tls_free(server_ctx);
    listener->tls_ctx = NULL;
    tls_config_free(cfg);
    return 3;  /* Return error when configuration fails */
  }

  tls_config_free(cfg);
  return 0;
}

int ircd_tls_negotiate(struct Client *cptr)
{
  const char *hash;
  struct tls *tls;
  int res;
  const char* const error_tls = "ERROR :TLS connection error\r\n";

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return 1;

  /* Check for handshake timeout */
  if (CurrentTime - cli_firsttime(cptr) > TLS_HANDSHAKE_TIMEOUT) {
    Debug((DEBUG_DEBUG, "libtls handshake timeout for %s", cli_name(cptr)));
    return -1;
  }

  Debug((DEBUG_DEBUG, "libtls handshake for %s", cli_name(cptr)));

  res = tls_handshake(tls);
  if (res == 0)
  {
    ClearNegotiatingTLS(cptr);

    hash = tls_peer_cert_hash(tls);
    if (hash && !ircd_strncmp(hash, "SHA256:", 7))
    {
      /* Convert the hash to our fingerprint format */
      if (strlen(hash + 7) <= 64) {
        ircd_strncpy(cli_tls_fingerprint(cptr), hash + 7, 64);
        Debug((DEBUG_DEBUG, "Fingerprint for %s: %s", cli_name(cptr), cli_tls_fingerprint(cptr)));
      } else {
        memset(cli_tls_fingerprint(cptr), 0, 65);
        Debug((DEBUG_DEBUG, "Invalid fingerprint length: %zu", strlen(hash + 7)));
      }
    } else {
      memset(cli_tls_fingerprint(cptr), 0, 65);
      Debug((DEBUG_DEBUG, "Failed to get fingerprint for %s", cli_name(cptr)));
    }

    return 1;
  }
  
  if (res == TLS_WANT_POLLIN || res == TLS_WANT_POLLOUT) {
    return 0; /* Handshake in progress */
  }
  
  IOResult tls_result = tls_handle_error(cptr, tls, res);
  if (tls_result == IO_FAILURE) {
    Debug((DEBUG_DEBUG, "TLS handshake failed for %s", cli_name(cptr)));
    write(cli_fd(cptr), error_tls, strlen(error_tls));
    return -1;
  }
  /* tls_result == IO_BLOCKED - handshake still in progress */
  return 0;
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
  if (res > 0)
  {
    *count_out = res;
    return IO_SUCCESS;
  }

  return tls_handle_error(cptr, tls, res);
}

IOResult ircd_tls_sendv(struct Client *cptr, struct MsgQ *buf,
                        unsigned int *count_in, unsigned int *count_out)
{
  struct iovec iov[512];
  struct tls *tls;
  struct Connection *con;
  IOResult result = IO_BLOCKED;
  int ii, count, res;

  con = cli_connect(cptr);
  tls = s_tls(&con_socket(con));
  if (!tls)
    return IO_FAILURE;

  /* tls_write() does not document any restriction on retries. */
  *count_out = 0;
  if (con->con_rexmit)
  {
    res = tls_write(tls, con->con_rexmit, con->con_rexmit_len);
    if (res <= 0) {
      if (res == TLS_WANT_POLLIN || res == TLS_WANT_POLLOUT)
        return IO_BLOCKED;
      return tls_handle_error(cptr, tls, res);
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
    res = tls_write(tls, iov[ii].iov_base, iov[ii].iov_len);
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

    /* We only reach this if the tls_write failed. */
    if (res == TLS_WANT_POLLIN || res == TLS_WANT_POLLOUT) {
      cli_connect(cptr)->con_rexmit = iov[ii].iov_base;
      cli_connect(cptr)->con_rexmit_len = iov[ii].iov_len;
      return IO_BLOCKED;
    }
    result = tls_handle_error(cptr, tls, res);
    break;
  }

  return result;
}
