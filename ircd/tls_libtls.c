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
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_tls.h"
#include "tls_io.h"
#include "listener.h"
#include "s_auth.h"
#include "send.h"
#include "s_conf.h"
#include "s_debug.h"
#include "ircd_sha1.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>

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

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
const char *ircd_tls_version = "libtls " TOSTRING(TLS_API);

static struct tls_config *client_cfg;

static struct tls_config *make_tls_config(const char *ciphers,
                                          const char *cacertdir,
                                          const char *cacertfile,
                                          ircd_tls_trust_policy policy,
                                          int systemca, int is_server);

int ircd_tls_init(void)
{
  static int libtls_init;
  struct tls_config *new_cfg;

  if (EmptyString(ircd_tls_keyfile) || EmptyString(ircd_tls_certfile))
  {
    if (client_cfg)
    {
      tls_config_free(client_cfg);
      client_cfg = NULL;
    }
    return 0;
  }

  if (!libtls_init)
  {
    libtls_init = 1;
    if (tls_init() < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "tls_init() failed");
      return 1;
    }
  }

  new_cfg = make_tls_config(NULL, NULL, NULL, TLS_TRUST_REQUIRE_SOFT,
                            LISTENER_TLS_SYSTEMCA_DEFAULT, 0);
  if (!new_cfg)
    return 2;

  if (client_cfg)
    tls_config_free(client_cfg);
  client_cfg = new_cfg;

  return 0;
}

static void tls_config_set_verify_policy(struct tls_config *cfg,
                                         ircd_tls_trust_policy policy,
                                         int is_server)
{
  switch (policy)
  {
  case TLS_TRUST_REQUIRE_CA:
    if (is_server)
      tls_config_verify_client(cfg);
    else
      tls_config_verify(cfg);
    return;

  case TLS_TRUST_REQUIRE_SOFT:
    if (is_server)
    {
      tls_config_verify_client(cfg);
      tls_config_insecure_noverifycert(cfg);
    }
    else
    {
      /* Require a peer cert but do not enforce CA or hostname; trust is
       * fingerprint pin or nothing.  tls_config_verify() enables name
       * checks that insecure_noverifycert() does not clear.
       */
      tls_config_verify(cfg);
      tls_config_insecure_noverifycert(cfg);
      tls_config_insecure_noverifyname(cfg);
    }
    return;

  case TLS_TRUST_REQUEST_SOFT:
    if (is_server)
    {
      tls_config_verify_client_optional(cfg);
      tls_config_insecure_noverifycert(cfg);
    }
    else
      tls_config_insecure_noverifycert(cfg);
    return;
  }
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

static int libtls_set_ca_from_file(struct tls_config *cfg, const char *path)
{
  if (tls_config_set_ca_file(cfg, path) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "unable to set CA file to %s: %s",
              path, tls_config_error(cfg));
    return 0;
  }
  return 1;
}

static int libtls_set_ca_from_files(struct tls_config *cfg,
                                    const char *file1, const char *file2)
{
  size_t len1 = 0, len2 = 0, total;
  char *buf1 = NULL, *buf2 = NULL, *combined = NULL;
  int ok = 0;

  if (!EmptyString(file1))
  {
    buf1 = tls_load_file(file1, &len1, NULL);
    if (!buf1)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "unable to load CA file %s", file1);
      return 0;
    }
  }
  if (!EmptyString(file2))
  {
    buf2 = tls_load_file(file2, &len2, NULL);
    if (!buf2)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "unable to load CA file %s", file2);
      goto out;
    }
  }

  if (!buf1 && !buf2)
    return 1;

  total = len1 + len2;
  combined = malloc(total);
  if (!combined)
    goto out;

  if (buf1)
    memcpy(combined, buf1, len1);
  if (buf2)
    memcpy(combined + len1, buf2, len2);

  if (tls_config_set_ca_mem(cfg, combined, total) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "unable to install CA bundle: %s",
              tls_config_error(cfg));
    goto out;
  }

  ok = 1;

out:
  free(combined);
  if (buf1)
    tls_unload_file(buf1, len1);
  if (buf2)
    tls_unload_file(buf2, len2);
  return ok;
}

static int libtls_load_ca(struct tls_config *cfg, const char *cacertfile,
                          const char *cacertdir, int systemca)
{
  const char *systemfile = NULL;
  int use_system = ircd_tls_use_system_ca(systemca, cacertfile, cacertdir);

  if (use_system)
    systemfile = tls_default_ca_cert_file();

  if (!EmptyString(cacertdir))
  {
    if (tls_config_set_ca_path(cfg, cacertdir) < 0)
    {
      log_write(LS_SYSTEM, L_ERROR, 0, "unable to set CA path to %s: %s",
                cacertdir, tls_config_error(cfg));
      return 0;
    }
  }

  if (!EmptyString(systemfile) && !EmptyString(cacertfile))
  {
    if (!libtls_set_ca_from_files(cfg, systemfile, cacertfile))
      return 0;
  }
  else if (!EmptyString(systemfile))
  {
    if (!libtls_set_ca_from_file(cfg, systemfile))
      return 0;
  }
  else if (!EmptyString(cacertfile))
  {
    if (!libtls_set_ca_from_file(cfg, cacertfile))
      return 0;
  }

  return 1;
}

static struct tls_config *make_tls_config(const char *ciphers,
                                          const char *cacertdir,
                                          const char *cacertfile,
                                          ircd_tls_trust_policy policy,
                                          int systemca, int is_server)
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

  if (!libtls_load_ca(new_cfg, cacertfile, cacertdir, systemca))
    goto fail;

  tls_config_set_verify_policy(new_cfg, policy, is_server);

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

static void ensure_conf_tls(struct ConfItem *aconf)
{
  if (!aconf || aconf->tls_ctx || !conf_tls_needs_custom_ctx(aconf))
    return;

  aconf->tls_ctx = make_tls_config(aconf->tls_ciphers, aconf->tls_cacertdir,
                                    aconf->tls_cacertfile,
                                    ircd_tls_connect_trust_policy(aconf),
                                    aconf->tls_systemca, 0);
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

  ensure_conf_tls(aconf);
  if (aconf && aconf->tls_ctx)
    cfg = (struct tls_config *)aconf->tls_ctx;
  else
    cfg = client_cfg;
  if (!cfg)
    return NULL;

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

  if (tls_connect_socket(tls, fd, aconf ? aconf->name : NULL) < 0)
  {
    log_write(LS_SYSTEM, L_ERROR, 0, "tls_connect_socket failed for %s: %s",
              aconf ? aconf->name : "?", tls_error(tls));
    goto fail;
  }

  return tls;
}

void ircd_tls_conf_free(struct ConfItem *aconf)
{
  if (aconf && aconf->tls_ctx)
  {
    tls_config_free((struct tls_config *)aconf->tls_ctx);
    aconf->tls_ctx = NULL;
  }
}

int ircd_tls_conf_reload(struct ConfItem *aconf)
{
  struct tls_config *new_cfg;

  if (!aconf || !conf_tls_needs_custom_ctx(aconf))
    return 0;

  new_cfg = make_tls_config(aconf->tls_ciphers, aconf->tls_cacertdir,
                            aconf->tls_cacertfile,
                            ircd_tls_connect_trust_policy(aconf),
                            aconf->tls_systemca, 0);
  if (!new_cfg)
    return 1;

  ircd_tls_conf_free(aconf);
  aconf->tls_ctx = new_cfg;
  return 0;
}

int ircd_tls_check_peer_hostname(struct Client *cptr, const char *name)
{
  struct tls *tls;

  if (!cptr || EmptyString(name))
    return 0;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return 1;

  return tls_peer_cert_contains_name(tls, name) == 1 ? 0 : 1;
}

void ircd_tls_close(void *ctx, const char *message)
{
  /* TODO: handle TLS_WANT_POLL{IN,OUT} from tls_close() */
  tls_close(ctx);
  tls_free(ctx);
}

int ircd_tls_listen(struct Listener *listener)
{
  struct tls_config *cfg;
  struct tls *server_ctx;
  int had_ctx;

  cfg = make_tls_config(listener->tls_ciphers, listener->tls_cacertdir,
                        listener->tls_cacertfile,
                        ircd_tls_listener_trust_policy(listener),
                        listener->tls_systemca, 1);
  if (!cfg)
    return 1;

  had_ctx = listener->tls_ctx != NULL;
  if (had_ctx)
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
    if (!had_ctx)
    {
      tls_free(server_ctx);
      listener->tls_ctx = NULL;
    }
    tls_config_free(cfg);
    return 3;
  }

  tls_config_free(cfg);
  return 0;
}

int ircd_tls_listener_ready(const struct Listener *listener)
{
  return listener && listener->tls_ctx != NULL;
}

void ircd_tls_listen_free(struct Listener *listener)
{
  if (listener && listener->tls_ctx)
  {
    tls_free((struct tls *)listener->tls_ctx);
    listener->tls_ctx = NULL;
  }
}

IOResult tls_backend_handshake(struct Client *cptr, struct tls_peer *peer,
                               char *reason, size_t reasonlen,
                               enum ircd_tls_want *want)
{
  const char *hash;
  struct tls *tls;
  int res;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return IO_FAILURE;

  res = tls_handshake(tls);
  if (res == 0)
  {
    /* libtls enforces the configured verification during the handshake, so a
     * completed handshake is verified; report the material for the core. */
    hash = tls_peer_cert_hash(tls);
    peer->have_cert = (hash && hash[0]);
    peer->verified = 1;
    if (hash && !ircd_strncmp(hash, "SHA256:", 7))
      ircd_strncpy(peer->fp_hex, hash + 7, sizeof(peer->fp_hex) - 1);
    return IO_SUCCESS;
  }
  if (res == TLS_WANT_POLLIN)
  {
    *want = IRCD_TLS_WANT_READ;
    return IO_BLOCKED;
  }
  if (res == TLS_WANT_POLLOUT)
  {
    *want = IRCD_TLS_WANT_WRITE;
    return IO_BLOCKED;
  }

  {
    const char *tls_err = tls_error(tls);
    tls_reason(reason, reasonlen, "%s", tls_err ? tls_err : "handshake error");
  }
  return IO_FAILURE;
}

void tls_backend_drop(struct Client *cptr)
{
  struct tls *tls = s_tls(&cli_socket(cptr));

  if (tls)
  {
    s_tls(&cli_socket(cptr)) = NULL;
    tls_free(tls);
  }
}


IOResult tls_backend_read(struct Client *cptr, char *buf, unsigned int length,
                          unsigned int *count_out, enum ircd_tls_want *want)
{
  struct tls *tls;
  ssize_t res;

  *count_out = 0;
  *want = IRCD_TLS_WANT_NONE;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return IO_FAILURE;

  res = tls_read(tls, buf, length);
  if (res > 0)
  {
    *count_out = (unsigned int)res;
    return IO_SUCCESS;
  }
  if (res == TLS_WANT_POLLIN)
  {
    *want = IRCD_TLS_WANT_READ;
    return IO_BLOCKED;
  }
  if (res == TLS_WANT_POLLOUT)
  {
    *want = IRCD_TLS_WANT_WRITE;
    return IO_BLOCKED;
  }
  return IO_FAILURE;  /* core (tls_io_fatal) drops the session */
}

IOResult tls_backend_write(struct Client *cptr, const char *buf,
                           unsigned int len, unsigned int *written,
                           enum ircd_tls_want *want)
{
  struct tls *tls;
  ssize_t res;

  *written = 0;
  *want = IRCD_TLS_WANT_NONE;

  tls = s_tls(&cli_socket(cptr));
  if (!tls)
    return IO_FAILURE;

  res = tls_write(tls, buf, len);
  if (res > 0)
  {
    *written = (unsigned int)res;
    return IO_SUCCESS;
  }
  if (res == TLS_WANT_POLLIN)
  {
    *want = IRCD_TLS_WANT_READ;
    return IO_BLOCKED;
  }
  if (res == TLS_WANT_POLLOUT)
  {
    *want = IRCD_TLS_WANT_WRITE;
    return IO_BLOCKED;
  }
  return IO_FAILURE;  /* core (tls_io_fatal) drops the session */
}


int ircd_tls_sha1_base64(const void *data, size_t len, char *out, size_t outlen)
{
  return ircd_sha1_base64(data, len, out, outlen);
}
