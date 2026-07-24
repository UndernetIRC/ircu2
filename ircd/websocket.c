/*
 * IRC - Internet Relay Chat, ircd/websocket.c
 * Copyright (C) 2026 MrIron <mriron@undernet.org>
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "client.h"
#include "class.h"
#include "ircd.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "IPcheck.h"
#include "listener.h"
#include "s_debug.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msgq.h"
#include "packet.h"  /* for client_dopacket */
#include "parse.h"  /* for parse_client() */
#include "numeric.h"
#include "s_misc.h"
#include "s_user.h"  /* for SetClient, SetUser */
#include "ircd_tls.h"
#include "ircd_osdep.h"
#include "send.h"

/*
 * Outbound text frames: IRC lines from msgq are UTF-8–sanitized before framing.
 * sanitize_utf8() may replace each invalid input byte with U+FFFD (EF BF BD), 3 octets.
 *
 * WS_LINE_MAX bounds one outbound wire line: a message body (BUFSIZE) plus an
 * optional IRCv3 message-tags prefix (OUTBOUND_TAG_MAX, see ircd_defs.h).
 * make_wire_msgbuf() never queues a longer line.  The "+2" keeps the cap
 * safely above any CRLF-stripped payload edge case, and "*3" covers the
 * worst-case U+FFFD expansion.
 *
 * WS_FRAME_BUF_MAX: largest stack buffer for one wire frame = UTF-8 payload plus RFC 6455
 * header (2 bytes for len < 126, else 4 for 16-bit length). "+10" leaves slack beyond 4.
 */
#define WS_LINE_MAX       ((OUTBOUND_TAG_MAX) + (BUFSIZE))
#define WS_UTF8_OUT_MAX   ((WS_LINE_MAX + 2) * 3)
#define WS_FRAME_BUF_MAX  (10 + WS_UTF8_OUT_MAX)

/* Accept GUID for WebSocket per RFC 6455 */
static const char websocket_guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/* Forward declaration */
static int websocket_send_handshake(struct Client *cptr, const char *accept_key, const char *subprotocol);
static void trim_http_field(char *str);
static int websocket_apply_client_ip(struct Client *cptr, const char *ip);

/** Write raw octets to a WebSocket client (TLS-aware, no IRC/WS framing). */
static int websocket_write_raw(struct Client *cptr, const void *data, size_t len)
{
  struct MsgBuf *mb;
  unsigned int count;

  if (!cptr || len == 0 || len > UINT_MAX)
    return -1;
  if (IsNegotiatingTLS(cptr))
    return -1;

  if (IsTLS(cptr) && s_tls(&cli_socket(cptr))) {
    mb = msgq_raw_alloc(cptr, (unsigned int)len);
    if (!mb)
      return -1;
    memcpy(mb->msg, data, len);
    mb->length = (unsigned int)len;
    send_raw_buffer(cptr, mb, 0);
    msgq_clean(mb);
    if (IsDead(cptr))
      return -1;
    return 0;
  }

  if (os_send_nonb(cli_fd(cptr), data, (unsigned int)len, &count) != IO_SUCCESS
      || count != len)
    return -1;
  return 0;
}

/** Send a minimal HTTP 400 response for a failed WebSocket handshake, so a
 * plain HTTP client sees an error instead of a bare connection drop. */
int websocket_send_http_error(struct Client *cptr)
{
  static const char resp[] =
    "HTTP/1.1 400 Bad Request\r\n"
    "Connection: close\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

  return websocket_write_raw(cptr, resp, sizeof(resp) - 1);
}

/** Trim leading/trailing whitespace from an HTTP header field value. */
static void trim_http_field(char *str)
{
  char *start = str;
  char *end;

  while (*start == ' ' || *start == '\t')
    ++start;
  if (start != str)
    memmove(str, start, strlen(start) + 1);
  end = str + strlen(str);
  while (end > str && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
    --end;
  *end = '\0';
}

/** Case-insensitive test for whether \a token appears anywhere in \a value.
 * Used so header values that are comma lists (e.g. "keep-alive, Upgrade") or
 * differ in case still match the required token. */
static int header_has_token(const char *value, const char *token)
{
  size_t tlen = strlen(token);
  const char *p;

  for (p = value; *p; ++p)
    if (strncasecmp(p, token, tlen) == 0)
      return 1;
  return 0;
}

/** Check a handshake Origin against FEAT_WEBSOCKET_ALLOWED_ORIGINS.
 * Returns 1 if allowed. When the feature is unset (empty) all origins are
 * allowed (default, unchanged behavior); when set, the client's Origin must
 * match one of the space/comma-separated entries. */
static int websocket_origin_allowed(const char *origin)
{
  const char *list = feature_str(FEAT_WEBSOCKET_ALLOWED_ORIGINS);
  char buf[512];
  char *tok, *save;

  if (!list || !*list)
    return 1;                 /* no allowlist configured */
  if (!origin || !*origin)
    return 0;                 /* allowlist set but no Origin supplied */

  ircd_strncpy(buf, list, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  for (tok = strtok_r(buf, " ,", &save); tok; tok = strtok_r(NULL, " ,", &save))
    if (strcasecmp(tok, origin) == 0)
      return 1;
  return 0;
}

/** Replace a client's sock IP after verifying it parses and passes IPcheck. */
static int websocket_apply_client_ip(struct Client *cptr, const char *ip)
{
  struct irc_in_addr addr;
  time_t next_target = 0;

  if (!ip || !*ip || !ipmask_parse(ip, &addr, NULL))
    return 0;

  if (IsIPChecked(cptr))
    IPcheck_connect_fail(cptr, 0);

  if (!IPcheck_local_connect(&addr, &next_target)) {
    ++ServerStats->is_throttled;
    return 0;
  }
  SetIPChecked(cptr);

  memcpy(&cli_ip(cptr), &addr, sizeof(cli_ip(cptr)));
  ircd_ntoa_r(cli_sock_ip(cptr), &cli_ip(cptr));
  ircd_strncpy(cli_sockhost(cptr), cli_sock_ip(cptr), HOSTLEN);
  if (next_target)
    cli_nexttarget(cptr) = next_target;
  return 1;
}

/* Parse HTTP headers, perform handshake, and transition client to IRC over WebSocket. */
int websocket_handshake_handler(struct Client *cptr) {
    struct Connection *con = cli_connect(cptr);
    char *buf = con->con_ws_handshake;
    size_t buflen = con->con_ws_handshake_len;
    char sec_ws_key[128] = "";
    char sec_ws_version[16] = "";
    char origin[256] = "";
    char subprotocols[256] = "";
    char chosen_subprotocol[64] = "";
    char accept_key[128];
    char cf_connecting_ip[SOCKIPLEN + 1] = "";
    int has_upgrade = 0, has_connection = 0, has_key = 0;
    int trust_cloudflare = 0;
    char *line, *saveptr;

    if (IsCloudflarePort(cptr))
      trust_cloudflare = 1;

    /* Only process if we have a full HTTP header (ends with \r\n\r\n) */
    if (buflen < 4 || strstr(buf, "\r\n\r\n") == NULL) {
        Debug((DEBUG_DEBUG, "Waiting for full HTTP header from %C", cptr));
        Debug((DEBUG_DEBUG, "Current handshake buffer: %s", buf));
        return 1; /* Wait for more data */
    }

    /* Parse headers */
    char header_copy[WEBSOCKET_HANDSHAKE_MAX + 1];
    strncpy(header_copy, buf, buflen);
    header_copy[buflen] = '\0';
    for (line = strtok_r(header_copy, "\r\n", &saveptr); line; line = strtok_r(NULL, "\r\n", &saveptr)) {
        /* Header values may vary in case and be comma lists (e.g.
         * "Connection: keep-alive, Upgrade"), so match by token, not prefix. */
        if (strncasecmp(line, "Upgrade:", 8) == 0)
            has_upgrade = header_has_token(line + 8, "websocket");
        else if (strncasecmp(line, "Connection:", 11) == 0)
            has_connection = header_has_token(line + 11, "upgrade");
        else if (strncasecmp(line, "Sec-WebSocket-Version:", 22) == 0) {
            strncpy(sec_ws_version, line + 22, sizeof(sec_ws_version) - 1);
            sec_ws_version[sizeof(sec_ws_version) - 1] = '\0';
            trim_http_field(sec_ws_version);
        } else if (strncasecmp(line, "Origin:", 7) == 0) {
            strncpy(origin, line + 7, sizeof(origin) - 1);
            origin[sizeof(origin) - 1] = '\0';
            trim_http_field(origin);
        } else if (strncasecmp(line, "Sec-WebSocket-Key:", 18) == 0) {
            strncpy(sec_ws_key, line + 18, sizeof(sec_ws_key) - 1);
            sec_ws_key[sizeof(sec_ws_key) - 1] = '\0';
            trim_http_field(sec_ws_key);
        } else if (strncasecmp(line, "Sec-WebSocket-Protocol:", 23) == 0) {
            strncpy(subprotocols, line + 23, sizeof(subprotocols) - 1);
            subprotocols[sizeof(subprotocols) - 1] = '\0';
            trim_http_field(subprotocols);
        } else if (trust_cloudflare
                   && strncasecmp(line, "CF-Connecting-IP:", 17) == 0) {
            strncpy(cf_connecting_ip, line + 17, sizeof(cf_connecting_ip) - 1);
            cf_connecting_ip[sizeof(cf_connecting_ip) - 1] = '\0';
            trim_http_field(cf_connecting_ip);
        }
    }
    if (has_upgrade && has_connection && sec_ws_key[0])
        has_key = 1;
    if (!has_key) {
        Debug((DEBUG_DEBUG, "WebSocket handshake failed for %C", cptr));
        return 0; /* Fail handshake */
    }

    /* RFC 6455: only version 13 is defined. Reject any other stated version
     * (absent version is tolerated for lenient clients). */
    if (sec_ws_version[0] && strcmp(sec_ws_version, "13") != 0) {
        Debug((DEBUG_DEBUG, "Unsupported WebSocket version '%s' for %C",
               sec_ws_version, cptr));
        return 0;
    }

    /* Optional Origin allowlist (FEAT_WEBSOCKET_ALLOWED_ORIGINS). Off by
     * default; when configured, only listed origins may connect. */
    if (!websocket_origin_allowed(origin)) {
        Debug((DEBUG_DEBUG, "WebSocket origin '%s' rejected for %C", origin, cptr));
        return 0;
    }

    if (trust_cloudflare && !websocket_apply_client_ip(cptr, cf_connecting_ip)) {
        Debug((DEBUG_DEBUG, "WebSocket Cloudflare IP rejected for %C", cptr));
        return 0;
    }

    /* Negotiate subprotocol: respect client order of preference */
    enum ws_mode_t negotiated_mode = WS_TEXT;
    chosen_subprotocol[0] = '\0';
    if (subprotocols[0]) {
        char *tok, *saveptr2;
        char subprotos[256];
        strncpy(subprotos, subprotocols, sizeof(subprotos)-1);
        subprotos[sizeof(subprotos)-1] = '\0';
        for (tok = strtok_r(subprotos, ",", &saveptr2); tok; tok = strtok_r(NULL, ",", &saveptr2)) {
            while (*tok == ' ' || *tok == '\t') ++tok; /* skip leading space */
            if (strcmp(tok, "binary.ircv3.net") == 0) {
                strncpy(chosen_subprotocol, "binary.ircv3.net", sizeof(chosen_subprotocol) - 1);
                negotiated_mode = WS_BINARY;
                break;
            } else if (strcmp(tok, "text.ircv3.net") == 0) {
                strncpy(chosen_subprotocol, "text.ircv3.net", sizeof(chosen_subprotocol) - 1);
                negotiated_mode = WS_TEXT;
                break;
            }
        }
    }

    /* Compute Sec-WebSocket-Accept */
    {
        char input[256];
        int input_len = snprintf(input, sizeof(input), "%s%s", sec_ws_key, websocket_guid);
        if (input_len <= 0 || input_len >= (int)sizeof(input))
            return 0;
        if (ircd_tls_sha1_base64(input, input_len, accept_key, sizeof(accept_key)) != 0)
            return 0;
    }

    /* Send handshake response (plain HTTP; WS mode set only after 101 is sent). */
    if (websocket_send_handshake(cptr, accept_key, chosen_subprotocol) != 0)
        return 0;

    cli_ws_mode(cptr) = negotiated_mode;
    return 1;
}

/* Send the HTTP 101 Switching Protocols response */
static int websocket_send_handshake(struct Client *cptr, const char *accept_key, const char *subprotocol) {
    char response[512];
    int len;
    if (subprotocol && *subprotocol) {
        len = snprintf(response, sizeof(response),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "Sec-WebSocket-Protocol: %s\r\n"
            "\r\n",
            accept_key, subprotocol);
    } else {
        len = snprintf(response, sizeof(response),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "\r\n",
            accept_key);
    }
    if (len <= 0 || len >= (int)sizeof(response))
        return -1;
    return websocket_write_raw(cptr, response, (size_t)len);
}

/* Sanitizes input into valid UTF-8.
 * Invalid bytes/sequences are replaced with U+FFFD (EF BF BD).
 * Returns output length.
 */
static size_t
sanitize_utf8(const char *in, size_t inlen, char *out, size_t outsz)
{
    static const unsigned char repl[3] = { 0xEF, 0xBF, 0xBD };
    size_t i = 0, o = 0;

#define PUT_REPL()                                                     \
    do {                                                               \
        if (o + 3 > outsz)                                             \
            return o;                                                  \
        out[o++] = (char)repl[0];                                      \
        out[o++] = (char)repl[1];                                      \
        out[o++] = (char)repl[2];                                      \
    } while (0)

    while (i < inlen) {
        unsigned char c0 = (unsigned char)in[i];

        /* ASCII */
        if (c0 <= 0x7F) {
            if (o + 1 > outsz)
                return o;
            out[o++] = (char)c0;
            i++;
            continue;
        }

        /* 2-byte: C2..DF 80..BF */
        if (c0 >= 0xC2 && c0 <= 0xDF) {
            if (i + 1 < inlen) {
                unsigned char c1 = (unsigned char)in[i + 1];
                if (c1 >= 0x80 && c1 <= 0xBF) {
                    if (o + 2 > outsz)
                        return o;
                    out[o++] = (char)c0;
                    out[o++] = (char)c1;
                    i += 2;
                    continue;
                }
            }
            PUT_REPL();
            i++;
            continue;
        }

        /* 3-byte sequences */
        if (c0 >= 0xE0 && c0 <= 0xEF) {
            if (i + 2 < inlen) {
                unsigned char c1 = (unsigned char)in[i + 1];
                unsigned char c2 = (unsigned char)in[i + 2];
                int ok = 0;

                if (c0 == 0xE0) {
                    ok = (c1 >= 0xA0 && c1 <= 0xBF &&
                          c2 >= 0x80 && c2 <= 0xBF);
                } else if (c0 >= 0xE1 && c0 <= 0xEC) {
                    ok = (c1 >= 0x80 && c1 <= 0xBF &&
                          c2 >= 0x80 && c2 <= 0xBF);
                } else if (c0 == 0xED) {
                    /* avoid UTF-16 surrogates */
                    ok = (c1 >= 0x80 && c1 <= 0x9F &&
                          c2 >= 0x80 && c2 <= 0xBF);
                } else { /* EE..EF */
                    ok = (c1 >= 0x80 && c1 <= 0xBF &&
                          c2 >= 0x80 && c2 <= 0xBF);
                }

                if (ok) {
                    if (o + 3 > outsz)
                        return o;
                    out[o++] = (char)c0;
                    out[o++] = (char)c1;
                    out[o++] = (char)c2;
                    i += 3;
                    continue;
                }
            }
            PUT_REPL();
            i++;
            continue;
        }

        /* 4-byte sequences */
        if (c0 >= 0xF0 && c0 <= 0xF4) {
            if (i + 3 < inlen) {
                unsigned char c1 = (unsigned char)in[i + 1];
                unsigned char c2 = (unsigned char)in[i + 2];
                unsigned char c3 = (unsigned char)in[i + 3];
                int ok = 0;

                if (c0 == 0xF0) {
                    ok = (c1 >= 0x90 && c1 <= 0xBF &&
                          c2 >= 0x80 && c2 <= 0xBF &&
                          c3 >= 0x80 && c3 <= 0xBF);
                } else if (c0 >= 0xF1 && c0 <= 0xF3) {
                    ok = (c1 >= 0x80 && c1 <= 0xBF &&
                          c2 >= 0x80 && c2 <= 0xBF &&
                          c3 >= 0x80 && c3 <= 0xBF);
                } else { /* F4 */
                    ok = (c1 >= 0x80 && c1 <= 0x8F &&
                          c2 >= 0x80 && c2 <= 0xBF &&
                          c3 >= 0x80 && c3 <= 0xBF);
                }

                if (ok) {
                    if (o + 4 > outsz)
                        return o;
                    out[o++] = (char)c0;
                    out[o++] = (char)c1;
                    out[o++] = (char)c2;
                    out[o++] = (char)c3;
                    i += 4;
                    continue;
                }
            }
            PUT_REPL();
            i++;
            continue;
        }

        /* Invalid leading byte: 80..BF, C0..C1, F5..FF */
        PUT_REPL();
        i++;
    }

    return o;

#undef PUT_REPL
}

/** Server→client RFC6455 Ping (empty payload, unmasked). Not IRC PING. */
int websocket_send_keepalive_ping(struct Client *cptr) {
    static const unsigned char frm[2] = { 0x89, 0x00 };

    if (cli_fd(cptr) < 0)
        return -1;
    return websocket_write_raw(cptr, frm, sizeof frm);
}

/** Send an unmasked Close frame (RFC6455 status 1000, normal closure). */
static int websocket_write_close(struct Client *cptr) {
    static const unsigned char frm[4] = { 0x88, 0x02, 0x03, 0xE8 }; /* 1000 */

    if (cli_fd(cptr) < 0)
        return -1;
    return websocket_write_raw(cptr, frm, sizeof frm);
}

/** Send unmasked Pong with same application data as peer's Ping (RFC6455). */
static int websocket_write_pong(struct Client *cptr, const unsigned char *payload, size_t plen) {
    unsigned char out[2 + 125];

    if (plen > 125 || cli_fd(cptr) < 0)
        return -1;
    out[0] = 0x8A;
    out[1] = (unsigned char)plen;
    if (plen)
        memcpy(out + 2, payload, plen);
    return websocket_write_raw(cptr, out, 2 + plen);
}

/*
 * Parse one WebSocket frame; payload (text/binary/continuation) is pushed into
 * recvQ for line reassembly. On the final fragment (FIN set) a newline is
 * appended so recvQ holds a complete IRC line; fragmented messages (FIN=0
 * followed by continuation frames) accumulate until the final fragment.
 * Return value: >0 bytes consumed from buf, 0 if more data needed, <0 on dbuf_put failure.
 */
int websocket_parse_frame(struct Client *cptr, const char *buf, size_t buflen) {
    if (buflen < 2) return 0; /* need frame header */

    unsigned char fin = (buf[0] & 0x80) ? 1 : 0;
    unsigned char opcode = buf[0] & 0x0F;
    unsigned char mask = buf[1] & 0x80;
    size_t payload_len = buf[1] & 0x7F;
    size_t header_len = 2;
    size_t i;
    unsigned char masking_key[4];

    /* RFC 6455 5.1: every client-to-server frame MUST be masked. An unmasked
     * frame is a protocol error; fail the connection rather than mis-parsing it
     * (previously unmasked payloads were read verbatim as IRC input). */
    if (!mask)
        return -2;

    if (payload_len == 126) {
        if (buflen < 4) return 0;
        /* Cast each length byte to unsigned char before shifting: buf is
         * signed char, so a byte >= 0x80 would otherwise sign-extend and
         * corrupt the length. */
        payload_len = ((size_t)(unsigned char)buf[2] << 8)
                    | (size_t)(unsigned char)buf[3];
        header_len = 4;
    } else if (payload_len == 127) {
        if (buflen < 10) return 0;
        /* Only support up to 32-bit length for simplicity (buf[2..5] ignored);
         * cast to unsigned char before shifting to avoid sign extension. */
        payload_len = ((size_t)(unsigned char)buf[6] << 24)
                    | ((size_t)(unsigned char)buf[7] << 16)
                    | ((size_t)(unsigned char)buf[8] << 8)
                    | (size_t)(unsigned char)buf[9];
        header_len = 10;
    }
    if (mask) {
        if (buflen < header_len + 4) return 0;
        memcpy(masking_key, buf + header_len, 4);
        header_len += 4;
    }
    /* Control frames (RFC6455): must arrive whole (payload <= 125). */
    if (opcode & 0x08) {
        if (buflen < header_len + payload_len) return 0;
        if (payload_len > 125)
            return header_len + payload_len;
        if (opcode == 0x8) {
            /* Close: echo a Close frame and signal the caller to shut down. */
            (void)websocket_write_close(cptr);
            return -3;
        }
        if (opcode == 0x9) {
            unsigned char udata[125];
            for (i = 0; i < payload_len; ++i)
                udata[i] = (unsigned char)buf[header_len + i] ^ masking_key[i % 4];
            (void)websocket_write_pong(cptr, udata, payload_len);
        }
        /* Pong (0xA) and other control frames are simply consumed. */
        return header_len + payload_len;
    }

    /* Reserved non-control opcodes: skip the whole (fully-present) frame. */
    if (opcode != 0x0 && opcode != 0x1 && opcode != 0x2) {
        if (buflen < header_len + payload_len) return 0;
        return header_len + payload_len;
    }

    /* Data (0x1 text, 0x2 binary) and continuation (0x0) frames carry payload.
     * Continuation frames belong to a message started by an earlier FIN=0 frame;
     * their bytes simply append to recvQ, so no start-frame state is needed.
     *
     * IRC lines are bounded, so we only ever deliver the first line's worth of
     * octets; the rest of an oversized frame is drained by the caller (which
     * uses the returned full frame length). This means only header + up to one
     * line need be buffered, not the whole frame. */
    {
        char irc_line[READBUFSIZE + 1];
        size_t deliver = payload_len < sizeof(irc_line) - 1
                       ? payload_len : sizeof(irc_line) - 1;

        if (buflen < header_len + deliver)
            return 0; /* wait until header + deliverable prefix is present */

        for (i = 0; i < deliver; ++i)
            irc_line[i] = (char)((unsigned char)buf[header_len + i]
                                 ^ masking_key[i % 4]);
        irc_line[deliver] = '\0';

        if (dbuf_put(&(cli_recvQ(cptr)), irc_line, deliver) == 0)
            return -1; /* Buffer error */

        /* Terminate the IRC line on the final fragment; continuation frames
         * (FIN=0) keep accumulating in recvQ until then. */
        if (fin && dbuf_put(&(cli_recvQ(cptr)), "\n", 1) == 0)
            return -1;
    }

    return header_len + payload_len;
}

/*
 * Build one RFC 6455 server→client data frame for an IRC line queued via send_buffer().
 *
 * @param cptr   Destination client (must be WebSocket); mode selects text (UTF-8 sanitize) vs binary.
 * @param line   Raw line bytes (typically from msgq_make); may include trailing CRLF, which is stripped.
 * @param linelen Length of line in bytes.
 *
 * Text mode replaces invalid UTF-8 with U+FFFD before framing; binary mode copies octets as-is.
 * The frame is unmasked (server frames do not use a mask). Length uses the 7-bit/16-bit forms only
 * (payload < 64 KiB); larger logical messages return NULL.
 *
 * @return New MsgBuf holding the wire frame (length = full frame size), or NULL on error.
 *         The caller must not msgq_clean the original msgq_make buffer here; send_buffer() queues
 *         this buffer via msgq_add() and the sendq path frees it after send.
 */
struct MsgBuf *websocket_frame_msgbuf(struct Client *cptr, const char *line, size_t linelen) {
    unsigned char frame[WS_FRAME_BUF_MAX];
    char utf8buf[WS_UTF8_OUT_MAX];
    size_t framelen = 0;
    int is_binary = (cli_ws_mode(cptr) == WS_BINARY);

    if (linelen == 0)
        return NULL;

    /* Strip trailing \r\n if present (msgq lines include them) */
    while (linelen >= 2 && line[linelen - 2] == '\r' && line[linelen - 1] == '\n') {
        linelen -= 2;
    }

    const char *sendbuf = line;
    size_t sendlen = linelen;

    if (!is_binary) {
        sendlen = sanitize_utf8(line, linelen, utf8buf, sizeof(utf8buf));
        sendbuf = utf8buf;
    }

    frame[0] = 0x80 | (is_binary ? 0x2 : 0x1); /* FIN + opcode */
    if (sendlen < 126) {
        frame[1] = sendlen;
        framelen = 2;
    } else if (sendlen < 65536) {
        frame[1] = 126;
        frame[2] = (sendlen >> 8) & 0xFF;
        frame[3] = sendlen & 0xFF;
        framelen = 4;
    } else {
        /* Too long for a single frame */
        return NULL;
    }
    memcpy(frame + framelen, sendbuf, sendlen);
    framelen += sendlen;

    /* Allocate a MsgBuf for the framed message (binary safe; not msgq_make CRLF). */
    struct MsgBuf *mb = msgq_raw_alloc(cptr, framelen);
    if (!mb || framelen > (1U << mb->power)) {
        if (mb) msgq_clean(mb);
        return NULL;
    }
    mb->length = framelen;
    memcpy(mb->msg, frame, framelen);
    return mb;
}
