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
#include <unistd.h> /* for write() */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "client.h"
#include "class.h"
#include "ircd.h"
#include "s_debug.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msgq.h"
#include "packet.h"  /* for client_dopacket */
#include "parse.h"  /* for parse_client() */
#include "numeric.h"
#include "s_misc.h"
#include "s_user.h"  /* for SetClient, SetUser */

/*
 * Outbound text frames: IRC lines from msgq are UTF-8–sanitized before framing.
 * sanitize_utf8() may replace each invalid input byte with U+FFFD (EF BF BD), 3 octets.
 *
 * Input length is bounded by the normal msgq line size (BUFSIZE, see ircd_defs.h): formatted
 * lines use ircd_vsnprintf into a BUFSIZE-class MsgBuf. We use (BUFSIZE + 2) rather than
 * (BUFSIZE - 1) so the cap stays safely above any CRLF-stripped payload edge case.
 *
 * WS_FRAME_BUF_MAX: largest stack buffer for one wire frame = UTF-8 payload plus RFC 6455
 * header (2 bytes for len < 126, else 4 for 16-bit length). "+10" leaves slack beyond 4.
 */
#define WS_UTF8_OUT_MAX   (((BUFSIZE) + 2) * 3)
#define WS_FRAME_BUF_MAX  (10 + WS_UTF8_OUT_MAX)

/* Accept GUID for WebSocket per RFC 6455 */
static const char websocket_guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/* Forward declaration */
static int websocket_send_handshake(struct Client *cptr, const char *accept_key, const char *subprotocol);

/* Compute Sec-WebSocket-Accept from Sec-WebSocket-Key (RFC 6455):
 * concatenate key + GUID, SHA1, base64; OpenSSL SHA1 + BIO base64.
 * Returns 0 on success, -1 on failure.
 */
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

int websocket_base64_sha1(const char *key, char *out, size_t outlen) {
    char input[256];
    unsigned char sha1[SHA_DIGEST_LENGTH];
    int input_len;
    BIO *bmem = NULL, *b64 = NULL;
    BUF_MEM *bptr = NULL;
    if (!key || !out) return -1;
    input_len = snprintf(input, sizeof(input), "%s%s", key, websocket_guid);
    if (input_len <= 0 || input_len >= (int)sizeof(input)) return -1;
    SHA1((unsigned char*)input, input_len, sha1);
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, sha1, SHA_DIGEST_LENGTH);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    if (bptr && bptr->length < outlen) {
        memcpy(out, bptr->data, bptr->length);
        out[bptr->length] = '\0';
    } else {
        BIO_free_all(b64);
        return -1;
    }
    BIO_free_all(b64);
    return 0;
}

/* Parse HTTP headers, perform handshake, and transition client to IRC over WebSocket. */
int websocket_handshake_handler(struct Client *cptr) {
    struct Connection *con = cli_connect(cptr);
    char *buf = con->con_ws_handshake;
    size_t buflen = con->con_ws_handshake_len;
    char sec_ws_key[128] = "";
    char subprotocols[256] = "";
    char chosen_subprotocol[64] = "";
    char accept_key[128];
    int has_upgrade = 0, has_connection = 0, has_key = 0;
    char *line, *saveptr;

    /* Only process if we have a full HTTP header (ends with \r\n\r\n) */
    if (buflen < 4 || strstr(buf, "\r\n\r\n") == NULL) {
        Debug((DEBUG_DEBUG, "Waiting for full HTTP header from %C", cptr));
        Debug((DEBUG_DEBUG, "Current handshake buffer: %s", buf));
        return 1; /* Wait for more data */
    }

    /* Parse headers */
    char header_copy[WEBSOCKET_MAX_HEADER + 1];
    strncpy(header_copy, buf, buflen);
    header_copy[buflen] = '\0';
    for (line = strtok_r(header_copy, "\r\n", &saveptr); line; line = strtok_r(NULL, "\r\n", &saveptr)) {
        if (strncasecmp(line, "Upgrade: WebSocket", 17) == 0)
            has_upgrade = 1;
        else if (strncasecmp(line, "Connection: Upgrade", 19) == 0)
            has_connection = 1;
        else if (strncasecmp(line, "Sec-WebSocket-Key:", 18) == 0) {
            strncpy(sec_ws_key, line + 19, sizeof(sec_ws_key) - 1);
            sec_ws_key[sizeof(sec_ws_key) - 1] = '\0';
        } else if (strncasecmp(line, "Sec-WebSocket-Protocol:", 23) == 0) {
            strncpy(subprotocols, line + 24, sizeof(subprotocols) - 1);
            subprotocols[sizeof(subprotocols) - 1] = '\0';
        }
    }
    if (has_upgrade && has_connection && sec_ws_key[0])
        has_key = 1;
    if (!has_key) {
        Debug((DEBUG_DEBUG, "WebSocket handshake failed for %C", cptr));
        return 0; /* Fail handshake */
    }

    /* Negotiate subprotocol: respect client order of preference */
    cli_ws_mode(cptr) = WS_TEXT; /* default */
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
                cli_ws_mode(cptr) = WS_BINARY;
                break;
            } else if (strcmp(tok, "text.ircv3.net") == 0) {
                strncpy(chosen_subprotocol, "text.ircv3.net", sizeof(chosen_subprotocol) - 1);
                cli_ws_mode(cptr) = WS_TEXT;
                break;
            }
        }
    }

    /* Compute Sec-WebSocket-Accept */
    if (websocket_base64_sha1(sec_ws_key, accept_key, sizeof(accept_key)) != 0)
        return 0;

    /* Send handshake response */
    if (websocket_send_handshake(cptr, accept_key, chosen_subprotocol) != 0)
        return 0;

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
    if (write(cli_fd(cptr), response, len) != len)
        return -1;
    return 0;
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

/*
 * Parse one WebSocket frame; payload (text/binary) is pushed into recvQ for line reassembly.
 * Return value: >0 bytes consumed from buf, 0 if more data needed, <0 on dbuf_put failure.
 */
int websocket_parse_frame(struct Client *cptr, const char *buf, size_t buflen) {
    if (buflen < 2) return 0; /* need frame header */

    unsigned char opcode = buf[0] & 0x0F;
    unsigned char mask = buf[1] & 0x80;
    size_t payload_len = buf[1] & 0x7F;
    size_t header_len = 2;
    size_t i;
    unsigned char masking_key[4];

    if (payload_len == 126) {
        if (buflen < 4) return 0;
        payload_len = (buf[2] << 8) | buf[3];
        header_len = 4;
    } else if (payload_len == 127) {
        if (buflen < 10) return 0;
        // Only support up to 32-bit length for simplicity
        payload_len = (buf[6] << 24) | (buf[7] << 16) | (buf[8] << 8) | buf[9];
        header_len = 10;
    }
    if (mask) {
        if (buflen < header_len + 4) return 0;
        memcpy(masking_key, buf + header_len, 4);
        header_len += 4;
    }
    if (buflen < header_len + payload_len) return 0;

    // Only handle text (0x1) and binary (0x2) frames
    if (opcode != 0x1 && opcode != 0x2) {
        // For now, ignore other opcodes (ping/pong/close)
        return header_len + payload_len; // skip this frame
    }

    char irc_line[513];
    size_t copy_len = payload_len < sizeof(irc_line) - 1 ? payload_len : sizeof(irc_line) - 1;
    for (i = 0; i < copy_len; ++i) {
        unsigned char c = buf[header_len + i];
        if (mask) c ^= masking_key[i % 4];
        irc_line[i] = c;
    }
    irc_line[copy_len] = '\0';

    if (dbuf_put(&(cli_recvQ(cptr)), irc_line, copy_len) == 0)
        return -1; /* Buffer error */

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
