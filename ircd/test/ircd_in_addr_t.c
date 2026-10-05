/* ircd_in_addr_t.c - Test file for IP address manipulation */

#include "ircd_log.h"
#include "ircd_string.h"
#include "numnicks.h"
#include "res.h"
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

/** Structure to describe a test for IP address parsing and unparsing. */
struct address_test {
    const char *text; /**< Textual address to parse. */
    const char *canonical; /**< Canonical form of address. */
    struct irc_in_addr expected; /**< Parsed address. */
    const char *base64_v4; /**< v4-only compatible base64 encoding. */
    const char *base64_v6; /**< v6-compatible base64 encoding. */
    unsigned int is_valid : 1; /**< is address valid? */
    unsigned int is_ipv4 : 1; /**< is address ipv4? */
    unsigned int is_loopback : 1; /**< is address loopback? */
};

/** Array of addresses to test with. */
static struct address_test test_addrs[] = {
    { "::", "0::",
      {{ 0, 0, 0, 0, 0, 0, 0, 0 }},
      "AAAAAA", "_", 0, 0, 0 },
    { "::1", "0::1",
      {{ 0, 0, 0, 0, 0, 0, 0, 1 }},
      "AAAAAA", "_AAB", 1, 0, 1 },
    { "127.0.0.1", "127.0.0.1",
      {{ 0, 0, 0, 0, 0, 0xffff, 0x7f00, 1 }},
      "B]AAAB", "B]AAAB", 1, 1, 1 },
    { "::ffff:127.0.0.3", "127.0.0.3",
      {{ 0, 0, 0, 0, 0, 0xffff, 0x7f00, 3 }},
      "B]AAAD", "B]AAAD", 1, 1, 1 },
    { "::127.0.0.1", "127.0.0.1",
      {{ 0, 0, 0, 0, 0, 0, 0x7f00, 1 }},
      "B]AAAB", "B]AAAB", 1, 1, 1 },
    { "2002:7f00:3::1", "2002:7f00:3::1",
      {{ 0x2002, 0x7f00, 3, 0, 0, 0, 0, 1 }},
      "B]AAAD", "CACH8AAAD_AAB", 1, 0, 0 },
    { "8352:0344:0:0:0:0:2001:1204", "8352:344::2001:1204",
      {{ 0x8352, 0x344, 0, 0, 0, 0, 0x2001, 0x1204 }},
      "AAAAAA", "INSANE_CABBIE", 1, 0, 0 },
    { "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8",
      {{ 1, 2, 3, 4, 5, 6, 7, 8 }},
      "AAAAAA", "AABAACAADAAEAAFAAGAAHAAI", 1, 0, 0 },
    { "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
      "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
      {{ 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535 }},
      "AAAAAA", "P]]P]]P]]P]]P]]P]]P]]P]]", 0, 0, 0 },
    { 0 },
};

/** Perform tests for a single IP address.
 * @param[in] addr Address test structure.
 */
static void
test_address(struct address_test *addr)
{
    struct irc_in_addr parsed;
    unsigned int ii, len, val;
    char unparsed[64], base64_v4[64], base64_v6[64];

    /* Convert expected address to network order. */
    for (ii = 0; ii < 8; ++ii)
        addr->expected.in6_16[ii] = htons(addr->expected.in6_16[ii]);
    /* Make sure the text form is parsed as expected. */
    len = ircd_aton(&parsed, addr->text);
    assert(len == strlen(addr->text));
    assert(!irc_in_addr_cmp(&parsed, &addr->expected));
    /* Make sure it converts back to ASCII. */
    ircd_ntoa_r(unparsed, &parsed);
    assert(!strcmp(unparsed, addr->canonical));
    /* Check IP-to-base64 conversion. */
    iptobase64(base64_v4, &parsed, sizeof(base64_v4), 0);
    iptobase64(base64_v6, &parsed, sizeof(base64_v6), 1);
    if (addr->base64_v4)
        assert(!strcmp(base64_v4, addr->base64_v4));
    if (addr->base64_v6)
        assert(!strcmp(base64_v6, addr->base64_v6));
    /* Check testable attributes. */
    val = irc_in_addr_valid(&parsed);
    assert(!!val == addr->is_valid);
    val = irc_in_addr_is_ipv4(&parsed);
    assert(!!val == addr->is_ipv4);
    val = irc_in_addr_is_loopback(&parsed);
    assert(!!val == addr->is_loopback);
    /* Check base64-to-IP conversion. */
    if (addr->is_ipv4) {
        base64toip(addr->base64_v4, &parsed);
        assert(!memcmp(parsed.in6_16+6, addr->expected.in6_16+6, 4));
    } else {
        base64toip(addr->base64_v6, &parsed);
        assert(!memcmp(&parsed, &addr->expected, sizeof(parsed)));
    }
    /* Tests completed. */
    printf("Passed: %s (%s/%s)\n", addr->text, base64_v4, base64_v6);
}

/** Structure to describe a test for IP mask parsing. */
struct ipmask_test {
    const char *text; /**< Textual IP mask to parse. */
    struct irc_in_addr expected; /**< Canonical form of address. */
    unsigned int is_ipmask : 1; /**< Parse as an ipmask? */
    unsigned int is_parseable : 1; /**< Is address parseable? */
    unsigned int exp_bits : 8; /**< Number of bits expected in netmask */
};

/** Array of ipmasks to test with. */
static struct ipmask_test test_masks[] = {
    { "::", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 128 },
    { "::/0", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 0 },
    { "::10.0.0.0", {{ 0, 0, 0, 0, 0, 0, 0xa00, 0 }}, 1, 1, 128 },
    { "192.168/16", {{ 0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0 }}, 1, 1, 112 },
    { "192.*", {{ 0, 0, 0, 0, 0, 0xffff, 0xc000, 0 }}, 1, 1, 104 },
    { "192.*.*.*", {{ 0, 0, 0, 0, 0, 0xffff, 0xc000, 0 }}, 1, 1, 104 },
    { "192.*/8", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "192*", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "192.168.0.0/16", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 0, 0, 0 },
    { "ab.*", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "a*", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "*", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 0 },
    { "a:b", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "a::*", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "a:*", {{ 0xa, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 16 },
    { "a:*:*", {{ 0xa, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 16 },
    { "a:/16", {{ 0xa, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 16 },
    { "0.0.0.0.0/1", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 0, 0, 0 },
    { "2607:3f00:1:30c:9999*",
      {{ 0x2607, 0x3f00, 1, 0x30c, 0x9999, 0, 0, 0 }}, 1, 1, 80 },
    { "1234:5678:9abc:def0:feed:abba:cabb:1e55::",
      {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { 0 }
};

/** Perform tests for a single IP mask.
 * @param[in] mask IP mask test structure.
 */
static void
test_ipmask(struct ipmask_test *mask)
{
    struct irc_in_addr parsed;
    unsigned int len, ii;
    unsigned char bits = 0;

    /* Convert expected address to network order. */
    for (ii = 0; ii < 8; ++ii)
        mask->expected.in6_16[ii] = htons(mask->expected.in6_16[ii]);
    /* Try to parse; make sure its parseability and netmask length are
     * as expected. */
    len = ipmask_parse(mask->text, &parsed, mask->is_ipmask ? &bits : 0);
    assert(!!len == mask->is_parseable);
    if (!len) {
        printf("X-Fail: %s\n", mask->text);
        return;
    }
    if (mask->is_ipmask)
        assert(bits == mask->exp_bits);
    assert(!memcmp(&parsed, &mask->expected, sizeof(parsed)));
    printf("Passed: %s (%s/%u)\n", mask->text, ircd_ntoa(&parsed), bits);
}

/** Guarded destination for base64toip(): the 16-byte address is
 * followed by a canary region so that any write past the end of the
 * structure is detected rather than silently corrupting memory. */
struct guarded_addr {
    struct irc_in_addr addr;      /**< The real 16-byte destination. */
    unsigned short canary[16];    /**< Trailing guard words. */
};

/** Decode @a input into a guarded address and confirm nothing was
 * written past the 16-byte structure.
 * @param[in] label Human-readable description of the case.
 * @param[in] input base64 IP field to decode.
 * @param[out] out Receives the decoded address (may be NULL).
 */
static void
decode_guarded(const char *label, const char *input, struct irc_in_addr *out)
{
    struct guarded_addr g;
    unsigned int ii;

    for (ii = 0; ii < 16; ++ii)
        g.canary[ii] = 0xdead;

    /* If base64toip() runs off the end of g.addr it will either trip a
     * canary here or walk into unmapped memory and crash; either way the
     * test fails rather than passing silently. */
    base64toip(input, &g.addr);

    for (ii = 0; ii < 16; ++ii)
        assert(g.canary[ii] == 0xdead);

    if (out)
        *out = g.addr;
    printf("Passed: robustness [%s]\n", label);
}

/** Exercise base64toip() with malformed and boundary input. */
static void
test_base64_robustness(void)
{
    struct irc_in_addr addr;
    struct irc_in_addr zero;
    char buf[64];
    unsigned int ii;

    memset(&zero, 0, sizeof(zero));

    /* Case 1: overlong field beginning with '_'. On unpatched code the
     * unsigned subtraction (25 - strlen) underflows and the loop tries to
     * write ~1.4 billion words. Must not crash, must leave the address
     * zeroed. */
    memset(buf, 'A', sizeof(buf));
    buf[0] = '_';
    buf[31] = '\0';                 /* remainder length 31 (>= 26) */
    decode_guarded("underflow: '_' + long tail", buf, &addr);
    assert(!memcmp(&addr, &zero, sizeof(addr)));

    /* Case 2: valid groups first, so pos > 0 when the '_' underflow is
     * computed, then an overlong compressed tail. */
    memset(buf, 'A', sizeof(buf));
    buf[2] = 'B';                   /* "AAB" -> one decoded word */
    buf[3] = '_';
    buf[31] = '\0';                 /* remainder at '_' length 28 */
    decode_guarded("underflow: groups then long '_' tail", buf, &addr);

    /* Case 3: two-character field. Unpatched code reads past the NUL and
     * assembles adjacent bytes into the address (information leak). The
     * poison bytes after the terminator must not influence the result. */
    memset(buf, 'B', sizeof(buf));  /* 'B' decodes to a non-zero nibble */
    buf[0] = 'A';
    buf[1] = 'B';
    buf[2] = '\0';                  /* real input is just "AB" */
    decode_guarded("short field: 'AB' + poison", buf, &addr);
    assert(!memcmp(&addr, &zero, sizeof(addr)));

    /* Case 4: round-trip every address iptobase64() can emit, including
     * '_' compression at the start, middle and end, must decode back
     * identically through the hardened function. A 6-character encoding is
     * the IPv4 form, which by design normalises to a ::ffff: mapped address,
     * so for that form compare only the low 32 bits, exactly as the address
     * parsing tests above do. */
    for (ii = 0; test_addrs[ii].text; ++ii) {
        struct irc_in_addr parsed, rt;
        ircd_aton(&parsed, test_addrs[ii].text);
        iptobase64(buf, &parsed, sizeof(buf), 1);
        decode_guarded(test_addrs[ii].text, buf, &rt);
        if (strlen(buf) == 6)
            assert(!memcmp(rt.in6_16 + 6, parsed.in6_16 + 6, 4));
        else
            assert(!memcmp(&rt, &parsed, sizeof(rt)));
    }

    /* Case 5: a 24-character encoding with no '_' is the maximum legal
     * length and must still decode. */
    {
        struct irc_in_addr parsed, rt;
        ircd_aton(&parsed, "1:2:3:4:5:6:7:8");
        iptobase64(buf, &parsed, sizeof(buf), 1);
        assert(strlen(buf) == 24);
        decode_guarded("max-length 24-char encoding", buf, &rt);
        assert(!memcmp(&rt, &parsed, sizeof(rt)));
    }

    printf("Robustness tests completed.\n");
}

int
main(int argc, char *argv[])
{
    unsigned int ii;

    printf("Testing address parsing..\n");
    for (ii = 0; test_addrs[ii].text; ++ii)
        test_address(&test_addrs[ii]);

    printf("\nTesting ipmask parsing..\n");
    for (ii = 0; test_masks[ii].text; ++ii)
        test_ipmask(&test_masks[ii]);

    printf("\nTesting base64toip robustness..\n");
    test_base64_robustness();

    return 0;
}
