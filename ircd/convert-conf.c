/* convert-conf.c - Convert ircu2.10.11 ircd.conf to ircu2.10.12 format.
 * Copyright 2005 Michael Poole
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 */

#include <ctype.h> /* tolower() */
#include <stdio.h> /* *printf(), fgets() */
#include <stdlib.h> /* free(), strtol() */
#include <string.h> /* strlen(), memcpy(), strchr(), strspn() */

#define MAX_FIELDS 5

const char *admin_names[] = { "location", "contact", "contact", 0 },
    *connect_names[] = { "host", "password", "name", "#port", "class", 0 },
    *crule_names[] = { "server", "",  "rule", 0 },
    *general_names[] = { "name", "vhost", "description", "", "#numeric", 0 },
    *motd_names[] = { "host", "file", 0 },
    *class_names[] = { "name", "#pingfreq", "#connectfreq", "#maxlinks", "#sendq", 0 },
    *removed_features[] = { "VIRTUAL_HOST", "TIMESEC", "OPERS_SEE_IN_SECRET_CHANNELS", "LOCOP_SEE_IN_SECRET_CHANNELS", "HIS_STATS_h", "HIS_DESYNCS", "AUTOHIDE", 0 };
char orig_line[512], line[512], dbuf[512];
char *fields[MAX_FIELDS + 1];
unsigned int nfields;
unsigned int lineno;

/*** GENERIC SUPPORT CODE ***/

static int split_line(char *input, char **output)
{
    size_t quoted = 0, jj;
    char *dest = dbuf, ch;

    nfields = 1;
    output[0] = dest;
    while (*input != '\0' && *input != '#') switch (ch = *input++) {
    case ':':
        if (quoted)
            *dest++ = ch;
        else {
            *dest++ = '\0';
            if (nfields >= MAX_FIELDS)
                return nfields;
            output[nfields++] = dest;
        }
        break;
    case '\\':
        switch (ch = *input++) {
        case 'b': *dest++ = '\b'; break;
        case 'f': *dest++ = '\f'; break;
        case 'n': *dest++ = '\n'; break;
        case 'r': *dest++ = '\r'; break;
        case 't': *dest++ = '\t'; break;
        case 'v': *dest++ = '\v'; break;
        default: *dest++ = ch; break;
        }
        break;
    case '"': quoted = !quoted; break;
    default: *dest++ = ch;  break;
    }

    *dest = '\0';
    for (jj = nfields; jj < MAX_FIELDS; ++jj)
        output[jj] = dest;
    return nfields;
}

static void simple_line(const char *block, const char **names, const char *extra)
{
    size_t ii;

    /* Print the current line and start the new block. */
    fprintf(stdout, "# %s\n%s {\n", orig_line, block);

    /* Iterate over fields in input line, formatting each. */
    for (ii = 0; ii < nfields && names[ii]; ++ii) {
        if (!fields[ii][0] || !names[ii][0])
            continue;
        else if (names[ii][0] == '#')
            fprintf(stdout, "\t%s = %s;\n", names[ii] + 1, fields[ii]);
        else
            fprintf(stdout, "\t%s = \"%s\";\n", names[ii], fields[ii]);
    }

    /* Close the new block (including any fixed-form text). */
    if (extra)
        fprintf(stdout, "\t%s\n", extra);
    fputs("};\n", stdout);
}

#define dupstring(TARGET, SOURCE) do { free(TARGET); if (SOURCE) { size_t len = strlen(SOURCE) + 1; (TARGET) = malloc(len); memcpy((TARGET), (SOURCE), len); } else (TARGET) = 0; } while(0)

/*** MANAGING LISTS OF STRINGS ***/

struct string_list {
    struct string_list *next;
    char *origin;
    char *extra;
    char value[1];
};

/** Find or insert the element from \a list that contains \a value.
 * If an element of \a list already contains \a value, return it.
 * Otherwise, append a new element to \a list containing \a value and
 * return it.
 * @param[in,out] list A list of strings.
 * @param[in] value A string to search for.
 * @return A string list element from \a list containing \a value.
 */
static struct string_list *string_get(struct string_list **list, const char *value)
{
    struct string_list *curr;
    size_t len = strlen(value), ii;

    while ((curr = *list)) {
        for (ii = 0; tolower(curr->value[ii]) == tolower(value[ii]) && ii < len; ++ii) ;
        if (curr->value[ii] == '\0' && value[ii] == '\0')
            return curr;
        list = &curr->next;
    }

    *list = calloc(1, sizeof(**list) + len);
    memcpy((*list)->value, value, len);
    return *list;
}

/*** SERVER CONNECTION RELATED CODE ***/

struct connect {
    char *host;
    char *password;
    char *port;
    char *class;
    char *hub;
    char *maximum;
    struct connect *next;
    struct string_list *origins;
    char name[1];
} *connects;

static struct connect *get_connect(const char *name)
{
    struct connect *conn;
    size_t ii, nlen;

    /* Look for a pre-existing connection with the same name. */
    nlen = strlen(name);
    for (conn = connects; conn; conn = conn->next)
    {
        for (ii = 0; tolower(name[ii]) == tolower(conn->name[ii]) && ii < nlen; ++ii) ;
        if (conn->name[ii] == '\0' && name[ii] == '\0')
            break;
    }

    /* If none was found, create a new one. */
    if (!conn)
    {
        conn = calloc(1, sizeof(*conn) + nlen);
        for (ii = 0; ii < nlen; ++ii)
            conn->name[ii] = name[ii];
        conn->next = connects;
        connects = conn;
    }

    /* Return the connection. */
    return conn;
}

static void do_connect(void)
{
    struct connect *conn = get_connect(fields[2]);
    dupstring(conn->host, fields[0]);
    dupstring(conn->password, fields[1]);
    dupstring(conn->port, fields[3]);
    dupstring(conn->class, fields[4]);
    string_get(&conn->origins, orig_line);
}

static void do_hub(void)
{
    struct connect *conn = get_connect(fields[2]);
    dupstring(conn->hub, fields[0]);
    dupstring(conn->maximum, fields[3]);
    string_get(&conn->origins, orig_line);
}

static void do_leaf(void)
{
    struct connect *conn = get_connect(fields[2]);
    free(conn->hub);
    conn->hub = 0;
    string_get(&conn->origins, orig_line);
}

static void finish_connects(void)
{
    struct connect *conn;
    struct string_list *sl;

    for (conn = connects; conn; conn = conn->next)
    {
        for (sl = conn->origins; sl; sl = sl->next)
            fprintf(stdout, "# %s\n", sl->value);
	if (conn->name == NULL
            || conn->host == NULL
            || conn->password == NULL
            || conn->class == NULL)
        {
	    fprintf(stderr, "H:line missing C:line for %s\n",sl->value);
	    continue;
	}

        fprintf(stdout,
                "Connect {\n\tname =\"%s\";\n\thost = \"%s\";\n"
                "\tpassword = \"%s\";\n\tclass = \"%s\";\n",
                conn->name, conn->host, conn->password, conn->class);
        if (conn->port && conn->port[0] != '\0')
            fprintf(stdout, "\tport = %s;\n", conn->port);
        else
            fprintf(stdout,
                    "# Every Connect block should have a port number.\n"
                    "# To prevent autoconnects, set autoconnect = no.\n"
                    "#\tport = 4400;\n"
                    "\tautoconnect = no;\n");
        if (conn->maximum && conn->maximum[0] != '\0')
            fprintf(stdout, "\tmaxhops = %s;\n", conn->maximum);
        if (conn->hub && conn->hub[0] != '\0')
            fprintf(stdout, "\thub = \"%s\";\n", conn->hub);
        fprintf(stdout, "};\n\n");

    }
}

/*** FEATURE MANAGEMENT CODE ***/

struct feature {
    struct string_list *values;
    struct string_list *origins;
    struct feature *next;
    char name[1];
} *features;

struct remapped_feature {
    const char *name;
    const char *privilege;
    int flags; /* 2 = global, 1 = local */
    struct feature *feature;
} remapped_features[] = {
    /* Specially handled privileges: If you change the index of
     * anything with NULL privilege, change the code in
     * finish_operators() to match!
     */
    { "CRYPT_OPER_PASSWORD", NULL, 0, 0 }, /* default: true */
    { "OPER_KILL", NULL, 2, 0 }, /* default: true */
    { "LOCAL_KILL_ONLY", NULL, 2, 0 }, /* default: false */
    /* remapped features that affect all opers  */
    { "OPER_NO_CHAN_LIMIT", "chan_limit", 3, 0 },
    { "OPER_MODE_LCHAN", "mode_lchan", 3, 0 },
    { "OPER_WALK_THROUGH_LMODES", "walk_lchan", 3, 0 },
    { "NO_OPER_DEOP_LCHAN", "deop_lchan", 3, 0 },
    { "SHOW_INVISIBLE_USERS", "show_invis", 3, 0 },
    { "SHOW_ALL_INVISIBLE_USERS", "show_all_invis", 3, 0 },
    { "UNLIMIT_OPER_QUERY", "unlimit_query", 3, 0 },
    /* remapped features affecting only global opers */
    { "OPER_REHASH", "rehash", 2, 0 },
    { "OPER_RESTART", "restart", 2, 0 },
    { "OPER_DIE", "die", 2, 0 },
    { "OPER_GLINE", "gline", 2, 0 },
    { "OPER_LGLINE", "local_gline", 2, 0 },
    { "OPER_JUPE", "jupe", 2, 0 },
    { "OPER_LJUPE", "local_jupe", 2, 0 },
    { "OPER_OPMODE", "opmode", 2, 0 },
    { "OPER_LOPMODE", "local_opmode", 2, 0 },
    { "OPER_FORCE_OPMODE", "force_opmode", 2, 0 },
    { "OPER_FORCE_LOPMODE", "force_local_opmode", 2, 0 },
    { "OPER_BADCHAN", "badchan", 2, 0 },
    { "OPER_LBADCHAN", "local_badchan", 2, 0 },
    { "OPER_SET", "set", 2, 0 },
    { "OPER_WIDE_GLINE", "wide_gline", 2, 0 },
    /* remapped features affecting only local opers */
    { "LOCOP_KILL", "kill", 1, 0 },
    { "LOCOP_REHASH", "rehash", 1, 0 },
    { "LOCOP_RESTART", "restart", 1, 0 },
    { "LOCOP_DIE", "die", 1, 0 },
    { "LOCOP_LGLINE", "local_gline", 1, 0 },
    { "LOCOP_LJUPE", "local_jupe", 1, 0 },
    { "LOCOP_LOPMODE", "local_opmode", 1, 0 },
    { "LOCOP_FORCE_LOPMODE", "force_local_opmode", 1, 0 },
    { "LOCOP_LBADCHAN", "local_badchan", 1, 0 },
    { "LOCOP_WIDE_GLINE", "wide_gline", 1, 0 },
    { 0, 0, 0, 0 }
};

static void do_feature(void)
{
    struct feature *feat;
    size_t ii;

    ii = strlen(fields[0]);
    feat = calloc(1, sizeof(*feat) + ii);
    while (ii-- > 0)
        feat->name[ii] = fields[0][ii];
    feat->next = features;
    features = feat;
    string_get(&feat->origins, orig_line);
    for (ii = 1; fields[ii] && fields[ii][0]; ++ii)
        string_get(&feat->values, fields[ii]);
}

static void finish_features(void)
{
    struct remapped_feature *rmf;
    struct string_list *sl;
    struct feature *feat;
    size_t ii;

    fputs("Features {\n", stdout);
    fputs("\t\"OPLEVELS\" = \"FALSE\";\n", stdout);
    fputs("\t\"ZANNELS\" = \"FALSE\";\n", stdout);

    for (feat = features; feat; feat = feat->next) {
        /* Display the original feature line we are talking about. */
        for (sl = feat->origins; sl; sl = sl->next)
            fprintf(stdout, "# %s\n", sl->value);

        /* See if the feature was remapped to an oper privilege. */
        for (rmf = remapped_features; rmf->name; rmf++)
            if (0 == strcmp(feat->name, rmf->name))
                break;
        if (rmf->name) {
            rmf->feature = feat;
            fprintf(stdout, "# Above feature mapped to an oper privilege.\n");
            continue;
        }

        /* Was it removed? */
        for (ii = 0; removed_features[ii]; ++ii)
            if (0 == strcmp(feat->name, removed_features[ii]))
                break;
        if (removed_features[ii]) {
            fprintf(stdout, "# Above feature no longer exists.\n");
            continue;
        }

        /* Wasn't remapped, wasn't removed: print it out. */
        fprintf(stdout, "\t\"%s\" =", feat->name);
        for (sl = feat->values; sl; sl = sl->next)
            fprintf(stdout, " \"%s\"", sl->value);
        fprintf(stdout, ";\n");
    }
    fputs("};\n\n", stdout);

}

/*** OPERATOR BLOCKS ***/

struct operator {
    char *name;
    char *host;
    char *password;
    char *class;
    char *origin;
    int is_local;
    struct operator *next;
} *operators;

static void do_operator(int is_local)
{
    struct operator *oper;

    oper = calloc(1, sizeof(*oper));
    dupstring(oper->host, fields[0]);
    dupstring(oper->password, fields[1]);
    dupstring(oper->name, fields[2]);
    dupstring(oper->class, fields[4]);
    dupstring(oper->origin, orig_line);
    oper->is_local = is_local;
    oper->next = operators;
    operators = oper;
}

static void finish_operators(void)
{
    struct remapped_feature *remap;
    struct operator *oper;
    struct feature *feat;
    char *pw_salt = "";
    int global_kill = 0, mask = 0;
    size_t ii;

    if ((feat = remapped_features[0].feature) && feat->values
        && 0 == strcmp(feat->values->value, "FALSE"))
        pw_salt = "$PLAIN$";

    if ((feat = remapped_features[1].feature) && feat->values
        && 0 == strcmp(feat->values->value, "FALSE"))
        global_kill = 1;
    else if ((feat = remapped_features[2].feature) && feat->values
        && 0 == strcmp(feat->values->value, "FALSE"))
        global_kill = 2;

    for (oper = operators; oper; oper = oper->next) {
        fprintf(stdout, "# %s\nOperator {\n\tname = \"%s\";\n"
                "\thost = \"%s\";\n\tpassword = \"%s%s\";\n"
                "\tclass = \"%s\";\n",
                oper->origin, oper->name, oper->host, pw_salt,
                oper->password, oper->class);
        if (oper->is_local) {
            fputs("\tlocal = yes;\n", stdout);
            mask = 1;
        } else {
            fputs("\tlocal = no;\n", stdout);
            if (global_kill == 1)
                fputs("\tkill = no;\n\tlocal_kill = no;\n", stdout);
            else if (global_kill == 2)
                fputs("\tkill = no;\n\tlocal_kill = yes;\n", stdout);
            mask = 2;
        }
        for (ii = 0; (remap = &remapped_features[ii++])->name; ) {
            if (!remap->feature || !remap->privilege
                || !remap->feature->values || !(remap->flags & mask))
                continue;
            fprintf(stdout, "\t%s = %s;\n", remap->privilege,
                    strcmp(remap->feature->values->value, "TRUE") ? "no" : "yes");
        }
        fputs("};\n\n", stdout);
    }
}

/*** OTHER CONFIG TRANSFORMS ***/

static void do_kill(void)
{
    const char *host = fields[0], *reason = fields[1], *user = fields[2];

    if (!memcmp(host, "$R", 3)) {
        fprintf(stderr, "Empty realname K: line at line %u.\n", lineno);
        return;
    }

    /* Print the current line and start the new block. */
    fprintf(stdout, "# %s\nKill {\n", orig_line);

    /* Translate the user-matching portions. */
    if (host[0] == '$' && host[1] == 'R') {
        /* Realname kill, possibly with a username */
        fprintf(stdout, "\trealname = \"%s\";\n", host + 2);
        if (user[0] != '\0' && (user[0] != '*' || user[1] != '\0'))
            fprintf(stdout, "\thost = \"%s@*\";\n", user);
    } else {
        /* Normal host or IP-based kill */
        if (user[0] != '\0' && (user[0] != '*' || user[1] != '\0'))
            fprintf(stdout, "\thost = \"%s@%s\";\n", user, host);
        else
            fprintf(stdout, "\thost = \"%s\";\n", host);
    }

    /* Translate the reason section. */
    if (reason[0] == '!')
        fprintf(stdout, "\tfile = \"%s\";\n", reason + 1);
    else
        fprintf(stdout, "\treason = \"%s\";\n", reason);

    /* Close the block. */
    fprintf(stdout, "};\n");
}

static void do_port(void)
{
    const char *ipmask = fields[0], *iface = fields[1], *flags = fields[2], *port = fields[3];

    /* Print the current line and start the new block. */
    fprintf(stdout, "# %s\nPort {\n", orig_line);

    /* Print the easy fields. */
    fprintf(stdout, "\tport = %s;\n", port);
    if (iface && iface[0] != '\0')
        fprintf(stdout, "\tvhost = \"%s\";\n", iface);
    if (ipmask && ipmask[0] != '\0')
        fprintf(stdout, "\tmask = \"%s\";\n", ipmask);

    /* Translate flag field. */
    while (*flags) switch (*flags++) {
    case 'C': case 'c': /* client port is default state */; break;
    case 'S': case 's': fprintf(stdout, "\tserver = yes;\n"); break;
    case 'H': case 'h': fprintf(stdout, "\thidden = yes;\n"); break;
    }

    /* Close the block. */
    fprintf(stdout, "};\n");
}

struct string_list *quarantines;

static void do_quarantine(void)
{
    struct string_list *q;
    q = string_get(&quarantines, fields[0]);
    dupstring(q->origin, orig_line);
    dupstring(q->extra, fields[1]);
}

static void finish_quarantines(void)
{
    struct string_list *sl;

    if (quarantines)
    {
        fputs("Quarantine {\n", stdout);
        for (sl = quarantines; sl; sl = sl->next)
            fprintf(stdout, "# %s\n\t\"%s\" = \"%s\";\n", sl->origin, sl->value, sl->extra);
        fputs("};\n\n", stdout);
    }
}

static void do_uworld(void)
{
    fprintf(stdout, "# %s\n", orig_line);
    if (fields[0] && fields[0][0])
        fprintf(stdout, "Uworld { name = \"%s\"; };\n", fields[0]);
    if (fields[1] && fields[1][0])
        fprintf(stdout, "Jupe { nick = \"%s\"; };\n", fields[1]);
}

static void emit_client(const char *mask, const char *passwd, const char *class, long maxlinks, int is_ip)
{
    char *delim;
    size_t len;

    delim = strchr(mask, '@');
    if (delim) {
        *delim++ = '\0';
        if (is_ip) {
            len = strspn(delim, "0123456789.*");
            if (delim[len]) {
                fprintf(stderr, "Invalid IP mask on line %u.\n", lineno);
                return;
            }
            fprintf(stdout, "Client {\n\tusername = \"%s\";\n\tip = \"%s\";\n", mask, delim);
        } else {
            fprintf(stdout, "Client {\n\tusername =\"%s\";\n\thost = \"%s\";\n", mask, delim);
        }
    } else if (is_ip) {
        len = strspn(mask, "0123456789.*");
        if (mask[len])
            return;
        fprintf(stdout, "Client {\n\tip = \"%s\";\n", mask);
    } else {
        if (!strchr(mask, '.') && !strchr(mask, '*'))
            return;
        fprintf(stdout, "Client {\n\thost = \"%s\";\n", mask);
    }

    if (passwd)
        fprintf(stdout, "\tpassword = \"%s\";\n", passwd);

    if (maxlinks >= 0)
        fprintf(stdout, "\tmaxlinks = %ld;\n", maxlinks);

    fprintf(stdout, "\tclass = \"%s\";\n};\n", class);
}

static void do_client(void)
{
    char *passwd = NULL, *delim;
    long maxlinks;

    /* Print the current line. */
    fprintf(stdout, "# %s\n", orig_line);

    /* See if the password is really a maxlinks count. */
    maxlinks = strtol(fields[1], &delim, 10);
    if (fields[1][0] == '\0')
        maxlinks = -1;
    else if (maxlinks < 0 || maxlinks > 99 || *delim != '\0')
        passwd = fields[1];

    /* Translate the IP and host mask fields into blocks. */
    emit_client(fields[0], passwd, fields[4], maxlinks, 1);
    emit_client(fields[2], passwd, fields[4], maxlinks, 0);
}

int main(int argc, char *argv[])
{
    FILE *ifile;

    if (argc < 2)
        ifile = stdin;
    else if (!(ifile = fopen(argv[1], "rt"))) {
        fprintf(stderr, "Unable to open file %s for input.\n", argv[1]);
        return 1;
    }

    for (lineno = 1; fgets(line, sizeof(line), ifile); ++lineno) {
        /* Read line and pass comments through. */
        size_t len = strlen(line);
        if (line[0] == '#') {
            fputs(line, stdout);
            continue;
        }
        /* Strip trailing whitespace. */
        while (len > 0 && isspace(line[len-1]))
            line[--len] = '\0';
        /* Pass blank lines through. */
        if (len == 0) {
            fputc('\n', stdout);
            continue;
        }
        /* Skip but report invalid lines. */
        if (line[1] != ':') {
            fprintf(stdout, "# %s\n", line);
            fprintf(stderr, "Invalid input line %d.\n", lineno);
            continue;
        }
        /* Copy the original line into a reusable variable. */
        strcpy(orig_line, line);
        /* Split line into fields. */
        nfields = split_line(line + 2, fields);

        /* Process the input line. */
        switch (line[0]) {
        case 'A': case 'a': simple_line("Admin", admin_names, NULL); break;
        case 'C': case 'c': do_connect(); break;
        case 'D':           simple_line("CRule", crule_names, "all = yes;"); break;
                  case 'd': simple_line("CRule", crule_names, NULL); break;
        case 'F': case 'f': do_feature(); break;
        case 'H': case 'h': do_hub(); break;
        case 'I': case 'i': do_client(); break;
        case 'K': case 'k': do_kill(); break;
        case 'L': case 'l': do_leaf(); break;
        case 'M': case 'm': simple_line("General", general_names, NULL); break;
        case 'O':           do_operator(0); break;
                  case 'o': do_operator(1); break;
        case 'P': case 'p': do_port(); break;
        case 'Q': case 'q': do_quarantine(); break;
        case 'T': case 't': simple_line("Motd", motd_names, NULL); break;
        case 'U': case 'u': do_uworld(); break;
        case 'Y': case 'y': simple_line("Class", class_names, NULL); break;
        default:
            fprintf(stderr, "Unknown line %u with leading character '%c'.\n", lineno, line[0]);
            break;
        }
    }

    fclose(ifile);

    fputs("\n# The following lines were intentionally moved and rearranged."
          "\n# Our apologies for any inconvenience this may cause."
          "\n\n", stdout);
    finish_connects();
    finish_quarantines();
    finish_features();
    finish_operators();

    return 0;
}
