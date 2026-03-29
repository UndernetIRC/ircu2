/*
 * fast_cidr_lookups - cidr_lookups.h
 * Copyright (C) 2025 Hidden <hidden@undernet.org> and
 *                    Entrope <entrope@undernet.org>
 *
 * Source code available at https://github.com/hiddn/fast_cidr_lookups
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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

#ifndef __CIDR_LOOKUPS_H
#define __CIDR_LOOKUPS_H

#if !defined(IRCU2_BUILD)
/** Structure to store an IP address. */
struct irc_in_addr
{
  unsigned short in6_16[8]; /**< IPv6 encoded parts, little-endian. */
};
#else
#include "../include/res.h" /* struct irc_in_addr */
#endif /* IRCU2_BUILD */

typedef struct _cidr_node {
    struct irc_in_addr ip;
    unsigned char bits;
    struct _cidr_node *parent;
    struct _cidr_node *l;
    struct _cidr_node *r;
    void *data;
} cidr_node;

typedef struct _cidr_root_node {
    struct _cidr_node *ipv4;
    struct _cidr_node *ipv6;
} cidr_root_node;

/** CIDR_ITER - iterate over all nodes in the CIDR tree.
 * Use this macro like if it were a loop with {} brackets. You can break using `break;` at any point.
 * @param[in] root Pointer to the root of the CIDR tree
 * @param[in] node Pointer to the current node in the iteration
 */
#define CIDR_ITER(root, node) _CIDR_ITER(root, node, 0)

/** _CIDR_ITER - iterate over all nodes in the CIDR tree.
 * @param[in] root Pointer to the root of the CIDR tree
 * @param[in] node Pointer to the current node in the iteration
 * @param[in] show_virtual_nodes If 1, virtual nodes are shown in the iteration
 */
#define _CIDR_ITER(root, node, show_virtual_nodes) \
do {                                               \
    cidr_node *_stack[129];                        \
    cidr_node **_stack_ptr = _stack;               \
    cidr_root_node *_root = (root);                \
    cidr_node *_node = _root->ipv4;                \
    short ipv4_done = 0;                           \
    while (((node) = _node)) {                     \
        if (_node->data || (show_virtual_nodes))

#define CIDR_ITER_END                              \
        if (_node->l) {                            \
            if (_node->r) {                        \
                *_stack_ptr++ = _node->r;          \
            }                                      \
            _node = _node->l;                      \
        }                                          \
        else if (_node->r)                         \
            _node = _node->r;                      \
        else if (_stack_ptr != _stack)             \
            _node = *--_stack_ptr;                 \
        else {                                     \
            if (!ipv4_done) {                      \
                _node = _root->ipv6;               \
                ipv4_done = 1;                     \
            }                                      \
            else {                                 \
                _node = 0;                         \
            }                                      \
        }                                          \
    }                                              \
} while(0)

/** CIDR_SEARCH_ALL_MATCHES - iterate over all nodes in the CIDR tree that match/cover \a ip.
 * Use this macro like if it were a loop with {} brackets. You can break using `break;` at any point.
 * @param[in] root Pointer to the root of the CIDR tree
 * @param[in] node Pointer to the current node in the iteration
 * @param[in] ip ip address to search for
 */
#define CIDR_SEARCH_ALL_MATCHES(root, node, ip) \
do { \
    cidr_node *_node = cidr_search_best(root, (ip), 128); \
    while ((node = _node)) { \
        if (_node->data) \

#define CIDR_SEARCH_ALL_MATCHES_END \
        _node = _node->parent; \
    } \
} while(0)


/** cidr_new_tree - create a new CIDR tree
 * @return Pointer to the created CIDR tree root node
 */
cidr_root_node *cidr_new_tree();

/** cidr_add_node - add a new node to the CIDR tree
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] ip IP address (mask) to store
 * @param[in] nbits Length of CIDR prefix in \a ip
 * @param[in] data Pointer to the data associated with the node
 * @return Pointer to the added CIDR node
 */
cidr_node *cidr_add_node(const cidr_root_node *root_tree, const struct irc_in_addr *ip, unsigned char nbits, void *data);

/** _cidr_find_exact_node - find a node in the CIDR tree
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] ip IP address (mask) to look up
 * @param[in] nbits Length of CIDR prefix in \a ip
 * @return Pointer to the found CIDR node
 */
#define _cidr_find_exact_node(TREE, IP, BITS) _cidr_find_node(TREE, IP, BITS, 1)

/** cidr_search_best - find a non-virtual node in the CIDR tree that covers the given CIDR string
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] ip IP address (mask) to look up
 * @param[in] nbits Length of CIDR prefix in \a ip
 * @return Pointer to the found CIDR node, returns NULL if not found
 */
#define cidr_search_best(TREE, IP, BITS) _cidr_find_node(TREE, IP, BITS, 0)

/** _cidr_find_node - find a node in the CIDR tree
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] ip IP address (mask) to look up
 * @param[in] nbits Length of CIDR prefix in \a ip
 * @param[in] is_exact If 0, returns the closest parent node that is not virtual, otherwise returns the exact node if found
 * @return Pointer to the found CIDR node, returns NULL if not found
 */
cidr_node *_cidr_find_node(const cidr_root_node *root_tree, const struct irc_in_addr *ip, unsigned char nbits, const unsigned short is_exact);

/** cidr_rem_node_by_cidr - remove a node from the CIDR tree by CIDR string
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] ip IP address (mask) to remove
 * @param[in] nbits Length of CIDR prefix in \a ip
 * @return 1 if the node was removed, 0 otherwise
 */
int cidr_rem_node_by_cidr(const cidr_root_node *root_tree, const struct irc_in_addr *ip, unsigned char nbits);

/** cidr_rem_node - remove a node from the CIDR tree
 * @param[in] node Pointer to the node to be removed
 * @return 1 if the node was removed, 0 otherwise
 */
int cidr_rem_node(cidr_node *node);

/** cidr_get_data - get data associated with a node in the CIDR tree
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] ip IP address (mask) to look up
 * @param[in] nbits Length of CIDR prefix in \a ip
 * @return Pointer to the data associated with the node
 */
void *cidr_get_data(const cidr_root_node *root_tree, const struct irc_in_addr *ip, unsigned char nbits);

/** get_cidr_mask - get the CIDR mask of a node
 *  Be careful: it returns a pointer to a static buffer that gets overwritten on each call
 * @param[in] node Pointer to the node
 * @return The CIDR mask of the node
 */
const char *get_cidr_mask(const cidr_node *node);

/** set_cidr_mask - copies the node's cidr mask to buffer buf
 * @param[in] node Pointer to the node
 * @param[out] buf Buffer to store the CIDR mask
 */
void set_cidr_mask(cidr_node *node, char *buf);

/** _cidr_get_bit - get a specific bit from an IP address
 * @param[in] ip Pointer to the IP address
 * @param[in] bit_index Bit index - must be between 0 and 127
 * @return The specific bit from the IP address
 */
unsigned short _cidr_get_bit(const struct irc_in_addr *ip, const unsigned int bit_index);


/* This one is from Undernet's gnuworld, with a couple of modifications */
void irc_in6_CIDRMinIP(struct irc_in_addr *ircip, unsigned int CClonesCIDR);


#endif /* __CIDR_LOOKUPS_H */