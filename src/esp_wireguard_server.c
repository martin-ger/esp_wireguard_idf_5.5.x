/*
 * WireGuard server (responder) API, see esp_wireguard_server.h.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include <lwip/ip.h>
#include <lwip/netif.h>
#include <lwip/ip_addr.h>
#include <esp_err.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_random.h>
#include <esp_wireguard_server.h>

#include "wireguard-platform.h"
#include "wireguard.h"
#include "wireguardif.h"
#include "crypto.h"

#define TAG "esp_wireguard_srv"

_Static_assert(ESP_WIREGUARD_TIMESTAMP_LEN == WIREGUARD_TAI64N_LEN, "timestamp length mismatch");

static struct netif srv_netif_struct;
static struct netif *srv_netif = NULL;   /* written on the tcpip thread only */
static bool platform_ready = false;

static err_t srv_ip_input(struct pbuf *p, struct netif *inp)
{
    return ip_input(p, inp);
}

static bool decode_key(const char *b64, uint8_t *key)
{
    size_t len = WIREGUARD_PUBLIC_KEY_LEN;
    return b64 && wireguard_base64_decode(b64, key, &len) && (len == WIREGUARD_PUBLIC_KEY_LEN);
}

/* ---- callbacks below run on the tcpip thread ---- */

static esp_err_t server_start_cb(void *ctx)
{
    const esp_wireguard_server_config_t *config = (const esp_wireguard_server_config_t *)ctx;
    struct wireguardif_init_data init;
    ip4_addr_t ip, mask, gw;

    if (srv_netif != NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    memset(&init, 0, sizeof(init));
    init.private_key = config->private_key;
    init.listen_port = config->listen_port;
    init.bind_netif = NULL;
    init.netif_key = config->netif_key;
    init.link_always_up = true;

    /* Add with no address, as the client does: with netif->state pointing at
     * our device, ESP-IDF's address-change callback would misread it as an
     * esp_netif_t. The address is set below with state hidden. */
    memset(&srv_netif_struct, 0, sizeof(srv_netif_struct));
    struct netif *n = netif_add(&srv_netif_struct, IP4_ADDR_ANY4, IP4_ADDR_ANY4, IP4_ADDR_ANY4,
                                &init, &wireguardif_init, &srv_ip_input);
    if (n == NULL) {
        return ESP_FAIL;
    }

    ip4_addr_set_u32(&ip, config->address);
    ip4_addr_set_u32(&mask, config->netmask);
    ip4_addr_set_zero(&gw);

    void *device = n->state;
    n->state = NULL;
    netif_set_addr(n, &ip, &mask, &gw);
    netif_set_up(n);
    n->state = device;

    if (config->mtu != 0) {
        n->mtu = config->mtu;
    }
    netif_set_link_up(n);

    srv_netif = n;
    return ESP_OK;
}

static esp_err_t server_stop_cb(void *ctx)
{
    (void)ctx;
    struct netif *n = srv_netif;

    if (n == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    srv_netif = NULL;

    void *device = n->state;
    n->state = NULL;
    netif_set_ipaddr(n, IP4_ADDR_ANY4);
    n->state = device;

    /* Stops the timer and the UDP pcb; the peers and their keys go with the
     * device, which wireguardif_fini() releases. */
    wireguardif_shutdown(n);
    netif_remove(n);
    crypto_zero(n->state, sizeof(struct wireguard_device));
    wireguardif_fini(n);
    return ESP_OK;
}

static esp_err_t add_peer_cb(void *ctx)
{
    const esp_wireguard_server_peer_t *cfg = (const esp_wireguard_server_peer_t *)ctx;
    struct wireguardif_peer peer;
    uint8_t key[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t psk[WIREGUARD_SESSION_KEY_LEN];
    u8_t index = WIREGUARDIF_INVALID_INDEX;
    esp_err_t ret;

    if (srv_netif == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!decode_key(cfg->public_key, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    /* wireguardif_add_peer() reports success for a known key without applying
     * the new settings, so refuse duplicates here. */
    if (peer_lookup_by_pubkey((struct wireguard_device *)srv_netif->state, key) != NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    wireguardif_peer_init(&peer);
    peer.public_key = cfg->public_key;
    if (cfg->preshared_key != NULL) {
        if (!decode_key(cfg->preshared_key, psk)) {
            return ESP_ERR_INVALID_ARG;
        }
        peer.preshared_key = psk;
    }
    ip_addr_set_ip4_u32_val(peer.allowed_ip, cfg->allowed_ip);
    ip_addr_set_ip4_u32_val(peer.allowed_mask, IPADDR_BROADCAST);
    /* No endpoint: it is learned from the peer's first authenticated packet */
    peer.endport_port = 0;
    peer.keep_alive = cfg->keepalive;
    if (cfg->greatest_timestamp != NULL) {
        memcpy(peer.greatest_timestamp, cfg->greatest_timestamp, sizeof(peer.greatest_timestamp));
    }

    switch (wireguardif_add_peer(srv_netif, &peer, &index)) {
        case ERR_OK:  ret = ESP_OK; break;
        case ERR_MEM: ret = ESP_ERR_NO_MEM; break;
        default:      ret = ESP_ERR_INVALID_ARG; break;
    }
    crypto_zero(psk, sizeof(psk));
    return ret;
}

static esp_err_t lookup_peer(const char *public_key, struct wireguard_device **device_out,
                             struct wireguard_peer **peer_out)
{
    uint8_t key[WIREGUARD_PUBLIC_KEY_LEN];

    if (srv_netif == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!decode_key(public_key, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    struct wireguard_device *device = (struct wireguard_device *)srv_netif->state;
    struct wireguard_peer *peer = peer_lookup_by_pubkey(device, key);
    if (peer == NULL) {
        return ESP_ERR_NOT_FOUND;
    }
    *device_out = device;
    *peer_out = peer;
    return ESP_OK;
}

static esp_err_t remove_peer_cb(void *ctx)
{
    struct wireguard_device *device;
    struct wireguard_peer *peer;

    esp_err_t ret = lookup_peer((const char *)ctx, &device, &peer);
    if (ret == ESP_OK) {
        wireguardif_remove_peer(srv_netif, wireguard_peer_index(device, peer));
    }
    return ret;
}

struct stats_ctx {
    const char *public_key;
    esp_wireguard_server_peer_stats_t *stats;
};

static esp_err_t peer_stats_cb(void *ctx)
{
    struct stats_ctx *c = (struct stats_ctx *)ctx;
    struct wireguard_device *device;
    struct wireguard_peer *peer;

    esp_err_t ret = lookup_peer(c->public_key, &device, &peer);
    if (ret != ESP_OK) {
        return ret;
    }
    esp_wireguard_server_peer_stats_t *s = c->stats;
    s->up = peer->curr_keypair.valid || peer->prev_keypair.valid;
    s->endpoint_ip = IP_IS_V4_VAL(peer->ip) ? ip4_addr_get_u32(ip_2_ip4(&peer->ip)) : 0;
    s->endpoint_port = peer->port;
    s->handshake_age_s = (peer->last_session_millis != 0)
            ? (wireguard_sys_now() - peer->last_session_millis) / 1000
            : UINT32_MAX;
    s->rx_bytes = peer->rx_bytes;
    s->tx_bytes = peer->tx_bytes;
    memcpy(s->greatest_timestamp, peer->greatest_timestamp, sizeof(s->greatest_timestamp));
    return ESP_OK;
}

static esp_err_t server_stats_cb(void *ctx)
{
    esp_wireguard_server_stats_t *s = (esp_wireguard_server_stats_t *)ctx;

    if (srv_netif == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    const struct wireguard_device *device = (const struct wireguard_device *)srv_netif->state;
    s->rejected_unknown_peer = device->rejected_unknown_peer;
    s->rejected_invalid = device->rejected_invalid;
    return ESP_OK;
}

/* ---- public API ---- */

esp_err_t esp_wireguard_server_start(const esp_wireguard_server_config_t *config)
{
    if (config == NULL || config->private_key == NULL || config->listen_port == 0 ||
        config->address == 0 || config->netmask == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!platform_ready) {
        esp_err_t err = wireguard_platform_init();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "wireguard_platform_init: %s", esp_err_to_name(err));
            return err;
        }
        platform_ready = true;
    }
    return esp_netif_tcpip_exec(server_start_cb, (void *)config);
}

esp_err_t esp_wireguard_server_stop(void)
{
    return esp_netif_tcpip_exec(server_stop_cb, NULL);
}

bool esp_wireguard_server_is_running(void)
{
    return srv_netif != NULL;
}

struct netif *esp_wireguard_server_netif(void)
{
    return srv_netif;
}

esp_err_t esp_wireguard_server_add_peer(const esp_wireguard_server_peer_t *peer)
{
    if (peer == NULL || peer->public_key == NULL || peer->allowed_ip == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    return esp_netif_tcpip_exec(add_peer_cb, (void *)peer);
}

esp_err_t esp_wireguard_server_remove_peer(const char *public_key)
{
    if (public_key == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return esp_netif_tcpip_exec(remove_peer_cb, (void *)public_key);
}

esp_err_t esp_wireguard_server_get_peer_stats(const char *public_key,
                                              esp_wireguard_server_peer_stats_t *stats)
{
    struct stats_ctx ctx = { .public_key = public_key, .stats = stats };

    if (public_key == NULL || stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return esp_netif_tcpip_exec(peer_stats_cb, &ctx);
}

esp_err_t esp_wireguard_server_get_stats(esp_wireguard_server_stats_t *stats)
{
    if (stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return esp_netif_tcpip_exec(server_stats_cb, stats);
}

static esp_err_t encode_key(const uint8_t *key, char *out, size_t out_size)
{
    size_t len = out_size;
    return wireguard_base64_encode(key, WIREGUARD_PUBLIC_KEY_LEN, out, &len) ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

esp_err_t esp_wireguard_generate_private_key(char *out, size_t out_size)
{
    uint8_t key[WIREGUARD_PRIVATE_KEY_LEN];

    if (out == NULL || out_size < ESP_WIREGUARD_KEY_B64_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }
    /* Not wireguard_random_bytes(): its DRBG context belongs to the tcpip
     * thread, and this may run in any task. */
    esp_fill_random(key, sizeof(key));
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
    esp_err_t ret = encode_key(key, out, out_size);
    crypto_zero(key, sizeof(key));
    return ret;
}

esp_err_t esp_wireguard_public_key(const char *private_key, char *out, size_t out_size)
{
    static const uint8_t basepoint[WIREGUARD_PUBLIC_KEY_LEN] = { 9 };
    uint8_t priv[WIREGUARD_PRIVATE_KEY_LEN];
    uint8_t pub[WIREGUARD_PUBLIC_KEY_LEN];
    esp_err_t ret = ESP_ERR_INVALID_ARG;

    if (out == NULL || out_size < ESP_WIREGUARD_KEY_B64_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }
    if (decode_key(private_key, priv) && (wireguard_x25519(pub, priv, basepoint) == 0)) {
        ret = encode_key(pub, out, out_size);
    }
    crypto_zero(priv, sizeof(priv));
    return ret;
}
