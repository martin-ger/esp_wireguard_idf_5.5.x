/*
 * WireGuard server (responder) API: one interface, several peers without a
 * configured endpoint. Peers connect in; the interface never dials out.
 *
 * All functions that touch the interface run their work on the lwIP tcpip
 * thread (esp_netif_tcpip_exec), so they may be called from any task except
 * the tcpip thread itself. The key helpers are pure and run in the caller.
 *
 * Only one server instance exists, and it must not be combined with the
 * client API in esp_wireguard.h on the same underlying interface and port.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#if !defined(__ESP_WIREGUARD_SERVER__H__)
#define __ESP_WIREGUARD_SERVER__H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <esp_err.h>
#include <lwip/netif.h>

/** Size of a buffer holding a base64 WireGuard key including the NUL. */
#define ESP_WIREGUARD_KEY_B64_SIZE  (45)

/** Length of a TAI64N handshake timestamp. */
#define ESP_WIREGUARD_TIMESTAMP_LEN (12)

typedef struct {
    const char *private_key;   /**< base64 private key of the server. Only read during start. */
    uint16_t    listen_port;   /**< UDP port to listen on. */
    uint32_t    address;       /**< tunnel address of the server, network byte order. */
    uint32_t    netmask;       /**< tunnel netmask, network byte order. */
    uint16_t    mtu;           /**< tunnel MTU, 0 for the WireGuard default (1420). */
    const char *netif_key;     /**< esp_netif key of the interface to listen on
                                    ("WIFI_STA_DEF", "ETH_DEF"). NULL = "WIFI_STA_DEF". */
} esp_wireguard_server_config_t;

typedef struct {
    const char *public_key;     /**< base64 public key of the peer. */
    const char *preshared_key;  /**< base64 preshared key, NULL if unused. */
    uint32_t    allowed_ip;     /**< tunnel address of the peer (/32), network byte order. */
    uint16_t    keepalive;      /**< persistent keepalive in seconds, 0 = off. */
    const uint8_t *greatest_timestamp; /**< ESP_WIREGUARD_TIMESTAMP_LEN bytes saved from an earlier
                                            run (see peer stats), NULL if none. Handshake initiations
                                            not newer than this are rejected as replays. */
} esp_wireguard_server_peer_t;

typedef struct {
    bool     up;                 /**< the peer has a usable session. */
    uint32_t endpoint_ip;        /**< last seen outer IPv4 address, network byte order, 0 if none. */
    uint16_t endpoint_port;      /**< last seen outer UDP port, host byte order. */
    uint32_t handshake_age_s;    /**< seconds since the last session was created, UINT32_MAX if none. */
    uint64_t rx_bytes;           /**< inner bytes received from the peer. */
    uint64_t tx_bytes;           /**< inner bytes sent to the peer. */
    uint8_t  greatest_timestamp[ESP_WIREGUARD_TIMESTAMP_LEN]; /**< TAI64N of the newest accepted
                                      handshake initiation. Persist it and hand it back in
                                      esp_wireguard_server_peer_t after a restart. */
} esp_wireguard_server_peer_stats_t;

typedef struct {
    uint32_t rejected_unknown_peer; /**< handshake initiations from a key that is not a configured
                                         peer (e.g. a deleted client still retrying). Each first one
                                         in 10 s is also logged as a warning with the key. */
    uint32_t rejected_invalid;      /**< handshake initiations that passed mac1 but were forged or
                                         corrupt. Only possible for a sender that knows the server's
                                         public key. */
} esp_wireguard_server_stats_t;

/**
 * @brief Create the server interface and start listening.
 *
 * The underlying interface must already exist. The tunnel interface is added
 * to lwIP with the given address, set up, and its link is kept up so that the
 * tunnel subnet always routes to it.
 *
 * @return ESP_OK, ESP_ERR_INVALID_ARG, ESP_ERR_INVALID_STATE if already
 *         running, ESP_FAIL if the interface could not be created.
 */
esp_err_t esp_wireguard_server_start(const esp_wireguard_server_config_t *config);

/** @brief Remove all peers and the server interface. */
esp_err_t esp_wireguard_server_stop(void);

/** @brief True between a successful start and stop. */
bool esp_wireguard_server_is_running(void);

/**
 * @brief The lwIP netif of the server, NULL if not running.
 *
 * Only dereference it on the tcpip thread.
 */
struct netif *esp_wireguard_server_netif(void);

/**
 * @brief Add a peer to the running server.
 *
 * @return ESP_OK, ESP_ERR_INVALID_STATE if not running or the key is already
 *         registered, ESP_ERR_INVALID_ARG for a bad key, ESP_ERR_NO_MEM if all
 *         CONFIG_WIREGUARD_MAX_PEERS slots are in use.
 */
esp_err_t esp_wireguard_server_add_peer(const esp_wireguard_server_peer_t *peer);

/**
 * @brief Remove a peer by public key. Its sessions end immediately.
 *
 * @return ESP_OK, ESP_ERR_NOT_FOUND, ESP_ERR_INVALID_STATE, ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wireguard_server_remove_peer(const char *public_key);

/** @brief Read the state and counters of a peer by public key. */
esp_err_t esp_wireguard_server_get_peer_stats(const char *public_key,
                                              esp_wireguard_server_peer_stats_t *stats);

/**
 * @brief Read the server-wide counters. They count since the server started.
 *
 * @return ESP_OK, ESP_ERR_INVALID_STATE if not running, ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wireguard_server_get_stats(esp_wireguard_server_stats_t *stats);

/**
 * @brief Generate a new private key from the hardware RNG.
 *
 * The RNG is only a true random source while Wi-Fi or Bluetooth is enabled
 * (or the bootloader entropy source is active), see esp_fill_random().
 *
 * @param[out] out  buffer of at least ESP_WIREGUARD_KEY_B64_SIZE bytes.
 */
esp_err_t esp_wireguard_generate_private_key(char *out, size_t out_size);

/**
 * @brief Derive the base64 public key from a base64 private key.
 *
 * Costs one X25519 operation in the calling task.
 */
esp_err_t esp_wireguard_public_key(const char *private_key, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif
