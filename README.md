# `esp_wireguard`, WireGuard Implementation for ESP-IDF

An implementation of [WireGuard&reg;](https://www.wireguard.com/) for
ESP-IDF, based on
[WireGuard Implementation for lwIP](https://github.com/smartalock/wireguard-lwip).

This is a fork of [trombik/esp_wireguard](https://github.com/trombik/esp_wireguard),
maintained for ESP-IDF 5.5. Changes compared to the original:

- Works with ESP-IDF 5.5.x (the WireGuard netif no longer confuses the
  esp_netif IP event callback)
- Selectable underlying interface (`netif_key`): Wi-Fi station, Ethernet, or
  any other esp_netif
- Server mode: one interface that accepts several peers connecting in (see
  [Server mode](#server-mode))
- Security and robustness fixes ported from wireguard-lwip
  (GHSA-7grw-r329-8g8c and later), see [Security](#security)
- Anti-replay window of 256 packets (RFC 6479) instead of 32
- Handshake load control with cookies and rate limits
- Per-peer traffic counters; decrypted packets pass `netif->input`, so
  applications can filter tunnel traffic like that of any other interface

## Status

The client (a single tunnel to one peer) is in daily use, among
others in [esp32_nat_router](https://github.com/martin-ger/esp32_nat_router)
as a VPN uplink over Wi-Fi and Ethernet.

Server mode is new in 0.10.0.

IPv6 inside the tunnel is not supported yet (see [IPv6](#ipv6)).

## Supported ESP-IDF versions and targets

Developed and tested with **ESP-IDF v5.5.x** on `esp32`, `esp32s3`,
`esp32c3`, `esp32c5` and `esp32c6`.

The original project also supported ESP-IDF v4.2 to v4.4 and the ESP8266 RTOS
SDK v3.4 (`TCP/IP Adapter`). That code is still there but is not tested in this
fork. Server mode requires ESP-IDF 5.

## Installation

Add the component to your project's `main/idf_component.yml`:

```yaml
dependencies:
  esp_wireguard:
    git: https://github.com/martin-ger/esp_wireguard_idf_5.5.x.git
    version: v0.10.1
```

## Usage

Both peers must have synced time: the handshake carries a timestamp, and a
peer rejects initiations that are not newer than the last one it accepted.
The library does not sync time (use SNTP).

A working network interface is required.

Create a WireGuard configuration, `wireguard_config_t`. Use
`ESP_WIREGUARD_CONFIG_DEFAULT` to initialize the `wireguard_config_t` variable.
Create `wireguard_ctx_t`. Pass the variables to `esp_wireguard_init()`. Then,
call `esp_wireguard_connect()`. Call `esp_wireguard_disconnect()` to
disconnect from the peer (and destroy the WireGuard interface).

```c
#include <esp_wireguard.h>

esp_err_t err = ESP_FAIL;

wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();

wg_config.private_key = CONFIG_WG_PRIVATE_KEY;
wg_config.listen_port = CONFIG_WG_LOCAL_PORT;
wg_config.public_key = CONFIG_WG_PEER_PUBLIC_KEY;
wg_config.preshared_key = NULL;               /* optional, base64 */
wg_config.allowed_ip = CONFIG_WG_LOCAL_IP_ADDRESS;
wg_config.allowed_ip_mask = CONFIG_WG_LOCAL_IP_NETMASK;
wg_config.endpoint = CONFIG_WG_PEER_ADDRESS;
wg_config.port = CONFIG_WG_PEER_PORT;
wg_config.netif_key = "WIFI_STA_DEF";         /* underlying interface, e.g. "ETH_DEF"; NULL = "WIFI_STA_DEF" */

/* If the device is behind NAT or stateful firewall, set persistent_keepalive.
   persistent_keepalive is disabled by default */
// wg_config.persistent_keepalive = 25;

wireguard_ctx_t ctx = {0};
err = esp_wireguard_init(&wg_config, &ctx);

/* start establishing the link. after this call, esp_wireguard starts
   establishing the connection. */
err = esp_wireguard_connect(&ctx);

/* after some time, see if the link is up. note that it takes some time to
   establish the link */
err = esp_wireguardif_peer_is_up(&ctx);
if (err == ESP_OK) {
    /* the link is up */
} else {
    /* the link is not up */
}

/* optional: route all traffic through the tunnel */
err = esp_wireguard_set_default(&ctx);

/* do something */

err = esp_wireguard_disconnect(&ctx);
```

## Server mode

With `CONFIG_WIREGUARD_SERVER` (`[Component config]` -> `[WireGuard]` ->
`Server API`), `esp_wireguard_server.h` provides a WireGuard server: one
interface that listens on a UDP port and accepts several peers without a
configured endpoint. Peers connect in; the server never dials out. The option
also raises the default of `CONFIG_WIREGUARD_MAX_PEERS` to 8.

```c
#include <esp_wireguard_server.h>

esp_wireguard_server_config_t cfg = {
    .private_key = server_private_key,   /* base64 */
    .listen_port = 51820,
    .address = ipaddr_addr("10.8.0.1"),  /* tunnel address, network byte order */
    .netmask = ipaddr_addr("255.255.255.0"),
    .netif_key = "WIFI_STA_DEF",         /* interface to listen on */
};
err = esp_wireguard_server_start(&cfg);

esp_wireguard_server_peer_t peer = {
    .public_key = client_public_key,     /* base64 */
    .allowed_ip = ipaddr_addr("10.8.0.2"),
};
err = esp_wireguard_server_add_peer(&peer);
```

- All functions that touch the interface run their work on the lwIP tcpip
  thread, so call them from any task except that one.
- `esp_wireguard_server_get_peer_stats()` returns the session state, the last
  endpoint, the handshake age, inner byte counters, and the TAI64N timestamp
  of the newest accepted handshake. Persist the timestamp and pass it back in
  `esp_wireguard_server_peer_t` after a reboot, otherwise a recorded
  handshake initiation can be replayed once.
- `esp_wireguard_server_get_stats()` counts rejected handshakes: from keys
  that are not a configured peer (also logged as a warning, at most once
  every 10 s), and forged or corrupt ones.
- `esp_wireguard_generate_private_key()` and `esp_wireguard_public_key()`
  create key pairs on the device.
- The netif is available from `esp_wireguard_server_netif()`. Its link stays
  up while no peer is connected, so the tunnel subnet never follows the
  default route. Routing or NAT between the tunnel and other interfaces is up
  to the application.
- The server and the client API must not use the same underlying interface
  and port at the same time.

## Security

On top of the WireGuard protocol itself:

- **Replays**: data packets are checked against a 256-bit sliding window
  (RFC 6479) before they can update the peer's endpoint or session state.
  Handshake initiations must carry a newer timestamp than the last accepted
  one (see the server notes above on persisting it).
- **Handshake load**: handshakes with a valid mac1 are counted per second.
  Above 5 per second the device requires a cookie (mac2) for 5 s, which
  proves the sender receives at its source address. At most 10 handshakes per
  second reach the public key operations, and at most 20 cookie replies per
  second are sent.
- **Logging**: a handshake from an unknown key is logged as a warning at most
  once every 10 s; forged or corrupt handshakes are only logged at debug
  level, so they cannot flood the log from the tcpip thread.
- **Key material** is wiped from the stack after use.

## IPv6

Enable `CONFIG_LWIP_IPV6` under `lwip` component in `menuconfig`.

IPv6 inside the tunnel is not supported: decrypted IPv6 packets are dropped
until allowed-IPs filtering for IPv6 exists. An IPv6 endpoint as transport
is untested. Dual stack (IPv4 and IPv6) is not supported (see trombik Issue
#5); the first address of `endpoint` decides between IPv4 and IPv6 as
transport, and that transport must be available.

## Driver configuration

The driver configuration is under `[Component config]` -> `[WireGuard]`.

| Option | Default | Meaning |
|--------|---------|---------|
| `WIREGUARD_ESP_ADAPTER_SELECTION` | `ESP-NETIF` | `TCP/IP Adapter` only for SDKs older than ESP-IDF v4.1 and the ESP8266 RTOS SDK |
| `WIREGUARD_SERVER` | off | Build the server API |
| `WIREGUARD_MAX_PEERS` | 1 (8 with the server) | Peers per interface |
| `WIREGUARD_MAX_SRC_IPS` | 2 | Allowed IP ranges per peer |
| `MAX_INITIATIONS_PER_SECOND` | 2 | Accepted handshake initiations per peer and second |
| `WIREGUARD_x25519_IMPLEMENTATION` | Default | Scalar multiplication implementation, see below |

`WIREGUARD_x25519_IMPLEMENTATION_DEFAULT` is derived from
[WireGuard Implementation for lwIP](https://github.com/smartalock/wireguard-lwip).
`WIREGUARD_x25519_IMPLEMENTATION_NACL` uses
[crypto_scalarmult()](https://nacl.cr.yp.to/scalarmult.html) from NaCL. Note
that, with `WIREGUARD_x25519_IMPLEMENTATION_NACL`, some stack sizes must be
increased. 5KB for both `CONFIG_LWIP_TCPIP_TASK_STACK_SIZE` and
`CONFIG_MAIN_TASK_STACK_SIZE` is known to work on `ESP32-D0WD-V3`.

The replay window and the handshake load limits are compile-time constants
in `src/wireguard.h`.

## Known issues

The implementation uses `lwIP` as TCP/IP protocol stack.

IPv6 is not supported inside the tunnel, see [IPv6](#ipv6).

Older `esp-idf` versions with `TCP/IP Adapter`, such as v4.1.x, may work, but
are not tested in this fork.

## License

BSD 3-Clause "New" or "Revised" License (SPDX ID: BSD-3-Clause).
See [LICENSE](LICENSE) for details.

[src/nacl/crypto_scalarmult/curve25519/ref/smult.c] is Public domain.

## Authors

* Daniel Hope (daniel.hope@smartalock.com)
* Kenta Ida (fuga@fugafuga.org)
* Matthew Dempsky
* D. J. Bernstein
* Tomoyuki Sakurai (original `esp_wireguard`)
* martin-ger (ESP-IDF 5.5 fork, server mode)
