# `esp_wireguard`, WireGuard Implementation for ESP-IDF

**Added hack to get it to work on ESP IDF 5.5.x**

**Added option to select other interfaces than WIFI_STA**

This is an implementation of the [WireGuard&reg;](https://www.wireguard.com/)
for ESP-IDF, based on
[WireGuard Implementation for lwIP](https://github.com/smartalock/wireguard-lwip).

[![Build examples](https://github.com/trombik/esp_wireguard/actions/workflows/build.yml/badge.svg)](https://github.com/trombik/esp_wireguard/actions/workflows/build.yml)

## Status

The code is alpha.

A single tunnel to a WireGuard peer has been working.

## Supported ESP-IDF versions and targets

The following ESP-IDF versions are supported:

* **`esp-idf` `v5.5.x`**
* `esp-idf` `master`
* `esp-idf` `v4.2.x`
* `esp-idf` `v4.3.x`
* `esp-idf` `v4.4.x`
* ESP8266 RTOS SDK `v3.4`

The following targets are supported:

* `esp32`
* `esp32s2`
* `esp32c3`
* `esp8266`

## Usage

In `menuconfig` under `WireGuard`, choose a TCP/IP adapter. The default is
`ESP-NETIF`. SDKs older than `esp-idf` `v4.1`, including ESP8266 RTOS SDK v3.4
requires `TCP/IP Adapter`.

Both peers must have synced time. The library does not sync time.

A working network interface is required.

Create WireGuard configuration, `wireguard_config_t`. Use
`ESP_WIREGUARD_CONFIG_DEFAULT` to initialize `wireguard_config_t` variable.
Create `wireguard_ctx_t`.  Pass the variables to `esp_wireguard_init()`. Then,
call `esp_wireguard_connect()`. Call `esp_wireguard_disconnect()` to
disconnect from the peer (and destroy the WireGuard interface).

```c
#include <esp_wireguard.h>

esp_err_t err = ESP_FAIL;

wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();

wg_config.private_key = CONFIG_WG_PRIVATE_KEY;
wg_config.listen_port = CONFIG_WG_LOCAL_PORT;
wg_config.public_key = CONFIG_WG_PEER_PUBLIC_KEY;
wg_config.allowed_ip = CONFIG_WG_LOCAL_IP_ADDRESS;
wg_config.allowed_ip_mask = CONFIG_WG_LOCAL_IP_NETMASK;
wg_config.endpoint = CONFIG_WG_PEER_ADDRESS;
wg_config.port = CONFIG_WG_PEER_PORT;
wg_config.netif_key = CONFIG_WG_IF_KEY;  // new: key of the interface (e.g. "WIFI_STA_DEF" (default) or "ETH_DEF").

/* If the device is behind NAT or stateful firewall, set persistent_keepalive.
   persistent_keepalive is disabled by default */
// wg_config.persistent_keepalive = 10;

wireguard_ctx_t ctx = {0};
err = esp_wireguard_init(&wg_config, &ctx);

/* start establishing the link. after this call, esp_wireguard start
   establishing connection. */
err = esp_wireguard_connect(&ctx);

/* after some time, see if the link is up. note that it takes some time to
   establish the link */
err = esp_wireguardif_peer_is_up(&ctx);
if (err == ESP_OK) {
    /* the link is up */
else {
    /* the link is not up */
}

/* do something */

err = esp_wireguard_disconnect(&ctx);
```

See examples at [examples](examples).

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

## IPv6 support

Enable `CONFIG_LWIP_IPV6` under `lwip` component in `menuconfig`.

IPv6 support is alpha and probably broken. See also Known issues.

## Driver configuration

The driver configuration is under `[Component config]` -> `[WireGuard]`.

Under `WIREGUARD_x25519_IMPLEMENTATION`, you may choose an implementation of
scalar multiplication. The default is
`WIREGUARD_x25519_IMPLEMENTATION_DEFAULT`, which is derived from
[WireGuard Implementation for lwIP](https://github.com/smartalock/wireguard-lwip).
`WIREGUARD_x25519_IMPLEMENTATION_NACL` uses
[crypto_scalarmult()](https://nacl.cr.yp.to/scalarmult.html) from NaCL. Note
that, with `WIREGUARD_x25519_IMPLEMENTATION_NACL`,
some stack sizes must be increased.  In my test, 5KB for both
`CONFIG_LWIP_TCPIP_TASK_STACK_SIZE`, and `CONFIG_MAIN_TASK_STACK_SIZE` is
known to work on `ESP32-D0WD-V3`.

## Known issues

The implementation uses `LwIP` as TCP/IP protocol stack.

IPv6 support is not tested.  Dual stack (IPv4 and IPv6) is not supported (see
Issue #5). The first address of `endpoint` is used to choose IPv4 or IPv6 as a
transport. The chosen transport must be available and usable.

The library assumes the interface is WiFi interface. Ethernet is not
supported.

Older `esp-idf` versions with `TCP/IP Adapter`, such as v4.1.x, should work,
but there are others issues, not directly related to the library.

## License

BSD 3-Clause "New" or "Revised" License (SPDX ID: BSD-3-Clause).
See [LICENSE](LICENSE) for details.

[src/nacl/crypto_scalarmult/curve25519/ref/smult.c] is Public domain.

## Authors

* Daniel Hope (daniel.hope@smartalock.com)
* Kenta Ida (fuga@fugafuga.org)
* Matthew Dempsky
* D. J. Bernstein
