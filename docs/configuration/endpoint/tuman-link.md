!!! question "Tuman fork only"

    `tuman-link` exists only in the [tuman-vpn/sing-box](https://github.com/tuman-vpn/sing-box)
    fork (see `TUMAN.md` at the repository root). It requires the `with_gvisor`
    build tag; without it the type is registered but fails with a rebuild hint.
    Unix-like hosts only (Linux, macOS, iOS, Android): the credential
    permission checks cannot be satisfied on Windows yet.

`tuman-link` is a TL1 client endpoint backed by
[`github.com/tuman-vpn/link`](https://github.com/tuman-vpn/link). It admits the
device to a TL1 gateway over an outer UDP socket (compact UDP, RTP-shaped or
QUIC-shaped carrier, optionally with DNS-carried setup), receives an address
lease and runs a userspace gVisor stack on that lease. Like other endpoints it
is used as an outbound: route traffic to its tag.

### Structure

```json
{
  "type": "tuman-link",
  "tag": "tl1",

  "descriptor": {
    "file": "/path/to/tl1/gateway.tl1"
  },
  "credentials_dir": "/path/to/tl1/device",
  "setup_order": ["quic"],
  "direct_timeout": "",
  "cover_sni": [],
  "no_cover_probe": false,
  "cover_probation": "",
  "resolver": "",
  "mtu": 0,
  "workers": 0,

  ... // Dial Fields
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### descriptor

==Required==

The signed gateway descriptor (`canonical || signature` bytes, as written by
`linkctl sign-descriptor`). Exactly one of:

* `{"file": "/path/gateway.tl1"}`: path to the binary descriptor. Must start
  with `/` or `./`; `./` is relative to sing-box's working directory, not to
  the configuration file.
* `{"base64": "..."}`: the same bytes in standard padded base64.
* `"..."`: compact form of `{"base64": "..."}`.

The descriptor is verified against the root public key stored in
`credentials_dir/credentials.json`, the current time and the persisted version
floor. Base64 is only an encoding, not authentication. When a newer valid
descriptor is loaded, the endpoint raises `version_floor` in
`credentials.json`, so an older descriptor is rejected afterwards.

#### credentials_dir

==Required==

Existing private directory (mode `0700`) holding this device's identity. Give
every endpoint its own directory and never share one between processes.

* `credentials.json` (mode `0600`, written by `linkctl enroll-device`):
  `device_id`, `gateway_id`, `static_private_key`, `k_adm`, `root_public_key`
  (hex), `epoch` and `version_floor`. Unknown fields are rejected.
* `admission.db` (mode `0600`) is created and owned by the endpoint: it keeps
  the admission counters and must stay with `credentials.json`. Never delete or
  recreate it from an enrollment file. An enrollment that already carries
  counters (`counter`, `proven`, `silent_attempts`, `sealed_m1`) is accepted
  only when `admission.db` exists.

The directory and both files are re-read each time the endpoint rebuilds its
link. Keep secrets out of the configuration file itself.

#### setup_order

Ordered setup paths. At most one direct entry and at most one `dns`:

| Entry    | Meaning                                              |
|----------|------------------------------------------------------|
| `rtp`    | Direct setup and data on the RTP-shaped carrier (3)  |
| `quic`   | Direct setup and data on the QUIC-shaped carrier (4) |
| `udp`    | Direct setup and data on compact UDP (carrier 0)     |
| `direct` | Direct setup on the default carrier (RTP)            |
| `dns`    | DNS-carried setup, then direct data                  |

Examples: `["quic"]`; `["quic", "dns"]` (direct first, then DNS, see
`direct_timeout`); `["dns", "udp"]` (DNS-first setup with compact UDP data).
When empty, the descriptor's path preference is used with RTP data by default.
Unknown or duplicate entries fail `sing-box check`; an explicitly requested
`dns` that the descriptor cannot serve fails at start.

The gateway listener must run the carrier you select.

#### direct_timeout

How long direct setup is tried before advancing to the next path, `0s`–`7s`.

`0s` (no direct timeout) is used by default. `"3s"` with `["rtp", "dns"]`
matches the `linkcli --setup auto` path policy (linkcli additionally uses the
system resolver; set `resolver` for the same effect).

#### cover_sni

QUIC cover hostname pool for the `quic` carrier, the same syntax as
`linkcli --cover-sni`. Accepts a string, a list, and comma-separated entries
(`"a.example,b.example"` equals `["a.example", "b.example"]`). Names must be
lowercase DNS hostnames (letters, digits, `-`; no trailing dot, no IP
literals); duplicates are rejected.

The descriptor's cover name (`github.com` when the descriptor sets none) is
always part of the pool as the fallback, so listing only that name changes
nothing. The
client starts each QUIC flow in probation: a name is proven (and remembered for
the next start) once authenticated downlink arrives after the first 12 uplink
records, or data still flows after 15 s. A name whose flow is cut during
probation is marked failed and the next name is tried. This setting is not
authenticated and changes no keys or descriptor bytes.

#### no_cover_probe

Diagnostic only: disable the probation PINGs on the `quic` carrier. Covers are
then proven by data alone.

#### cover_probation

Probation window after a QUIC flow is established, in whole seconds.

`60s` is used when omitted or `0s`; probation cannot be disabled.

#### resolver

Numeric resolver address and port used for DNS-carried setup, for example
`192.0.2.53:53` or `[2001:db8::53]:53`, tried before the descriptor's
resolvers. Loopback, unspecified, multicast and zoned addresses are rejected:
pass the real upstream, not a local stub.

Only the descriptor's resolvers are used by default.

#### mtu

Cap for the inner netstack MTU, `1280`–`1400`. The effective MTU is
`min(mtu, lease MTU)`; the cap never changes the negotiated lease.

The lease MTU is used by default.

#### workers

Reserved. Accepted for compatibility (`0`–`256`) and currently has no effect.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details. They apply to the
outer UDP socket (and to the resolver socket during DNS setup).
`bind_interface` binds that socket and fails closed if the bind is impossible;
it cannot be combined with `detour`. Keep `route.auto_detect_interface`
enabled on clients that also run a `tun` inbound, so the outer socket cannot
loop back into the tunnel.

### Host-controlled fields

`credentials_dir`, `resolver`, `detour` and `bind_interface` decide which
identity is used and where setup traffic goes. Apps must set them themselves
and must not accept them from remote or user-supplied configuration.

### Recovery

The endpoint rebuilds its link after `Down` with a backoff that doubles from
1 s to 30 s (±20% jitter), and
reports `Up`, `Lease`, `Down`, `Refresh` and `Degraded` in the log. Dials fail
with `tuman-link is not ready` until a lease is applied. A credential epoch or
descriptor refresh request cannot be resolved by the endpoint: it logs the
cause and passes it to the handler installed with
`tumanlink.SetAuthFailureHandler` (Go API, for apps that embed sing-box).

### Example

A local proxy that sends everything, including DNS, through TL1 over the QUIC
carrier, using the descriptor's cover name (`examples/tuman-link/config.json`;
a whole-device `tun` variant is in `examples/tuman-link/tun.json`). Add
`"cover_sni": ["name-a.example", "name-b.example"]` to rotate through a pool
of your own cover names.

```json
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "udp",
        "tag": "dns-tl1",
        "detour": "tl1",
        "server": "1.1.1.1"
      }
    ],
    "final": "dns-tl1"
  },
  "endpoints": [
    {
      "type": "tuman-link",
      "tag": "tl1",
      "descriptor": {
        "file": "/path/to/tl1/gateway.tl1"
      },
      "credentials_dir": "/path/to/tl1/device",
      "setup_order": [
        "quic"
      ]
    }
  ],
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "route": {
    "final": "tl1",
    "auto_detect_interface": true,
    "default_domain_resolver": "dns-tl1"
  }
}
```

```shell
sing-box run -c examples/tuman-link/config.json
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org
```
