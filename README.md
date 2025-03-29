<div align="center">

# <img align="center" src="https://github.com/sandialabs/wiretap/raw/main/media/wiretap_logo.png" width="20%"> Wiretap Lite

[Wiretap](https://github.com/sandialabs/wiretap) is a transparent, VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
</div>

The original Wiretap project is designed to support multiple server nodes with strong encryption between all of them. To accomplish this, it relies on there being two layers of WireGuard encapsulation (encryption) between any two nodes.
Such architecture is more advanced & complex than probably the vast majority of use cases, particularly when only two peers (ie, 1 client & 1 server) are to be linked.
The goal of this fork is to provide a more simplified wiretap binary that should be somehwat easier (and thus potentially faster) to deploy.

_Running `wiretap-lite` with no arguments, is essentially equivalent to running `wiretap serve --simple` on the original wiretap. This also means that` wiretap-lite` run without any arguments won't output any help - for that, you'll need to explicitly run `wiretap-lite --help` instead._

## Usage Examples

```
WIRETAP_INTERFACE_PRIVATEKEY="insert-private-key-for-this-node-here" \
WIRETAP_INTERFACE_PORT="51820" \
WIRETAP_PEER_PUBLICKEY="insert-public-key-of-remote-node-here" \
WIRETAP_PEER_ENDPOINT="some.ip.address:55550" \
WIRETAP_INTERFACE_IPV4=172.20.0.1 \
WIRETAP_INTERFACE_LOCALHOSTIP=172.16.0.100 \
WIRETAP_PEER_ALLOWED=172.20.0.2/32 \
./wiretap-lite
```

Or:

`./wiretap-lite --private insert-private-key-for-this-node-here --port 51820 --public insert-public-key-of-remote-node-here --endpoint some.ip.address:55550 --ipv4 172.20.0.1 --localhost-ip 172.16.0.100 --allowed="172.20.0.2/32"`

Or `./wiretap-lite -f wiretap_server.cfg`:

wiretap_server.conf:
```
[Interface]
PrivateKey = insert-private-key-for-this-node-here
Port = 51820
IPv4 = 172.20.0.1
LocalhostIP = 172.16.0.100

[Peer]
PublicKey = insert-public-key-of-remote-node-here
Endpoint = some.ip.address:55550
Allowed = 172.20.0.2/32
```

At this point, you should be able to access services hosted at the wiretap node, by routing to its (virtual) "localhost IP" via its peer IP (`IPv4`). Additionally, Wiretap's built-in virtual network stack will "forward and masquerade" any traffic that is routed through it, such as other devices on the host's LAN network (a completely different IP range). In theory, the wiretap peer could thus also be used as an internet gateway this way.

Note that some of the key names in the configuration file do differ slightly from the official WireGuard configuration. These changes are inherited from Wiretap. We may consider changing this in a future release of wiretap-lite, in order to minimize discrepencies with wireguard's official syntax

IPv6 functionality has also been preserved. For more information (& additional parameters/arguments), please refer to the readme and/or documentation for the official wiretap.

## What about Docker?

wiretap-lite is a single, standalone binary tool that is easy to deploy and run as-is. It is available for a wide range of system architectures. For Docker and other automations, consider using the official Wiretap instead. Feel free to submit a PR

## Warranty

None whatsoever. This was a hobby project for me that I decided to upload for whoever could benefit from it. You use it entirely at your own risk & discretion. Pull requests welcome :)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## Coffee

Did this make you happy? I'd love to do more development like this! Please donate to show your support :)

BTC: 1Q4QkBn2Rx4hxFBgHEwRJXYHJjtfusnYfy

XMR: 4AfeGxGR4JqDxwVGWPTZHtX5QnQ3dTzwzMWLBFvysa6FTpTbz8Juqs25XuysVfowQoSYGdMESqnvrEQ969nR9Q7mEgpA5Zm
