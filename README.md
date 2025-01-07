<div align="center">

# <img align="center" src="media/wiretap_logo.png" width="20%"> Wiretap Lite

[Wiretap](https://github.com/sandialabs/wiretap) is a transparent, VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
</div>

Unlike the original project (which is designed to run with a fairly more complex, layered configuration), this fork provides a wiretap binary intended for use as a direct drop-in replacement for WireGuard.

_Running wiretap lite with no arguments, is essentially equivalent to running `wiretap serve --simple` on the original wiretap._

## Usage Examples

```WIRETAP_INTERFACE_PRIVATEKEY="insert-private-key-for-this-node-here" \
WIRETAP_INTERFACE_PORT="51820" \
WIRETAP_PEER_PUBLICKEY="insert-public-key-of-remote-node-here" \
WIRETAP_PEER_ENDPOINT="some.ip.address:55550" \
WIRETAP_INTERFACE_IPV4=172.20.0.1 \
WIRETAP_INTERFACE_LOCALHOSTIP=172.20.0.1 \
WIRETAP_PEER_ALLOWED=172.20.0.2/32,0.0.0.0/0 \
./wiretap
```

Or:

`./wiretap --private insert-private-key-for-this-node-here --port 51820 --public insert-public-key-of-remote-node-here --endpoint some.ip.address:55550 --ipv4 172.20.0.1 --localhost-ip 172.20.0.1 --allowed="172.20.0.2/32,0.0.0.0/0"`

For more information, please refer to the readme and/or documentation for the official wiretap.

### Donate
Did this make you happy? I'd love to do more development like this! Please donate to show your support :)

BTC: 1Q4QkBn2Rx4hxFBgHEwRJXYHJjtfusnYfy

XMR: 4AfeGxGR4JqDxwVGWPTZHtX5QnQ3dTzwzMWLBFvysa6FTpTbz8Juqs25XuysVfowQoSYGdMESqnvrEQ969nR9Q7mEgpA5Zm
