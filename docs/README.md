# Documentation

The index of the documents in this folder.

`vibe-vpn` builds a point-to-point IPv4 tunnel between a Linux server and a
client, and keeps the carrier under the tunnel separate from the session
above it. The documents here cover the protocol, the guarantees, the
deployment and the shape of the code.

| Document | What it covers |
| --- | --- |
| [architecture.md](architecture.md) | The layers, the module table, the wire format and the decisions behind them. |
| [protocol.md](protocol.md) | The protocol specification: the handshake, the frames, the invariants and the message types. |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What the tunnel protects against, what it does not, and where the guarantees stop. |
| [deployment.md](deployment.md) | Putting the server and the client in front of the internet. |
| [audit.md](audit.md) | The state of the audit: what was checked, what was found and what was left. |
| [screenshots/README.md](screenshots/README.md) | Why the repository carries no screenshots. |
| [../README.md](../README.md) | The front door: the carriers, the configuration keys and the commands. |
| [../PRODUCT.md](../PRODUCT.md) | Who the prototype is for, and what it must not be used for. |
| [../AGENTS.md](../AGENTS.md) | The commands, the layout of the tree, and the traps. |
| [../DESIGN.md](../DESIGN.md) | The visual record: a terminal program with no visual identity. |

## Reading order

New here: [../README.md](../README.md), then [protocol.md](protocol.md) for
the handshake and the frame format.

Before trusting the guarantees: [THREAT_MODEL.md](THREAT_MODEL.md). It says
where the protection stops, and that matters more than the feature list.

Changing the code: [architecture.md](architecture.md), then
[../AGENTS.md](../AGENTS.md) for the traps. The traps cover the transport
selector, the replay window and the handshake cookie, which are the parts
that cost a rebuild to learn.

Putting it in front of the internet: [deployment.md](deployment.md).
