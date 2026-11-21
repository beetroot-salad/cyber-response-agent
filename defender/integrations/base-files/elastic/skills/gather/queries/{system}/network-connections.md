---
id: {system}.network-connections
status: established
verb: query
params: [end, start, sort]
---

## Goal

Network connection events over a window: which source reached which destination, on what port and protocol, in which
direction, and how much moved. One **capability** template for flow questions: what a host talked to around an alert,
whether a pair has ever connected, outbound destinations of one source. Keyword recall: network, flow, connection,
conn, source.ip, destination.ip, destination.port, network.protocol, network.direction, bytes, outbound, egress.

This is a **wide/superset** query: it matches every network event and carries no entity predicate. **You narrow it to
the lead** by adding the predicates the lead constrains.

## Query

Lucene, the verb's default events index.

```
event.category: "network"
```

**Narrowing examples:**

- *Outbound from one source*: add `AND source.ip: "<ip>" AND network.direction: "outbound"`.
- *Who reached a destination port*: add `AND destination.ip: "<ip>" AND destination.port: <port>`.
- *One protocol*: add `AND network.protocol: "<protocol>"`.

## Pitfalls

- **A flow sensor describes a flow by addresses only.** Its events carry no `host.name`, so a host predicate drops them.
  Attribute an address to a host through the events that do carry both, or through another system.
- **Shared and translated addresses.** An address behind NAT, or one several hosts report as their own, matches more
  than one host. Treat an address match as evidence of the address, not of one machine.
- **Direction is the sensor's judgement,** and may be null. Do not rely on `network.direction` alone to mean outbound;
  compare the addresses.
- **High-volume.** Prefer `esql` aggregation for counts and distributions.
