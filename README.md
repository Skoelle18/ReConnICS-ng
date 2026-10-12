# Reconisec - Arsenal FOSS Project

Operational technology (OT) is the hardware and software that directly monitors, controls and automates physical processes and infrastructure in industrial settings.

We are building a FOSS alternative for an asset inventoy system  that OT platforms already use through existing solutions

# Local Advisory Index

## What we do here

We cannnot actively allow internet access to OT devices to learn of latest or past CVEs, since internet access is a security flaw. So we instead do a scheduled update of local advisory index that contains CISA's CSAF OT advisores through KEV (Known Exploted Vulnerabilities) list.

We use git as a distribution source to build a advisory DB that can be exported to offline devices via USB or any supported file transfer interface.

Not done: Explore beyond USB for file transfer protocols and also see what OT devices really work like.

## Architecture

![architecture of local advisory index](/docs/local-advisory-arch.png)


## End users

![swimlane diagram of end users](/docs/local-advisory-swimlane.png)

## Running it (Java 21+, Maven; no runtime dependencies)

```
mvn package                                                 # builds + tests -> target/reconics.jar
java -jar target/reconics.jar keygen --keys keys              # once, on the online side
java -jar target/reconics.jar build-index --sign-key keys/index-signing.key   # -> data/index.json(.sig)
# copy data/index.json, data/index.json.sig to the offline side (pubkey copied once, separately)
java -jar target/reconics.jar match --index data/index.json --pubkey keys/index-signing.pub --format html --out report.html docs/examples/assets.json
java -jar target/reconics.jar serve --index data/index.json --pubkey keys/index-signing.pub   # ingest API for the PCAP project
```

Plan and connector design: [docs/plan.md](docs/plan.md). Ingest contract for the PCAP project: [docs/ingest-api.md](docs/ingest-api.md).

## Implementation progress

- [x] Plan architecture - Dataflow Level 1
- [ ] Plan architecture - Swimlane Diagram
- [x] CSAF OT mirror + KEV -> signed local advisory index (Java)
- [x] EXACT / PROBABLE / POSSIBLE / NONE matcher, JSON/CSV/HTML reports
- [x] Loopback ingest API for the PCAP project
- [ ] CSAF PGP signature verification, staleness warning, vendor aliases (see docs/plan.md)
