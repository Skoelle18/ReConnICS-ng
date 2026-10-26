# Advisory index and matching

## Verifying the index

CI rebuilds and signs the index daily and publishes it as the `advisory-index` release (`index.json`, `index.json.sig`). Get
the current public key (`git pull`), download the index and verify it before use:

```bash
mkdir -p data
gh release download advisory-index -R Skoelle18/ReConnICS-ng -D data
java -jar target/reconnics-ng.jar verify --index data/index.json --pubkey keys/index-signing.pub   # exit 0 only if the signature is valid
```

> **Older checkout?** The signing key was replaced. Run `git pull` to get the new `keys/index-signing.pub` and replace any
> `data/index.json(.sig)` you downloaded earlier: an index signed with the old key no longer verifies, so
> `serve --pubkey keys/index-signing.pub` refuses it.

Copy the public key to the offline side once, separately from the USB that carries the index, and check it:

```bash
sha256sum keys/index-signing.pub   # must equal: eb439797f996809f6329f0748fe21e6f5a6d912bbfbeb09d7102543a200be256
```

Release jars (from v0.1, built by `.github/workflows/release.yml`): `sha256sum -c reconnics-ng.jar.sha256` and `gh attestation verify reconnics-ng.jar -R Skoelle18/ReConnICS-ng`. Precondition for v0.1: attestations only work on a public repo (or GitHub Enterprise Cloud), so the repo must be public before the tag is pushed.

## Advisory matching (local advisory index)

## What we do here

We cannnot actively allow internet access to OT devices to learn of latest or past CVEs, since internet access is a security flaw. So we instead do a scheduled update of local advisory index that contains CISA's CSAF OT advisores through KEV (Known Exploted Vulnerabilities) list.

We use git as a distribution source to build a advisory DB that can be exported to offline devices via USB or any supported file transfer interface.

Not done: Explore beyond USB for file transfer protocols and also see what OT devices really work like.

## Architecture

![architecture of local advisory index](/docs/local-advisory-arch.png)


## End users

![swimlane diagram of end users](/docs/local-advisory-swimlane.png)

## Running it

To use the index CI publishes, see [Verifying the index](#verifying-the-index). The commands below build and sign one yourself
(online side; no GitHub access, or your own key). Use a key directory other than `keys/` for local experiments, or you
overwrite the project's `keys/index-signing.pub`; an index you sign yourself is for local demos only.

```
mvn package                                                 # builds + tests -> target/reconnics-ng.jar
java -jar target/reconnics-ng.jar keygen --keys keys              # once, on the online side
java -jar target/reconnics-ng.jar build-index --sign-key keys/index-signing.key   # -> data/index.json(.sig)
# copy data/index.json, data/index.json.sig to the offline side (pubkey copied once, separately)
java -jar target/reconnics-ng.jar match --index data/index.json --pubkey keys/index-signing.pub --format html --out report.html docs/examples/assets.json
java -jar target/reconnics-ng.jar serve --index data/index.json --pubkey keys/index-signing.pub   # ingest API for the PCAP project
```

Plan and connector design: [docs/plan.md](docs/plan.md). Ingest contract for the PCAP project: [docs/ingest-api.md](docs/ingest-api.md).

## Implementation progress

- [x] Plan architecture - Dataflow Level 1
- [ ] Plan architecture - Swimlane Diagram
- [x] CSAF OT mirror + KEV -> signed local advisory index (Java)
- [x] EXACT / PROBABLE / POSSIBLE / NONE matcher, JSON/CSV/HTML reports
- [x] Loopback ingest API for the PCAP project
- [x] PCAP parser and advisory matcher in one jar; `analyze --post` feeds the ingest API
- [ ] CSAF PGP signature verification, staleness warning, vendor aliases (see docs/plan.md)
