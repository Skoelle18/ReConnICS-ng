# Deployment: advisory index distribution

There is no server. GitHub Actions builds and signs the index on a schedule, and devices download it from a GitHub release.

```
 CISA CSAF + KEV ──► GitHub Actions (daily, .github/workflows/advisory-index.yml)
                     ├ mvn package
                     ├ build-index --sign-key  (private key from the INDEX_SIGNING_KEY secret)
                     ├ verify against keys/index-signing.pub (committed)
                     └ upload index.json + index.json.sig ──► release "advisory-index"
                                                                    │
                     connected machine: gh release download + verify ◄┘
                                                                    │ USB
                     air-gapped analyst laptop: match / serve / inventory --pubkey ◄┘
```

## One-time setup

1. **Public key in the repo:** `keys/index-signing.pub` is committed. `.gitignore` still excludes `keys/*` and `*.key`, so
   the private key can't be committed by accident.
2. **Private key as a secret:** in repo Settings → Secrets and variables → Actions, add `INDEX_SIGNING_KEY` with the output of
   ```
   base64 -w0 keys/index-signing.key
   ```
   Then keep `keys/index-signing.key` offline, as a backup only. Nothing else needs it.
3. **Merge to `main`.** GitHub only runs scheduled workflows from the default branch. For the first run, use Actions →
   advisory-index → *Run workflow*.

## Getting the index onto a device

The repo is private, so downloads need a GitHub login (`gh auth login`) on the connected machine:

```bash
gh release download advisory-index -R Skoelle18/ReConnICS-ng -D staging --clobber
java -jar reconnics-ng.jar verify --index staging/index.json --pubkey keys/index-signing.pub \
  && mv staging/index.json staging/index.json.sig data/
```

`verify` exits non-zero on a missing, wrong or tampered signature, so a bad download never replaces the current index.
Carry `data/index.json` and `data/index.json.sig` to air-gapped machines. There, `match`, `serve` and `inventory` with
`--pubkey` verify the signature again.

## Security notes

- **The private key exists only as an Actions secret, plus your offline backup.** Workflows from forks don't receive secrets.
  Anyone with write access to this repo can change the workflow and use the key, so keep write access tight. Optionally,
  protect `main` and restrict the secret to an environment that requires approval.
- **Devices trust `keys/index-signing.pub`, not GitHub.** Copy the public key to devices once, out of band. A compromised
  release can only make devices fall behind; they can't be made to accept an index signed by another key.
- **Upload timing:** the two assets are uploaded one after the other. A download in that window gets a mismatched
  pair, `verify` fails, and the next try succeeds.

## Rotating the key

Run `java -jar reconnics-ng.jar keygen --keys newkeys`. Commit the new `.pub` as `keys/index-signing.pub`, replace the
`INDEX_SIGNING_KEY` secret, re-run the workflow, and re-pin the new public key on every device.
