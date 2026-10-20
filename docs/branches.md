# Branch inventory

Snapshot taken 2026-10-20 against `origin/main` (5680de3). "Ahead" is `git rev-list --count origin/main..<branch>`;
`git cherry` found no patch-equivalent-only commits, so every branch with "ahead 0" is a plain ancestor of `main`
(its commits are in main's history under the same SHAs, nothing was squashed away). No branch has been deleted.

| Branch | Where | Ahead of main | Class | Notes |
|---|---|---|---|---|
| `main` | local + origin | 0 | MERGED | Same commit as `origin/main`. |
| `integration` | local (stale, 1169404) + origin (d5c3a71) | 0 | MERGED | Origin tip is in main; the local copy is just behind. Used to stage `feature/ui`, `yashash/lab-and-labels`, `merge/feature-ui-into-main` before they reached main. |
| `feature/ui` | local + origin | 0 | MERGED | Site console UI. Landed through `integration`, not through a PR. |
| `merge/feature-ui-into-main` | local + origin | 0 | MERGED | PR #9. Includes the EndToEndAnalysisTest ENIP/S7 CI fix. |
| `test/vineeth-ui-unit-tests` | origin | 0 | MERGED | UI unit tests (`src/test/ui`), merged by e06565e. |
| `fix/main-ci` | origin | 0 | MERGED | PR #10. |
| `yashash/ingest-413-fix` | origin | 0 | MERGED | PR #11. |
| `yashash/lab-and-labels` | origin | 0 | MERGED | PR #7. Simulated lab captures and advisory labels (also merged via `integration`). |
| `feature/sriganesh` | origin | 0 | MERGED | PR #8 (ENIP/S7 end-to-end identity tests). |
| `yashash/dev` | origin | 0 | MERGED | PR #1. |
| `yashash/plan-deliverables` | origin | 0 | MERGED | PR #6. |
| `yashash/fix-advisory` | origin | 0 | MERGED | PR #5. |
| `yashash/fix-advisory-pr1` | origin | 0 | MERGED | PR #3 (PR #4 was merged into it). |
| `yashash/fix-advisory-pr2` | origin | 0 | MERGED | PR #4 (merged into pr1). |
| `yashash/fix-parser` | origin | 0 | MERGED | PR #2. Parser fixes P1-P11. |
| `feat/add-cve-management` | local + origin | 0 | MERGED | Advisory index, matcher, ingest API, Maven build. Nothing unmerged. |
| `feature/pcap-reader` | origin | 0 | MERGED / SUPERSEDED | Fully in history. The prototype `com.reconnics.*` packages it added were later replaced by `com.pcap.*` on main, so a diff against main shows them as "missing"; that is intentional, not lost work. |
| `backup/pre-squash` | local only | 4 | BACKUP/ARCHIVE | The four commits before `feat/add-cve-management` was squashed. Its tree is byte-identical to `origin/feat/add-cve-management` (empty `git diff`), so nothing is lost by keeping or deleting it. |
| `deploy/github-actions` | local only | 1 (0bfa998) | HAS-UNMERGED-WORK, now merged into `consolidate/main-2026-10` | Signed advisory index workflow, `verify` command, `SignatureTest`, `docs/deployment.md`, committed `keys/index-signing.pub`. See the merge commit for the conflict resolution and the custody caveat below. |
| `worktree-agent-*` | local | 0 | ARCHIVE | Scratch branches of Claude worktrees, at main. Safe to remove with their worktrees. |
| `consolidate/main-2026-10` | local only | main + 4 | NEW | This consolidation branch: deploy/github-actions merge, review fixes, this file. |

## Notes on `deploy/github-actions`

- `AdvisoryCli` conflicted with main's `(--pubkey | --insecure-no-verify)` usage; main's behaviour kept, `verify` added.
- The workflow's schedule is commented out. It signs in CI with the private key as an Actions secret, but
  `docs/plan.md` ("Signing key custody") says the key is never in CI. The team has to pick one; see the note in `plan.md`.
- `keys/index-signing.pub` is committed (SHA-256 `8feb23a7...5527`); README still says the fingerprint is TBD until a holder is named.
