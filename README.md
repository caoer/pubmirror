# pubmirror

Guards what a private repository publishes: an allowlist manifest, a leak
scanner, git hooks and a publisher that writes the public mirror.

Design: [DESIGN.md](DESIGN.md).

## Adopt

A repository adopts pubmirror in five parts: a manifest and hooks in every
clone, a public repository on GitHub that only the publisher can write, a
pipeline on the forge, and publishes that someone approves. A forge that
serves a canonical repository publicly also runs the forge guard (6).

Names used below:

| Name | Is |
|---|---|
| `OWNER/REPO` | the private repository on the forge |
| `GH_OWNER/REPO` | the public repository on GitHub |
| `REGISTRY` | the host name of the forge's container registry |
| `IMG_OWNER` | the owner of the pubmirror repository on the forge, whose pipeline builds the publisher image |
| `DIGEST` | the publisher image's digest, `sha256:…` |
| `PUBMIRROR_CHECKOUT` | a checkout of this repository; `templates/` paths are relative to it |

The commands assume `gh` logged in as `GH_OWNER`, `woodpecker-cli` configured,
and `WOODPECKER_SERVER` and `WOODPECKER_TOKEN` set.

### 1. The tool and the denylist

- Install pubmirror: `nix profile install .` in `PUBMIRROR_CHECKOUT` (the
  package brings git and gitleaks), or `go build ./cmd/pubmirror` with
  [gitleaks](https://github.com/gitleaks/gitleaks) on `PATH`. The hooks run
  `pubmirror` from `PATH`, or the file `$PUBMIRROR` names.
- Write the denylist, your private values, one per line, to
  `~/.config/pubmirror/denylist.txt`, or to a file you name in
  `PUBMIRROR_DENYLIST` in every shell that commits. Format: DESIGN.md §
  Denylist. Without it every check exits 2 and the hooks only warn.

### 2. The manifest and the hooks

1. Choose a mode. `snapshot`: the private history stays private; each publish
   is one new commit on the public side, and `internal` paths never leave.
   `exact`: the canonical history is itself clean and is pushed as it is;
   `internal` must be empty and every commit's author and committer must be the
   manifest's `author`.
2. Write `.pubmirror.toml` at the repository root (DESIGN.md § Manifest).
   `author` is the identity of the public commits. `[verify]` is optional.
   Every tracked file must be classified. In snapshot mode list the CI files
   other than `.woodpecker/public-mirror.yml`, such as `.woodpecker/`, under
   `internal`. A file under `testdata/` or `defaults/`, and any audio, model,
   archive or binary file, needs a `[[fixture]]` entry: its `path`, its
   `sha256` (`shasum -a 256 FILE`) and a `provenance` saying where it came from
   (DESIGN.md § Scanner rules).
3. `git add` the manifest, then run `pubmirror check --staged` until it prints
   no `unclassified` line and no finding. It reads the index.
4. Commit the manifest and push it to the forge's `main`.
5. Run `pubmirror install` once in each clone. It writes the shims under the
   clone's git directory (not into the tree), covers every worktree of the
   clone, branches that predate the manifest included, and keeps any hooks
   already in `.git/hooks` running. Run it again after adding a hook there.
   To undo: `git config --unset core.hooksPath`.

The hooks run `check --staged` before a commit, `check-msg` on the message
(exact mode), and `guard-push` before a push, which refuses a push to the
manifest's public remote. A hook that cannot run pubmirror (exit 2, or no
binary) warns and lets the commit through: the pipeline is the binding check.

### 3. The public repository

1. Create it empty, with no README, license or `.gitignore`:
   `gh repo create GH_OWNER/REPO --public`.
2. Generate its deploy key outside any repository and add the public half with
   write access. Keep the private half in your secret store; it becomes a CI
   secret in step 4.

   ```sh
   ssh-keygen -t ed25519 -N "" -C "pubmirror publisher" -f deploy_key
   gh repo deploy-key add deploy_key.pub --repo GH_OWNER/REPO --allow-write --title "pubmirror publisher"
   ```

3. Apply the two rulesets. They refuse every branch and tag creation, update
   and deletion to everyone, the owner's own token included; a deploy key is
   the one bypass. (On a private repository rulesets need a paid plan.)

   ```sh
   gh api -X POST repos/GH_OWNER/REPO/rulesets --input templates/github-ruleset-branches.json
   gh api -X POST repos/GH_OWNER/REPO/rulesets --input templates/github-ruleset-tags.json
   ```

4. Turn on secret scanning with push protection (public repositories; a
   private one on a free plan answers 422):

   ```sh
   gh api -X PATCH repos/GH_OWNER/REPO \
     -F 'security_and_analysis[secret_scanning][status]=enabled' \
     -F 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
   ```

### 4. The pipeline

1. Find the publisher image. The pubmirror repository's own pipeline builds it
   (`.woodpecker/image.yml`) on each change to the code; the last line of the
   newest pipeline that ran the `image` workflow names it:
   `woodpecker-cli pipeline log show IMG_OWNER/pubmirror N image | tail -1`
   prints `image REGISTRY/IMG_OWNER/pubmirror@DIGEST`.
2. Copy `templates/public-mirror.yml` to `.woodpecker/public-mirror.yml` and
   put the digest in both image lines (they read `pubmirror@sha256:DIGEST`;
   replace `sha256:DIGEST`). The lines take the registry host and owner from
   the pipeline's variables, so the file names no host; if `IMG_OWNER` is not
   the repository's owner, write it in place of `${CI_REPO_OWNER}`.
3. Activate the repository in Woodpecker. `repo add` takes the forge's id of
   the repository:

   ```sh
   woodpecker-cli repo add $(curl -fsS -H "Authorization: Bearer $WOODPECKER_TOKEN" \
     "$WOODPECKER_SERVER/api/user/repos?all=true" | jq -r '.[] | select(.full_name=="OWNER/REPO") | .forge_remote_id')
   ```

4. If the canonical repository is public (exact mode, for instance), make its
   CI private, or anyone can read its pipeline logs:
   `woodpecker-cli repo update --visibility private OWNER/REPO`.
5. Add the two secrets, both limited to the publisher image. `--image` takes
   the literal image, digest included: Woodpecker resolves the image line
   first and compares the result with this value.

   ```sh
   IMG=REGISTRY/IMG_OWNER/pubmirror@DIGEST
   woodpecker-cli repo secret add --repository OWNER/REPO --name pubmirror_denylist \
     --value @"$HOME/.config/pubmirror/denylist.txt" --event push --event manual --image "$IMG"
   woodpecker-cli repo secret add --repository OWNER/REPO --name pubmirror_deploy_key \
     --value @deploy_key --event manual --image "$IMG"
   ```

   CI hands an image-limited secret only to a plugin step of that image, one
   with no commands, entrypoint or environment, and the image runs nothing but
   `check` and `publish`. A step that runs commands, on any branch, never
   holds the denylist or the key; its pipeline fails before it starts.
   Pull requests run no check: the secrets do not reach that event.
6. Let the publisher read the canonical repository. It fetches `main` itself
   with the pipeline's clone credential, which Woodpecker gives only to images
   the repository trusts for it. No CLI flag sets this:

   ```sh
   ID=$(curl -fsS -H "Authorization: Bearer $WOODPECKER_TOKEN" "$WOODPECKER_SERVER/api/repos/lookup/OWNER/REPO" | jq .id)
   curl -fsS -X PATCH -H "Authorization: Bearer $WOODPECKER_TOKEN" -H 'Content-Type: application/json' \
     "$WOODPECKER_SERVER/api/repos/$ID" -d '{"netrc_trusted":["REGISTRY/IMG_OWNER/pubmirror"]}'
   ```

7. Commit the pipeline file and push. The `check` step runs on every push;
   `publish` runs only on a manual run that carries an approval.

When the image changes, move its digest in the two image lines and in both
secrets' `--image` (`woodpecker-cli repo secret update`, same flags),
together.

### 5. Publish

1. Push the commit X to the forge's `main`. In the private clone, with the
   denylist, stage it: `pubmirror stage --commit X [--out DIR]`. It reads the
   public remote with your own git credentials to find the last published
   tree, and prints the public tree's hash H, the denylist hash D, the diff
   against the last published tree, and the line `approve X:H:D`.
2. Someone other than the author reads the staged tree (`--out DIR` writes it).
3. Start a manual pipeline on `main` with the variable `PUBMIRROR_APPROVE`:
   `woodpecker-cli pipeline create --branch main --var PUBMIRROR_APPROVE=X:H:D OWNER/REPO`
   (or "Run pipeline" in the web interface). The publisher refuses a commit
   that is not on `main`, a tree that no longer hashes to H, and a denylist
   that no longer hashes to D.
4. Check the result: `pubmirror verify --approve X:H:D` clones the public
   repository anonymously, rescans its history and compares the tree with H.
   A repository that cannot be read anonymously gives exit 2.

A path that moves from public to internal leaves the public tip and stays in
public history. Anything that reached GitHub is disclosed: rotate a
credential at once.

### 6. The forge guard

The client hooks can be missing from a clone, and CI runs after the forge has
accepted a push; on a canonical the forge serves publicly, that push is
already public. Install `pubmirror guard-receive` as the pre-receive hook of
the forge that holds the canonical repositories: it refuses a push that
carries a finding before the forge accepts it. Rules per mode: DESIGN.md §
Forge guard.

- Put the denylist on the forge host, readable by the forge's user, and point
  `PUBMIRROR_DENYLIST` at it. It must hash to the same `D` as yours: a clean
  push prints `D` in its summary line.
- Run the hook in every repository. One without a manifest at the pushed tip
  is not judged and needs no denylist.
- Forgejo and Gitea run every executable file in a repository's
  `hooks/pre-receive.d/` alongside their own hook, and keep it there when
  they rewrite their hooks:

  ```sh
  #!/bin/sh
  export PUBMIRROR_DENYLIST=/path/to/denylist.txt
  exec pubmirror guard-receive
  ```

- A refused push shows the findings and the ref on the pusher's terminal as
  `remote:` lines. Rewrite the pushed commits and push again; nothing refused
  reached the forge.

## License

Apache-2.0 (`LICENSE`).
