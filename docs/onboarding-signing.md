# Commit signing — one-page onboarding

`main` on every Flux Point Studios public repo is protected so that **every commit must be cryptographically signed**. If your local git isn't set up for signing, your next push to a branch will be accepted, but the eventual squash-merge will go through with only the GitHub-side signature, and any direct merge commit you try will be rejected.

This page is the one paste that gets a fresh machine signing-ready.

## Repos under this rule

| Repo | URL |
|---|---|
| materios-intent-settlement | <https://github.com/Flux-Point-Studios/materios-intent-settlement> |
| materios | <https://github.com/Flux-Point-Studios/materios> |
| materios-operator-kit | <https://github.com/Flux-Point-Studios/materios-operator-kit> |

All three enforce: PR required (no direct push to main), CI status check required, no force push, no deletion, conversation resolution required, **signed commits required**.

## Setup (one paste, ~2 minutes)

```bash
# 1. Pick an SSH key to use for signing. If you already use one for auth, the
#    same key works; otherwise generate a dedicated one:
#       ssh-keygen -t ed25519 -C "you@machine" -f ~/.ssh/id_ed25519_signing
#    Add it to ssh-agent so signing is non-interactive:
#       ssh-add ~/.ssh/id_ed25519_signing

# 2. Configure git globally for SSH signing.
#    user.email must be a *verified* email on your GitHub account, or a
#    `<numeric-id>+<username>@users.noreply.github.com` (always implicitly
#    verified, recommended for privacy). You can find the noreply form
#    under https://github.com/settings/emails.
SIGNING_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)"   # or whichever key you picked
GH_EMAIL="<numeric-id>+<username>@users.noreply.github.com"
git config --global gpg.format ssh
git config --global user.signingkey "$SIGNING_PUBKEY"
git config --global user.email "$GH_EMAIL"
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# 3. Tell git which keys it should trust for *verification* (so
#    `git log --show-signature` works locally on your own commits).
EMAIL="$(git config --global user.email)"
echo "$EMAIL $SIGNING_PUBKEY" >> ~/.ssh/allowed_signers
chmod 600 ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers

# 4. Register the same public key with GitHub as a *signing* key (not just
#    an auth key — these are separate lists in GitHub). Needs the
#    admin:ssh_signing_key scope on your gh CLI:
gh auth refresh -h github.com -s admin:ssh_signing_key
gh api --method POST user/ssh_signing_keys \
  --field title="$(hostname) (commit signing)" \
  --field "key=$SIGNING_PUBKEY"

# 5. Smoke test:
( cd "$(mktemp -d)" && git init -q && git commit --allow-empty -m 'signing test' \
  && git log -1 --show-signature 2>&1 | grep -E '^(Good|commit)' )
# You should see:
#   commit <sha>
#   Good "git" signature for <email> with ED25519 key SHA256:...
```

## Verify on github.com

Push any branch and open it in the GitHub UI. Each commit should show a green **Verified** badge next to the SHA. If a commit shows **Unverified** instead, check the JSON `verification` block on the commit (`gh api repos/.../commits/<sha>` → `.commit.verification`). Common `reason` values:

- *`unknown_key`* → the signing pubkey isn't registered as a **signing** key on your GitHub account (auth keys don't count — they're a separate list under Settings → SSH and GPG keys). Re-do step 4.
- *`no_user`* → the committer email (`git config user.email`) is **not a verified email on your GitHub account**. This is the single most common gotcha. Use one of:
  - your GitHub-noreply email: `<numeric-id>+<username>@users.noreply.github.com` (always implicitly verified, recommended for privacy)
  - any email you've added under Settings → Emails and clicked the verification link in
- *`bad_email`* → email looks right but the `allowed_signers` file you supplied to git doesn't map this email → key. Update `~/.ssh/allowed_signers` to list every email you might commit as.
- *`expired_key` / `not_signing_key`* → the key on GitHub doesn't have the "Signing Key" flag. Some older entries are auth-only; re-add with `gh api --method POST user/ssh_signing_keys ...` or in the web UI under SSH and GPG keys → New SSH key → key type Signing Key.

To check before you push: `git log -1 --show-signature` shows local verification; `gh api repos/<owner>/<repo>/commits/HEAD --jq .commit.verification` shows what GitHub thinks.

## Multi-machine

The setup above is per-machine. If you commit from Gemtek and a MacBook and Node-3, each one needs:

1. Its own SSH key pair (or share a private key — *don't*, generate per-machine).
2. Its own `git config` block from step 2.
3. Its own pubkey registered as a GitHub signing key from step 4. GitHub allows multiple signing keys per account — list them via `gh api user/ssh_signing_keys`.

The verification email + pubkey mapping in `~/.ssh/allowed_signers` only needs to know the local machine's key; it's not shared.

## CI / squash-merge interaction

You don't need to do anything special for squash-merges. When you click **Merge** on a PR or run `gh pr merge --squash`, GitHub creates the merge commit on `main` server-side and signs it with its own key (`committer: GitHub <noreply@github.com>`, PGP signature). That's accepted as "verified" by the `required_signatures` rule.

The signing setup above is what makes your **branch commits** show as Verified before they're merged — operationally cosmetic, but a clean trail for reviewers.

## Disabling temporarily

Don't. If you have to skip signing for an emergency commit, use `git commit --no-gpg-sign`, then sign again on the merge commit. Don't disable the branch protection rule — the value is that it's always on.

## See also

- [CONTRIBUTING.md](../CONTRIBUTING.md) — general PR / review workflow
- [SECURITY.md](../SECURITY.md) — vulnerability disclosure
- GitHub docs on SSH signing: <https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-signature-verification>
