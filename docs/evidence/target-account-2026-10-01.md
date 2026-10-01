# VCW Remote Runner target-account isolation evidence

Evidence date: 2026-10-01
Target role: acceptance VPS for `VCW_SERVER_ID=test-vps-1`
Verification tier: direct read-only observation on the target VPS
Scope: Unix account / filesystem / SSH-account privilege boundary only

This file does not prove the current Hostless Runner build, RPC behavior, PostgreSQL persistence, host-key negative injection, rate limiting, or audit redaction. Those remain separate acceptance gates.

## Observed account identity

```text
vcwrunner:x:1001:1001::/home/vcwrunner:/bin/bash
uid=1001(vcwrunner) gid=1001(vcwrunner) groups=1001(vcwrunner)
```

Observed:

- dedicated `vcwrunner` account exists;
- no supplementary groups were present;
- the account is not in a docker/admin-equivalent group.

## Sudo and password status

Direct query:

```text
User vcwrunner is not allowed to run sudo on instance-X6fwAZMl.
vcwrunner L ...
```

Result:

- no sudo;
- Unix password is locked.

## Project and SSH metadata permissions

Direct filesystem metadata:

```text
vcwrunner vcwrunner 755 /srv/vcw-runner-test
vcwrunner vcwrunner 750 /home/vcwrunner
vcwrunner vcwrunner 700 /home/vcwrunner/.ssh
vcwrunner vcwrunner 600 /home/vcwrunner/.ssh/authorized_keys
```

The authorized-key line begins with:

```text
restrict ssh-ed25519
```

The public key body is intentionally not recorded in this evidence file.

## Effective access probes as vcwrunner

```text
/root                read=no  write=no
/root/.ssh           read=no  write=no
/etc/shadow          read=no  write=no
/etc/sudoers         read=no  write=no
/var/run/docker.sock read=no  write=no
/run/docker.sock     read=no  write=no
/srv                 read=yes write=no
```

Project root:

```text
/srv/vcw-runner-test read=yes write=yes
```

## P0 finding and remediation outcome

Initial read-only audit found that `vcwrunner` could write:

```text
/home/vcwrunner
/home/vcwrunner/.ssh
/home/vcwrunner/.ssh/authorized_keys
```

This made the inline `restrict` option insufficient as a durable account boundary because an allowed interpreter could modify the account's own SSH authentication/startup state.

The finding was treated as P0 and the earlier least-privilege PASS was retracted.

### Applied remediation

Authorized action scope: harden only the `vcwrunner` SSH authentication/home boundary, reload sshd, verify a fresh SSH login, and verify rollback.

Final applied SSH user policy:

```text
Match User vcwrunner
    AuthorizedKeysFile /etc/ssh/vcw-authorized-keys/%u
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    DisableForwarding yes
    PermitTTY no
    PermitTunnel no
    PermitUserRC no
    X11Forwarding no
Match all
```

Final authentication source:

```text
root root 755 /etc/ssh/vcw-authorized-keys
root root 644 /etc/ssh/vcw-authorized-keys/vcwrunner
```

The file is public-key material, not a secret. Mode `0644` is required for sshd's authentication read path on this host while remaining non-writable by `vcwrunner`.

Final real-home state:

```text
root vcwrunner 750 /home/vcwrunner
root root      700 /home/vcwrunner/.ssh
root root      600 /home/vcwrunner/.ssh/authorized_keys
```

Effective writeability as `vcwrunner`:

```text
/home/vcwrunner                              write=no
/home/vcwrunner/.ssh                         write=no
/home/vcwrunner/.ssh/authorized_keys         write=no
/etc/ssh/vcw-authorized-keys/vcwrunner       write=no
/srv/vcw-runner-test                         write=yes
```

The current public-key fingerprint remained:

```text
SHA256:5HYVX64bndjEBFrOWfPBgb64RylwM5Ei3Zz7zHTRz/A
```

The fingerprint was independently matched against the public key derived from the Runner private key before mutation.

### Reload and fresh-login verification

`sshd -t` passed before reload.

After reload:

```text
service = active
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
x11forwarding no
permittty no
permituserrc no
disableforwarding yes
authorizedkeysfile /etc/ssh/vcw-authorized-keys/%u
authenticationmethods publickey
permittunnel no
```

A completely new key-authenticated SSH command succeeded first via `127.0.0.1:22` and then via the actual Runner target address `210.126.235.162:22`.

The remote session observed UID `1001`, no write access to the real home/authentication source, and write access to the intended project root.

Result: PASS.

### First-attempt failure and automatic rollback

The first hardening attempt installed the external public-key file as root-owned `0600`. sshd logged:

```text
Could not open user 'vcwrunner' authorized keys '/etc/ssh/vcw-authorized-keys/vcwrunner': Permission denied
```

The action wrapper detected the failed fresh-login test and automatically restored the original sshd drop-ins and original `/home/vcwrunner`, validated `sshd -t`, and reloaded sshd.

The root cause was confirmed from the sshd journal before retrying. No blind retry was performed.

The second attempt used root-owned `0644` for the public-key file and passed all post-conditions.

### Rollback verification

Successful hardening backup:

```text
/root/vcw-runner-hardening-backup-20261001T121005Z
```

Verified:

- original sshd drop-ins are archived;
- original `/home/vcwrunner` is archived with ownership/modes;
- rollback script passes `bash -n`;
- extracted home backup reproduces the original metadata manifest;
- the backed-up pre-hardening sshd configuration was reconstructed in a temporary tree and passed `sshd -t`;
- rollback does not require the new SSH authentication source to remain present.

Rollback was rehearsed non-destructively after the successful deployment. The successful hardened state was intentionally left active.

## Runner runtime-home compatibility

Runner code prepares for the non-writable real home by setting command `HOME`, XDG cache, and npm cache to project-local Runner metadata before invoking tools.

A direct compatibility precheck with project-local runtime home successfully executed:

```text
git version 2.43.0
Python 3.12.3
v20.20.2
npm 10.8.2
npx 10.8.2
```

The real `/home/vcwrunner` metadata remained unchanged during that precheck.

The corresponding Runner regression test is part of the branch CI.

## Process sharing

At verification time, `ps -u vcwrunner` returned no unrelated running processes.

## Remaining limits

- argv execution is not a filesystem sandbox;
- sampled inaccessible paths do not prove the absence of every world-readable host path;
- the dedicated target account can still write the intended project and normal host temporary areas permitted by Unix permissions;
- this evidence is point-in-time and must be rechecked after any account, sshd, key, group, sudoers, project ownership, or deployment-topology change.

## Conclusion

Current target-account isolation state: PASS within the bounded acceptance scope.

The prior P0 user-writable SSH authentication/home finding is remediated and directly read back.

This evidence closes the target-account isolation gate only. It does not close durable Hostless PostgreSQL persistence, wrong-host-key injection, runtime audit-canary scanning, or final release freeze.
