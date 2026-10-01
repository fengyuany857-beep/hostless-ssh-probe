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

## P0 finding: authentication and shell-startup state are user-writable

Direct writeability probes returned:

```text
/home/vcwrunner                              write=yes
/home/vcwrunner/.ssh                         write=yes
/home/vcwrunner/.ssh/authorized_keys         write=yes
```

Effective sshd settings for `vcwrunner` before remediation include:

```text
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
passwordauthentication yes
pubkeyauthentication yes
permituserrc yes
permittty yes
allowtcpforwarding yes
disableforwarding no
x11forwarding yes
authenticationmethods any
```

The current key's inline `restrict` option does disable forwarding/PTY/user rc for that key, but the authentication source itself is owned and writable by the target account.

Because Runner intentionally permits powerful executables such as `python3` and `node`, a caller that reaches an allowed exec action could modify `~/.ssh/authorized_keys` or shell startup files outside `VCW_PROJECT_ROOT`. It could then create persistent account-level behavior or add another SSH key without the current inline restrictions.

Therefore the earlier least-privilege PASS is retracted.

Current target-account isolation state: FAIL / P0 until the authentication source and shell startup state are removed from `vcwrunner` write control.

## Proposed hardening, syntax-validated but not applied

A temporary sshd configuration was syntax-checked successfully with this user-specific policy:

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

The effective temporary configuration resolved to the expected user-specific values.

Required filesystem side of the remediation:

- move/copy the accepted public key to a root-owned file outside the user's writable home;
- make `/home/vcwrunner` and its shell startup/SSH metadata root-owned and non-writable by `vcwrunner`;
- keep `/srv/vcw-runner-test` writable by `vcwrunner`;
- validate `sshd -t` before reload;
- prove a new key-authenticated `vcwrunner` SSH command still works after reload;
- prove `vcwrunner` can no longer modify the authentication source or shell startup state.

Runner code now prepares for an unwritable real home by setting command `HOME`, XDG cache, and npm cache to protected project-local Runner metadata before invoking tool commands. A real-host regression must be rerun after the account hardening is applied.

## Toolchain compatibility precheck

With command `HOME` and caches pointed to project-local Runner metadata, the target account successfully executed:

```text
git version 2.43.0
Python 3.12.3
v20.20.2
npm 10.8.2
npx 10.8.2
```

A before/after metadata snapshot showed no change under the real `/home/vcwrunner` during that precheck.

## Process sharing

At verification time, `ps -u vcwrunner` returned no unrelated running processes.

## Remaining limits

- argv execution is not a filesystem sandbox;
- sampled inaccessible paths do not prove the absence of every world-readable host path;
- the hardening configuration above has been syntax/effective-config tested only, not applied;
- this evidence is point-in-time and must be rechecked after any account, sshd, key, group, sudoers, project ownership, or deployment-topology change.

## Conclusion

Current target-account isolation terminal state: BLOCKED by the user-writable SSH authentication/home boundary.

Do not freeze Runner v1 until the P0 is remediated and independently read back.
