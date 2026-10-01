# VCW Remote Runner target-account isolation evidence

Evidence date: 2026-10-01
Target role: acceptance VPS for `VCW_SERVER_ID=test-vps-1`
Verification tier: direct read-only observation on the target VPS
Scope: Unix account / filesystem privilege boundary only

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

## Sudo

Direct query:

```text
User vcwrunner is not allowed to run sudo on instance-X6fwAZMl.
```

Result: PASS for the acceptance target.

## Project and SSH metadata permissions

Direct filesystem metadata:

```text
vcwrunner vcwrunner 755 /srv/vcw-runner-test
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

## Process sharing

At verification time, `ps -u vcwrunner` returned no running processes.

Result: no unrelated long-lived process was observed sharing the Runner target identity at that instant.

## Conclusion

Within this bounded read-only check, the acceptance target satisfies the intended least-privilege account baseline:

- dedicated non-root user;
- no sudo;
- no supplementary admin/docker groups;
- no access to sampled root/system secret locations or Docker sockets;
- write access to the intended acceptance project;
- restricted SSH authorized-key option and narrow SSH metadata permissions.

Remaining unknowns:

- this is not a proof that no world-readable non-secret host path exists outside the project;
- argv execution is not a filesystem sandbox;
- the result is point-in-time and must be rechecked if the account, groups, sudoers, SSH key options, project ownership, or deployment topology changes.
