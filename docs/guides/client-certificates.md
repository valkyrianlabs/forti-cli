---
title: Client certificates
description: Require a client certificate for the REST API user with forti cert create, set up the FortiGate side, and renew, inspect or remove the certificate.
order: 35
status: published
tags:
  - guides
---

# Client certificates

FortiOS can require a client certificate from a REST API user on top of its API key (PKI, or
"peer", authentication). `forti cert create` makes everything forti needs for that in one command: a
private CA, a client certificate signed by it, and the PKCS#12 bundle the profile presents. It then
prints the exact FortiGate commands that trust the certificate.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Before you start

- **A working profile.** Create it first with `forti configure` ([Profiles and credentials](/guides/profiles-and-credentials)).
  `forti cert create` refuses a profile that does not exist.
- **The `openssl` command** on `PATH`. forti runs it to make the keys and certificates (with an
  argument vector, never a shell). OpenSSL 3 and macOS's built-in `/usr/bin/openssl` (LibreSSL) both
  work. The Debian package depends on `openssl`.
- **Administrator access to the FortiGate CLI**, to import the CA and enable peer authentication for
  the API user.

## Create the certificate

```sh
forti cert create --profile fw01
```

Without `--profile`, forti uses the default profile. It makes:

- a private CA (`O=forti, CN=forti-fw01 CA`), valid for at least 3650 days;
- a client certificate with CN `forti-<profile>` (here `forti-fw01`), signed by that CA, valid for
  `--days` days (default 1095);
- RSA 3072 keys and SHA-256 signatures throughout.

Everything is generated in a private staging directory and renamed into place at the end, so a failure
leaves the previous certificate (or nothing) behind, never half a set. The profile then points at the
result: `client_cert` becomes `client.p12`, and the certificate password is read from `client.pass`.

| Option | Meaning |
|---|---|
| `--profile NAME` | the profile to make the certificate for (default: the default profile) |
| `--days N` | client certificate validity, 1 to 36500 days (default 1095; the CA gets at least 3650) |
| `--force` | replace an existing CA and certificate (see [Renew or replace](#renew-or-replace)) |
| `--keychain` | keep the password in the secret store instead of `client.pass` |

### The files

Everything lives in `~/.forti/certs/<profile>/` (in the [forti home](/reference/configuration-files#the-forti-home)):

| File | Mode | Contents |
|---|---|---|
| `ca.crt` | 0644 | the CA certificate: the only file the FortiGate needs |
| `ca/ca.key` | 0600, directory 0700 | the CA's private key. It never leaves this machine |
| `client.crt` | 0644 | the client certificate |
| `client.p12` | 0600 | the client certificate, its private key and the CA: the profile's `client_cert` |
| `client.pass` | 0600 | the `.p12` password, one line of random hex: the profile's certificate password |

The client's private key exists only inside `client.p12`. The bundle is encrypted with
PBE-SHA1-3DES and a SHA-1 MAC, which OpenSSL 3 (without the legacy provider), LibreSSL, libcurl and
FortiOS all read.

### The password

forti never prints the password. Its output shows the command that reads it instead:

```sh
cat ~/.forti/certs/fw01/client.pass
```

You need it only when another tool opens `client.p12` (a browser, to test the certificate by hand).
The profile reads it from the file itself, through the `file` credential source (see
[Using your own certificate](#using-your-own-certificate)).

With `--keychain`, forti keeps the password in the secret store and writes no `client.pass`: the macOS
Keychain (service `forti`, account `fw01/cert-password`), or the 0600 file store on Linux and with
`FORTI_SECRET_STORE=file`. The printed command then reads it from there:

```sh
security find-generic-password -s forti -a fw01/cert-password -w   # macOS Keychain
sed -n 2p ~/.forti/credentials/fw01.cert-password                  # file store
```

A password in the secret store is [bound to the profile's device](/guides/profiles-and-credentials#credential-sources),
like a stored API key.

## Set up the FortiGate

`forti cert create` prints these steps with the names for your profile filled in. The examples below
are for profile `fw01`. Run them in the FortiOS CLI.

:::steps{
  variant="cards"
  layout="stack"
  numbered
  stepTheme="muted"
}

### Import the CA certificate

Paste the PEM of `ca.crt` (the output of `cat ~/.forti/certs/fw01/ca.crt`) between the quotes:

```text
config vpn certificate ca
    edit "forti-fw01-ca"
        set ca "<paste the output of: cat ~/.forti/certs/fw01/ca.crt>"
    next
end
```

Imported in the GUI instead, the CA gets a name such as `CA_Cert_1`. Use that name in the next step.

:::callout[Only ca.crt goes to the FortiGate]{variant="warning"}
Never copy `ca/ca.key`, `client.p12` or `client.pass` to the device. Anyone with the CA key can issue
certificates the FortiGate accepts.
:::

### Create the PKI user and peer group

```text
config user peer
    edit "forti-fw01"
        set ca "forti-fw01-ca"
        set cn "forti-fw01"
    next
end
config user peergrp
    edit "forti-fw01-peers"
        set member "forti-fw01"
    next
end
```

FortiOS limits PKI user and peer group names to 35 characters, so forti shortens the names it prints
for long profile names. The `cn` is always the certificate's CN.

### Require the certificate for the API user

Put the name of your REST API administrator in place of `<api-user>`:

```text
config system api-user
    edit "<api-user>"
        set peer-auth enable
        set peer-group "forti-fw01-peers"
    next
end
```

From now on, the API user's key works only together with a certificate from that peer group.

### Check the connection

```sh
forti doctor --profile fw01
```

`tls_files` checks that the certificate is readable, then `connection` and `auth` make one read of the
device. Authentication failures are never retried, because FortiOS locks out an API user after
repeated failures. If `auth` fails, check the three steps above before running it again.

:::

forti-mcp reads the same profile, so the AI tools present the certificate too.

## Inspect it

```sh
forti cert show --profile fw01
```

Shows the subject, expiry (and days left) and SHA-256 fingerprint of the client and CA certificates,
each file with its mode, whether the profile uses this certificate, and the command that reads its
password. An expired certificate is marked `EXPIRED`.

## Renew or replace

`forti cert create` refuses to replace an existing CA, because a FortiGate may trust it:

```text
forti: error: profile fw01 already has a CA (~/.forti/certs/fw01/ca/ca.key); nothing was changed
  hint: a FortiGate may trust it: pass --force to replace it, then import the new ca.crt there
```

To renew, check the expiry with `forti cert show`, then:

```sh
forti cert create --profile fw01 --force
```

`--force` makes a new set: a new CA **and** a new client certificate (with `--days` as before). The old
set is moved aside and deleted only once the new one is in place. Because the CA is new, the FortiGate
does not trust the new certificate until you follow the printed steps again: import the new `ca.crt`
and make the PKI user's `ca` name it. Until then the profile cannot connect, so renew in a maintenance
window, well before the old certificate expires.

## Renaming, copying and removing

- `forti profile rename fw01 edge` moves `certs/fw01/` to `certs/edge/` and updates the profile's
  paths. The certificate keeps CN `forti-fw01`, so the FortiGate needs no change.
- `forti profile copy fw01 fw02` copies settings only, never the certificate. Run
  `forti cert create --profile fw02` for the new device.
- `forti cert remove --profile fw01` deletes `certs/fw01/`. When the profile used that certificate, it
  also clears the profile's client certificate and password (and deletes a password kept in the secret
  store). If the API user still has `peer-auth` enabled, the profile cannot connect until you create a
  new certificate or disable `peer-auth` on the FortiGate.

## Using your own certificate

A PKCS#12 bundle from your own PKI works too. Point the profile at it, and at its password:

```sh
forti configure --profile fw01 --client-cert ~/pki/fw01.p12 --cert-password-file ~/pki/fw01.pass
```

`--cert-password-file PATH` uses the `file` credential source, the same one `forti cert create` sets up:

- the path is stored as an absolute path, and the file's first line is the password;
- the file must be a regular file (not a symbolic link) that you own, with no access for group or
  others. Fix it with `chmod 600`. forti checks this when you configure the profile and on every use;
- like environment and command sources, a file source is not bound to the device.

The password can also come from `--cert-password-stdin`, `--cert-password-env VAR` or
`--cert-password-command CMD`; see [Credential sources](/guides/profiles-and-credentials#credential-sources).
In `config.json` the file source is `{"source": "file", "path": "/absolute/path"}`.
