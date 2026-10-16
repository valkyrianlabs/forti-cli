---
title: Client certificates
description: Require a client certificate for the REST API user. forti configure makes or reuses one and prints the FortiGate commands; forti cert lists, renews, shares and removes them.
order: 35
status: published
tags:
  - guides
---

# Client certificates

FortiOS can require a client certificate from a REST API user on top of its API key (PKI, or
"peer", authentication). forti makes the certificate, keeps it in the forti home, and prints the
FortiGate commands that make the device require it, ready to paste.

The quickest way is `forti configure`: answer **y** to *Use a client certificate?* and forti does the
rest, including a connection check once the FortiGate is set up. `forti cert` does the same steps on
their own, for scripts and for managing certificates later.

:::toc[On this page]{depth="2" theme="compact"}
:::

## How forti organizes certificates

- **Certificates are named and need no profile.** Each one lives in `~/.forti/certs/<name>/`. A
  profile points at one, and several profiles can share one: a single certificate can serve every
  FortiGate you manage.
- **The forti CA issues them.** On first use forti makes a private CA in `~/.forti/ca/`. A FortiGate
  imports the forti CA once and then accepts any forti certificate you register on it. Renewing a
  certificate needs no change on the FortiGate.
- **A certificate can have its own CA instead** (`--own-ca`, or *with a CA of its own* in
  `forti configure`), for a certificate the other FortiGates must never accept.

The client's name on the FortiGate is its CN, `forti-<name>`. The FortiGate accepts a certificate only
when its PKI user names both the CA and that CN.

## Before you start

- **The `openssl` command** on `PATH`. forti runs it to make the keys and certificates (with an
  argument vector, never a shell). OpenSSL 3 and macOS's built-in `/usr/bin/openssl` (LibreSSL) both
  work. The Debian package depends on `openssl`.
- **Administrator access to the FortiGate CLI**, to import the CA and enable peer authentication for
  the API user.

## With forti configure

`forti configure` asks about the client certificate after the API key:

```text
Use a client certificate? (y/N): y
Reuse a certificate you already have? (Y/n): n

New certificate:
  1) issued by the forti CA (recommended: a FortiGate imports the forti CA once and then
     accepts every certificate it issues)
  2) with a CA of its own (the FortiGate imports that CA as well)
  3) a PKCS#12 file I already have
choice [1]:
Certificate name [fw01]:
Making the certificate... done: ~/.forti/certs/fw01 (and the forti CA, ~/.forti/ca)
```

When you already have certificates, forti lists them first. Press Enter to reuse the first one, or
type its number, or `0` for a new one:

```text
Reuse a certificate you already have? (Y/n):

  1) fw01  forti CA, until 2029-10-15; used by fw01
  2) lab   own CA, until 2027-03-02; used by lab
  0) none of these: create a new one
Certificate [1]:
```

Before checking the connection, forti prints the FortiGate commands for that certificate and waits:

```text
Press Enter when the FortiGate is ready, to check the connection (s: save without checking):
```

Paste the commands into the FortiOS CLI ([Set up the FortiGate](#set-up-the-fortigate)), then press
Enter. The check then proves the API key and the certificate work together. Type `s` to save the
profile without checking, and run `forti doctor` later.

A certificate made during `forti configure` is kept even if the check fails, so you do not redo the
FortiGate steps: choose it again (*reuse*) when you rerun `forti configure`. On an existing profile,
forti asks *Keep the client certificate?* first.

Scripts use `--cert NAME` instead of the prompts:

```sh
forti configure --profile fw02 --host fw02.example.net --api-key-env FW02_KEY --cert fw01
```

## With forti cert

```sh
forti cert create fw01                    # a certificate named fw01, issued by the forti CA
forti cert create --profile fw01          # the same, and profile fw01 uses it now
forti cert create edge --own-ca           # a certificate with a CA of its own
forti cert use fw01 --profile fw02        # profile fw02 uses certificate fw01 too
```

`forti cert create` without a name creates one named after the default profile and makes that
profile use it. With no profile at all it creates a certificate named `default`. It prints the files,
the command that reads the password, and the FortiGate commands.

| Option | Meaning |
|---|---|
| `--profile NAME` | the profile that uses the new certificate (it must exist) |
| `--own-ca` | a CA for this certificate only, instead of the forti CA |
| `--days N` | validity, 1 to 36500 days (default 1095). A certificate from the forti CA cannot outlive the CA (20 years) |
| `--force` | replace an existing certificate of that name (see [Renew](#renew)) |
| `--keychain` | keep the password in the secret store of `--profile` instead of `client.pass` |

Everything is generated in a private staging directory and renamed into place at the end, so a failure
leaves the previous certificate (or nothing) behind, never half a set. Keys are RSA 3072 and
signatures SHA-256 throughout.

## The files

All in the [forti home](/reference/configuration-files#the-forti-home):

| File | Mode | Contents |
|---|---|---|
| `ca/ca.crt` | 0644 | the forti CA's certificate: what a FortiGate imports |
| `ca/ca.key` | 0600, directory 0700 | the forti CA's private key. It never leaves this machine |
| `certs/<name>/ca.crt` | 0644 | the certificate's CA (a copy of the forti CA's, or its own) |
| `certs/<name>/ca/ca.key` | 0600, directory 0700 | with `--own-ca` only: that CA's private key |
| `certs/<name>/client.crt` | 0644 | the client certificate |
| `certs/<name>/client.p12` | 0600 | the client certificate, its private key and the CA: a profile's `client_cert` |
| `certs/<name>/client.pass` | 0600 | the `.p12` password, one line of random hex: a profile's certificate password |

The client's private key exists only inside `client.p12`. The bundle is encrypted with
PBE-SHA1-3DES and a SHA-1 MAC, which OpenSSL 3 (without the legacy provider), LibreSSL, libcurl and
FortiOS all read. `forti mcp install` denies AI agents in the forti home every one of these private
files.

### The password

forti never prints the password. Its output shows the command that reads it instead:

```sh
cat ~/.forti/certs/fw01/client.pass
```

You need it only when another tool opens `client.p12` (a browser, to test the certificate by hand).
Profiles read it from the file through the `file` credential source.

With `--keychain`, forti keeps the password in the secret store and writes no `client.pass`: the macOS
Keychain (service `forti`, account `fw01/cert-password`), or the 0600 file store on Linux and with
`FORTI_SECRET_STORE=file`. Another profile that reuses the certificate gets its own copy in the store.
A password in the secret store is [bound to the profile's device](/guides/profiles-and-credentials#credential-sources),
like a stored API key.

## Set up the FortiGate

forti prints these commands with the names filled in, and the CA certificate inline. The examples below
are for certificate `fw01` issued by the forti CA. Run them in the FortiOS CLI.

:::steps{
  variant="cards"
  layout="stack"
  numbered
  stepTheme="muted"
}

### Import the CA certificate

Once per FortiGate for the forti CA: skip this step when the device already has it. forti names it
`forti-ca-<id>`, from the CA's own name, so the forti CAs of different machines never clash.

```text
config vpn certificate ca
    edit "forti-ca-716e5208"
        set ca "-----BEGIN CERTIFICATE-----
MIIE...
-----END CERTIFICATE-----"
    next
end
```

Imported in the GUI instead, the CA gets a name such as `CA_Cert_1`. Use that name in the next step.

:::callout[Only the CA certificate goes to the FortiGate]{variant="warning"}
Never copy `ca.key`, `client.p12` or `client.pass` to the device. Anyone with a CA key can issue
certificates the FortiGate accepts.
:::

### Create the PKI user and peer group

```text
config user peer
    edit "forti-fw01"
        set ca "forti-ca-716e5208"
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
for long certificate names. The `cn` is always the certificate's CN.

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

`forti configure` checks it when you press Enter. Otherwise:

```sh
forti doctor --profile fw01
```

`tls_files` checks that the certificate is readable, then `connection` and `auth` make one read of the
device. Authentication failures are never retried, because FortiOS locks out an API user after
repeated failures. If `auth` fails, check the three steps above before running it again.

:::

forti-mcp reads the same profiles, so the AI tools present the certificate too.

## List and inspect

```sh
forti cert list
forti cert show fw01
```

`list` shows the forti CA (its FortiGate name and expiry) and every certificate with its issuer,
expiry and the profiles using it. `show` prints the subject, issuer, expiry (and days left) and
SHA-256 fingerprint, each file with its mode, and, for each profile using it, where the password comes
from. Without a name, `show` picks the certificate of `--profile` or the default profile. An expired
certificate is marked `EXPIRED`.

## Renew

```sh
forti cert create fw01 --force
```

For a certificate issued by the forti CA, the new certificate has the same CA and the same CN, so
**the FortiGate needs no change**: profiles using it keep working. The old files are moved aside and
deleted only once the new ones are in place.

A certificate with its own CA gets a new CA too (`--own-ca --force`). The FortiGate does not accept
it until you import the new CA and make the PKI user's `ca` name it, so renew it in a maintenance
window, well before the old certificate expires.

Without `--force`, `forti cert create` refuses a name that exists:

```text
forti: error: a certificate named "fw01" already exists; nothing was changed
  hint: use it as it is (forti cert use fw01), or replace it: forti cert create fw01 --force
```

## Share, rename and remove

- `forti cert use fw01 --profile fw02` points another profile at a certificate. Register it on that
  profile's FortiGate with steps 2 and 3 above (and step 1 if the device does not have the CA yet).
- `forti profile rename fw01 edge` renames `certs/fw01/` to `certs/edge/` with it and updates every
  profile that pointed there. The certificate keeps CN `forti-fw01`, so the FortiGate needs no change.
- `forti profile copy fw01 fw02` copies settings only, never the certificate. Give the copy one with
  `forti cert use` or `forti configure --profile fw02`.
- `forti cert remove fw01` deletes `certs/fw01/` and detaches it from every profile that used it
  (deleting passwords kept in the secret store). If an API user still has `peer-auth` enabled, those
  profiles cannot connect until they get another certificate or `peer-auth` is disabled on the
  FortiGate. The forti CA stays.

## Using your own certificate

A PKCS#12 bundle from your own PKI works too: choose *a PKCS#12 file I already have* in
`forti configure`, or point the profile at it and at its password:

```sh
forti configure --profile fw01 --client-cert ~/pki/fw01.p12 --cert-password-file ~/pki/fw01.pass
```

`--cert-password-file PATH` uses the `file` credential source, as forti's own certificates do:

- the path is stored as an absolute path, and the file's first line is the password;
- the file must be a regular file (not a symbolic link) that you own, with no access for group or
  others. Fix it with `chmod 600`. forti checks this when you configure the profile and on every use;
- like environment and command sources, a file source is not bound to the device.

The password can also come from `--cert-password-stdin`, `--cert-password-env VAR` or
`--cert-password-command CMD`; see [Credential sources](/guides/profiles-and-credentials#credential-sources).
In `config.json` the file source is `{"source": "file", "path": "/absolute/path"}`.
