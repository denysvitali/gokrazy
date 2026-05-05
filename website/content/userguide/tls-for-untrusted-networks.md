---
title: "Using TLS in untrusted networks"
weight: 50
---

Let’s assume that you have [installed gokrazy on a Raspberry Pi](/quickstart/)
and are currently successfully updating it over the network like so:

```bash
gok update
```

## Enabling TLS

To start using TLS, edit your gokrazy instance’s `config.json`:

```bash
gok edit
```

In the `config.json`, in the `Update` field, add a `"UseTLS": "self-signed"`
line (don’t forget adding a comma to the previous line):

{{< highlight json "hl_lines=5" >}}
{
    "Hostname": "docs",
    "Update": {
        "HTTPPassword": "secret",
        "UseTLS": "self-signed"
    },
    "Packages": [
        "github.com/gokrazy/fbstatus",
        "github.com/gokrazy/hello",
        "github.com/gokrazy/serial-busybox",
        "github.com/gokrazy/breakglass"
    ]
}
{{< /highlight >}}

Save your changes and close the file, then run a first update with the
`--insecure` flag:

```bash
gok update --insecure
```

The gok CLI will:
* generate a self-signed certificate
* include the certificate in the gokrazy installation
* verify the certificate fingerprint in future updates

On first boot, gokrazy stores TLS certificates on the permanent data partition
as `/perm/ssl/gokrazy-web.pem` and `/perm/ssl/gokrazy-web.key.pem`. On later
boots, certificates in `/perm/ssl` take precedence over certificates included
in the root file system. This keeps the active certificate stable across rootfs
updates and reflashes.

If you distribute images and need each device to generate a unique certificate
on first boot, include the marker file
`/etc/ssl/gokrazy-web.generate-self-signed` in the image:

{{< highlight json "hl_lines=9-13" >}}
{
    "Hostname": "docs",
    "Update": {
        "HTTPPassword": "secret",
        "UseTLS": "self-signed"
    },
    "PackageConfig": {
        "github.com/gokrazy/breakglass": {
            "ExtraFileContents": {
                "/etc/ssl/gokrazy-web.generate-self-signed": ""
            }
        }
    },
    "Packages": [
        "github.com/gokrazy/fbstatus",
        "github.com/gokrazy/hello",
        "github.com/gokrazy/serial-busybox",
        "github.com/gokrazy/breakglass"
    ]
}
{{< /highlight >}}

The gokrazy installation will start listening on TCP port 443 for HTTPS
connections and redirect any HTTP traffic to HTTPS. When opening the gokrazy web
interface in your browser, you will need to explicitly permit communication due
to the self-signed certificate.

For all future updates, remove the `--insecure` flag:

```bash
gok update
```

You can now safely update your gokrazy installation over untrusted networks,
such as [unencrypted WiFi networks](/userguide/unencrypted-wifi/).

## Disabling TLS

Change the `UseTLS` line to `"UseTLS": "off"` in your instance’s `config.json`.

Run `gok update --insecure`, and afterwards gokrazy will no longer contain the
certificates and will serve unencrypted HTTP again.
