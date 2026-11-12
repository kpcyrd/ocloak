# ocloak - Open RFC 9458 OHTTP Relay

See [Oblivious HTTP](https://en.wikipedia.org/wiki/Oblivious_HTTP) and [RFC
9458](https://www.rfc-editor.org/rfc/rfc9458) for details.

Optionally uses [RFC 9540](https://www.rfc-editor.org/rfc/rfc9540) to require
the `ohttp` parameter in `HTTPS` DNS records as opt-in signal to receive
anonymized requests.

```sh
cargo run --release -- plumbing check-dns -v \
    ohttp.test.orca.toys target.ohttp.info example.com ccc.de crypto.cloudflare.com x.y.z.abc
```

```sh
# https://github.com/cloudflareresearch/pvcli
pvcli --ohttp --proxy https://ohttp-repro.exe.xyz --gateway-path /.well-known/ohttp-gateway --config-path /.well-known/ohttp-gateway -v https://ohttp-repro.exe.xyz/attestations/sha256:a8b7bdca41ee219ebc632b4174ead70a7117411198058d4b353ec9beb4043e0d --first-hop 'http://127.0.0.1:3000/ohttp/ohttp-repro.exe.xyz'
```
