# Notch

> **For learning purposes.** This project demonstrates network steganography and
> can be used as an offensive tool. Use it only on systems and networks you are
> authorized to test. You are responsible for how you use it and for complying
> with applicable laws; use it at your own risk.

Work-in-progress network steganography tool. Prebuilt downloads,
when available, are published on [GitHub Releases](https://github.com/IdanKoblik/notch/releases).

## Injection Methods

| Method                | Status      | Details                                                                       |
| --------------------- | ----------- | ----------------------------------------------------------------------------- |
| TCP SYN ISN injection | Available   | Encodes payload data in the Initial Sequence Number (ISN) of TCP SYN packets. |
| ICMP                  | In progress | Planned transport method.                                                     |

> Authenticated injection - Uses `SECRET` to authenticate encoded data.  
>

## Build

Install Rust, then build with Cargo:

```sh
cargo build --release
```

## Inject a payload

The payload is read from standard input by default. Each authenticated packet
encodes two payload bytes; use `--no-auth` to encode four bytes per packet.
Authenticated mode requires the `SECRET` environment variable.

```sh
printf '\x12\x34' | sudo -E target/release/notch inject \
  --dest 192.0.2.10 --interface eth0
```

To read payload bytes from a file instead, pass its path with `--payload`:

```sh
sudo -E SECRET='shared secret' target/release/notch inject \
  --dest 192.0.2.10 --interface eth0 --payload payload.bin --rate 10
```

The sender displays the injection details and asks for confirmation before
sending. Raw TCP packet transmission requires `CAP_NET_RAW` (often provided by
running with `sudo`).

Run `notch inject --help` for all options. This project is in active development;
there is no receiver command yet.
