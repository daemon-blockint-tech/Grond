# Recon tooling sources (Nmap, Ncrack, Npcap)

Upstream trees live under `recon/nmap`, `recon/ncrack`, and `recon/npcap` and are **not committed** (gitignored). Clone the official projects there if you use `./recon/build.sh`, or rely on system packages. **Grond’s Python API** normally uses the **`nmap` on your PATH** (via `python-nmap`)—build here when you want pinned versions or offline builds.

## Quick build (macOS / Linux)

From repo root:

```bash
./recon/build.sh all-install
```

Or in two steps:

```bash
./recon/build.sh all
./recon/build.sh install
```

Install prefix defaults to `recon/dist` (ignored by git as `dist/`). Override:

```bash
PREFIX=/usr/local ./recon/build.sh all-install   # needs write access to PREFIX
```

### Dependencies

| Platform | Notes |
|----------|--------|
| **macOS** | Xcode CLT; **OpenSSL** recommended: `brew install openssl` (the script passes `--with-openssl` when `brew --prefix openssl@3` exists). |
| **Linux** | `build-essential`, `libssl-dev`, `libpcap-dev` (or let Nmap build its bundled libpcap). |

## Targets

| Command | Description |
|---------|-------------|
| `./recon/build.sh nmap` | `configure` + `make` for Nmap only |
| `./recon/build.sh ncrack` | `configure` + `make` for Ncrack only |
| `./recon/build.sh all` | Ncrack after Nmap (shared conventions; both install to `PREFIX`) |
| `./recon/build.sh all-install` | Build both, then `make install` into `PREFIX` |
| `./recon/build.sh install` | `make install` only (after a successful `all`) |
| `./recon/build.sh npcap` | **Not a local compile on macOS/Linux** — prints Windows build hints |

## Npcap (Windows only)

Npcap is a **Windows kernel driver and user-mode stack**, not something you compile on macOS/Linux like Nmap.

- **Users**: install from [npcap.com](https://npcap.com/#download).
- **Developers** (build from this tree): use **Visual Studio** on Windows per the [Npcap Developer's Guide — building](https://npcap.com/guide/npcap-devguide.html).

After installing Npcap, the Windows Nmap installer / build links against the Npcap SDK.

## Environment

- **`PREFIX`** — installation directory (default `recon/dist`).
- **`JOBS`** — make parallelism (default: `sysctl -n hw.ncpu` on macOS, else `nproc`, else `4`).
- **`OPENSSL_PREFIX`** — force OpenSSL location (otherwise auto-detected on macOS with Homebrew).

## References

- Nmap install: https://nmap.org/book/install.html  
- Ncrack: https://nmap.org/ncrack/  
- Npcap: https://npcap.com/guide/
