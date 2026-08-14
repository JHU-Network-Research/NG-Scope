# tomlc99 (vendored)

Public-domain-style MIT TOML parser used by the TOML config backend
(`ngscope/src/dciLib/load_config_toml.c`).

- Upstream: https://github.com/cktan/tomlc99
- License: MIT (see `LICENSE`)
- Files: `toml.c`, `toml.h`, unmodified

Vendored rather than taken as a system dependency because it is two files with no
transitive dependencies, which keeps `cmake && make` working on a bare checkout.
