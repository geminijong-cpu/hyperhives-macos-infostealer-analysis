# Sample directory

**Do not commit malware to Git.** This folder is gitignored for known sample filenames.

To reproduce analysis locally:

1. Obtain the Mach-O universal binary matching SHA-256 `5c7385c3a4d919d30e81d851d87068dfcc4d9c5489f1c2b06da6904614bf8dd3` only from lawful sources (your own quarantine, law enforcement, or trusted sharing).
2. Save it as `sample/installer_binary`.
3. Build and run the lab: `docker compose build && docker compose run --rm lab python3 /lab/scripts/decrypt_all.py`

The container has **no outbound network** by default.
