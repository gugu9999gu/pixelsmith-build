# Pixel Smith build runner

This public repository holds workflow definitions for an explicitly requested Android build runner. Game source, player saves, signing keys and credentials are kept in private storage.

- **Runner check** tests standard GitHub-hosted runner availability with no repository secrets.
- **Sealed Android build** is dispatched by the repository owner on `main`. It downloads an encrypted source archive pinned by SHA-256, authenticates and unpacks it on an ephemeral runner, and verifies its shallow commit and clean tree before running tests and Android release compilation.

The `sealed-build` environment exposes `SEALED_SOURCE_KEY` only to the source extraction step. Signed assembly additionally requires all four existing Android signing credentials. The original build checks enforce the pinned Android identity, signing certificate, and embedded runtime. A compile-only receipt records compilation when signing credentials are missing.

The result is one encrypted artifact retained for one day. Its archive contains a receipt, private logs, and the verified APK and manifests when available. Successful signed builds record the pinned source commit and measured test counts in the APK provenance. The Android checks run on the hosted runner and cover compilation, unit tests and APK inspection.

## Operator commands

Run these from a local checkout with Node.js and Python 3. The archive must be a gzip tar with only tracked source files and a clean, shallow `.git` directory without remotes, credentials or hooks. Keep archive and key files outside this repository.

```sh
# Supply an already-exported SEALED_SOURCE_KEY as canonical base64 for 32 random bytes.
node sealed.cjs encrypt-input /private/path/source.tar.gz /private/path/source.sealed
```

Update `source-plan.json` with the source commit, ciphertext asset HTTPS URL, its SHA-256, and the recipient RSA public SPKI PEM. After dispatch, download and unpack the GitHub artifact wrapper in private storage. Use the matching RSA private key and a new destination directory.

```sh
node sealed.cjs decrypt-output source-plan.json /private/path/recipient.pem /private/path/sealed-build-output.bin /private/path/result
```

The recipient key is separate from the input source key. The source and result envelopes use AES-256-GCM, and result envelopes wrap a fresh AES key with RSA-OAEP-SHA256. Repository publication and distribution remain separate operator actions.
