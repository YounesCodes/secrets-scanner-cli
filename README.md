# Secrets CLI Scanner

CLI tool written in Python to detect hardcoded secrets (using regex and entropy) in source code (local or github repo).


### Detected Secret Types

| Group | Examples |
|---|---|
| aws | Access Key ID, Secret Access Key, Session Token |
| github | PAT, OAuth, App, Fine-grained tokens |
| database | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| crypto | Private keys, PEM certificates |
| generic | API keys, passwords, auth tokens (keyword + entropy) |
| ++ more | Azure, GCP, Stripe, Slack, Telegram... |

## Install & Usage

```sh
pip install secrets-scanner
```

```sh
secrets-scan [path] [options]
```

### Scan a local directory

```sh
secrets-scan ./myproject
```

### Scan a single file

```sh
secrets-scan ./config/.env
```

### Scan a GitHub repo

```sh
secrets-scan --url https://github.com/user/repo.git
secrets-scan --url https://github.com/user/repo.git --delete   # delete cloned repo after scan
```

### Output formats

```sh
secrets-scan ./myproject --format table    # default output format
secrets-scan ./myproject --format json     # json
secrets-scan ./myproject --format yaml     # yaml
```

### Export to file

```sh
secrets-scan ./myproject --format json -o report.json
secrets-scan ./myproject --format yaml -o report.yaml
```

## Supported File Types

Scans all text-based files recursively. 

Skips binaries, lock files, and common dependency directories.

