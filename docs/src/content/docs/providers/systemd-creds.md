---
title: Systemd Credentials Provider
description: Store secrets using systemd's encrypted credential system
---

The **systemd-creds** provider uses systemd's credential encryption to store secrets as encrypted files. Each secret is stored separately with support for user and system scope isolation.

## Features

- Encryption using systemd's host keys or TPM
- User/system scope isolation
- Individual `.cred` files with project/profile namespacing

## Requirements

- Linux system with systemd
- `systemd-creds` command available in PATH
- Appropriate permissions for the configured directory
- For system scope: will likely require elevated privileges

## Configuration

```toml
# secretspec.toml  
[profiles.production.provider]
provider = "systemd-creds:///etc/credstore.encrypted?scope=system"  # System scope

[profiles.development.provider] 
provider = "systemd-creds://./local-creds"  # User scope (default)
```

### URI Format
```
systemd-creds://directory
systemd-creds://directory?scope=user
systemd-creds://directory?scope=system
```

- `systemd-creds:///etc/credstore.encrypted?scope=system` - System scope with absolute path
- `systemd-creds://./creds` - User scope (default) with relative path
- `systemd-creds:///var/secrets` - User scope (default) with absolute path

**Note**: Directory path is always required.

## Scope Configuration

**User Scope (Default)**: User-specific keys, no sudo required
```bash
secretspec set --provider "systemd-creds://./creds" API_KEY "secret123"
```

**System Scope**: Encrypted with system-wide keys, will likely require root
```bash
sudo secretspec set --provider "systemd-creds:///etc/credstore.encrypted?scope=system" API_KEY "secret123"
```

## Setup

```bash
# Initialize systemd credentials (run once)
sudo systemd-creds setup

# Verify installation
systemd-creds --version
```

## Usage

Files are named `{project}-{profile}-{key}.cred` in the configured directory.

```bash
# System scope commands
sudo secretspec set --provider "systemd-creds:///etc/credstore.encrypted?scope=system" DATABASE_URL "postgres://..."
sudo secretspec get --provider "systemd-creds:///etc/credstore.encrypted?scope=system" DATABASE_URL
sudo secretspec run --provider "systemd-creds:///etc/credstore.encrypted?scope=system" -- ./app

# User scope commands
secretspec set --provider "systemd-creds://./dev" API_KEY "dev-key"
```

## Security

- **System scope**: System-wide encryption, will likely require root
- **User scope**: User-specific encryption, isolated per user
- **Backup**: Encrypted files can be safely backed up
- **Recovery**: Keys are tied to host/user

## Troubleshooting

```bash
# Check if systemd-creds is available
systemd-creds --version

# List credentials
systemd-creds list

# List credentials in directory
ls -la /etc/credstore.encrypted/
```

Common issues:
- **Permission denied**: Run as root for system scope or switch to user scope
- **Scope mismatch**: Ensure consistent scope usage across commands
- **Missing systemd-creds**: Install systemd package