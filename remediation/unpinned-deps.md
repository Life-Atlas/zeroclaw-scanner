# Finding: Unpinned Dependencies

## Why it's dangerous
Specifying floating package dependencies (without exact version lock bounds) allows the installer to dynamically fetch the newest release. This introduces risk where an upstream patch update can break API compatibility, trigger system crashes, or fetch a package compromised by attackers (supply chain hijack).

## How to fix it
Always pin your dependencies to an exact version specifier in your project requirements file (`requirements.txt` or `package.json`). For added safety, lock cryptographically verified package hashes.

## Before (vulnerable)
```
# Dependency manager is free to fetch any version
fastapi
requests
```

## After (fixed)
```
# Explicitly locked to audited/stable package versions
fastapi==0.115.0
requests==2.32.3
```
