# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a fork of the keyring-rs library used by lpop. It's a cross-platform library for managing passwords/credentials in platform-specific secure stores (Keychain on macOS/iOS, Credential Manager on Windows, Secret Service on Linux).

## Build and Test Commands

```bash
# Build the library
cargo build

# Run all tests
cargo test

# Run a specific test
cargo test test_name

# Run tests with debug output
RUST_LOG=debug cargo test --verbose

# Build with no default features
cargo build --no-default-features

# Run clippy (linting)
cargo clippy -- -D warnings

# Format check
cargo fmt --all -- --check

# Build the CLI example
cargo build --release --example keyring-cli

# Run the CLI example
cargo run --example keyring-cli
```

## Architecture and Key Components

### Platform-Specific Implementations

- **macOS** (`src/macos.rs`): Uses Security Framework's Keychain Services API. Creates generic passwords with service as _name_ and user as _account_ attributes. Supports multiple keychains (User, System, Common, Dynamic, Protected/Data Protection).
- **iOS** (`src/ios.rs`): Uses simplified Keychain Services API with single default keychain. Similar credential structure to macOS but without multi-keychain support.
- **Windows** (`src/windows.rs`): Uses Windows Credential Manager API
- **Linux/BSD** (`src/secret_service.rs`): Uses DBus-based Secret Service

### Core Abstractions

- **Entry** (`src/lib.rs`): Main user-facing API, platform-independent interface
- **Credential** (`src/credential.rs`): Trait-based abstraction for platform-specific credential implementations
- **CredentialBuilder**: Factory pattern for creating platform-specific credentials

### Current macOS Implementation Features

The macOS implementation now supports:

- ✅ iCloud Keychain synchronization via `kSecAttrSynchronizable`
- ✅ Team ID/signature as accessor via `kSecAttrAccessGroup`
- ✅ Enhanced SecItem API for advanced keychain features
- ✅ Backward compatibility with existing implementations
- Maps to keychain attributes (service → name, user → account)
- Uses `security_framework` crate v3 for Keychain Services API calls

### New API Methods

- `MacCredential::new_with_icloud_sync()` - Create credentials with iCloud sync and access group support
- Enhanced implementation using SecItem APIs for advanced features
- Automatic fallback to legacy keychain API for backward compatibility

### Testing Strategy

- Each platform module has its own test suite in the module file
- Common test utilities in `tests/common/mod.rs`
- Integration tests in `tests/basic.rs` and `tests/threading.rs`
- Tests use random service/user names to avoid conflicts
- Platform-specific tests are conditionally compiled
- ✅ Comprehensive tests for iCloud sync and access group functionality
- Tests validate entitlement requirements (error -34018 expected without proper provisioning)

## iCloud Keychain Implementation Details

### ✅ Implemented Features

1. **iCloud Synchronization**:

   - Uses `kSecAttrSynchronizable` attribute
   - Requires proper app entitlements
   - Works across user's iCloud-connected devices

2. **Access Groups**:

   - Uses `kSecAttrAccessGroup` with "TEAMID.bundleid" format
   - Enables keychain sharing between apps from same developer team
   - Works independently of iCloud sync

3. **Entitlement Requirements**:

   - App must have `keychain-access-groups` entitlement
   - Access groups must be whitelisted in provisioning profile
   - Proper code signing with valid Apple Developer certificate required

4. **Error Handling**:
   - Error -34018 indicates missing entitlements (expected for unsigned test binaries)
   - Graceful fallback to legacy API for non-enhanced credentials

## Feature Flags

- `apple-native`: Keychain Services on macOS/iOS
- `windows-native`: Windows Credential Manager
- `secret-service`: DBus Secret Service on Linux/BSD
- `vendored`: Static linking of external libraries
