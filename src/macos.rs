/*!

# macOS Keychain credential store

All credentials on macOS are stored in secure stores called _keychains_.
The OS automatically creates three of them that live on filesystem,
called _User_ (aka login), _Common_, and _System_. In addition, removable
media can contain a keychain which can be registered under the name _Dynamic_.
Finally, on Apple Silicon devices, there is a more highly protected keychain
(called the _Data Protection_ or simply _Protected_ keychain). This is the same
keychain that is used by apps on iOS; so this module actually returns
iOS credentials for entries in the Data Protection keychain.

The target attribute of an [Entry](crate::Entry) determines (case-insensitive)
which keychain that entry's credential is created in or searched for.
If the entry has no target, or the specified target doesn't name (case-insensitive)
one of the keychains listed above, the 'User' keychain is used.

For a given service/user pair, this module creates/searches for a credential
in the target keychain whose _account_ attribute holds the user
and whose _name_ attribute holds the service.
Because of a quirk in the Mac keychain services API, neither the _account_
nor the _name_ may be the empty string. (Empty strings are treated as
wildcards when looking up credentials by attribute value.)

In the _Keychain Access_ UI on Mac, credentials created by this module
show up in the passwords area (with their _where_ field equal to their _name_).
What the Keychain Access lists under _Note_ entries on the Mac are
also generic credentials, so existing _notes_ created by third-party
applications can be accessed by this module if you know the value
of their _account_ attribute (which is not displayed by _Keychain Access_).

## iCloud Keychain and Access Group Support

This module now supports iCloud Keychain synchronization and team ID/access group
functionality through the [`MacCredential::new_with_icloud_sync`] constructor.

### iCloud Keychain Synchronization

When `synchronizable` is set to `true`, credentials are marked with the
`kSecAttrSynchronizable` attribute, enabling them to sync across the user's
devices via iCloud Keychain. This requires:

1. **Proper Entitlements**: The application must have the `keychain-access-groups`
   entitlement in its provisioning profile.
2. **Team ID**: For iCloud sync, the access group must be in the format
   `"TEAMID.bundleid"` where `TEAMID` is your Apple Developer Team ID.
3. **Signed Binary**: The application must be properly signed with a valid
   Apple Developer certificate.

### Access Groups

Access groups allow multiple applications from the same developer team to
share keychain items. The `access_group` parameter should be formatted as
`"TEAMID.identifier"` where:

- `TEAMID` is your 10-character Apple Developer Team ID
- `identifier` can be your app's bundle identifier or a custom group identifier

Access groups work independently of iCloud sync and can be used for local
keychain sharing between apps from the same team.

### Backward Compatibility

The original [`MacCredential::new_with_target`] constructor continues to work
exactly as before, creating credentials without iCloud sync or access group
features. This ensures full backward compatibility with existing code.

### Error Handling

When using iCloud sync or access groups without proper entitlements, you may
encounter error `-34018` ("A required entitlement isn't present."). This
indicates that the system correctly recognizes the enhanced features but
the application lacks the necessary provisioning profile entitlements.

Credentials on macOS can have a large number of _key/value_ attributes,
but this module controls the _account_ and _name_ attributes and
ignores all the others. so clients can't use it to access or update any attributes.
 */
use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{Error as ErrorCode, Result, decode_password};
use crate::ios::IosCredential;
use security_framework::base::Error;
use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
use security_framework::os::macos::passwords::find_generic_password;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::base::{CFType, TCFType};
use core_foundation::string::CFString;
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use security_framework::base::Error as SecError;
use std::ptr;

// Define all required Security Framework constants
unsafe extern "C" {
    // Keychain item constants
    #[link_name = "kSecClass"]
    static K_SEC_CLASS: *const std::ffi::c_void;
    #[link_name = "kSecClassGenericPassword"]
    static K_SEC_CLASS_GENERIC_PASSWORD: *const std::ffi::c_void;
    #[link_name = "kSecAttrService"]
    static K_SEC_ATTR_SERVICE: *const std::ffi::c_void;
    #[link_name = "kSecAttrAccount"]
    static K_SEC_ATTR_ACCOUNT: *const std::ffi::c_void;
    #[link_name = "kSecValueData"]
    static K_SEC_VALUE_DATA: *const std::ffi::c_void;
    #[link_name = "kSecReturnData"]
    static K_SEC_RETURN_DATA: *const std::ffi::c_void;
    #[link_name = "kSecAttrSynchronizable"]
    static K_SEC_ATTR_SYNCHRONIZABLE: *const std::ffi::c_void;
    #[link_name = "kSecAttrAccessGroup"] 
    static K_SEC_ATTR_ACCESS_GROUP: *const std::ffi::c_void;
    
    // Core SecItem functions
    fn SecItemAdd(attributes: *const std::ffi::c_void, result: *mut *const std::ffi::c_void) -> i32;
    fn SecItemUpdate(query: *const std::ffi::c_void, attributesToUpdate: *const std::ffi::c_void) -> i32;
    fn SecItemCopyMatching(query: *const std::ffi::c_void, result: *mut *const std::ffi::c_void) -> i32;
    fn SecItemDelete(query: *const std::ffi::c_void) -> i32;
}

const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;

/// The representation of a generic Keychain credential.
///
/// The actual credentials can have lots of attributes
/// not represented here.  There's no way to use this
/// module to get at those attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacCredential {
    pub domain: MacKeychainDomain,
    pub service: String,
    pub account: String,
    pub access_group: Option<String>,
    pub synchronizable: bool,
}

impl CredentialApi for MacCredential {
    /// Create and write a credential with password for this entry.
    ///
    /// The new credential replaces any existing one in the store.
    /// Since there is only one credential with a given _account_ and _user_
    /// in any given keychain, there is no chance of ambiguity.
    fn set_password(&self, password: &str) -> Result<()> {
        self.set_secret(password.as_bytes())
    }

    /// Create and write a credential with secret for this entry.
    ///
    /// The new credential replaces any existing one in the store.
    /// Since there is only one credential with a given _account_ and _user_
    /// in any given keychain, there is no chance of ambiguity.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        // Use enhanced keychain storage with iCloud sync and access group support
        self.set_secret_with_enhanced_attributes(secret)
    }

    /// Look up the password for this entry, if any.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    fn get_password(&self) -> Result<String> {
        let secret_bytes = self.get_secret()?;
        decode_password(secret_bytes)
    }

    /// Look up the secret for this entry, if any.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    fn get_secret(&self) -> Result<Vec<u8>> {
        if self.synchronizable || self.access_group.is_some() {
            self.get_secret_with_secitem_api()
        } else {
            // Fallback to legacy keychain API for backwards compatibility
            let (password_bytes, _) =
                find_generic_password(Some(&[get_keychain(self)?]), &self.service, &self.account)
                    .map_err(decode_error)?;
            Ok(password_bytes.to_owned())
        }
    }

    /// Delete the underlying generic credential for this entry, if any.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    fn delete_credential(&self) -> Result<()> {
        if self.synchronizable || self.access_group.is_some() {
            self.delete_credential_with_secitem_api()
        } else {
            // Fallback to legacy keychain API for backwards compatibility
            let (_, item) =
                find_generic_password(Some(&[get_keychain(self)?]), &self.service, &self.account)
                    .map_err(decode_error)?;
            item.delete();
            Ok(())
        }
    }

    /// Return the underlying concrete object with an `Any` type so that it can
    /// be downgraded to a [MacCredential] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Expose the concrete debug formatter for use via the [Credential] trait
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl MacCredential {
    /// Construct a credential from the underlying generic credential.
    ///
    /// On Mac, this is basically a no-op, because we represent any attributes
    /// other than the ones we use to find the generic credential.
    /// But at least this checks whether the underlying credential exists.
    pub fn get_credential(&self) -> Result<Self> {
        let (_, _) =
            find_generic_password(Some(&[get_keychain(self)?]), &self.service, &self.account)
                .map_err(decode_error)?;
        Ok(self.clone())
    }

    /// Create a credential representing a Mac keychain entry.
    ///
    /// Creating a credential does not put anything into the keychain.
    /// The keychain entry will be created
    /// when [set_password](MacCredential::set_password) is
    /// called.
    ///
    /// This will fail if the service or user strings are empty,
    /// because empty attribute values act as wildcards in the
    /// Keychain Services API.
    pub fn new_with_target(
        target: Option<MacKeychainDomain>,
        service: &str,
        user: &str,
    ) -> Result<Self> {
        if service.is_empty() {
            return Err(ErrorCode::Invalid(
                "service".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        if user.is_empty() {
            return Err(ErrorCode::Invalid(
                "user".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        let domain = if let Some(target) = target {
            target
        } else {
            MacKeychainDomain::User
        };
        Ok(Self {
            domain,
            service: service.to_string(),
            account: user.to_string(),
            access_group: None,
            synchronizable: false,
        })
    }

    /// Create a credential with iCloud sync and access group support.
    ///
    /// The access_group should be in the format "TEAMID.bundleid" where
    /// TEAMID is your Apple Developer Team ID.
    pub fn new_with_icloud_sync(
        target: Option<MacKeychainDomain>,
        service: &str,
        user: &str,
        access_group: Option<String>,
        synchronizable: bool,
    ) -> Result<Self> {
        if service.is_empty() {
            return Err(ErrorCode::Invalid(
                "service".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        if user.is_empty() {
            return Err(ErrorCode::Invalid(
                "user".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        
        // Validate access group format if provided
        if let Some(ref group) = access_group {
            if synchronizable && !group.contains('.') {
                return Err(ErrorCode::Invalid(
                    "access_group".to_string(),
                    "must be in format 'TEAMID.bundleid' for iCloud sync".to_string(),
                ));
            }
        }
        
        let domain = if let Some(target) = target {
            target
        } else {
            MacKeychainDomain::User
        };
        
        Ok(Self {
            domain,
            service: service.to_string(),
            account: user.to_string(),
            access_group,
            synchronizable,
        })
    }

    /// Enhanced secret storage with iCloud sync and access group support
    fn set_secret_with_enhanced_attributes(&self, secret: &[u8]) -> Result<()> {
        if self.synchronizable || self.access_group.is_some() {
            self.set_secret_with_secitem_api(secret)
        } else {
            // Fallback to legacy keychain API for backwards compatibility
            get_keychain(self)?
                .set_generic_password(&self.service, &self.account, secret)
                .map_err(decode_error)?;
            Ok(())
        }
    }

    /// Use SecItem API for enhanced keychain features
    fn set_secret_with_secitem_api(&self, secret: &[u8]) -> Result<()> {
        unsafe {
            // Create mutable dictionary for keychain item attributes
            let mut dict: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();
            
            // Set basic attributes
            dict.add(
                &CFString::wrap_under_create_rule(K_SEC_CLASS as _),
                &CFString::wrap_under_create_rule(K_SEC_CLASS_GENERIC_PASSWORD as _).as_CFType()
            );
            
            dict.add(
                &CFString::wrap_under_create_rule(K_SEC_ATTR_SERVICE as _),
                &CFString::new(&self.service).as_CFType()
            );
            
            dict.add(
                &CFString::wrap_under_create_rule(K_SEC_ATTR_ACCOUNT as _),
                &CFString::new(&self.account).as_CFType()
            );
            
            dict.add(
                &CFString::wrap_under_create_rule(K_SEC_VALUE_DATA as _),
                &CFData::from_buffer(secret).as_CFType()
            );

            // Add access group if specified
            if let Some(ref access_group) = self.access_group {
                dict.add(
                    &CFString::wrap_under_create_rule(K_SEC_ATTR_ACCESS_GROUP as _),
                    &CFString::new(access_group).as_CFType()
                );
            }

            // Add synchronizable attribute if enabled
            if self.synchronizable {
                dict.add(
                    &CFString::wrap_under_create_rule(K_SEC_ATTR_SYNCHRONIZABLE as _),
                    &CFBoolean::true_value().as_CFType()
                );
            }

            // Try to add the item
            let status = SecItemAdd(dict.as_concrete_TypeRef() as _, ptr::null_mut());
            
            if status == ERR_SEC_SUCCESS {
                Ok(())
            } else if status == ERR_SEC_DUPLICATE_ITEM {
                // Item exists, update it instead
                let mut query_dict: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();
                query_dict.add(
                    &CFString::wrap_under_create_rule(K_SEC_CLASS as _),
                    &CFString::wrap_under_create_rule(K_SEC_CLASS_GENERIC_PASSWORD as _).as_CFType()
                );
                query_dict.add(
                    &CFString::wrap_under_create_rule(K_SEC_ATTR_SERVICE as _),
                    &CFString::new(&self.service).as_CFType()
                );
                query_dict.add(
                    &CFString::wrap_under_create_rule(K_SEC_ATTR_ACCOUNT as _),
                    &CFString::new(&self.account).as_CFType()
                );
                
                if let Some(ref access_group) = self.access_group {
                    query_dict.add(
                        &CFString::wrap_under_create_rule(K_SEC_ATTR_ACCESS_GROUP as _),
                        &CFString::new(access_group).as_CFType()
                    );
                }

                let mut update_dict: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();
                update_dict.add(
                    &CFString::wrap_under_create_rule(K_SEC_VALUE_DATA as _),
                    &CFData::from_buffer(secret).as_CFType()
                );

                let status = SecItemUpdate(
                    query_dict.as_concrete_TypeRef() as _,
                    update_dict.as_concrete_TypeRef() as _
                );
                
                if status == ERR_SEC_SUCCESS {
                    Ok(())
                } else {
                    Err(decode_error(SecError::from_code(status)))
                }
            } else {
                Err(decode_error(SecError::from_code(status)))
            }
        }
    }

    /// Get secret using SecItem API for enhanced keychain features
    fn get_secret_with_secitem_api(&self) -> Result<Vec<u8>> {
        unsafe {
            let mut query_dict: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();
            
            query_dict.add(
                &CFString::wrap_under_create_rule(K_SEC_CLASS as _),
                &CFString::wrap_under_create_rule(K_SEC_CLASS_GENERIC_PASSWORD as _).as_CFType()
            );
            
            query_dict.add(
                &CFString::wrap_under_create_rule(K_SEC_ATTR_SERVICE as _),
                &CFString::new(&self.service).as_CFType()
            );
            
            query_dict.add(
                &CFString::wrap_under_create_rule(K_SEC_ATTR_ACCOUNT as _),
                &CFString::new(&self.account).as_CFType()
            );
            
            query_dict.add(
                &CFString::wrap_under_create_rule(K_SEC_RETURN_DATA as _),
                &CFBoolean::true_value().as_CFType()
            );
            
            // Add access group if specified
            if let Some(ref access_group) = self.access_group {
                query_dict.add(
                    &CFString::wrap_under_create_rule(K_SEC_ATTR_ACCESS_GROUP as _),
                    &CFString::new(access_group).as_CFType()
                );
            }

            // Add synchronizable attribute for query consistency
            if self.synchronizable {
                query_dict.add(
                    &CFString::wrap_under_create_rule(K_SEC_ATTR_SYNCHRONIZABLE as _),
                    &CFBoolean::true_value().as_CFType()
                );
            }

            let mut result: *const std::ffi::c_void = ptr::null();
            let status = SecItemCopyMatching(
                query_dict.as_concrete_TypeRef() as _,
                &mut result
            );

            if status == ERR_SEC_SUCCESS {
                let data = CFData::wrap_under_create_rule(result as _);
                Ok(data.bytes().to_vec())
            } else {
                Err(decode_error(SecError::from_code(status)))
            }
        }
    }

    /// Delete with enhanced SecItem API support
    fn delete_credential_with_secitem_api(&self) -> Result<()> {
        unsafe {
            let mut query_dict: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();
            
            query_dict.add(
                &CFString::wrap_under_create_rule(K_SEC_CLASS as _),
                &CFString::wrap_under_create_rule(K_SEC_CLASS_GENERIC_PASSWORD as _).as_CFType()
            );
            
            query_dict.add(
                &CFString::wrap_under_create_rule(K_SEC_ATTR_SERVICE as _),
                &CFString::new(&self.service).as_CFType()
            );
            
            query_dict.add(
                &CFString::wrap_under_create_rule(K_SEC_ATTR_ACCOUNT as _),
                &CFString::new(&self.account).as_CFType()
            );
            
            // Add access group if specified
            if let Some(ref access_group) = self.access_group {
                query_dict.add(
                    &CFString::wrap_under_create_rule(K_SEC_ATTR_ACCESS_GROUP as _),
                    &CFString::new(access_group).as_CFType()
                );
            }

            // Add synchronizable attribute for query consistency
            if self.synchronizable {
                query_dict.add(
                    &CFString::wrap_under_create_rule(K_SEC_ATTR_SYNCHRONIZABLE as _),
                    &CFBoolean::true_value().as_CFType()
                );
            }

            let status = SecItemDelete(query_dict.as_concrete_TypeRef() as _);

            if status == ERR_SEC_SUCCESS {
                Ok(())
            } else {
                Err(decode_error(SecError::from_code(status)))
            }
        }
    }
}

/// The builder for Mac keychain credentials
pub struct MacCredentialBuilder {}

/// Returns an instance of the Mac credential builder.
///
/// On Mac, with default features enabled,
/// this is called once when an entry is first created.
pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(MacCredentialBuilder {})
}

impl CredentialBuilderApi for MacCredentialBuilder {
    /// Build a [MacCredential] for the given target, service, and user.
    ///
    /// If a target is specified but not recognized as a keychain name,
    /// the User keychain is selected.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        let domain: MacKeychainDomain = if let Some(target) = target {
            target.parse().unwrap_or(MacKeychainDomain::User)
        } else {
            MacKeychainDomain::User
        };
        match domain {
            MacKeychainDomain::Protected => Ok(Box::new(IosCredential::new_with_target(
                None, service, user,
            )?)),
            _ => Ok(Box::new(MacCredential::new_with_target(
                Some(domain),
                service,
                user,
            )?)),
        }
    }

    /// Return the underlying builder object with an `Any` type so that it can
    /// be downgraded to a [MacCredentialBuilder] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The four pre-defined Mac keychains.
pub enum MacKeychainDomain {
    User,
    System,
    Common,
    Dynamic,
    Protected,
}

impl std::fmt::Display for MacKeychainDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MacKeychainDomain::User => "User".fmt(f),
            MacKeychainDomain::System => "System".fmt(f),
            MacKeychainDomain::Common => "Common".fmt(f),
            MacKeychainDomain::Dynamic => "Dynamic".fmt(f),
            MacKeychainDomain::Protected => "Protected".fmt(f),
        }
    }
}

impl std::str::FromStr for MacKeychainDomain {
    type Err = ErrorCode;

    /// Convert a target specification string to a keychain domain.
    ///
    /// We accept any case in the string,
    /// but the value has to match a known keychain domain name
    /// or else we assume the login keychain is meant.
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "user" => Ok(MacKeychainDomain::User),
            "system" => Ok(MacKeychainDomain::System),
            "common" => Ok(MacKeychainDomain::Common),
            "dynamic" => Ok(MacKeychainDomain::Dynamic),
            "protected" => Ok(MacKeychainDomain::Protected),
            "data protection" => Ok(MacKeychainDomain::Protected),
            _ => Err(ErrorCode::Invalid(
                "target".to_string(),
                format!("'{s}' is not User, System, Common, Dynamic, or Protected"),
            )),
        }
    }
}

fn get_keychain(cred: &MacCredential) -> Result<SecKeychain> {
    let domain = match cred.domain {
        MacKeychainDomain::User => SecPreferencesDomain::User,
        MacKeychainDomain::System => SecPreferencesDomain::System,
        MacKeychainDomain::Common => SecPreferencesDomain::Common,
        MacKeychainDomain::Dynamic => SecPreferencesDomain::Dynamic,
        MacKeychainDomain::Protected => panic!("Protected is not a keychain domain on macOS"),
    };
    match SecKeychain::default_for_domain(domain) {
        Ok(keychain) => Ok(keychain),
        Err(err) => Err(decode_error(err)),
    }
}

/// Map a Mac API error to a crate error with appropriate annotation
///
/// The macOS error code values used here are from
/// [this reference](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-78/lib/SecBase.h.auto.html)
pub fn decode_error(err: Error) -> ErrorCode {
    match err.code() {
        -25291 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecNotAvailable
        -25292 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecReadOnly
        -25294 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecNoSuchKeychain
        -25295 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecInvalidKeychain
        -25300 => ErrorCode::NoEntry,                        // errSecItemNotFound
        _ => ErrorCode::PlatformFailure(Box::new(err)),
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::{CredentialPersistence, CredentialApi};
    use crate::{Entry, Error, tests::generate_random_string};

    use super::{MacCredential, default_credential_builder};

    #[test]
    fn test_persistence() {
        assert!(matches!(
            default_credential_builder().persistence(),
            CredentialPersistence::UntilDelete
        ))
    }

    fn entry_new(service: &str, user: &str) -> Entry {
        crate::tests::entry_from_constructor(
            |_, s, u| MacCredential::new_with_target(None, s, u),
            service,
            user,
        )
    }

    #[test]
    fn test_invalid_parameter() {
        let credential = MacCredential::new_with_target(None, "", "user");
        assert!(
            matches!(credential, Err(Error::Invalid(_, _))),
            "Created credential with empty service"
        );
        let credential = MacCredential::new_with_target(None, "service", "");
        assert!(
            matches!(credential, Err(Error::Invalid(_, _))),
            "Created entry with empty user"
        );
    }

    #[test]
    fn test_missing_entry() {
        crate::tests::test_missing_entry(entry_new);
    }

    #[test]
    fn test_empty_password() {
        crate::tests::test_empty_password(entry_new);
    }

    #[test]
    fn test_round_trip_ascii_password() {
        crate::tests::test_round_trip_ascii_password(entry_new);
    }

    #[test]
    fn test_round_trip_non_ascii_password() {
        crate::tests::test_round_trip_non_ascii_password(entry_new);
    }

    #[test]
    fn test_round_trip_random_secret() {
        crate::tests::test_round_trip_random_secret(entry_new);
    }

    #[test]
    fn test_update() {
        crate::tests::test_update(entry_new);
    }

    #[test]
    fn test_get_credential() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let credential: &MacCredential = entry
            .get_credential()
            .downcast_ref()
            .expect("Not a mac credential");
        assert!(
            credential.get_credential().is_err(),
            "Platform credential shouldn't exist yet!"
        );
        entry
            .set_password("test get_credential")
            .expect("Can't set password for get_credential");
        assert!(credential.get_credential().is_ok());
        entry
            .delete_credential()
            .expect("Couldn't delete after get_credential");
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    }

    #[test]
    fn test_get_update_attributes() {
        crate::tests::test_noop_get_update_attributes(entry_new);
    }

    #[test]
    fn test_select_keychain() {
        for name in ["unknown", "user", "common", "system", "dynamic"] {
            let cred = Entry::new_with_target(name, name, name)
                .expect("couldn't create credential")
                .inner;
            let mac_cred: &MacCredential = cred
                .as_any()
                .downcast_ref()
                .expect("credential not a MacCredential");
            if name == "unknown" {
                assert!(
                    matches!(mac_cred.domain, super::MacKeychainDomain::User),
                    "wrong domain for unknown specifier"
                )
            }
        }
        for name in ["data protection", "protected"] {
            let cred = Entry::new_with_target(name, name, name)
                .expect("couldn't create credential")
                .inner;
            let _: &super::IosCredential = cred
                .as_any()
                .downcast_ref()
                .expect("credential not an iOS credential");
        }
    }

    #[test]
    fn test_icloud_sync_credential_creation() {
        let service = generate_random_string();
        let user = generate_random_string();
        let access_group = Some("TEAM123.com.example.test".to_string());
        
        // Test creating a credential with iCloud sync enabled
        let credential = MacCredential::new_with_icloud_sync(
            None, // use default keychain domain
            &service,
            &user,
            access_group.clone(),
            true, // enable synchronization
        );
        
        assert!(credential.is_ok(), "Failed to create iCloud sync credential");
        let cred = credential.unwrap();
        assert_eq!(cred.service, service);
        assert_eq!(cred.account, user);
        assert_eq!(cred.access_group, access_group);
        assert!(cred.synchronizable);
    }

    #[test] 
    fn test_access_group_validation() {
        let service = generate_random_string();
        let user = generate_random_string();
        
        // Test invalid access group format for iCloud sync
        let invalid_result = MacCredential::new_with_icloud_sync(
            None,
            &service,
            &user,
            Some("invalid-format".to_string()), // missing dot separator
            true, // sync enabled
        );
        
        assert!(invalid_result.is_err(), "Should reject invalid access group format");
        assert!(matches!(invalid_result, Err(Error::Invalid(_, _))));
        
        // Test valid access group format
        let valid_result = MacCredential::new_with_icloud_sync(
            None,
            &service,
            &user,
            Some("TEAM123.com.example.app".to_string()),
            true,
        );
        
        assert!(valid_result.is_ok(), "Should accept valid access group format");
    }

    #[test]
    fn test_non_sync_credential_with_access_group() {
        let service = generate_random_string();
        let user = generate_random_string();
        
        // Test creating credential with access group but no sync (should be allowed)
        let credential = MacCredential::new_with_icloud_sync(
            None,
            &service,
            &user,
            Some("invalid-no-dot".to_string()), // invalid format but sync is false
            false, // no sync
        );
        
        assert!(credential.is_ok(), "Should allow any access group format when sync is disabled");
    }

    #[test]
    fn test_round_trip_with_icloud_sync() {
        let service = generate_random_string();
        let user = generate_random_string();
        let password = "test icloud sync password";
        let access_group = Some("TEST123.com.keyring.test".to_string());
        
        // Create credential with iCloud sync
        let credential = MacCredential::new_with_icloud_sync(
            None,
            &service,
            &user,
            access_group,
            true,
        ).expect("Failed to create iCloud sync credential");
        
        // Set password
        credential.set_password(password)
            .expect("Failed to set password with iCloud sync");
        
        // Get password back
        let retrieved_password = credential.get_password()
            .expect("Failed to get password with iCloud sync");
        
        assert_eq!(password, retrieved_password, "Password mismatch with iCloud sync");
        
        // Clean up
        credential.delete_credential()
            .expect("Failed to delete credential with iCloud sync");
        
        // Verify deletion
        assert!(matches!(credential.get_password(), Err(Error::NoEntry)));
    }

    #[test] 
    fn test_round_trip_with_access_group_only() {
        let service = generate_random_string();
        let user = generate_random_string();
        let secret = b"test access group secret data";
        let access_group = Some("TEAM456.com.keyring.accesstest".to_string());
        
        // Create credential with access group but no sync
        let credential = MacCredential::new_with_icloud_sync(
            None,
            &service, 
            &user,
            access_group,
            false, // no sync
        ).expect("Failed to create access group credential");
        
        // Set secret
        credential.set_secret(secret)
            .expect("Failed to set secret with access group");
        
        // Get secret back  
        let retrieved_secret = credential.get_secret()
            .expect("Failed to get secret with access group");
        
        assert_eq!(secret, retrieved_secret.as_slice(), "Secret mismatch with access group");
        
        // Clean up
        credential.delete_credential()
            .expect("Failed to delete credential with access group");
        
        // Verify deletion
        assert!(matches!(credential.get_secret(), Err(Error::NoEntry)));
    }

    #[test]
    fn test_backward_compatibility() {
        let service = generate_random_string();
        let user = generate_random_string();
        let password = "test backward compatibility";
        
        // Create old-style credential (no iCloud sync features)
        let credential = MacCredential::new_with_target(None, &service, &user)
            .expect("Failed to create legacy credential");
        
        // Verify it has default values for new fields
        assert_eq!(credential.access_group, None);
        assert!(!credential.synchronizable);
        
        // Test round trip with legacy keychain API
        credential.set_password(password)
            .expect("Failed to set password with legacy credential");
        
        let retrieved_password = credential.get_password()
            .expect("Failed to get password with legacy credential");
        
        assert_eq!(password, retrieved_password, "Password mismatch with legacy credential");
        
        // Clean up
        credential.delete_credential()
            .expect("Failed to delete legacy credential");
        
        // Verify deletion
        assert!(matches!(credential.get_password(), Err(Error::NoEntry)));
    }
}
