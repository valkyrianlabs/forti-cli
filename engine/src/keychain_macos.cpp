//
// The macOS Keychain secret store: generic passwords in the user's default (login) keychain, service
// "forti", account "<profile>/api-key" or "<profile>/cert-password" (architecture.md, "Profiles and
// credentials").
//
// The legacy file-based keychain is used on purpose: the data-protection keychain needs a signed
// binary with a keychain-access-groups entitlement, which a Homebrew or source build does not have.
// Its consequence is the per-application ACL: the binary that creates an item may read it silently;
// another binary (forti-mcp, or forti after an upgrade changed its signature) gets a one-time
// "allow access" prompt. Without a GUI session (SSH, launchd) no prompt can be shown, and the
// keychain may be locked: both surface as errSecInteractionNotAllowed and are reported as such.
//

#include <forti/engine/error.hpp>
#include <forti/engine/profile.hpp>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <format>
#include <utility>

namespace forti::engine {

    namespace {

        // Owns one CoreFoundation reference.
        template<typename T>
        class Cf {
            T ref_ = nullptr;

        public:
            Cf() = default;
            explicit Cf(T ref) : ref_(ref) {}
            Cf(Cf&& other) noexcept : ref_(std::exchange(other.ref_, nullptr)) {}
            Cf(const Cf&) = delete;
            Cf& operator=(const Cf&) = delete;
            Cf& operator=(Cf&&) = delete;
            ~Cf() {
                if (ref_) CFRelease(ref_);
            }
            [[nodiscard]] T get() const { return ref_; }
            T* out() { return &ref_; }
        };

        Cf<CFStringRef> cf_string(std::string_view text) {
            return Cf<CFStringRef>(CFStringCreateWithBytes(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(text.data()),
                                                           static_cast<CFIndex>(text.size()), kCFStringEncodingUTF8, false));
        }

        std::string describe(OSStatus status) {
            Cf<CFStringRef> message(SecCopyErrorMessageString(status, nullptr));
            if (!message.get()) return std::format("OSStatus {}", status);
            char buffer[512];
            if (!CFStringGetCString(message.get(), buffer, sizeof buffer, kCFStringEncodingUTF8))
                return std::format("OSStatus {}", status);
            return std::format("{} (OSStatus {})", buffer, status);
        }

        // A Failure for a keychain error. Never includes the secret; names the account only.
        [[noreturn]] void fail(std::string_view action, std::string_view account, OSStatus status) {
            std::string hint;
            switch (status) {
                case errSecInteractionNotAllowed:
                    hint = "the Keychain is locked or cannot prompt (for example over SSH): unlock it with "
                           "`security unlock-keychain`, or use --api-key-env / --api-key-command, or set "
                           "FORTI_SECRET_STORE=file";
                    break;
                case errSecUserCanceled:
                case errSecAuthFailed:
                    hint = "access to the Keychain item was denied: allow forti when macOS asks, or check the item's "
                           "access control in Keychain Access (service \"forti\")";
                    break;
                case errSecNoSuchKeychain:
                case errSecNotAvailable:
                case errSecNoDefaultKeychain:
                    hint = "no default keychain is available for this user session: set FORTI_SECRET_STORE=file, "
                           "or use --api-key-env / --api-key-command";
                    break;
                default:
                    hint = "see `forti doctor`; FORTI_SECRET_STORE=file selects the 0600 file store instead";
            }
            throw Failure(Code::config,
                          std::format("macOS Keychain: cannot {} {}: {}", action, account, describe(status)),
                          {{"store", "keychain"}, {"account", account}, {"os_status", status}, {"hint", hint}});
        }

        class KeychainSecretStore final : public SecretStore {
            std::string service_;

            // The identifying attributes of one item.
            Cf<CFMutableDictionaryRef> query(const Cf<CFStringRef>& service, const Cf<CFStringRef>& account) const {
                Cf<CFMutableDictionaryRef> dict(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
                                                                          &kCFTypeDictionaryValueCallBacks));
                CFDictionarySetValue(dict.get(), kSecClass, kSecClassGenericPassword);
                CFDictionarySetValue(dict.get(), kSecAttrService, service.get());
                CFDictionarySetValue(dict.get(), kSecAttrAccount, account.get());
                return dict;
            }

        public:
            explicit KeychainSecretStore(std::string service) : service_(std::move(service)) {}

            std::string_view kind() const override { return "keychain"; }

            // The binding (Profile::secret_binding()) lives in the item's generic attribute (kSecAttrGeneric).
            std::optional<StoredSecret> get(std::string_view account) override {
                auto service = cf_string(service_);
                auto name = cf_string(account);
                auto search = query(service, name);
                CFDictionarySetValue(search.get(), kSecReturnData, kCFBooleanTrue);
                CFDictionarySetValue(search.get(), kSecReturnAttributes, kCFBooleanTrue);
                CFDictionarySetValue(search.get(), kSecMatchLimit, kSecMatchLimitOne);
                Cf<CFTypeRef> result;
                OSStatus status = SecItemCopyMatching(search.get(), result.out());
                if (status == errSecItemNotFound) return std::nullopt;
                if (status != errSecSuccess) fail("read", account, status);
                if (!result.get() || CFGetTypeID(result.get()) != CFDictionaryGetTypeID())
                    throw Failure(Code::config, std::format("macOS Keychain: unexpected reply for {}", account));
                auto item = static_cast<CFDictionaryRef>(result.get());
                auto bytes = [](const void* value) -> std::optional<std::string> {
                    if (!value || CFGetTypeID(value) != CFDataGetTypeID()) return std::nullopt;
                    auto data = static_cast<CFDataRef>(value);
                    return std::string(reinterpret_cast<const char*>(CFDataGetBytePtr(data)),
                                       static_cast<std::size_t>(CFDataGetLength(data)));
                };
                auto secret = bytes(CFDictionaryGetValue(item, kSecValueData));
                if (!secret)
                    throw Failure(Code::config, std::format("macOS Keychain: the item for {} holds no password data", account));
                return StoredSecret{std::move(*secret), bytes(CFDictionaryGetValue(item, kSecAttrGeneric)).value_or("")};
            }

            void put(std::string_view account, std::string_view secret, std::string_view binding) override {
                auto service = cf_string(service_);
                auto name = cf_string(account);
                Cf<CFDataRef> data(CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(secret.data()),
                                                static_cast<CFIndex>(secret.size())));
                Cf<CFDataRef> bound(CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(binding.data()),
                                                 static_cast<CFIndex>(binding.size())));

                auto match = query(service, name);
                Cf<CFMutableDictionaryRef> update(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
                                                                            &kCFTypeDictionaryValueCallBacks));
                CFDictionarySetValue(update.get(), kSecValueData, data.get());
                CFDictionarySetValue(update.get(), kSecAttrGeneric, bound.get());
                OSStatus status = SecItemUpdate(match.get(), update.get());
                if (status == errSecSuccess) return;
                if (status != errSecItemNotFound) fail("update", account, status);

                auto item = query(service, name);
                auto label = cf_string(std::format("{} ({})", service_, account));
                auto description = cf_string("FortiOS REST API credential (forti-cli)");
                CFDictionarySetValue(item.get(), kSecValueData, data.get());
                CFDictionarySetValue(item.get(), kSecAttrGeneric, bound.get());
                CFDictionarySetValue(item.get(), kSecAttrLabel, label.get());
                CFDictionarySetValue(item.get(), kSecAttrDescription, description.get());
                status = SecItemAdd(item.get(), nullptr);
                if (status != errSecSuccess) fail("store", account, status);
            }

            bool erase(std::string_view account) override {
                auto service = cf_string(service_);
                auto name = cf_string(account);
                OSStatus status = SecItemDelete(query(service, name).get());
                if (status == errSecItemNotFound) return false;
                if (status != errSecSuccess) fail("delete", account, status);
                return true;
            }
        };

    }  // namespace

    std::shared_ptr<SecretStore> keychain_secret_store(std::string service) {
        return std::make_shared<KeychainSecretStore>(std::move(service));
    }

}  // namespace forti::engine
