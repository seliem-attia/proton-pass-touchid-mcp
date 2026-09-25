// pass-keychain: Touch-ID-gated secret storage in the macOS login keychain.
//
//   pass-keychain store  <service> <account>                   # reads secret from stdin
//   pass-keychain read   <service> <account> ["prompt reason"] # Touch ID, then prints secret
//   pass-keychain delete <service> <account>
//   pass-keychain rebind <service> <account> ["prompt reason"]  # re-trust this build (after a rebuild)
//   pass-keychain auth   ["prompt reason"]                     # pure Touch ID gate, exit 0 on success
//
// Items are stored in the login keychain (never iCloud-synced). Note: the
// kSecAttrAccessible* attribute has no effect in the file-based login keychain. IMPORTANT: Touch ID is enforced IN THIS PROCESS (requireTouchID
// before every read), NOT by a keychain ACL. A real .userPresence ACL (SecAccessControl)
// needs the data-protection keychain and therefore an Apple Developer certificate with
// entitlements. Direct access via `security find-generic-password` therefore bypasses
// Touch ID (it only shows the regular keychain dialog). Mitigation: FileVault + screen
// lock. See SECURITY.md.
//
// Build: swiftc -O pass-keychain.swift -o pass-keychain && codesign --force --sign - pass-keychain
import Foundation
import LocalAuthentication
import Security

func die(_ msg: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(code)
}

let args = CommandLine.arguments
guard args.count >= 2 else { die("usage: pass-keychain <store|read|delete|auth> ...", 64) }
let cmd = args[1]

// Default: Touch ID with fallback to the login password / Apple Watch
// (.deviceOwnerAuthentication), so a failing sensor can never lock you out.
// PASS_KEYCHAIN_BIOMETRY_ONLY=1 requires the fingerprint itself (no password fallback).
let policy: LAPolicy = ProcessInfo.processInfo.environment["PASS_KEYCHAIN_BIOMETRY_ONLY"] == "1"
    ? .deviceOwnerAuthenticationWithBiometrics
    : .deviceOwnerAuthentication

func evaluateOwner(_ reason: String) -> Bool {
    let ctx = LAContext()
    ctx.localizedCancelTitle = "Cancel"
    var e: NSError?
    guard ctx.canEvaluatePolicy(policy, error: &e) else {
        die("Authentication unavailable: \(e?.localizedDescription ?? "?")", 2)
    }
    let sem = DispatchSemaphore(value: 0); var ok = false
    ctx.evaluatePolicy(policy, localizedReason: reason) { s, _ in ok = s; sem.signal() }
    sem.wait()
    return ok
}

func query(_ service: String, _ account: String) -> [CFString: Any] {
    [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account]
}
func readItem(_ service: String, _ account: String) -> Data {
    var q = query(service, account); q[kSecReturnData] = true
    var out: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &out)
    if status == errSecItemNotFound { die("not found: \(service)/\(account)", 44) }
    guard status == errSecSuccess, let data = out as? Data else { die("read failed: OSStatus \(status)", 1) }
    return data
}
// A new item's access list trusts exactly the binary that created it (this helper).
func addItem(_ service: String, _ account: String, _ secret: Data) -> OSStatus {
    var q = query(service, account)
    q[kSecValueData] = secret
    q[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    return SecItemAdd(q as CFDictionary, nil)
}
func deleteItem(_ service: String, _ account: String) -> OSStatus {
    SecItemDelete(query(service, account) as CFDictionary)
}

switch cmd {
case "auth":
    let reason = args.count > 2 ? args[2] : "Confirm access"
    exit(evaluateOwner(reason) ? 0 : 1)

case "store":
    guard args.count >= 4 else { die("usage: pass-keychain store <service> <account>", 64) }
    let service = args[2], account = args[3]
    let secret = FileHandle.standardInput.readDataToEndOfFile()
    guard !secret.isEmpty else { die("empty secret on stdin", 65) }
    _ = deleteItem(service, account) // remove any existing item first
    let status = addItem(service, account, secret)
    guard status == errSecSuccess else { die("store failed: OSStatus \(status)", 71) }
    FileHandle.standardError.write("stored \(service)/\(account)\n".data(using: .utf8)!)

case "read":
    guard args.count >= 4 else { die("usage: pass-keychain read <service> <account> [reason]", 64) }
    let reason = args.count > 4 ? args[4] : "Confirm Proton Pass secret access"
    // hard gate: no secret is returned without biometrics/passcode
    guard evaluateOwner(reason) else { die("Touch ID denied or cancelled", 1) }
    FileHandle.standardOutput.write(readItem(args[2], args[3]))

case "rebind":
    // Re-creates an item so that its access list trusts THIS build of the helper. An ad-hoc
    // signature changes with every rebuild, and macOS then asks for the login password.
    // Order is add-copy → delete → add → delete-copy, so the secret is never lost midway.
    guard args.count >= 4 else { die("usage: pass-keychain rebind <service> <account> [reason]", 64) }
    let service = args[2], account = args[3], temp = account + ".rebind"
    let reason = args.count > 4 ? args[4] : "Re-authorize the Proton Pass helper"
    guard evaluateOwner(reason) else { die("Touch ID denied or cancelled", 1) }
    let secret = readItem(service, account)
    _ = deleteItem(service, temp)
    var status = addItem(service, temp, secret)
    guard status == errSecSuccess, readItem(service, temp) == secret else { die("rebind: backup copy failed: OSStatus \(status)", 71) }
    status = deleteItem(service, account)
    guard status == errSecSuccess else { die("rebind: delete failed: OSStatus \(status) (backup kept as \(temp))", 71) }
    status = addItem(service, account, secret)
    guard status == errSecSuccess, readItem(service, account) == secret else { die("rebind: re-add failed: OSStatus \(status) (backup kept as \(temp))", 71) }
    _ = deleteItem(service, temp)
    FileHandle.standardError.write("rebound \(service)/\(account)\n".data(using: .utf8)!)

case "delete":
    guard args.count >= 4 else { die("usage: pass-keychain delete <service> <account>", 64) }
    let status = deleteItem(args[2], args[3])
    guard status == errSecSuccess || status == errSecItemNotFound else { die("delete failed: OSStatus \(status)", 1) }

default:
    die("unknown command: \(cmd)", 64)
}
