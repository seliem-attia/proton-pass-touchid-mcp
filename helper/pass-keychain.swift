// pass-keychain: Touch-ID-gated secret storage in the macOS login keychain.
//
//   pass-keychain store  <service> <account>                   # reads secret from stdin
//   pass-keychain read   <service> <account> ["prompt reason"] # Touch ID, then prints secret
//   pass-keychain delete <service> <account>
//   pass-keychain auth   ["prompt reason"]                     # pure Touch ID gate, exit 0 on success
//
// Items are stored with kSecAttrAccessibleWhenUnlockedThisDeviceOnly (device-bound,
// never iCloud-synced). IMPORTANT: Touch ID is enforced IN THIS PROCESS (requireTouchID
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

// Touch ID with device-passcode fallback (.deviceOwnerAuthentication) so a failing
// sensor can never lock you out. Returns true on success.
func evaluateOwner(_ reason: String) -> Bool {
    let ctx = LAContext()
    ctx.localizedCancelTitle = "Cancel"
    var e: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &e) else {
        die("Authentication unavailable: \(e?.localizedDescription ?? "?")", 2)
    }
    let sem = DispatchSemaphore(value: 0); var ok = false
    ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { s, _ in ok = s; sem.signal() }
    sem.wait()
    return ok
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
    // remove any existing item first
    SecItemDelete([
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
    ] as CFDictionary)
    let status = SecItemAdd([
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
        kSecValueData: secret,
        kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ] as CFDictionary, nil)
    guard status == errSecSuccess else { die("store failed: OSStatus \(status)", 71) }
    FileHandle.standardError.write("stored \(service)/\(account)\n".data(using: .utf8)!)

case "read":
    guard args.count >= 4 else { die("usage: pass-keychain read <service> <account> [reason]", 64) }
    let service = args[2], account = args[3]
    let reason = args.count > 4 ? args[4] : "Confirm Proton Pass secret access"
    // hard gate: no secret is returned without biometrics/passcode
    guard evaluateOwner(reason) else { die("Touch ID denied or cancelled", 1) }
    var out: CFTypeRef?
    let status = SecItemCopyMatching([
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
        kSecReturnData: true,
    ] as CFDictionary, &out)
    if status == errSecItemNotFound { die("not found: \(service)/\(account)", 44) }
    guard status == errSecSuccess, let data = out as? Data else { die("read failed: OSStatus \(status)", 1) }
    FileHandle.standardOutput.write(data)

case "delete":
    guard args.count >= 4 else { die("usage: pass-keychain delete <service> <account>", 64) }
    let status = SecItemDelete([
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: args[2],
        kSecAttrAccount: args[3],
    ] as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { die("delete failed: OSStatus \(status)", 1) }

default:
    die("unknown command: \(cmd)", 64)
}
