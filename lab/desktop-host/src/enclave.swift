// Secure Enclave keys for the app's passkeys (ELASTOS-DESKTOP-APP P6, LAB DRAFT).
// The private key never leaves the Secure Enclave; the stored blob only works on
// this Mac, and every signature needs Touch ID or the Mac password.
import CryptoKit
import Foundation
import LocalAuthentication

private let ok: Int32 = 0
private let refused: Int32 = 1
private let failed: Int32 = 2

private let lock = NSLock()
private var epoch: UInt64 = 0
private var current: LAContext?

/// Registers `context` as the one Touch ID in progress, unless a cancel came after `expected`.
private func begin(_ context: LAContext, _ expected: UInt64) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard epoch == expected else { return false }
    current = context
    return true
}

private func end(_ context: LAContext) {
    lock.lock()
    if current === context { current = nil }
    lock.unlock()
}

@_cdecl("elastos_enclave_epoch")
public func elastosEnclaveEpoch() -> UInt64 {
    lock.lock()
    defer { lock.unlock() }
    return epoch
}

/// Ends the Touch ID in progress, and refuses any not yet started from an earlier epoch.
@_cdecl("elastos_enclave_cancel")
public func elastosEnclaveCancel() {
    lock.lock()
    epoch &+= 1
    let context = current
    current = nil
    lock.unlock()
    context?.invalidate()
}

private func copy(_ data: Data, _ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ len: UnsafeMutablePointer<Int>) -> Bool {
    guard data.count <= cap else { return false }
    data.copyBytes(to: out, count: data.count)
    len.pointee = data.count
    return true
}

/// Asks for Touch ID with `reason`, then creates a key that signs only after Touch ID
/// or the Mac password. Writes the key blob and the 65-byte uncompressed public key.
@_cdecl("elastos_enclave_create")
public func elastosEnclaveCreate(
    _ expected: UInt64,
    _ reason: UnsafePointer<CChar>,
    _ blob: UnsafeMutablePointer<UInt8>, _ blobCap: Int, _ blobLen: UnsafeMutablePointer<Int>,
    _ publicKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let context = LAContext()
    guard begin(context, expected) else { return refused }
    defer { end(context) }
    let done = DispatchSemaphore(value: 0)
    var allowed = false
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: String(cString: reason)) { success, _ in
        allowed = success
        done.signal()
    }
    done.wait()
    guard allowed else { return refused }
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], nil
    ) else { return failed }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
        let point = key.publicKey.x963Representation
        guard point.count == 65, copy(key.dataRepresentation, blob, blobCap, blobLen) else { return failed }
        point.copyBytes(to: publicKey, count: 65)
        return ok
    } catch {
        return failed
    }
}

/// Signs `message` (SHA-256 then ECDSA P-256, DER) with the key in `blob`, after
/// Touch ID or the Mac password with `reason`.
@_cdecl("elastos_enclave_sign")
public func elastosEnclaveSign(
    _ expected: UInt64,
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int,
    _ message: UnsafePointer<UInt8>, _ messageLen: Int,
    _ reason: UnsafePointer<CChar>,
    _ signature: UnsafeMutablePointer<UInt8>, _ signatureCap: Int, _ signatureLen: UnsafeMutablePointer<Int>
) -> Int32 {
    let context = LAContext()
    guard begin(context, expected) else { return refused }
    defer { end(context) }
    context.localizedReason = String(cString: reason)
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blobLen), authenticationContext: context)
        let signed = try key.signature(for: Data(bytes: message, count: messageLen))
        return copy(signed.derRepresentation, signature, signatureCap, signatureLen) ? ok : failed
    } catch {
        return refused
    }
}
