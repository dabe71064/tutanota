import sjcl from "../internal/sjcl.js"
import { assertNotNull, concat, uint8ArrayToBase64 } from "@tutao/tutanota-utils"
import { CryptoError } from "../misc/CryptoError.js"
import { hmacSha256 } from "./Hmac.js"
import { Aes256Key, AesKey, bitArrayToUint8Array, IV_BYTE_LENGTH, keyToUint8Array, uint8ArrayToBitArray } from "./symmetric/SymmetricCipherUtils"
import { AesKeyLength, getAndVerifyAesKeyLength } from "./symmetric/AesKeyLength"
import { SYMMETRIC_CIPHER_FACADE } from "./symmetric/SymmetricCipherFacade"

/**
 * Encrypts bytes with AES128 or AES256 in CBC mode.
 * @param key The key to use for the encryption.
 * @param bytes The plain text.
 * @param iv The initialization vector.
 * @return The encrypted bytes
 */
export function aesEncrypt(key: AesKey, bytes: Uint8Array, iv: Uint8Array = generateIV()) {
	const keyLength = getAndVerifyAesKeyLength(key)

	if (iv.length !== IV_BYTE_LENGTH) {
		throw new CryptoError(`Illegal IV length: ${iv.length} (expected: ${IV_BYTE_LENGTH}): ${uint8ArrayToBase64(iv)} `)
	}

	let subKeys = getAesSubKeys(key, useMac)
	let encryptedBits = sjcl.mode.cbc.encrypt(new sjcl.cipher.aes(subKeys.cKey), uint8ArrayToBitArray(bytes), uint8ArrayToBitArray(iv), [], usePadding)
	let data = concat(iv, bitArrayToUint8Array(encryptedBits))

	const macBytes = hmacSha256(assertNotNull(subKeys.mKey), data)
	data = concat(new Uint8Array([MAC_ENABLED_PREFIX]), data, macBytes)

	const ciphertext = SYMMETRIC_CIPHER_FACADE.encryptBytes()
	return data
}

/**
 * Encrypts bytes with AES 256 in CBC mode without mac. This is legacy code and should be removed once the index has been migrated.
 * @param key The key to use for the encryption.
 * @param bytes The plain text.
 * @param iv The initialization vector (only to be passed for testing).
 * @param usePadding If true, padding is used, otherwise no padding is used and the encrypted data must have the key size.
 * @return The encrypted text as words (sjcl internal structure)..
 */
export function aes256EncryptSearchIndexEntry(key: Aes256Key, bytes: Uint8Array, iv: Uint8Array = generateIV(), usePadding: boolean = true): Uint8Array {
	getAndVerifyAesKeyLength(key, [AesKeyLength.Aes256])

	if (iv.length !== IV_BYTE_LENGTH) {
		throw new CryptoError(`Illegal IV length: ${iv.length} (expected: ${IV_BYTE_LENGTH}): ${uint8ArrayToBase64(iv)} `)
	}

	let subKeys = getAesSubKeys(key, false)
	let encryptedBits = sjcl.mode.cbc.encrypt(new sjcl.cipher.aes(subKeys.cKey), uint8ArrayToBitArray(bytes), uint8ArrayToBitArray(iv), [], usePadding)
	let data = concat(iv, keyToUint8Array(encryptedBits))

	return data
}

/**
 * Decrypts the given words with AES-128/256 in CBC mode (with HMAC-SHA-256 as mac). The mac is enforced for AES-256 but optional for AES-128.
 * @param key The key to use for the decryption.
 * @param encryptedBytes The ciphertext encoded as bytes.
 * @return The decrypted bytes.
 */
export function aesDecrypt(key: AesKey, encryptedBytes: Uint8Array): Uint8Array {
	return SYMMETRIC_CIPHER_FACADE.decryptBytes(key, encryptedBytes)
}

/**
 * Decrypts the given words with AES-128/256 in CBC mode. Does not enforce a mac.
 * We always must enforce macs. This only exists for backward compatibility in some exceptional cases like search index entry encryption.
 *
 * @param key The key to use for the decryption.
 * @param encryptedBytes The ciphertext encoded as bytes.
 * @param usePadding If true, padding is used, otherwise no padding is used and the encrypted data must have the key size.
 * @return The decrypted bytes.
 * @deprecated
 */
export function unauthenticatedAesDecrypt(key: Aes256Key, encryptedBytes: Uint8Array, usePadding: boolean = true): Uint8Array {
	return usePadding
		? SYMMETRIC_CIPHER_FACADE.decryptBytesDeprecatedUnauthenticated(key, encryptedBytes)
		: keyToUint8Array(SYMMETRIC_CIPHER_FACADE.decryptKeyDeprecatedUnauthenticated(key, encryptedBytes))
}

//TODO export function unauthenticatedAesDecryptKey
