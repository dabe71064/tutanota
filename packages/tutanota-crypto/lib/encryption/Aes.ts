import sjcl from "../internal/sjcl.js"
import { assertNotNull, concat, uint8ArrayToBase64 } from "@tutao/tutanota-utils"
import { CryptoError } from "../misc/CryptoError.js"
import { hmacSha256, MacTag, verifyHmacSha256 } from "./Hmac.js"
import {
	Aes256Key,
	AesKey,
	bitArrayToUint8Array,
	IV_BYTE_LENGTH,
	keyToUint8Array,
	MAC_LENGTH_BYTES,
	uint8ArrayToBitArray,
} from "./symmetric/SymmetricCipherUtils"
import { AesKeyLength, getAndVerifyAesKeyLength } from "./symmetric/AesKeyLength"
import { SYMMETRIC_CIPHER_FACADE } from "./symmetric/SymmetricCipherFacade"
import { Type } from "cborg"

/**
 * Encrypts bytes with AES128 or AES256 in CBC mode.
 * @param key The key to use for the encryption.
 * @param bytes The plain text.
 * @param iv The initialization vector.
 * @param usePadding If true, padding is used, otherwise no padding is used and the encrypted data must have the key size.
 * @param useMac If true, use HMAC (note that this is required for AES-256)
 * @return The encrypted bytes
 */
export function aesEncrypt(key: AesKey, bytes: Uint8Array, iv: Uint8Array = generateIV(), usePadding: boolean = true, useMac: boolean = true) {
	const keyLength = getAndVerifyAesKeyLength(key)

	if (iv.length !== IV_BYTE_LENGTH) {
		throw new CryptoError(`Illegal IV length: ${iv.length} (expected: ${IV_BYTE_LENGTH}): ${uint8ArrayToBase64(iv)} `)
	}

	if (!useMac && keyLength === AesKeyLength.Aes256) {
		throw new CryptoError(`Can't use AES-256 without MAC`)
	}

	let subKeys = getAesSubKeys(key, useMac)
	let encryptedBits = sjcl.mode.cbc.encrypt(new sjcl.cipher.aes(subKeys.cKey), uint8ArrayToBitArray(bytes), uint8ArrayToBitArray(iv), [], usePadding)
	let data = concat(iv, bitArrayToUint8Array(encryptedBits))

	if (useMac) {
		const macBytes = hmacSha256(assertNotNull(subKeys.mKey), data)
		data = concat(new Uint8Array([MAC_ENABLED_PREFIX]), data, macBytes)
	}

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
	//Decrypt without padding and 128 bit key is only used with fixed iv (decryptKey and aes256DecryptWithRecoveryKey)
	//TODO we need not pass padding at all
	return usePadding ? SYMMETRIC_CIPHER_FACADE.decryptBytes(key, encryptedBytes) : keyToUint8Array(SYMMETRIC_CIPHER_FACADE.decryptKey(key, encryptedBytes))
}

/**
 * Decrypts the given words with AES-128/ AES-256 in CBC mode with HMAC-SHA-256 as mac. Enforces the mac.
 * @param key The key to use for the decryption.
 * @param encryptedBytes The ciphertext encoded as bytes.
 * @param usePadding If true, padding is used, otherwise no padding is used and the encrypted data must have the key size.
 * @return The decrypted bytes.
 */
export function authenticatedAesDecrypt(key: AesKey, encryptedBytes: Uint8Array, usePadding: boolean = true): Uint8Array {
	return aesDecryptImpl(key, encryptedBytes, usePadding, true)
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

/**
 * Decrypts the given words with AES-128/256 in CBC mode.
 * @param key The key to use for the decryption.
 * @param encryptedBytes The ciphertext encoded as bytes.
 * @param usePadding If true, padding is used, otherwise no padding is used and the encrypted data must have the key size.
 * @param enforceMac if true decryption will fail if there is no valid mac. we only support false for backward compatibility.
 * 				 it must not be used with new cryto anymore.
 * @return The decrypted bytes.
 */
function aesDecryptImpl(key: AesKey, encryptedBytes: Uint8Array, usePadding: boolean, enforceMac: boolean): Uint8Array {
	getAndVerifyAesKeyLength(key)
	const hasMac = encryptedBytes.length % 2 === 1
	if (enforceMac && !hasMac) {
		throw new CryptoError("mac expected but not present")
	}
	const subKeys = getAesSubKeys(key, hasMac)
	let cipherTextWithoutMac

	if (hasMac) {
		cipherTextWithoutMac = encryptedBytes.subarray(1, encryptedBytes.length - MAC_LENGTH_BYTES)
		const providedMacBytes = encryptedBytes.subarray(encryptedBytes.length - MAC_LENGTH_BYTES)
		verifyHmacSha256(assertNotNull(subKeys.mKey), cipherTextWithoutMac, providedMacBytes as MacTag)
	} else {
		cipherTextWithoutMac = encryptedBytes
	}

	// take the iv from the front of the encrypted data
	const iv = cipherTextWithoutMac.slice(0, IV_BYTE_LENGTH)

	if (iv.length !== IV_BYTE_LENGTH) {
		throw new CryptoError(`Invalid IV length in aesDecrypt: ${iv.length} bytes, must be 16 bytes (128 bits)`)
	}

	const ciphertext = cipherTextWithoutMac.slice(IV_BYTE_LENGTH)

	try {
		const decrypted = sjcl.mode.cbc.decrypt(new sjcl.cipher.aes(subKeys.cKey), uint8ArrayToBitArray(ciphertext), uint8ArrayToBitArray(iv), [], usePadding)
		return bitArrayToUint8Array(decrypted)
	} catch (e) {
		throw new CryptoError("aes decryption failed", e as Error)
	}
}
