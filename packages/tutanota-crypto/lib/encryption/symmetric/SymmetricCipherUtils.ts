import { random } from "../../random/Randomizer"
import { Aes256Key, AesKey } from "../Aes"
import { CryptoError } from "../../misc/CryptoError"
import {
	Base64,
	base64ToBase64Url,
	base64ToUint8Array,
	Base64Url,
	uint8ArrayToArrayBuffer,
	uint8ArrayToBase64
} from "@tutao/tutanota-utils"
import { sha256Hash } from "../../hashes/Sha256"
import sjcl from "../../internal/sjcl"
import { KEY_LENGTH_BYTES_AES_256 } from "./AesKeyLength"

export const FIXED_IV_HEX = "88888888888888888888888888888888"
export const  BLOCK_SIZE_BYTES = 16;
export const IV_BYTE_LENGTH = BLOCK_SIZE_BYTES;
export const  SYMMETRIC_CIPHER_VERSION_PREFIX_LENGTH_BYTES = 1;
export const  SYMMETRIC_AUTHENTICATION_TAG_LENGTH_BYTES = 32;
/**
 * Does not account for padding or the IV, but only the version byte and the authentication tag.
 */
export const  SYMMETRIC_CIPHER_VERSION_AND_TAG_OVERHEAD_BYTES = SYMMETRIC_AUTHENTICATION_TAG_LENGTH_BYTES + SYMMETRIC_CIPHER_VERSION_PREFIX_LENGTH_BYTES;


export type BitArray = number[]

/**
 * Creates the auth verifier from the password key.
 * @param passwordKey The key.
 * @returns The auth verifier
 */
export function createAuthVerifier(passwordKey: AesKey): Uint8Array {
	// TODO Compatibility Test
	return sha256Hash(bitArrayToUint8Array(passwordKey))
}

export function createAuthVerifierAsBase64Url(passwordKey: AesKey): Base64Url {
	return base64ToBase64Url(uint8ArrayToBase64(createAuthVerifier(passwordKey)))
}

/**
 * Converts the given BitArray (SJCL) to an Uint8Array.
 * @param bits The BitArray.
 * @return The uint8array.
 */
export function bitArrayToUint8Array(bits: BitArray): Uint8Array {
	return new Uint8Array(sjcl.codec.arrayBuffer.fromBits(bits, false))
}

/**
 * Converts the given uint8array to a BitArray (SJCL).
 * @param uint8Array The uint8Array key.
 * @return The key.
 */
export function uint8ArrayToBitArray(uint8Array: Uint8Array): BitArray {
	return sjcl.codec.arrayBuffer.toBits(uint8ArrayToArrayBuffer(uint8Array))
}

/**
 * Converts the given key to a base64 coded string.
 * @param key The key.
 * @return The base64 coded string representation of the key.
 */
export function keyToBase64(key: AesKey): Base64 {
	return sjcl.codec.base64.fromBits(key)
}

/**
 * Converts the given base64 coded string to a key.
 * @param base64 The base64 coded string representation of the key.
 * @return The key.
 * @throws {CryptoError} If the conversion fails.
 */
export function base64ToKey(base64: Base64): AesKey {
	try {
		return sjcl.codec.base64.toBits(base64)
	} catch (e) {
		throw new CryptoError("hex to aes key failed", e as Error)
	}
}

export function uint8ArrayToKey(array: Uint8Array): AesKey {
	return base64ToKey(uint8ArrayToBase64(array))
}

export function keyToUint8Array(key: BitArray): Uint8Array {
	return base64ToUint8Array(keyToBase64(key))
}

/**
	 * Create a random 256-bit symmetric AES key.
	 *
	 * @return The key.
	 */
	export function aes256RandomKey(): Aes256Key {
		return uint8ArrayToBitArray(random.generateRandomData(KEY_LENGTH_BYTES_AES_256))
	}

	/**
	 * Converts the given key to an array of bytes.
	 *
	 * @param key The key.
	 * @return The bytes representation of the key.
	 */
	public static byte[] keyToBytes(SecretKeySpec key) {
		return key.getEncoded();
	}

	/**
	 * Converts the given byte array to a key.
	 *
	 * @param key The bytes representation of the key.
	 * @return The key.
	 * @throws InvalidKeyException if the key has the wrong length
	 */
	public static SecretKeySpec bytesToKey(byte[] key) throws InvalidKeyException {
		if (key.length != AesKeyLength.Aes128.getKeyLengthBytes() && key.length != AesKeyLength.Aes256.getKeyLengthBytes()) {
			throw new InvalidKeyException("key length: " + key.length + " (expected: 16 or 32)");
		}
		return new SecretKeySpec(key, "AES");
	}