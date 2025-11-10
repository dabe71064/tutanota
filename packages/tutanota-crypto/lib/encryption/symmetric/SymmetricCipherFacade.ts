package de.tutao.common.crypto.symmetric;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import de.tutao.common.crypto.RandomizerFacade;
import de.tutao.common.crypto.RsaFacade;
import de.tutao.common.instance.data.InvalidDataFormatException;
import de.tutao.common.instance.data.VersionedEncryptedKey;
import de.tutao.common.instance.data.VersionedKey;
import de.tutao.common.util.EncodingConverter;
import de.tutao.common.util.NotNullByDefault;
import de.tutao.common.util.TutaDbException;
import de.tutao.common.util.VisibleForTesting;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;

import static de.tutao.common.crypto.symmetric.AesKeyLength.Aes128;
import static de.tutao.common.crypto.symmetric.SymmetricCipherUtils.FIXED_IV_HEX;
import static de.tutao.common.crypto.symmetric.SymmetricCipherUtils.IV_LENGTH_BYTES;

/**
 * This facade contains all methods for encryption/ decryption for symmetric encryption incl. AES-128 and AES-256 in CBC mode or AEAD.
 *
 * Depending on the symmetric cipher version it adds an HMAC tag (Encrypt-then-Mac), in which case two different keys for encryption and authentication are
 * derived from the provided secret key.
 *
 * In case of AEAD, there is additional associated data. Needed both for encryption and decryption, but it is not part of the created ciphertext.
 */
@NotNullByDefault
@Singleton
public class SymmetricCipherFacade {
	private final RsaFacade rsaFacade;
	private final SecureRandom secureRandom;
	private final AeadFacade aeadFacade;
	private final AesCbcFacade aesCbcFacade;

	@Inject
	public SymmetricCipherFacade(RsaFacade rsaFacade,
								 AeadFacade aeadFacade,
								 AesCbcFacade aesCbcFacade) {
		this(rsaFacade, RandomizerFacade.getSecureRandom(), aeadFacade, aesCbcFacade);
	}

	@VisibleForTesting
	public SymmetricCipherFacade(RsaFacade rsaFacade,
								 SecureRandom secureRandom,
								 AeadFacade aeadFacade,
								 AesCbcFacade aesCbcFacade) {
		this.rsaFacade = rsaFacade;
		this.secureRandom = secureRandom;
		this.aeadFacade = aeadFacade;
		this.aesCbcFacade = aesCbcFacade;
	}

	@VisibleForTesting
	public static SymmetricCipherFacade createInstance() {
		return createInstance(RsaFacade.createInstance());
	}

	@VisibleForTesting
	public static SymmetricCipherFacade createInstance(RsaFacade rsaFacade) {
		var symmetricKeyDeriver = new SymmetricKeyDeriver();
		return new SymmetricCipherFacade(rsaFacade, new AeadFacade(symmetricKeyDeriver), new AesCbcFacade(symmetricKeyDeriver));
	}

	/**
	 * Encrypts a byte array with AES in CBC mode.
	 *
	 * @param key   The key to use for the encryption.
	 * @param bytes The data to encrypt.
	 * @return The encrypted bytes.
	 */
	public byte[] encryptBytes(SecretKeySpec key, byte[] bytes) {
		return encrypt(key, bytes, true, SymmetricCipherVersion.AesCbcThenHmac);
	}

	/**
	 * Encrypts a byte array with AES in CBC mode.
	 *
	 * Forces encryption without authentication. Only use in backward compatibility tests.
	 *
	 * @param key   The key to use for the encryption.
	 * @param bytes The data to encrypt.
	 * @return The encrypted bytes.
	 */
	@VisibleForTesting
	@Deprecated
	public byte[] encryptBytesDeprecatedUnauthenticated(SecretKeySpec key, byte[] bytes) {
		return encrypt(key, bytes, true, SymmetricCipherVersion.UnusedReservedUnauthenticated);
	}

	/**
	 * Decrypts byte array with AES in CBC mode.
	 *
	 * @param key   The key to use for the decryption.
	 * @param bytes A byte array that was encrypted with the same key before.
	 * @return The decrypted bytes.
	 */
	public byte[] decryptBytes(SecretKeySpec key, byte[] bytes) {
		return decrypt(key, bytes, true);
	}

	/**
	 * Encrypts an utf8 coded string with AES in CBC mode.
	 *
	 * @param key  The key to use for the encryption.
	 * @param utf8 Utf8 coded data.
	 * @return The encrypted text.
	 */
	public byte[] encryptUtf8(SecretKeySpec key, String utf8) {
		return encrypt(key, utf8.getBytes(StandardCharsets.UTF_8), true, SymmetricCipherVersion.AesCbcThenHmac);
	}

	/**
	 * Decrypts binary data with AES in CBC mode.
	 *
	 * @param key       The key to use for the decryption.
	 * @param encrypted A byte array that was encrypted with the same key before.
	 * @return The decrypted text, utf8 coded.
	 */
	public String decryptUtf8(SecretKeySpec key, byte[] encrypted) {
		return new String(decrypt(key, encrypted, true), StandardCharsets.UTF_8);
	}

	/**
	 * Encrypts a hex coded key with AES in CBC mode.
	 *
	 * @param key          The key to use for the encryption.
	 * @param keyToEncrypt The key that shall be encrypted.
	 * @return The encrypted key.
	 */
	public byte[] encryptKey(SecretKeySpec key, SecretKeySpec keyToEncrypt) {
		return switch (AesKeyLength.get(key)) {
			// we never authenticate keys encrypted with a legacy AES-128 key, because we rotate all keys to 256 to ensure authentication
			case Aes128 -> encrypt(key, SymmetricCipherUtils.keyToBytes(keyToEncrypt), false, false, SymmetricCipherVersion.UnusedReservedUnauthenticated);
			case Aes256 -> encrypt(key, SymmetricCipherUtils.keyToBytes(keyToEncrypt), false, SymmetricCipherVersion.AesCbcThenHmac);
		};
	}

	/**
	 * Encrypts a hex coded key with AES in CBC mode.
	 *
	 * @param key          The key to use for the encryption.
	 * @param keyToEncrypt The key that shall be encrypted.
	 * @return The encrypted key.
	 */
	public VersionedEncryptedKey encryptKey(VersionedKey key, SecretKeySpec keyToEncrypt) {
		var encrypted = encryptKey(key.key(), keyToEncrypt);
		return new VersionedEncryptedKey(encrypted, key.version());
	}

	/**
	 * Decrypts a key with AES in CBC mode.
	 *
	 * @param key   The key to use for the decryption.
	 * @param bytes The key that shall be decrypted.
	 * @return The decrypted key.
	 */
	public SecretKeySpec decryptKey(SecretKeySpec key, byte[] bytes) {
		return switch (AesKeyLength.get(key)) {
			case Aes128 -> new SecretKeySpec(decrypt(key, bytes, false, false), "AES");
			case Aes256 -> new SecretKeySpec(decrypt(key, bytes, false), "AES");
		};
	}

	/**
	 * Encrypts a hex coded key with AES in CBC mode.
	 *
	 * @param key          The key to use for the encryption.
	 * @param keyToEncrypt The key that shall be encrypted.
	 * @return The encrypted key
	 */
	public byte[] encryptPrivateRsaKey(SecretKeySpec key, RSAPrivateCrtKey keyToEncrypt) {
		byte[] byteKey = rsaFacade.privateKeyToBytes(keyToEncrypt);
		return encrypt(key, byteKey, true, SymmetricCipherVersion.AesCbcThenHmac);
	}

	/**
	 * Decrypts a key with AES in CBC mode.
	 *
	 * @param key   The key to use for the decryption.
	 * @param bytes The key that shall be decrypted.
	 * @return The decrypted key.
	 */
	public RSAPrivateCrtKey decryptPrivateRsaKey(SecretKeySpec key, byte[] bytes) {
		byte[] decryptedKey = decrypt(key, bytes, true);
		return rsaFacade.bytesToPrivateKey(decryptedKey);
	}

	private byte[] encrypt(SecretKeySpec key, byte[] plainText, boolean padding, SymmetricCipherVersion cipherVersion) {
		return encrypt(key, plainText, true, padding, cipherVersion);
	}

	private byte[] encrypt(SecretKeySpec key, byte[] plainText, boolean hasRandomIv, boolean padding, SymmetricCipherVersion cipherVersion) {
		try {
			byte[] iv;
			if (hasRandomIv) {
				iv = new byte[IV_LENGTH_BYTES];
				secureRandom.nextBytes(iv);
			} else {
				iv = EncodingConverter.hexToBytes(FIXED_IV_HEX);
			}
			return switch (cipherVersion) {
				case UnusedReservedUnauthenticated, AesCbcThenHmac -> {
					yield aesCbcFacade.encrypt(key, plainText, hasRandomIv, iv, padding, cipherVersion);
				}
				case Aead -> {
					assert hasRandomIv; // we do not allow fixed ivs for AEAD
					// we can only use this once all clients support it
					throw new RuntimeException("Not enabled");
				}
			};
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException
				 | InvalidAlgorithmParameterException | InvalidDataFormatException e) {
			throw new TutaDbException(e);
		}
	}

	private byte[] decrypt(SecretKeySpec key, byte[] cipherText, boolean padding) {
		return decrypt(key, cipherText, true, padding);
	}

	private byte[] decrypt(SecretKeySpec key, byte[] cipherText, boolean randomIv, boolean padding) {
		var cipherVersion = getCipherVersion(cipherText, key);
		return switch (cipherVersion) {
			case UnusedReservedUnauthenticated, AesCbcThenHmac -> {
				yield aesCbcFacade.decrypt(key, cipherText, randomIv, padding, cipherVersion);
			}
			case Aead -> {
				// use this as soon as we define what to use as associated data
				throw new RuntimeException("not yet enabled");
			}
		};
	}

	private SymmetricCipherVersion getCipherVersion(byte[] cipherText, SecretKeySpec key) {
		var cipherVersion = SymmetricCipherVersion.getFromCiphertext(cipherText);
		if (cipherVersion == SymmetricCipherVersion.UnusedReservedUnauthenticated && AesKeyLength.get(key) != Aes128) {
			// if there is no version byte there also is no mac. so we throw here.
			// we cannot enforce for the legacy aes128 keys as there are untagged ciphertexts that we must remain compatibility with
			throw new TutaDbException("mac is enforced but not present");
		}
		return cipherVersion;
	}
}
