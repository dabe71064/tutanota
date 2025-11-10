package de.tutao.common.crypto.symmetric;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import de.tutao.common.crypto.HMacFacade;
import de.tutao.common.instance.data.InvalidDataFormatException;
import de.tutao.common.util.ArrayUtils;
import de.tutao.common.util.EncodingConverter;
import de.tutao.common.util.NotNullByDefault;
import de.tutao.common.util.TutaDbException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static de.tutao.common.crypto.symmetric.SymmetricCipherUtils.*;

/**
 * This facade provides the implementation for both encryption and decryption of AES in CBC mode. Supports 128 and 256-bit keys.
 * Depending on the cipher version the encryption is authenticated with HMAC-SHA-256.
 * SymmetricCipherFacade is responsible for handling parameters for encryption/decryption.
 */
@NotNullByDefault
@Singleton
public class AesCbcFacade {

	private final SymmetricKeyDeriver symmetricKeyDeriver;

	@Inject
	public AesCbcFacade(SymmetricKeyDeriver symmetricKeyDeriver) {
		this.symmetricKeyDeriver = symmetricKeyDeriver;
	}

	/**
	 * This should not be called directly! Use SymmetricCipherFacade instead
	 */
	byte[] encrypt(SecretKeySpec key,
				   byte[] plainText,
				   boolean hasRandomIvToPrepend,
				   byte[] iv,
				   boolean padding,
				   SymmetricCipherVersion cipherVersion) throws InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance((padding) ? AES_ENCRYPTION_MODE_PADDING : AES_ENCRYPTION_MODE_NO_PADDING);
		IvParameterSpec params = new IvParameterSpec(iv);

		var subKeys = symmetricKeyDeriver.deriveSubKeys(key, cipherVersion);

		cipher.init(Cipher.ENCRYPT_MODE, subKeys.encryptionKey(), params);
		byte[] cipherText = cipher.doFinal(plainText);

		byte[] unauthenticatedCiphertext;
		if (hasRandomIvToPrepend) {
			//version byte is not included into authentication tag for legacy reasons
			unauthenticatedCiphertext = ArrayUtils.merge(iv, cipherText);
		} else {
			unauthenticatedCiphertext = cipherText;
		}
		return switch (cipherVersion) {
			case UnusedReservedUnauthenticated -> {
				yield unauthenticatedCiphertext;
			}
			case AesCbcThenHmac -> {
				assert subKeys.authenticationKey() != null;
				byte[] authenticationTag = HMacFacade.hmac256(subKeys.authenticationKey(), unauthenticatedCiphertext);
				yield ArrayUtils.merge(SymmetricCipherVersion.AesCbcThenHmac.asBytes(), unauthenticatedCiphertext, authenticationTag);
			}
			default -> {
				throw new RuntimeException("unexpected cipher version " + cipherVersion);
			}
		};
	}

	/**
	 * This should not be called directly! Use SymmetricCipherFacade instead
	 */
	byte[] decrypt(SecretKeySpec key, byte[] cipherText, boolean randomIv, boolean padding, SymmetricCipherVersion cipherVersion) {
		try {
			var subKeys = symmetricKeyDeriver.deriveSubKeys(key, cipherVersion);
			byte[] cipherTextWithoutMacAndVersionByte;
			switch (cipherVersion) {
				case UnusedReservedUnauthenticated -> {
					cipherTextWithoutMacAndVersionByte = cipherText;
				}
				case AesCbcThenHmac -> {
					assert subKeys.authenticationKey() != null;
					cipherTextWithoutMacAndVersionByte = Arrays.copyOfRange(cipherText, SYMMETRIC_CIPHER_VERSION_PREFIX_LENGTH_BYTES,
							cipherText.length - SYMMETRIC_AUTHENTICATION_TAG_LENGTH_BYTES);
					byte[] providedMacBytes = Arrays.copyOfRange(cipherText, cipherText.length - SYMMETRIC_AUTHENTICATION_TAG_LENGTH_BYTES, cipherText.length);
					HMacFacade.verifyHmacSha256(providedMacBytes, subKeys.authenticationKey(), cipherTextWithoutMacAndVersionByte);
				}
				default -> {
					throw new RuntimeException("unexpected cipher version " + cipherVersion);
				}
			}
			Cipher cipher = Cipher.getInstance((padding) ? AES_ENCRYPTION_MODE_PADDING : AES_ENCRYPTION_MODE_NO_PADDING);
			byte[] iv;
			byte[] aesCbcCiphertext;
			if (randomIv) {
				iv = Arrays.copyOfRange(cipherTextWithoutMacAndVersionByte, 0, IV_LENGTH_BYTES);
				aesCbcCiphertext = Arrays.copyOfRange(cipherTextWithoutMacAndVersionByte, IV_LENGTH_BYTES, cipherTextWithoutMacAndVersionByte.length);
			} else {
				iv = EncodingConverter.hexToBytes(FIXED_IV_HEX);
				aesCbcCiphertext = cipherTextWithoutMacAndVersionByte;
			}
			IvParameterSpec params = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, subKeys.encryptionKey(), params);
			return cipher.doFinal(aesCbcCiphertext);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException
				 | InvalidAlgorithmParameterException | InvalidDataFormatException e) {
			throw new TutaDbException(e);
		}
	}
}
