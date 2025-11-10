package de.tutao.common.crypto.symmetric;

import com.google.inject.Singleton;
import de.tutao.common.crypto.Hkdf;
import de.tutao.common.crypto.ShaFacade;
import de.tutao.common.util.ArrayUtils;
import de.tutao.common.util.NotNullByDefault;
import de.tutao.common.util.VisibleForTesting;

import javax.annotation.Nullable;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import static de.tutao.common.crypto.symmetric.AesKeyLength.AES256_KEY_LENGTH_BYTES;

/**
 * This facade derives encryption and authentication keys as needed for the symmetric cipher implementations
 */
@NotNullByDefault
@Singleton
public class SymmetricKeyDeriver {
	@VisibleForTesting
	static final String AEAD_KEY_DERIVATION_INFO = "AEAD key splitting";

	record SubKeys(SecretKeySpec encryptionKey, @Nullable byte[] authenticationKey) {
	}

	SubKeys deriveSubKeys(SecretKeySpec key, SymmetricCipherVersion symmetricCipherVersion) {
		AesKeyLength keyLength = AesKeyLength.get(key);
		final byte[] keyBytes = SymmetricCipherUtils.keyToBytes(key);
		return switch (symmetricCipherVersion) {
			case UnusedReservedUnauthenticated -> {
				if (keyLength != AesKeyLength.Aes128) {
					throw new RuntimeException("key length " + keyLength + "is incompatible with cipherVersion " + symmetricCipherVersion);
				}
				yield new SubKeys(key, null);
			}
			case AesCbcThenHmac -> {
				byte[] hash = switch (keyLength) {
					case Aes128 -> ShaFacade.hash(keyBytes);
					case Aes256 -> ShaFacade.hash512(keyBytes);
				};
				var encryptionKey = new SecretKeySpec(Arrays.copyOfRange(hash, 0, keyLength.getKeyLengthBytes()), "AES");
				var authenticationKey = Arrays.copyOfRange(hash, keyLength.getKeyLengthBytes(), 2 * keyLength.getKeyLengthBytes());
				yield new SubKeys(encryptionKey, authenticationKey);
			}
			case Aead -> {
				//(EK , AK ) ← HKDF (K , null, "AEAD key splitting"||VAEAD , 2 ∗ 256)
				var infoWithCipherVersion = ArrayUtils.merge(AEAD_KEY_DERIVATION_INFO.getBytes(), symmetricCipherVersion.asBytes());
				int outputKeyLength = 2 * AES256_KEY_LENGTH_BYTES;
				byte[] derivedKeys = Hkdf.hkdf(null, keyBytes, infoWithCipherVersion, outputKeyLength);
				var encryptionKey = new SecretKeySpec(Arrays.copyOfRange(derivedKeys, 0, AES256_KEY_LENGTH_BYTES), "AES");
				var authenticationKey = Arrays.copyOfRange(derivedKeys, AES256_KEY_LENGTH_BYTES, outputKeyLength);
				yield new SubKeys(encryptionKey, authenticationKey);
			}
		};
	}

}
