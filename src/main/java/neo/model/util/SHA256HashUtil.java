package neo.model.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * utilities having to do with the SHA256 hash.
 *
 * @author coranos
 *
 */
public final class SHA256HashUtil {

	/** Instance of a SHA-256 digest which we will use as needed */
	private static final MessageDigest digest;
	static {
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);  // Can't happen.
		}
	}
	/**
	 * returns the sha256 hash of the sha256 hash of the bytes. (it calls the has
	 * function twice, passing the output of the first call as the input to the
	 * second call.)
	 *
	 * @param bytes
	 *            the bytes to hash.
	 * @return the hash.
	 */
	public static byte[] getDoubleSHA256Hash(final byte[] bytes) {
		return getSHA256Hash(getSHA256Hash(bytes));
	}

	/**
	 * returns the sha256 hash of the bytes.
	 *
	 * @param bytes
	 *            the bytes to hash.
	 * @return the hash.
	 */
	public static byte[] getSHA256Hash(final byte[] bytes) {
		return getSHA256Hash(bytes, 0, bytes.length);
	}

	/**
	 * Calculate the SHA-256 hash of the input and then hash the resulting hash again
	 *
	 * @param       input           Data to be hashed
	 * @param       offset          Starting offset within the data
	 * @param       length          Number of data bytes to hash
	 * @return                      The hash digest
	 */
	public static byte[] getSHA256Hash(byte[] input, int offset, int length) {
		byte[] bytes;
		synchronized (digest) {
			digest.reset();
			digest.update(input, offset, length);
			bytes = digest.digest();
		}
		return bytes;
	}


	/**
	 * the constructor.
	 */
	private SHA256HashUtil() {

	}
}
