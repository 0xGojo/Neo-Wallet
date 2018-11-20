package neo.model.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.jar.Attributes;

import com.google.common.primitives.Longs;
import neo.model.core.TransactionAttribute;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;
import org.h2.mvstore.db.TransactionStore;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import neo.model.ByteArraySerializable;
import neo.model.ByteSizeable;
import neo.model.ToJsonObject;
import neo.model.bytes.Fixed8;
import neo.model.bytes.UInt128;
import neo.model.bytes.UInt16;
import neo.model.bytes.UInt160;
import neo.model.bytes.UInt256;
import neo.model.bytes.UInt32;
import neo.model.bytes.UInt64;
import neo.model.core.CoinReference;
import neo.model.core.Transaction;
import neo.model.core.TransactionOutput;
import neo.model.db.BlockDb;

import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.Data;

/**
 * the utilities for editing the neo model.
 *
 * @author coranos
 * @author thachtb
 */
public final class ModelUtil {

	/**
	 * a fixed8 representation of zero.
	 */
	public static final Fixed8 FIXED8_ZERO = ModelUtil.getFixed8(BigInteger.ZERO);

	/**
	 * the UTF-8 charset.
	 */
	private static final String UTF_8 = "UTF-8";

	/**
	 * gas.
	 */
	public static final String GAS = "gas";

	/**
	 * neo.
	 */
	public static final String NEO = "neo";

	/**
	 * the logger.
	 */
	private static final Logger LOG = LoggerFactory.getLogger(ModelUtil.class);

	/**
	 * the encoded byte to mean a variable length is a long.
	 */
	private static final byte LENGTH_LONG = (byte) 0xFF;

	/**
	 * the encoded byte to mean a variable length is a int.
	 */
	private static final byte LENGTH_INT = (byte) 0xFE;

	/**
	 * the encoded byte to mean a variable length is a short.
	 */
	private static final byte LENGTH_SHORT = (byte) 0xFD;

	/**
	 * the NEO coin hash.
	 */
	public static final String NEO_HASH_HEX_STR = "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b";

	/**
	 * the GAS coin hash.
	 */
	public static final String GAS_HASH_HEX_STR = "602c79718b16e442de58778e148d0b1084e3b2dffd5de6b7b16cee7969282de7";

	/**
	 * the hash of the NEO registration transaction.
	 */
	public static final UInt256 NEO_HASH;

	/**
	 * the hash of the GAS registration transaction.
	 */
	public static final UInt256 GAS_HASH;

	/**
	 * the divisor to use to convert a Fixed8 value to a decimal.
	 */
	public static final long DECIMAL_DIVISOR = 100000000;

	static {

		try {
			final byte[] neoBa = Hex.decodeHex(NEO_HASH_HEX_STR.toCharArray());
			// ArrayUtils.reverse(neoBa);
			NEO_HASH = new UInt256(neoBa);

			final byte[] gasBa = Hex.decodeHex(GAS_HASH_HEX_STR.toCharArray());
			// ArrayUtils.reverse(gasBa);
			GAS_HASH = new UInt256(gasBa);
		} catch (final DecoderException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * the address version.
	 */
	public static final byte ADDRESS_VERSION = 23;

	/**
	 * adds two Fixed8 values.
	 *
	 * @param value1
	 *            the first value
	 * @param value2
	 *            the second value.
	 * @return the sum of the two values.
	 */
	public static Fixed8 add(final Fixed8 value1, final Fixed8 value2) {
		final BigInteger oldBi = value1.toPositiveBigInteger();
		final BigInteger valBi = value2.toPositiveBigInteger();
		final BigInteger newBi = oldBi.add(valBi);
		final Fixed8 newValue = getFixed8(newBi);
		return newValue;
	}

	/**
	 * return the scripthash of the address.
	 *
	 * @param address
	 *            the address to use.
	 * @return the scripthash of the address.
	 */
	public static UInt160 addressToScriptHash(final String address){
		byte[] ProgramHash = Base58Util.decode(address);
		String ProgramHashString = ModelUtil.toHexString(ProgramHash).substring(0, 42);
		return new UInt160(ModelUtil.hexStringToByteArray(ProgramHashString.substring(2, 42)));
	}

	/**
	 * compares two arrays.
	 *
	 * @param list1
	 *            the first array.
	 * @param list2
	 *            the second array.
	 * @return the comparison of the two arrays.
	 */
	public static int compareTo(final byte[] list1, final byte[] list2) {
		if (list1.length != list2.length) {
			final Integer size1 = list1.length;
			final Integer size2 = list2.length;
			return size1.compareTo(size2);
		}

		for (int ix = 0; ix < list1.length; ix++) {
			final Byte obj1 = list1[ix];
			final Byte obj2 = list2[ix];
			final int c = obj1.compareTo(obj2);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	/**
	 * compares two lists.
	 *
	 * @param list1
	 *            the first list.
	 * @param list2
	 *            the second list.
	 * @param <T>
	 *            the type of the element in the list.
	 * @return the comparison of the two lists.
	 */
	public static <T extends Comparable<? super T>> int compareTo(final List<T> list1, final List<T> list2) {
		if (list1.size() != list2.size()) {
			final Integer size1 = list1.size();
			final Integer size2 = list2.size();
			return size1.compareTo(size2);
		}

		final Iterator<T> it1 = list1.iterator();
		final Iterator<T> it2 = list2.iterator();

		while (it1.hasNext() && it2.hasNext()) {
			final T obj1 = it1.next();
			final T obj2 = it2.next();
			final int c = obj1.compareTo(obj2);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	/**
	 * compares two arrays.
	 *
	 * @param list1
	 *            the first array.
	 * @param list2
	 *            the second array.
	 * @param <T>
	 *            the type of the element in the list.
	 * @return the comparison of the two arrays.
	 */
	public static <T extends Comparable<? super T>> int compareTo(final T[] list1, final T[] list2) {
		if (list1.length != list2.length) {
			final Integer size1 = list1.length;
			final Integer size2 = list2.length;
			return size1.compareTo(size2);
		}

		for (int ix = 0; ix < list1.length; ix++) {
			final T obj1 = list1[ix];
			final T obj2 = list2[ix];
			final int c = obj1.compareTo(obj2);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	/**
	 * copies and reverses a byte array.
	 *
	 * @param input
	 *            the byte array to copy and reverse.
	 * @return a copy of the byte array, in reverse byte order.
	 */
	public static byte[] copyAndReverse(final byte[] input) {
		final byte[] revInput = new byte[input.length];
		System.arraycopy(input, 0, revInput, 0, input.length);
		ArrayUtils.reverse(revInput);
		return revInput;
	}

	/**
	 * decodes a hex string.
	 *
	 * @param string
	 *            the string to decode.
	 * @return the decoded hex string.
	 */
	public static byte[] decodeHex(final String string) {
		try {
			return Hex.decodeHex(string.toCharArray());
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * converts a byte array to a BigInteger.
	 *
	 * @param ba
	 *            the byte array to use.
	 * @return the BigInteger.
	 */
	public static BigInteger getBigInteger(final byte[] ba) {
		return getBigInteger(ByteBuffer.wrap(ba));
	}

	/**
	 * converts a ByteBuffer to a BigInteger.
	 *
	 * @param bb
	 *            the ByteBuffer to use.
	 * @return the BigInteger.
	 */
	public static BigInteger getBigInteger(final ByteBuffer bb) {
		final byte lengthType = bb.get();

		final int length;
		if (lengthType == LENGTH_SHORT) {
			length = 2;
		} else if (lengthType == LENGTH_INT) {
			length = 4;
		} else if (lengthType == LENGTH_LONG) {
			length = 8;
		} else {
			length = -1;
		}

		if (length == -1) {
			final BigInteger retval = new BigInteger(1, new byte[] { lengthType });
			return retval;
		}

		final byte[] ba = new byte[length];
		bb.get(ba);

		ArrayUtils.reverse(ba);
		final BigInteger retval = new BigInteger(1, ba);

		return retval;
	}

	/**
	 * gets a boolean from a ByteBuffer.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @return true if the next byte was not zero, false otherwise.
	 */
	public static boolean getBoolean(final ByteBuffer bb) {
		return bb.get() != 0;
	}

	/**
	 * gets a byte from a ByteBuffer.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @return the byte.
	 */
	public static byte getByte(final ByteBuffer bb) {
		return bb.get();
	}

	/**
	 * creates a new Fixed8 from a BigInteger.
	 *
	 * @param newBi
	 *            the BigInteger to use.
	 * @return the new Fixed8.
	 */
	public static Fixed8 getFixed8(final BigInteger newBi) {
		final byte[] ba = new byte[UInt64.SIZE];
		final byte[] biBa = newBi.toByteArray();
		final int destPos;
		final int srcPos;
		final int length;
		if (biBa.length <= ba.length) {
			destPos = UInt64.SIZE - biBa.length;
			srcPos = 0;
			length = biBa.length;
		} else if (biBa[0] == 0) {
			destPos = 0;
			srcPos = 1;
			length = biBa.length - 1;
		} else {
			destPos = UInt64.SIZE - biBa.length;
			srcPos = 0;
			length = biBa.length;
		}
		try {
			System.arraycopy(biBa, srcPos, ba, destPos, length);
			ArrayUtils.reverse(ba);
			final Fixed8 newValue = new Fixed8(ByteBuffer.wrap(ba));
			return newValue;
		} catch (final ArrayIndexOutOfBoundsException e) {
			final JSONObject msgJson = new JSONObject();
			msgJson.put("ba", Hex.encodeHexString(ba));
			msgJson.put("biBa", Hex.encodeHexString(biBa));
			msgJson.put("destPos", destPos);
			msgJson.put("srcPos", srcPos);
			msgJson.put("length", length);
			final String msg = msgJson.toString();
			throw new RuntimeException(msg, e);
		}
	}

	/**
	 * returned a Fixed8.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @return the new Fixed8.
	 */
	public static Fixed8 getFixed8(final ByteBuffer bb) {
		return new Fixed8(bb);
	}

	/**
	 * gets a fixed length byte array from the ByteBuffer.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @param size
	 *            the size of the byte array.
	 * @param reverse
	 *            if true, reverse the byte array.
	 * @return the fixed length byte array.
	 */
	public static byte[] getFixedLengthByteArray(final ByteBuffer bb, final int size, final boolean reverse) {
		final byte[] ba = new byte[size];
		bb.get(ba);
		if (reverse) {
			ArrayUtils.reverse(ba);
		}
		return ba;
	}

	/**
	 * returns a String, which was previously encoded as a fixed length UTF-8 byte
	 * array.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @param length
	 *            the length to use.
	 * @return the string.
	 */
	public static String getFixedLengthString(final ByteBuffer bb, final int length) {
		final byte[] ba = getFixedLengthByteArray(bb, length, false);
		return new String(ba, StandardCharsets.UTF_8);
	}

	/**
	 * returns the transaction output for this coin reference.
	 *
	 * @param blockDb
	 *            the block database to ues.
	 * @param coinReference
	 *            the coin reference to use.
	 * @return the TransactionOutput.
	 */
	public static TransactionOutput getTransactionOutput(final BlockDb blockDb, final CoinReference coinReference) {
		final UInt256 prevHashReversed = coinReference.prevHash.reverse();
		final Transaction tiTx = blockDb.getTransactionWithHash(prevHashReversed);
		final int prevIndex = coinReference.prevIndex.asInt();
		final TransactionOutput ti = tiTx.outputs.get(prevIndex);
		return ti;
	}

	/**
	 * returns a UInt128 read from the ByteBuffer.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @return the new UInt128.
	 */
	public static UInt128 getUInt128(final ByteBuffer bb) {
		final byte[] ba = getFixedLengthByteArray(bb, UInt128.SIZE, true);
		return new UInt128(ba);
	}

	/**
	 * returns a UInt16 read from the ByteBuffer.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @return the new UInt16.
	 */
	public static UInt16 getUInt16(final ByteBuffer bb) {
		final byte[] ba = getFixedLengthByteArray(bb, UInt16.SIZE, true);
		return new UInt16(ba);
	}

	/**
	 * returns a UInt160 read from the ByteBuffer.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @param reverse
	 *            if true, reverse the byte array creating the data used to create
	 *            the object before creating the object.
	 * @return the new UInt160.
	 */
	public static UInt160 getUInt160(final ByteBuffer bb, final boolean reverse) {
		final byte[] ba = getFixedLengthByteArray(bb, UInt160.SIZE, true);
		if (reverse) {
			ArrayUtils.reverse(ba);
		}
		return new UInt160(ba);
	}

	/**
	 * returns a UInt256 read from the ByteBuffer.
	 *
	 * @param bb
	 *            the byte buffer to use.
	 * @return the new UInt256.
	 */
	public static UInt256 getUInt256(final ByteBuffer bb) {
		return getUInt256(bb, false);
	}

	/**
	 * returns a UInt256 read from the ByteBuffer.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @param reverse
	 *            if true, reverse the byte array creating the data used to create
	 *            the object before creating the object.
	 * @return the new UInt256.
	 */
	public static UInt256 getUInt256(final ByteBuffer bb, final boolean reverse) {
		final byte[] ba = getFixedLengthByteArray(bb, UInt256.SIZE, true);
		if (reverse) {
			ArrayUtils.reverse(ba);
		}
		return new UInt256(ba);
	}

	/**
	 * returns a UInt32 read from the ByteBuffer.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @return the new UInt32.
	 */
	public static UInt32 getUInt32(final ByteBuffer bb) {
		final byte[] ba = getFixedLengthByteArray(bb, UInt32.SIZE, true);
		return new UInt32(ba);
	}

	/**
	 * returns a UInt64 read from the ByteBuffer.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @return the new UInt64.
	 */
	public static UInt64 getUInt64(final ByteBuffer bb) {
		final byte[] ba = getFixedLengthByteArray(bb, UInt64.SIZE, true);
		return new UInt64(ba);
	}

	/**
	 * gets a variable length byte array from the ByteBuffer.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @return a variable length byte array.
	 */
	public static byte[] getVariableLengthByteArray(final ByteBuffer bb) {
		final BigInteger length = getBigInteger(bb);
		final byte[] ba = new byte[length.intValue()];
		bb.get(ba);
		return ba;
	}

	/**
	 * returns a String, which was previously encoded as a variable length UTF-8
	 * byte array.
	 *
	 * @param bb
	 *            the ByteBuffer to read.
	 * @return the string.
	 */
	public static String getVariableLengthString(final ByteBuffer bb) {
		final byte[] ba = getVariableLengthByteArray(bb);
		return new String(ba, StandardCharsets.UTF_8);
	}

	/**
	 * return the size of the byteArray, if stored as a variable length byte array.
	 *
	 * @param byteArray
	 *            the byteArray.
	 * @return the size of the byteArray, if stored as a variable length byte array.
	 */
	public static int getVarSize(final byte[] byteArray) {
		return getVarSize(byteArray.length) + byteArray.length;
	}

	/**
	 * return the size of the value, if stored as a variable length int.
	 *
	 * @param value
	 *            the value.
	 * @return the size of the value, if stored as a variable length int.
	 */
	public static int getVarSize(final int value) {
		if (value < 0xFD) {
			return 1;
		} else if (value <= 0xFFFF) {
			return 1 + 2;
		} else {
			return 1 + 4;
		}
	}

	/**
	 * return the size of the value, if stored as a variable length string.
	 *
	 * @param value
	 *            the value.
	 * @return the size of the value, if stored as a variable length string.
	 */
	public static int getVarSize(final String value) {
		final int size = value.getBytes(Charset.forName("UTF8")).length;
		return getVarSize(size) + size;
	}

	/**
	 * return the size of the list, if stored as a variable length list.
	 *
	 * @param list
	 *            the list.
	 * @param <T>
	 *            the type of the elemnt in the list.
	 * @return the size of the list, if stored as a variable length list.
	 */
	public static <T extends ByteSizeable> int getVarSize(final T[] list) {
		int size = getVarSize(list.length);
		for (final ByteSizeable elt : list) {
			size += elt.getByteSize();
		}
		return size;
	}

	/**
	 * reads a variable length list of byte array serializable objects.
	 *
	 * @param bb
	 *            the byte buffer to read.
	 * @param cl
	 *            the class of the objects in the list, which must implement
	 *            ByteArraySerializable.
	 * @param <T>
	 *            the type of the objects in the list.
	 * @return the list.
	 */
	public static <T extends ByteArraySerializable> List<T> readVariableLengthList(final ByteBuffer bb,
			final Class<T> cl) {
		final BigInteger lengthBi = getBigInteger(bb);
		final int length = lengthBi.intValue();

		LOG.trace("readArray length {} class {}", length, cl.getSimpleName());

		final List<T> list = new ArrayList<>();
		for (int ix = 0; ix < length; ix++) {

			LOG.trace("STARTED readArray class {} [{}]", cl.getSimpleName(), ix);
			final T t;
			try {
				final Constructor<T> con = cl.getConstructor(ByteBuffer.class);
				t = con.newInstance(bb);
			} catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException
					| IllegalArgumentException | InvocationTargetException e) {
				throw new RuntimeException(
						"error reading record " + (ix + 1) + " of " + length + " class " + cl.getSimpleName(), e);
			}

			LOG.trace("SUCCESS readArray class {} [{}]: {} {}", cl.getSimpleName(), ix,
					Hex.encodeHexString(t.toByteArray()), t);

			list.add(t);
		}
		return list;
	}

	/**
	 * coverts a scriptHash to an address.
	 *
	 * @param scriptHash
	 *            the scriptHash to use.
	 * @return the address.
	 */
	public static String scriptHashToAddress(final UInt160 scriptHash) {
		if (scriptHash == null) {
			return null;
		}
		final byte[] data = new byte[21];

		if (LOG.isTraceEnabled()) {
			LOG.trace("toAddress ADDRESS_VERSION {}", ModelUtil.toHexString(ADDRESS_VERSION));
		}

		final byte[] scriptHashBa = scriptHash.toByteArray();
		System.arraycopy(scriptHashBa, 0, data, 0, scriptHashBa.length);

		data[data.length - 1] = ADDRESS_VERSION;
		if (LOG.isTraceEnabled()) {
			LOG.trace("toAddress data {}", ModelUtil.toHexString(data));
		}

		final byte[] dataAndChecksum = new byte[25];
		ArrayUtils.reverse(data);
		System.arraycopy(data, 0, dataAndChecksum, 0, data.length);
		final byte[] hash = SHA256HashUtil.getDoubleSHA256Hash(data);
		final byte[] hash4 = new byte[4];
		System.arraycopy(hash, 0, hash4, 0, 4);
		System.arraycopy(hash4, 0, dataAndChecksum, 21, 4);
		if (LOG.isTraceEnabled()) {
			LOG.trace("toAddress dataAndChecksum {}", ModelUtil.toHexString(dataAndChecksum));
		}

		final String address = toBase58String(dataAndChecksum);
		return address;
	}

	/**
	 * subtracts two Fixed8 values.
	 *
	 * @param left
	 *            the left value
	 * @param right
	 *            the right value.
	 * @return left minus right
	 */
	public static Fixed8 subtract(final Fixed8 left, final Fixed8 right) {
		final BigInteger leftBi = left.toPositiveBigInteger();
		final BigInteger rightBi = right.toPositiveBigInteger();
		final BigInteger newBi = rightBi.subtract(leftBi);
		if (newBi.signum() < 0) {
			throw new RuntimeException("tried to subtract " + leftBi + "(Fixed8:" + left + ")  from " + rightBi
					+ " (Fixed8:" + right + ")" + " cannot have a negative fixed8 with value " + newBi + ".");
		}
		final Fixed8 newValue = getFixed8(newBi);
		return newValue;
	}

	/**
	 * converts an array of bytes to a base58 string.
	 *
	 * @param bytes
	 *            the bytes to use.
	 * @return the new string.
	 */
	public static String toBase58String(final byte[] bytes) {
		return Base58Util.encode(bytes);
	}

	/**
	 * converts an array of bytes to a base64 string.
	 *
	 * @param bytes
	 *            the bytes to use.
	 * @return the new string.
	 */
	public static String toBase64String(final byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	/**
	 * returns the list of byte arrays as a encoded byte array.
	 *
	 * @param baList
	 *            the byte array list.
	 * @return the encoded byte array.
	 */
	public static byte[] toByteArray(final byte[]... baList) {
		return toByteArray(Arrays.asList(baList));
	}

	/**
	 * converts a list of byte arrays into a byte array.
	 *
	 * @param baList
	 *            the byte array list to use.
	 * @return the byte array.
	 */
	public static byte[] toByteArray(final List<byte[]> baList) {
		final ByteArrayOutputStream bout;
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			NetworkUtil.writeLong(out, baList.size());
			for (final byte[] ba : baList) {
				NetworkUtil.writeByteArray(out, ba);
			}
			bout = out;
		} catch (final IOException e) {
			throw new RuntimeException(e);
		}
		return bout.toByteArray();
	}

	/**
	 * converts a byte array into a list of byte arrays.
	 *
	 * @param ba
	 *            the byte array to use.
	 * @return the byte array.
	 */
	public static List<byte[]> toByteArrayList(final byte[] ba) {
		final List<byte[]> baList = new ArrayList<>();
		final ByteBuffer listBb = ByteBuffer.wrap(ba);
		final long size = listBb.getLong();
		for (long ix = 0; ix < size; ix++) {
			final byte[] keyBa = ModelUtil.getVariableLengthByteArray(listBb);
			baList.add(keyBa);
		}
		return baList;
	}

	/**
	 * converts a byte array to a hex string.
	 *
	 * @param ba
	 *            the byte array to encode.
	 * @return the string.
	 */
	public static String toHexString(final byte... ba) {
		return new String(Hex.encodeHex(ba));
	}

	public static String num2hexstring(int size, final byte... data) {
		size = size * 2;
		String hexstring = toHexString(data);
		hexstring = hexstring.length() % size == 0 ? hexstring : (new String(new char[size]).replace("\0", "0")+ hexstring).substring(hexstring.length());
		// if (littleEndian) hexstring = reverseHex(hexstring);
		return hexstring;
	}

	/**
	 * Serialize transaction
	 *
	 * @param tx
	 * 			  Constructor of raw transaction
	 * @param signed
	 * 			  This flag served for multiple signatures purpose
	 */

	public static String serializeTransaction(Transaction tx, boolean signed){
		String result = "";
		result += num2hexstring( 1, tx.type.getTypeByte());
		result += num2hexstring(1, tx.version);
		// result += rerializzExclusize - this add another type of transaction to be executed
		result += num2VarInt(tx.attributes.size());
		for(int i = 0; i < tx.attributes.size(); i++){
			result += serializeTransactionAttribute(tx.attributes.get(i));
		}
		result += num2VarInt(tx.inputs.size());
		for(int i = 0; i < tx.inputs.size(); i++){
			result += serializeTransactionInput(tx.inputs.get(i));
		}

		result += num2VarInt(tx.outputs.size());
		for(int i = 0; i < tx.outputs.size(); i++){
			result += serializeTransactionOutput(tx.outputs.get(i));
		}

		return result;
	}

	private static String serializeTransactionAttribute(TransactionAttribute attr){
		if (attr.getCopyOfData().length > 65535) throw new Error();
		String serial_arrt = num2hexstring(1, attr.usage.getTypeByte());
		if (attr.usage.getTypeByte() == (byte)0x81) {
			serial_arrt += num2hexstring(1, (byte)(attr.getCopyOfData().length / 2));
		} else if (attr.usage.getTypeByte() == (byte)0x90 || attr.usage.getTypeByte() >= (byte)0xf0) {
			serial_arrt += num2VarInt(attr.getCopyOfData().length / 2);
		}
		if (attr.usage.getTypeByte() == 0x02 || attr.usage.getTypeByte() == 0x03) {
			serial_arrt += num2hexstring(1, attr.getCopyOfData()).substring(2, 64);
		} else {
			serial_arrt += num2hexstring(1, attr.getCopyOfData());
		}
		return serial_arrt;
	}

	static String num2VarInt(long data){
		if(data < 0xfd){
			return num2hexstring(1, (byte)data);
		} else if(data <= 0xffff){
			// uint16
			return "fd" + num2hexstring(2, (byte)data);
		} else if(data <= 0xffffffff){
			// uint32
			return "fe" + num2hexstring(4, (byte)data);
		}
		return "ff" + num2hexstring(8, (byte)data);
	}

	public static String serializeTransactionInput(CoinReference input){
		return num2hexstring(1, input.prevHash.reverse().toByteArray()) + num2hexstring(2, reverse(input.prevIndex.toByteArray()));
	}

	public static String serializeTransactionOutput(TransactionOutput output){
		byte[] temp = Longs.toByteArray(output.value.value * 100000000);
		String value = toHexString(reverse(temp));
//		String value = new StringBuffer((toHexString(reverse(temp)) + new String(new char[16 - temp.length * 2]).replace("\0", "0"))).reverse().toString();
		return num2hexstring(1, output.assetId.reverse().toByteArray()) + value + DatatypeConverter.printHexBinary(output.scriptHash.toByteArray()).toLowerCase();
	}

	public static String AddContract(String txData, String sign, String signatureScript) {
		// sign num
		String data = txData + "01";
		// sign struct len
		data = data + "41";
		// sign data len
		data = data + "40";
		// sign data
		data = data + sign;
		// Contract data len
		data = data + "23";
		// script data
		data = data + signatureScript;
		return data;
	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

	public static byte[] reverse(byte[] array) {
		if (array == null) {
			System.out.println("reserve func: The Array is empty, check input data");
			System.exit(1);
		}
		int i = 0;
		int j = array.length - 1;
		byte tmp;
		while (j > i) {
			tmp = array[j];
			array[j] = array[i];
			array[i] = tmp;
			j--;
			i++;
		}
		return array;
	}

	/**
	 * converts a list of objects that implement the ToJsonObject interface into a
	 * JSONArray of JSONObjects.
	 *
	 * @param ifNullReturnEmpty
	 *            if the list is null, return an empty list. If this value is false,
	 *            return null for a null list.
	 * @param list
	 *            the list of objects to use.
	 * @param <T>
	 *            the type of the objects that implements ToJsonObject .
	 * @return the JSONArray of JSONObjects.
	 */
	public static <T extends ToJsonObject> JSONArray toJSONArray(final boolean ifNullReturnEmpty, final List<T> list) {
		if (list == null) {
			if (ifNullReturnEmpty) {
				return new JSONArray();
			} else {
				return null;
			}
		}
		final JSONArray jsonArray = new JSONArray();

		for (final T t : list) {
			jsonArray.put(t.toJSONObject());
		}

		return jsonArray;
	}

	/**
	 * converts a byte array to a hex string in reverse byte order.
	 *
	 * @param bytes
	 *            the array of bytes.
	 * @return the string.
	 */
	public static String toReverseHexString(final byte... bytes) {
		final byte[] ba = new byte[bytes.length];
		System.arraycopy(bytes, 0, ba, 0, bytes.length);
		ArrayUtils.reverse(ba);
		final BigInteger bi = new BigInteger(1, ba);
		return bi.toString(16);
	}

	/**
	 * converts the value to a double, by dividing by DECIMAL_DIVISOR.
	 *
	 * @param value
	 *            the long value to convert.
	 * @return the converted value
	 */
	public static double toRoundedDouble(final long value) {
		final double input = value / DECIMAL_DIVISOR;
		return input;
	}

	/**
	 * converts the value to a double, by dividing by DECIMAL_DIVISOR. then formats
	 * it to a string with two decimal places.
	 *
	 * @param value
	 *            the long value to convert.
	 * @return the converted value as a string.
	 */
	public static String toRoundedDoubleAsString(final long value) {
		final double input = toRoundedDouble(value);
		return String.format("%.2f", input);
	}

	/**
	 * converts the value to a long, by dividing by DECIMAL_DIVISOR.
	 *
	 * @param value
	 *            the long value to convert.
	 * @return the converted value as a string.
	 */
	public static long toRoundedLong(final long value) {
		final long input = value / DECIMAL_DIVISOR;
		return input;
	}

	/**
	 * converts the value to a long, by dividing by DECIMAL_DIVISOR. then formats it
	 * to a string.
	 *
	 * @param value
	 *            the long value to convert.
	 * @return the converted value as a string.
	 */
	public static String toRoundedLongAsString(final long value) {
		final long input = toRoundedLong(value);
		return Long.toString(input);
	}

	/**
	 * return the RIPEMD160 hash of the script.
	 *
	 * @param script
	 *            the script to hash.
	 * @return the RIPEMD160 hash of the script.
	 */
	public static UInt160 toScriptHash(final byte[] script) {
		return new UInt160(RIPEMD160HashUtil.getRIPEMD160Hash(script));
	}

	/**
	 * Write an unsigned 32-bit value to a byte array in little-endian format
	 *
	 * @param       val             Value to be written
	 * @param       out             Output array
	 * @param       offset          Starting offset
	 */
	public static void uint32ToByteArrayLE(long val, byte[] out, int offset) {
		out[offset++] = (byte)val;
		out[offset++] = (byte)(val >> 8);
		out[offset++] = (byte)(val >> 16);
		out[offset] = (byte)(val >> 24);
	}

	/**
	 * Write an unsigned 64-bit value to a byte array in little-endian format
	 *
	 * @param       val             Value to be written
	 * @param       out             Output array
	 * @param       offset          Starting offset
	 */
	public static void uint64ToByteArrayLE(long val, byte[] out, int offset) {
		out[offset++] = (byte)val;
		out[offset++] = (byte)(val >> 8);
		out[offset++] = (byte)(val >> 16);
		out[offset++] = (byte)(val >> 24);
		out[offset++] = (byte)(val >> 32);
		out[offset++] = (byte)(val >> 40);
		out[offset++] = (byte)(val >> 48);
		out[offset] = (byte)(val >> 56);
	}

	/**
	 * Encode the value in little-endian format
	 *
	 * @param       value           Value to encode
	 * @return                      Byte array
	 */
	public static byte[] encode(long value) {
		byte[] bytes;
		if ((value&0xFFFFFFFF00000000L) != 0) {
			// 1 marker + 8 data bytes
			bytes = new byte[9];
			bytes[0] = (byte)255;
			uint64ToByteArrayLE(value, bytes, 1);
		} else if ((value&0x00000000FFFF0000L) != 0) {
			// 1 marker + 4 data bytes
			bytes = new byte[5];
			bytes[0] = (byte)254;
			uint32ToByteArrayLE(value, bytes, 1);
		} else if (value >= 253L) {
			// 1 marker + 2 data bytes
			bytes = new byte[]{(byte)253, (byte)value, (byte)(value>>8)};
		} else {
			// Single data byte
			bytes = new byte[]{(byte)value};
		}
		return bytes;
	}

	/**
	 * Converts a BigInteger to a fixed-length byte array.
	 *
	 * The regular BigInteger method isn't quite what we often need: it appends a
	 * leading zero to indicate that the number is positive and it may need padding.
	 *
	 * @param       bigInteger          Integer to format into a byte array
	 * @param       numBytes            Desired size of the resulting byte array
	 * @return                          Byte array of the desired length
	 */
	public static byte[] bigIntegerToBytes(BigInteger bigInteger, int numBytes) {
		if (bigInteger == null)
			return null;
		byte[] bigBytes = bigInteger.toByteArray();
		byte[] bytes = new byte[numBytes];
		int start = (bigBytes.length==numBytes+1) ? 1 : 0;
		int length = Math.min(bigBytes.length, numBytes);
		System.arraycopy(bigBytes, start, bytes, numBytes-length, length);
		return bytes;
	}

	/**
	 * the constructor.
	 */
	private ModelUtil() {

	}


}
