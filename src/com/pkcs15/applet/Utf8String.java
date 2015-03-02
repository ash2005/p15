package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * 
 * @author Lupascu Alexandru
 * This class represents a ASN1 UTF8STRING according to DER. 
 */
public class Utf8String extends ASN1Type {

	/*DER TAG for UTF8STRING*/
	public final byte TAG = (byte) 0x0C;
	
	
	public byte[] val = null;
	
	public byte[] encoding = null;
	
	public byte[] lengthEncoded = null;
	
	
	
	
	/**
	 * Implicit constructor
	 */
	public Utf8String(){
		val = null;
		encoding = null;
		lengthEncoded = null;
	}
	
	
	/**
	 * Constructor with byte array as parameter representing the utf8 string
	 * @param utf8str byte array which contains the utf8 string
	 * @param offset offset from where the utf8 string starts
	 * @param length length of the uft8 string
	 */
	public Utf8String(byte[] utf8str,short offset,short length){
		
		val = new byte[length];
		
		Util.arrayCopy(utf8str, (short)offset, val, (short)0, (short) length);
	}
	
	
	/**
	 * This method encodes a UTF8STRING.
	 * The value of the utf8 string must have been previously set.
	 * After this call, the this.encoding member will store the encoding.
	 * @return byte array containing the encoding of the utf8 string.If the value of utf8string was not set, null is returned.
	 */
	public byte[] encode(){
		
		encoding = null;
		
		if (val == null)
			  return null;
		 
		lengthEncoded = encodeLength((short)val.length);
		
		encoding = new byte[(short)( 1 + lengthEncoded.length + val.length)];
		
		encoding[0]=this.TAG;
		
		
		Util.arrayCopy(lengthEncoded,(short)0, encoding,(short)1,(short)lengthEncoded.length);
		Util.arrayCopy(val, (short)0, encoding, (short)(1+lengthEncoded.length), (short)val.length);
		
		return encoding;	
		
	}
	

	/**
	 * This method decodes a encoded utf8 string.
	 * The decoded utf8 string is also stored in this.val member.
	 * @param encodedUtf8String byte array which contains the utf8 string's encoding
	 * @param offset offset in the byte array from where the encoding starts
	 * @param length length of the encoding
	 * @return byte array containing the utf8 string
	 */
      public byte[] decode(byte[] encodedUtf8String,short offset,short length) {
		
		val = null;

		encoding = new byte[length];
		Util.arrayCopy(encodedUtf8String, offset,encoding,(short)0,length);
		
		return decode();
		
	}
	
	
	
	/**
	 * This method decodes a encoded utf8 string.
	 * The decoded utf8 string is also stored in this.val member.
	 * The object's encoding must have been previously set with specific constructor,or a previous call to encode().
	 * @return byte array containing the utf8 string, or null if the encoding has not been set.
	 */
	public byte[] decode(){
		
		if ( encoding == null)
			  return null;
		
        short vallength = decodeLength(encoding, (short)1);
		
		val = new byte[vallength];
		
		Util.arrayCopy(encoding, (short)(1+findLengthEncodedLength(encoding, (short)1)), val, (short)0, (short)vallength);
		
		return val;
		
	}
	
}
