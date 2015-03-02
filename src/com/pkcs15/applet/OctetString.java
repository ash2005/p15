package com.pkcs15.applet;
import javacard.framework.Util;

/**
 * 
 * @author Lupascu Alexandru
 * This class represents an OCTET STRING according to DER
 */
public class OctetString extends ASN1Type {

	public final byte TAG = (byte) 0x04;
	
	
	public byte[] val = null;
	
	public byte[] encoding = null;
	
	public byte[] lengthEncoded = null;
	
	
	
	
	/**
	 * Implicit constructor
	 */
	public OctetString(){
		val = null;
		encoding = null;
		lengthEncoded = null;
	}
	
	
	/**
	 * Constructor with the octet string as parameter
	 * @param octetstr byte array which contains the octet string
	 * @param offset offset from where the octet string starts
	 * @param length length of the octet string
	 */
	public OctetString(byte[] octetstr,short offset,short length){
		
		val = new byte[length];
		
		Util.arrayCopy(octetstr, (short)offset, val, (short)0, (short) length);
	}
	
	
	/**
	 * This method encodes a OCTET STRING.
	 * The value of the octet string must have been previously set.
	 * After this call, the this.encoding member will store the encoding.
	 * @return byte array containing the encoding of the octet string.If the value was not set, null is returned.
	 */
	public byte[] encode(){
		
		encoding = null;
		
		if (val == null)
			  return null;
		 
		lengthEncoded = encodeLength((short)val.length);
		
		encoding = new byte[(short)(1 + lengthEncoded.length + val.length)];
		
		encoding[0]=this.TAG;
		
		
		Util.arrayCopy(lengthEncoded,(short)0, encoding,(short)1,(short)lengthEncoded.length);
		Util.arrayCopy(val, (short)0, encoding, (short)(1+lengthEncoded.length), (short)val.length);
		
		return encoding;	
		
	}
	

	/**
	 * This method decodes a encoded octet string.
	 * The decoded octet string is also stored in this.val member.
	 * @param encodedOctetString byte array which contains the octet string's encoding
	 * @param offset offset in the byte array from where the encoding starts
	 * @param length length of the encoding
	 * @return byte array containing the octet string
	 */
      public byte[] decode(byte[] encodedOctetString,short offset,short length) {
		
		val = null;

		encoding = new byte[length];
		Util.arrayCopy(encodedOctetString, offset,encoding,(short)0,length);
		
		return decode();
		
	}
	
	
	
	/**
	 * This method decodes a encoded octet string.
	 * The decoded octet string is also stored in this.val member.
	 * The object's encoding must have been previously set with specific constructor,or a previous call to encode().
	 * @return byte array containing the octet string, or null if the encoding has not been set.
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
