package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * This class represents a ASN1 structure of RSAPublicKey as defined in PKCS#1
 * @author Lupascu Alexandru
 */
public class RSAPublicKey extends ASN1Type {

	
	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
	/* ASN1 INTEGER */
	public Integer modulus = null;
	
	/* ASN1 INTEGER */
	public Integer publicExponent = null;
	
	
	byte[] encoding = null;
	
	byte[] lengthEncoded = null;
	
	
	
	/**
	 * Implicit constructor
	 */
	public RSAPublicKey(){
	
	}

	/**
	 * Constructor
	 * @param n Integer representing the modulus
	 * @param e Integer representing the public exponent
	 */
	public RSAPublicKey(Integer n,Integer e){
		modulus = n;
		publicExponent = e;
	}

	
	
	/**
	 * This method encodes a RSA public key as defined in PKCS#1
	 * Members must have been previously set.
	 * @return byte array containing the encoding, if members were not set null is returned
	 */
	public byte[] encode() {
		encoding = null;
		
		if ((modulus ==null) || (publicExponent == null))
			   return null;
		
		byte[] modulusEnc = modulus.encode();
		byte[] pubExpEnc = publicExponent.encode();
		
		short length = (short) (modulusEnc.length + pubExpEnc.length);
		
		lengthEncoded = encodeLength((short)length);
		
		encoding = new byte[(short)( 1 + lengthEncoded.length + length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		
		offset += lengthEncoded.length;
		Util.arrayCopy(modulusEnc, (short)0, encoding,offset,(short)modulusEnc.length);
		
		offset += modulusEnc.length;
		Util.arrayCopy(pubExpEnc, (short)0, encoding, offset,(short)pubExpEnc.length);
		
		
		return encoding;
	}
	
	
	
	/**
	 * This method decodes a RSAPublicKey with encoding given as parameter
	 * @param enc Byte array containing the encoding 
	 * @param offset offset in the byte array from where the encoding starts
	 * @param len length of the encoding
	 */
	public void decode(byte[] enc,short offset,short len){
		
		encoding = new byte[len];
		
		Util.arrayCopy(enc,	offset, encoding, (short)0,(short)len);
		
		decode();
	}
	
	
	/**
	 * This method decodes a RSAPublicKey.
	 * The encoding must have been previously set using the specific constructor, or a previous call to encode() method.
	 * @return true if decoded was successful, and false if encoding was not previously set.
	 */
	public boolean decode(){
	
		if (encoding == null)
			  return false;
		
		short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		
		modulus = new Integer();
		short modulusenclen = 0;
		modulusenclen = (short) decodeLength(encoding, (short)(offset+1));
		modulus.setEncoding(encoding, offset,(short)( modulusenclen+1+findLengthEncodedLength(encoding,(short)( offset+1) )));
		modulus.decode();
		
		offset = (short) (offset + 1 + findLengthEncodedLength(encoding, (short)(offset+1)) + modulusenclen);
		
		publicExponent = new Integer();
		short expenclen = (short) decodeLength(encoding,(short) (offset+1));
		publicExponent.setEncoding(encoding, offset, (short)(1+expenclen+findLengthEncodedLength(encoding,(short)( offset+1))));
		publicExponent.decode();
		
		return true;
	}
	
	
	
}
