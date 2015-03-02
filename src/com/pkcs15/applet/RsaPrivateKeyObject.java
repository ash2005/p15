package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * This class represents an asn1 structure of  RSA Private Key object
 * as it is specified in PKCS#15.
 * @author Lupascu Alexandru
 * 
 */
public class RsaPrivateKeyObject extends ASN1Type {

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
	/* ASN1 INTEGER */
	public Integer modulus = null;
	
	/* ASN1 INTEGER */
	public Integer privateExponent = null;
	
	
	byte[] encoding = null;
	
	byte[] lengthEncoded = null;
	
	
	
	/**
	 * Implicit constructor
	 */
	public RsaPrivateKeyObject(){
		 
		modulus = null;
		privateExponent = null;
		encoding = null;
		lengthEncoded = null;
	}
	
	/**
	 * Constructor with modulus and private exponent as parameters
	 * @param mod Integer ASN1 
	 * @param prExp Integer ASN1 
	 */
	public RsaPrivateKeyObject(Integer mod,Integer prExp){
	
		encoding = null;
		lengthEncoded = null;
		
		setModulus(mod);
		setPrivateExponent(prExp);
	}
	
	
	/**
	 * Constructor with the encoding of rsa private key given as parameter
	 * @param encodedRsaPrKey Byte array containing the encoding of rsa private key
	 * @param offset Offset in the byte array from where the encoding starts
	 * @param length Length of the encoding
	 */
	public RsaPrivateKeyObject(byte[] encodedRsaPrKey,short offset,short length){
		
		this.modulus = null;
		this.privateExponent = null;
		
		encoding = new byte[length];
		
		Util.arrayCopy(encodedRsaPrKey, offset, encoding, (short)0,(short) length);
	}
	
	
	
	
	
	/**
	 * This method sets the modulus to the reference specified in parameter
	 * @param modulus Integer ASN1 
	 */
	public void setModulus(Integer modulus){
		
		this.modulus = modulus;
	}
	
	/**
	 * This method sets the private exponent to the reference specified in parameter
	 * @param privateExponent Integer ASN1 
	 */
	public void setPrivateExponent(Integer privateExponent){
		
		this.privateExponent = privateExponent;
	}
	
	
	/**
	 * This method encodes a RSA private key object.
	 * Modulus and private exponent must be set,otherwise null will be returned.
	 * @return byte array containing the DER encoding of a RSA private key object
	 */
	public byte[] encode() {
		
		encoding = null;
		
		if ((modulus == null) || ( privateExponent == null))
			   return null;
		
		byte[] ctxModulusEncoded = encodeContextSpecificExplicit(modulus.encode(),(byte)0x00);
		byte[] ctxPrivExpEncoded = encodeContextSpecificExplicit(privateExponent.encode(),(byte)0x02);
		
		if (( ctxModulusEncoded == null)||( ctxPrivExpEncoded ==null))
			   return null;
		
		short length = (short) (ctxModulusEncoded.length + ctxPrivExpEncoded.length);
		
		lengthEncoded = encodeLength((short)length);
		
		encoding = new byte[(short)( 1 + lengthEncoded.length + length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		
		offset += lengthEncoded.length;
		Util.arrayCopy(ctxModulusEncoded, (short)0, encoding,offset,(short)ctxModulusEncoded.length);
		
		offset += ctxModulusEncoded.length;
		Util.arrayCopy(ctxPrivExpEncoded, (short)0, encoding, offset,(short)ctxPrivExpEncoded.length);
		
		return encoding;
	}
	
	
	/**
	 * This method decodes a RSA private key object.
	 * The encoding must have been previously set using the specific constructor, or a previous call to encode() method.
	 * @return true if decoded was successful, and false if encoding was not previously set.
	 */
	public boolean decode(){
	
		if (encoding == null)
			  return false;
		
		short ctxlen =0;
		short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		
		byte[] ctxDecModulus = decodeContextSpecificExplicit(encoding, offset);
		ctxlen = (short) decodeLength(encoding, (short)(offset+1));
		modulus = new Integer();
		short modulusenclen = 0;
		modulusenclen = (short) decodeLength(ctxDecModulus, (short)1);
		modulus.setEncoding(ctxDecModulus, (short)0,(short)( modulusenclen+1+findLengthEncodedLength(ctxDecModulus,(short)1 )));
		modulus.decode();
		
		offset = (short) (offset + 1 + findLengthEncodedLength(encoding, (short)(offset+1)) + ctxlen);
		
		privateExponent = new Integer();
		byte[] ctxDecPrivExp = decodeContextSpecificExplicit(encoding, offset);
		short expenclen = (short) decodeLength(ctxDecPrivExp,(short)1);
		privateExponent.setEncoding(ctxDecPrivExp, (short)0, (short)(1+expenclen+findLengthEncodedLength(ctxDecPrivExp,(short)1)));
		privateExponent.decode();
		
		return true;
	}
	
	
	/**
	 * This method decodes a RSA private key object with encoding given as parameter
	 * @param enc Byte array containing the encoding of the RSA private key object
	 * @param offset offset in the byte array from where the encoding starts
	 * @param len length of the encoding
	 */
	public void decode(byte[] enc,short offset,short len){
		
		encoding = new byte[len];
		
		Util.arrayCopy(enc,	offset, encoding, (short)0,(short)len);
		
		decode();
	}

}
