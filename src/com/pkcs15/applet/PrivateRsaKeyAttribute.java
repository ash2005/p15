package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * 
 * @author Lupascu Alexandru
 * This class represents an asn1 structure of Private RSA Key Attribute
 * as it is specified in PKCS#15
 */
public class PrivateRsaKeyAttribute extends ASN1Type{

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
	/*ASN1 structure of RSA Private Key Object*/
	public RsaPrivateKeyObject value = null;
	
	/* ASN1 Integer*/
	public Integer modulusLength = null;
	
	
	byte[] encoding = null;
	
	byte[] lengthEncoded = null;
	
	
	
	/**
	 * Implicit constructor
	 */
	public PrivateRsaKeyAttribute(){
		
		value = null;
		modulusLength = null;
		encoding = null;
		lengthEncoded = null;
	}
	
	
	/**
	 * Constructor which takes the RsaPrivateKeyObject-value and Integer-modulusLength as parameters 
	 * @param obj RsaPrivateKeyObject which contains the key
	 * @param modLen ASN1 INTEGER containing the length in bits( ex. 1024)
	 */
	public PrivateRsaKeyAttribute(RsaPrivateKeyObject obj,Integer modLen){
		
		encoding = null;
		lengthEncoded = null;
		
		value = obj;
		modulusLength = modLen;
	}
	
	
	
	/**
	 * This method encodes a PrivateRsaKeyAttribute.
	 * The value of the member must have been previously set, otherwise it will return null.
	 * @return Byte array containing the encoding
	 */
	public byte[] encode() {

		encoding = null;
		
		if ((this.value == null)||(this.modulusLength == null))
				return null;
		
		byte[] ctxValueEnc = encodeContextSpecificExplicit(value.encode(),(byte)0x00);
		byte[] modLenEnc = modulusLength.encode();
		
		if ((ctxValueEnc == null) || (modLenEnc == null))
			   return null;
		
        short length = (short) (ctxValueEnc.length + modLenEnc.length);
		
		lengthEncoded = encodeLength((short)length);
		
		encoding = new byte[(short)( 1 + lengthEncoded.length + length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		
		offset += lengthEncoded.length;
		Util.arrayCopy(ctxValueEnc, (short)0, encoding,offset,(short)ctxValueEnc.length);
		
		offset += ctxValueEnc.length;
		Util.arrayCopy(modLenEnc, (short)0, encoding, offset,(short)modLenEnc.length);
		
		
		return encoding;
	}

	
	/**
	 * This method decodes a Private RSA Key Attribute.
	 * The encoding must have been previously set : a previous call to encode() method.
	 * @return true if decoded was successful, and false if encoding was not previously set.
	 */
	public boolean decode(){
		
		if (encoding == null)
			  return false;
		
        short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		
       
        ////Move offset after context specific explicit tag and length
        offset = (short) (offset + 1 + findLengthEncodedLength(encoding, (short)(offset+1)));
        
        
		short objenclen = 0;
		objenclen = (short) decodeLength(encoding, (short)(offset+1));
		value = new RsaPrivateKeyObject(encoding, offset,(short)( objenclen+1+findLengthEncodedLength(encoding,(short)( offset+1) )));
		value.decode();
		
		offset = (short) (offset + 1 + findLengthEncodedLength(encoding, (short)(offset+1)) + objenclen);
		
		
		this.modulusLength = new Integer();
		short modlenenclen = (short) decodeLength(encoding,(short) (offset+1));
		this.modulusLength.setEncoding(encoding, offset, (short)(1+modlenenclen+findLengthEncodedLength(encoding,(short)( offset+1))));
		this.modulusLength.decode();
		
		return true;
		
	}
	
	
	/**
	 * This method decodes a Private RSA key Attribute with encoding given as parameter
	 * @param enc Byte array containing the encoding of the Private RSA Key Attribute
	 * @param offset offset in the byte array from where the encoding starts
	 * @param len length of the encoding
	 */
	public void decode(byte[] enc,short offset,short len){
		
		encoding = new byte[len];
		
		Util.arrayCopy(enc,	offset, encoding, (short)0,(short)len);
		
		decode();
	}
	
}
