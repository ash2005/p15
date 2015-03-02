package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * @author Lupascu Alexandru
 * This class represents a ASN1 structure of CommonSecretKeyAttributes as defined in PKCS#15
 */
public class CommonSecretKeyAttributes extends ASN1Type {

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
	public Integer keyLen = null;
	
    public byte[] encoding = null;
	
	public byte[] lengthEncoded = null;
	
	
	
	/**
	 * Implicit constructor
	 */
	public CommonSecretKeyAttributes(){
		
	}
	
	/**
	 * Constructor
	 * @param keyLength ASN1 Integer containing the key length in bits
	 */
	public CommonSecretKeyAttributes(Integer keyLength){
		keyLen = keyLength;
	}
	
	
	
	/**
	 * This method encodes a CommonSecretKeyAttributes structure.
	 * The members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set, null is returned.
	 */
	public byte[] encode() {

		encoding = null;
		
		if (keyLen == null)
			  return null;
		
		byte[] keyLenEnc = keyLen.encode();
		
		lengthEncoded = encodeLength((short)keyLenEnc.length);
		
		encoding = new byte[ (short)(1 + lengthEncoded.length + keyLenEnc.length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		offset += lengthEncoded.length;
		
		Util.arrayCopy(keyLenEnc, (short)0, encoding,offset,(short)keyLenEnc.length);
		
		return encoding;
	}
	
	
	
	/**
	 * This method decodes a CommonSecretKeyAttributes structure.
	 * @param enc byte array which contains the  encoding
	 * @param offset offset in the byte array from where the encoding starts
	 * @param length length of the encoding
	 */
      public void decode(byte[] enc,short offset,short length) {
		
		encoding = new byte[length];
	
		Util.arrayCopy(enc, offset,encoding,(short)0,length);
		
		decode();
		
	}
      
      
      /**
  	 * This method decodes a CommonSecretKeyAttributes encoding.
  	 * The encoding must have been previously set.
  	 * @return true if successful, and false if encoding was not set.
  	 */
  	public boolean decode(){
  		
  		if (encoding == null)
  			return false;
  		
  		short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		 
		short memberlen = 0;
		memberlen = (short) decodeLength(encoding, (short) (offset+1));
		keyLen = new Integer();
		keyLen.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
		 
  
  		return true;
  	}
}
