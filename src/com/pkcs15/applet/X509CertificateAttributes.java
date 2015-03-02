package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * @author Lupascu Alexandru
 * This class represents a ASN1 structure of X509CertificateAttributes as defined in PKCS#15
 */
public class X509CertificateAttributes extends ASN1Type {

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
	public Certificate value = null;
	
	byte[] encoding = null;
	byte[] lengthEncoded = null;
	
	
	/*Implicit constructor*/
	public X509CertificateAttributes(){	}
	
	
	/**
	 * Constructor
	 * @param cert Certificate 
	 */
	public X509CertificateAttributes(Certificate cert){
		value = cert;
	}
	
	
	
	/**
	 * This method encodes a X509CertificateAttributes structure.
	 * The members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set, null is returned.
	 */
	public byte[] encode() {
		
		encoding = null;
		
		if (value == null) 
				return null;
		
		byte[] ctxEncValue = encodeContextSpecificExplicit(value.encode(),(byte)0x00);
		
		lengthEncoded = encodeLength((short)ctxEncValue.length);
		
		encoding = new byte[ (short)( 1 + lengthEncoded.length + ctxEncValue.length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		
		offset += lengthEncoded.length;
		
		Util.arrayCopy(ctxEncValue, (short)0, encoding,offset,(short)ctxEncValue.length);
		
		
		return encoding;
	}
	
	
	/**
	 * This method decodes a X509CertificateAttributes structure.
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
  	 * This method decodes a X509CertificateAttributes encoding.
  	 * The encoding must have been previously set.
  	 * @return true if successful, and false if encoding was not set.
  	 */
  	public boolean decode(){
  		
  		if (encoding == null)
  				return false;
  		
  		short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
  		
  		byte[] ctxEncoding = decodeContextSpecificExplicit(encoding, offset);
  		
  		
  		value = new Certificate(ctxEncoding);
  		value.decode();
  		
  		return true;
  	}
	
	

}
