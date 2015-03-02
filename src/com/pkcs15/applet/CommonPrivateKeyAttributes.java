package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * This class represents a ASN1 structure of CommonPrivateKeyAttributes according to PKCS#15.
 * @author Lupascu Alexandru	
 */

public class CommonPrivateKeyAttributes extends ASN1Type{

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
    public Name subjectName;
	
    public byte[] encoding = null;
	
	public byte[] lengthEncoded = null;
	
	
	
	/**
	 * Implicit constructor
	 */
	public CommonPrivateKeyAttributes(){
		
	}
	
	
	/**
	 * Constructor
	 * @param subjName Name of the subject in a Name object
	 */
	public CommonPrivateKeyAttributes(Name subjName){
		subjectName = subjName;
	}
	
	
	/**
	 * This method encodes structure of CommonPrivateKeyAttributes
	 * Members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set,null is returned
	 */
	public byte[] encode() {
		encoding = null;
		
		if (subjectName == null)
			  return null;
		
		byte[] subjNameEnc = subjectName.encode();
		
		lengthEncoded = encodeLength((short)subjNameEnc.length);
		
		encoding = new byte[(short) (1+ lengthEncoded.length + subjNameEnc.length) ];
		
		encoding[0] = this.TAG;
		
		Util.arrayCopy(lengthEncoded,(short)0, encoding, (short)1,(short)lengthEncoded.length);
		Util.arrayCopy(subjNameEnc,(short)0, encoding, (short)(1+lengthEncoded.length),(short)subjNameEnc.length);
		
		return encoding;
	}


	/**
	 * This method decodes a CommonPrivateKeyAttributes structure.
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
  	 * This method decodes a CommonPrivateKeyAttributes encoding.
  	 * The encoding must have been previously set.
  	 * @return true if successful, and false if encoding was not set.
  	 */
  	public boolean decode(){
  		
  		if (encoding == null)
  				return false;
  		
  		short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		
  		short memberlen =0;
  		memberlen = (short) decodeLength(encoding, (short)(offset+1));
  		subjectName = new Name();
  		subjectName.decode(encoding, offset,(short) (1+memberlen+ findLengthEncodedLength(encoding, (short)(offset+1) ))  );
  		
  		return true;
  	}

	
}
