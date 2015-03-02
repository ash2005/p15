package com.pkcs15.applet;

import javacard.framework.Util;


/**
 *  This class represents a ASN1 structure of GenericSecretKeyAttributes as defined in PKCS#15
 * @author Lupascu Alexandru
 */
public class GenericSecretKeyAttributes extends ASN1Type {

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
	
	/*OctetString storing the key*/
	public OctetString value = null;
	
	
	byte[] encoding = null;
	
	byte[] lengthEncoded = null;
	
	
	/**
	 * Implicit constructor
	 */
	public GenericSecretKeyAttributes(){
		
	}
	
	/**
	 * Constructor
	 * @param keyValue OctetString object containing the key
	 */
	public GenericSecretKeyAttributes(OctetString keyValue){
		value = keyValue;
	}
	
	
	
	/**
	 * This method encodes a GenericSecretKeyAttributes structure.
	 * The members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set, null is returned.
	 */
	public byte[] encode() {

		encoding = null;
		
		if (value == null)
			   return null;
		
		byte[] ctxValueEnc = encodeContextSpecificExplicit(value.encode(),(byte)0x00);
		
        lengthEncoded = encodeLength((short)ctxValueEnc.length);
		
		encoding = new byte[ (short)( 1 + lengthEncoded.length + ctxValueEnc.length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		
		offset += lengthEncoded.length;
		
		Util.arrayCopy(ctxValueEnc, (short)0, encoding,offset,(short)ctxValueEnc.length);
		
		
		return encoding;
	}

	
	
	/**
	 * This method decodes a GenericSecretKeyAttributes structure.
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
	 * This method decodes a GenericSecretKeyAttributes encoding.
	 * The encoding must have been previously set.
	 * @return true if successful, and false if encoding was not set.
	 */
	public boolean decode(){
	
		if (encoding == null )
			 return false;
		
		short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		 
		//Move offset after context specific explicit tag and length
		 offset = (short) (offset + 1 + findLengthEncodedLength(encoding, (short)(offset+1)));
		 short memberlen = 0;
		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
		 value = new OctetString();
		 value.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
		 
		return true;
	}

	
	
}
