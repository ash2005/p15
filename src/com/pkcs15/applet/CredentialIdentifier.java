package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * @author Lupascu Alexandru
 * This class represents a ASN1 structure of CredetialIdentifier as defined in PKCS#15
 */
public class CredentialIdentifier extends ASN1Type{

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
	
	public Integer idType = null;
	
	public OctetString idValue = null;
	
	
	public byte[] encoding =null;
	
	byte[] lengthEncoded = null;
	
	
	/**
	 * Implicit constructor
	 */
	public CredentialIdentifier(){
		
	}
	
	
	/**
	 * Constructor	
	 * @param type ASN1 Integer 
	 * @param value ASN1 OctetString
	 */
	public CredentialIdentifier(Integer type,OctetString value){
		
		idType = type;
		idValue = value;
	}
	
	
	/**
	 * This method encodes a CredentialIdentifier structure.
	 * The members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set, null is returned.
	 */
	public byte[] encode() {
	
		encoding = null;
		
		if ((idType == null) || (idValue == null))
				return null;
		
		byte[] idTypeEnc = idType.encode();
		byte[] idValueEnc = idValue.encode();
		
	    short length = (short) (idTypeEnc.length + idValueEnc.length);
		
		lengthEncoded = encodeLength((short)length);
		
		encoding = new byte[ (short)(1 + lengthEncoded.length + length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		offset += lengthEncoded.length;
		
		Util.arrayCopy(idTypeEnc, (short)0, encoding,offset,(short)idTypeEnc.length);
		offset += idTypeEnc.length;
		
		Util.arrayCopy(idValueEnc, (short)0, encoding,offset,(short)idValueEnc.length);
		
		
		return encoding;
	}
	
	
	/**
	 * This method decodes a CredentialIdentifier structure.
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
  	 * This method decodes a CredentialIdentifier encoding.
  	 * The encoding must have been previously set.
  	 * @return true if successful, and false if encoding was not set.
  	 */
  	public boolean decode(){
  	
  		if (encoding == null)
  			  return false;
  		
  		 short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		 
		 short memberlen = 0;
		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
		 idType = new Integer();
		 idType.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
		 
		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
		 idValue = new OctetString();
		 idValue.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
		 
  		
  		return true;
  	}
	
	
	
}
