package com.pkcs15.applet;

import javacard.framework.Util;


/**
 * @author Lupascu Alexandru
 * This class represents a ASN1 structure of CommonCertificateAttributes as defined in PKCS#15
 */
public class CommonCertificateAttributes extends ASN1Type{

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
	public OctetString iD = null;
	
	public Boolean authority = null;
	
	public CredentialIdentifier identifier = null;
	
	
	public byte[] encoding =null;
	
	byte[] lengthEncoded = null;
	
	
	/**
	 * Implicit constructor
	 */
	public CommonCertificateAttributes(){}
	
	
	/**
	 * Constructor
	 * @param id ASN1 Octet String
	 * @param isAuthority ASN1 boolean
	 * @param credIdentifier CredentialIdentifier
	 */
	public CommonCertificateAttributes(OctetString id,Boolean isAuthority,CredentialIdentifier credIdentifier){
		
		iD = id;
		authority = isAuthority;
		identifier = credIdentifier;
	}
	
	
	/**
	 * This method encodes a CommonCertificateAttributes structure.
	 * The members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set, null is returned.
	 */
	public byte[] encode() {
	
		encoding = null;
		
		if ( (iD == null) || (authority == null) || (identifier == null) )
			     return null;
		
		byte[] idEnc = iD.encode();
		byte[] authEnc = authority.encode();
		byte[] identEnc = identifier.encode();
		
		short length = (short) (idEnc.length + ( authority.val ? authEnc.length :(short)0 ) + identEnc.length);
		
        lengthEncoded = encodeLength((short)length);
		
		encoding = new byte[ (short)( 1 + lengthEncoded.length + length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		
		offset += lengthEncoded.length;
		
		Util.arrayCopy(idEnc, (short)0, encoding,offset,(short)idEnc.length);
		offset += idEnc.length;
		
		if (authority.val == true){
		Util.arrayCopy(authEnc, (short)0, encoding,offset,(short)authEnc.length);
		offset += authEnc.length;
		}
			
		Util.arrayCopy(identEnc, (short)0, encoding,offset,(short)identEnc.length);
		
		
		return encoding;
	}
	
	
	/**
	 * This method decodes a CommonCertificateAttributes structure.
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
    	 * This method decodes a CommonCertificateAttributes encoding.
    	 * The encoding must have been previously set.
    	 * @return true if successful, and false if encoding was not set.
    	 */
    	public boolean decode(){
    		
    		if (encoding == null)
    			   return false;
    		
    	 short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
   		 
   		 short memberlen = 0;
   		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
   		 iD = new OctetString();
   		 iD.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
   		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
   		 
   		 
   		 authority = new Boolean(false);
   		 if (encoding[offset] == (byte)0x01 ){
   		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
   		 authority.decode(encoding,offset);
   		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
   		 }
   		 
   		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
   		 identifier = new CredentialIdentifier();
   		 identifier.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
   		     		
    		
    	  return true;
    	}

}
