package com.pkcs15.applet;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * This class represents a ASN1 structure of DataObject as defined in PKCS#15
 * @author Lupascu Alexandru
 */
public class DataObject extends ASN1Type {

	
	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte)0x30;
	
	/*ASN1 structure for CommonObjectAttributes*/
	public CommonObjectAttributes commonObjectAttributes = null;
	
	/*ASN1 structure for CommonCertificateAttributes*/
	public CommonDataObjectAttributes classAtributes = null;
	
	/*ASN1 structure for X509CertificiateAttributes*/
	public Opaque typeAttribute = null;

		
	
	public byte[] encoding =null;
	byte[] lengthEncoded = null;

	public boolean isEncoded = false;
	
	/**
	 * Implicit constructor
	 * */
	public DataObject(){}
		
	
	public DataObject(CommonObjectAttributes coa,CommonDataObjectAttributes cdoa,Opaque op){
		commonObjectAttributes = coa;
		classAtributes = cdoa;
		typeAttribute = op;
	}
	
	
	/**
	 * This method sets the encoding and lengthEncoded references to null so the
	 * garbage collector can free the memory when needed.
	 */
	public void freeEncoding(){
		encoding = null;
		lengthEncoded = null;
		if (JCSystem.isObjectDeletionSupported())
			  JCSystem.requestObjectDeletion();
	}
	
	
	/**
	 * This method sets unused references of members to null so garbage collector can free the memory when needed
	 */
	public void freeMembers(){
		
		commonObjectAttributes = null;
		classAtributes = null;
		typeAttribute = null;
		if (JCSystem.isObjectDeletionSupported())
			  JCSystem.requestObjectDeletion();
	}
	
	
	
	/**
	 * This method encodes a DataObject structure.
	 * The members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set, null is returned.
	 */
	public byte[] encode() {
		
		encoding = null;
		
		if ((commonObjectAttributes == null)||(classAtributes == null)
				|| ( typeAttribute == null))
			  return null;
		
		byte[] coaEnc = commonObjectAttributes.encode();
		byte[] caEnc = classAtributes.encode();
		byte[] ctxTaEnc =  encodeContextSpecificExplicit(typeAttribute.encode(),(byte)0x01);
		
	    short length = (short) (coaEnc.length + caEnc.length + ctxTaEnc.length);
		
        lengthEncoded = encodeLength((short)length);
		
		encoding = new byte[(short)( 1 + lengthEncoded.length + length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		
		offset += lengthEncoded.length;
		
		Util.arrayCopy(coaEnc, (short)0, encoding,offset,(short)coaEnc.length);
		offset += coaEnc.length;
		
		Util.arrayCopy(caEnc, (short)0, encoding,offset,(short)caEnc.length);
		offset += caEnc.length;
		
		Util.arrayCopy(ctxTaEnc, (short)0, encoding,offset,(short)ctxTaEnc.length);
	
		isEncoded = true;
		return encoding;
	}
	
	
	/**
	 * This method decodes a DataObject structure.
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
  	 * This method decodes a DataObject encoding.
  	 * The encoding must have been previously set.
  	 * @return true if successful, and false if encoding was not set.
  	 */
  	public boolean decode(){
  	
  		if (encoding == null )
  			 return false;
  	   
  		short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
  		
  		 short memberlen = 0;
  		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
  		 commonObjectAttributes = new CommonObjectAttributes();
  		 commonObjectAttributes.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
  		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
  		 
  		 
  		 
  		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
  		 classAtributes = new CommonDataObjectAttributes();
  		 classAtributes.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
  		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
  		 
  		 
  		 //Move offset after context specific explicit tag and length
  	     offset = (short) (offset + 1 + findLengthEncodedLength(encoding, (short)(offset+1)));
  	     memberlen = (short) decodeLength(encoding, (short)(offset+1));
  		 typeAttribute = new Opaque();
  		 typeAttribute.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)(offset+1) ) ) );
  		
  		isEncoded = false;
  		return true;
  	}

	

}
