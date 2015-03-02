package com.pkcs15.applet;

import javacard.framework.Util;



/**
 * 
 * @author Lupascu Alexandru
 * This class represents an ASN1 structure of CommonKeyAttributes as defined PKCS#15
 */
public class CommonKeyAttributes  extends ASN1Type{

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
	/*ASN1 structure of octet string*/
	public OctetString iD = null;
	
	/*ASN1 structure of KeyusageFlags*/
	public KeyUsageFlags usage = null;
	
	/*ASN1 structure of BOOLEAN */
	public Boolean nativeFlag = null;
	
	/*ASN1 structure of KeyAccesFlags*/
	public KeyAccessFlags accessFlags = null;
	
	/*ASN1 structure of INTEGER*/
	public Integer keyReference = null;
	
	
	
	byte[] encoding = null;
	
	byte[] lengthEncoded = null;
	
	
	
	/**
	 * Implicit constructor
	 */
	public CommonKeyAttributes(){
		
		iD = null;
		usage = null;
		nativeFlag=null;
		accessFlags= null;
		keyReference = null;
		encoding = null;
		lengthEncoded = null;
	}
	
	
	/**
	 * Constructor
	 * @param id OctetString
	 * @param usageFlags KeyUsageFlags
	 * @param nativeFl Boolean
	 * @param access KeyAccessFlags
	 * @param ref Integer
	 */
	public CommonKeyAttributes(OctetString id,KeyUsageFlags usageFlags,Boolean nativeFl,KeyAccessFlags access,Integer ref){
	  
		iD = id;
		usage = usageFlags;
		nativeFlag = nativeFl;
		accessFlags = access;
		keyReference = ref;
		encoding = null;
		lengthEncoded = null;
	}
	
	
	
	/**
	 * This method encodes a CommonKeyAttributes structure.
	 * The members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set, null is returned.
	 */
	public byte[] encode() {

		encoding = null;
		
		if ((iD == null)||(usage == null)||(nativeFlag == null)||( accessFlags == null)||(keyReference == null))
				return null;
		
		byte[] idEnc = iD.encode();
		byte[] usageEnc = usage.encode();
		byte[] nativeEnc = nativeFlag.encode();
		byte[] accessEnc = accessFlags.encode();
		byte[] keyRefEnc = keyReference.encode();
		
		short length = (short) (idEnc.length + usageEnc.length + (nativeFlag.val ? (short)0 : nativeEnc.length) + accessEnc.length + keyRefEnc.length) ;
		
		lengthEncoded = encodeLength((short)length);
		
		encoding = new byte[ (short)(1 + lengthEncoded.length + length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		offset += lengthEncoded.length;
		
		Util.arrayCopy(idEnc, (short)0, encoding,offset,(short)idEnc.length);
		offset += idEnc.length;
		
		Util.arrayCopy(usageEnc, (short)0, encoding,offset,(short)usageEnc.length);
		offset +=usageEnc.length;
		
		if (nativeFlag.val == false) {
		Util.arrayCopy(nativeEnc, (short)0, encoding,offset,(short)nativeEnc.length);
		offset += nativeEnc.length;
		}
		
		Util.arrayCopy(accessEnc, (short)0, encoding,offset,(short)accessEnc.length);
		offset += accessEnc.length;
		
		Util.arrayCopy(keyRefEnc, (short)0, encoding,offset,(short)keyRefEnc.length);
				
		return encoding;
	}
	
	
	
	/**
	 * This method decodes a CommonKeyAttributes structure.
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
	 * Thie method decodes a CommonKeyAttributes encoding.
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
		 
		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
		 usage = new KeyUsageFlags();
		 usage.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
		 
		 nativeFlag = new Boolean(true);
		 if (encoding[offset] == (byte)0x01 ){
		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
		 nativeFlag.decode(encoding,offset);
		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
		 }
		 
		 
		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
		 accessFlags = new KeyAccessFlags();
		 accessFlags.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
		 
		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
		 keyReference = new Integer();
		 keyReference.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
		 
		return true;
	}


}
