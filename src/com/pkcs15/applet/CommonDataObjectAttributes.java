package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * This class represents a ASN1 structure of CommonDataObjectAttributes as defined in PKCS#15
 * @author Lupascu Alexandru
 *
 */
public class CommonDataObjectAttributes extends ASN1Type{

	/*DER Tag for SEQUENCE*/
	public final byte TAG = (byte)0x30;
	
	/*ASN1 Utf8String */
	public Utf8String applicationName = null;
	
	byte[] encoding = null;
	
	byte[] lengthEncoded = null;
	
	
	/**
	 * Implicit constructor
	 */
	public CommonDataObjectAttributes(){
		applicationName=null;
		encoding=null;
		lengthEncoded=null;
	}
	
	/**
	 * Constructor
	 * @param appName OctetString which represents the application name 
	 */
	public CommonDataObjectAttributes(Utf8String appName){
		encoding=null;
		lengthEncoded=null;
		
		applicationName=appName;
	}
	
	
	/**
	 * This method encodes a CommonDataObjectAttributes.
	 * The value of the member must have been previously set, otherwise it will return null.
	 * @return Byte array containing the encoding
	 */
	public byte[] encode() {
		encoding =null;
		
		if (applicationName==null)
			  return null;
		
		byte[] appNameEnc = applicationName.encode();
		
		if (appNameEnc == null)
			 return null;
		
		lengthEncoded = encodeLength((short)appNameEnc.length);
		
		encoding = new byte[(short)(1+ lengthEncoded.length + appNameEnc.length)];
		
		encoding[0]= (byte)this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		
		offset += lengthEncoded.length;
		Util.arrayCopy(appNameEnc, (short)0, encoding,offset,(short)appNameEnc.length);
		
		return encoding;
	}

	/**
	 * This method decodes a CommonDataObjectAttributes
	 * The encoding must have been previously set : a previous call to encode() method.
	 * @return true if decoded was successful, and false if encoding was not previously set.
	 */
	public boolean decode(){
		
		if (encoding==null)
			 return false;
		
		short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		
		short objenclen = 0;
		objenclen = (short) decodeLength(encoding, (short)(offset+1));
		applicationName= new Utf8String();
		applicationName.decode(encoding, offset,(short)( objenclen+1+findLengthEncodedLength(encoding,(short)( offset+1) )));
		applicationName.decode();
		
		
		return true;
	}
	
	

	/**
	 * This method decodes a CommonDataObjectAttributes with encoding given as parameter
	 * @param enc Byte array containing the encoding of the CommonDataObjectAttributes
	 * @param offset offset in the byte array from where the encoding starts
	 * @param len length of the encoding
	 */
	public void decode(byte[] enc,short offset,short len){
		
		encoding = new byte[len];
		
		Util.arrayCopy(enc,	offset, encoding, (short)0,(short)len);
		
		decode();
	}
}
