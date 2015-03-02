package com.pkcs15.applet;

import javacard.framework.Util;


/**
 * This class represents an ASN1 structure of OPAQUE	
 * @author Lupascu Alexandru
 *
 */
public class Opaque extends ASN1Type{

	
	/*ASN1 structure of OctetString*/
	public OctetString direct=null;
	

	byte[] encoding = null;
	
	byte[] lengthEncoded = null;
	

	/**
	 * Implicit constructor
	 */
	public Opaque(){
		encoding=null;
		lengthEncoded=null;
		direct=null;
	}
	
	/**
	 * Constructor which takes an OctectString as parameter
	 * @param directValue OctectString object
	 */
	public Opaque(OctetString directValue){
		encoding=null;
		lengthEncoded=null;
		
		direct = directValue;
	}
	
	
	/**
	 * This method encodes a Opaque structure.The value of the member must have been previously set.
	 * @return Byte array containing the encoding.
	 */
	public byte[] encode() {
		
		encoding =null;
		
		if (this.direct==null)
				return null;
		
		encoding = encodeContextSpecificExplicit(direct.encode(),(byte)0x00);
		
		
		return encoding;
	}
	
	
	/**
	 * This method decodes an Opaque structure.
	 * The encoding must have been previously set with a previous call to encode() method.
	 * @return True if successful, false otherwise
	 */
	public boolean decode(){
		if (encoding == null)
			 return false;
		
		short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		
		short objlen = (short) decodeLength (encoding,(short) (offset+1));
		direct = new OctetString();
		direct.decode(encoding,(short) offset,(short)(1+objlen+findLengthEncodedLength(encoding,(short) (offset+1) )));
		
		return true;
	}

	/**
	 * This method decodes a Opaque structure with encoding given as parameter
	 * @param enc Byte array containing the encoding of the Opaque structure
	 * @param offset offset in the byte array from where the encoding starts
	 * @param len length of the encoding
	 */
	public void decode(byte[] enc,short offset,short len){
		
		encoding = new byte[len];
		
		Util.arrayCopy(enc,	offset, encoding, (short)0,(short)len);
		
		decode();
	}
	
	
	
}
