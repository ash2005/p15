package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * 
 * @author Lupascu Alexandru
 * This class represents an ASN1 structure as defined in PKCS#15
 */
public class CommonObjectAttributes extends ASN1Type{

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;
	
	/*ASN1 structure for UTF8STRING*/
	public Utf8String label = null;
	
	/*ASN1 structure for CommonObjectFlags*/
	public CommonObjectFlags flags = null;
	
	/*ASN1 structure for OctetString*/
	public OctetString authId = null;
	
	
	byte[] encoding = null;
	byte[] lengthEncoded = null;
	
	/**
	 * Implicit constructor
	 */
	public CommonObjectAttributes(){}
	
	
	
	/**
	 * Constructor
	 * @param pLabel UTF8STRING
	 * @param cof CommonObjectFlags
	 * @param aid OctetString
	 */
	public CommonObjectAttributes(Utf8String pLabel,CommonObjectFlags cof,OctetString aid){
		
		label = pLabel;
		flags = cof;
		authId = aid;
		encoding = null;
		lengthEncoded = null;
		
	}
	
	
	/**
	 * This method encodes a CommonObjectAttributes structure.
	 * The members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set, null is returned.
	 */
	public byte[] encode() {
	
		encoding = null;
		
		if ((label == null )||(flags == null)||(authId == null))
			   return null;
		
		byte[] labelEnc = label.encode();
		byte[] flagsEnc = flags.encode();
		byte[] authIdEnc = authId.encode();
		
		short length = (short) (labelEnc.length + flagsEnc.length + authIdEnc.length);
		
        lengthEncoded = encodeLength((short)length);
		
		encoding = new byte[ (short)( 1 + lengthEncoded.length + length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		
		offset += lengthEncoded.length;
		
		Util.arrayCopy(labelEnc, (short)0, encoding,offset,(short)labelEnc.length);
		offset += labelEnc.length;
		
		Util.arrayCopy(flagsEnc, (short)0, encoding,offset,(short)flagsEnc.length);
		offset += flagsEnc.length;
		
		Util.arrayCopy(authIdEnc, (short)0, encoding,offset,(short)authIdEnc.length);
		
		
		return encoding;
		
	}
	
	
	
	/**
	 * This method decodes a CommonObjectAttributes structure.
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
	 * This method decodes a CommonObjectAttributes encoding.
	 * The encoding must have been previously set.
	 * @return true if successful, and false if encoding was not set.
	 */
	public boolean decode(){
	
		if (encoding == null )
			 return false;
		
		short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		 
		 short memberlen = 0;
		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
		 label = new Utf8String();
		 label.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
		 
		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
		 flags = new CommonObjectFlags();
		 flags.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
		 
		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
		 authId = new OctetString();
		 authId.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
		
		return true;
	}

	
}
