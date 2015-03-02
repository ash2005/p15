package com.pkcs15.applet;



/**
 * 
 * @author Lupascu Alexandru
 * This class represents an ASN1 structure of KeyUsageFlags as defined in PKCS#15
 */
public class KeyUsageFlags extends ASN1Type{

	
	/*DER TAG for BITSTRING*/
	public final byte TAG = (byte) 0x03;
	
	public boolean encrypt;
	public boolean decrypt;
	public boolean sign;
	public boolean signRecover;
	public boolean wrap;
	public boolean unwrap;
	public boolean verify;
	public boolean verifyRecover;
	public boolean derive;
	public boolean nonRepudiation;
	
	private BitString bs = null;
	
	/**
	 * Implicit constructor.
	 */
	public KeyUsageFlags(){
		bs= null;
	}
	
	/**
	 * Constructor which takes a boolean flags as parameters
	 */
	public KeyUsageFlags(boolean encryptFlag,boolean decryptFlag,boolean signFlag,boolean signRecoverFlag,
						 boolean wrapFlag,boolean unwrapFlag,boolean verifyFlag,boolean verifyRecoverFlag,
						 boolean deriveFlag,boolean nonRepudiationFlag){
		
		boolean[] bits = new boolean[10];
		
		bits[0] = encryptFlag;
		bits[1] = decryptFlag;
		bits[2] = signFlag;
		bits[3] = signRecoverFlag;
		bits[4] = wrapFlag;
		bits[5] = unwrapFlag;
		bits[6] = verifyFlag;
		bits[7] = verifyRecoverFlag;
		bits[8] = deriveFlag;
		bits[9] = nonRepudiationFlag;
		
		bs = new BitString(bits);
		
		encrypt = encryptFlag;
		decrypt = decryptFlag;
		sign = signFlag;
		signRecover = signRecoverFlag;
		wrap = wrapFlag;
		unwrap = unwrapFlag;
		verify = verifyFlag;
		verifyRecover = verifyRecoverFlag;
		derive = deriveFlag;
		nonRepudiation = nonRepudiationFlag;
		
	}	
	
	/**
	 * This method encodes a KeyUsageFlags.The boolean flag values must have been previously set.
	 * using the specific constructor,or a previous call to decode.
	 * After the call, the this.bs.encoding member will contain the encoding of KeyUsageFlags.
	 * Warning! It only encodes the values given on constructor or after decode! modification on members are not taken into consideration!
	 * @return Byte array containing the encoding of the KeyUsageFlags. If boolean array has not been set or the length of the array is 0 then null is returned.
	 */
	public byte[] encode(){
		
		return bs.encode();
	}
	
	
	/**
	 * This method decodes a KeyUsageFlags with encoding given as parameter
	 * @param enc Byte array containing the encoding of the KeyUsageFlags
	 * @param offset offset in the byte array from where the encoding starts
	 * @param len length of the encoding
	 */
	public void decode(byte[] enc,short offset,short len){
		
		if (bs == null)
			  bs = new BitString();
		
		bs.decode(enc, offset, len);
		
		encrypt = bs.val[0];
		decrypt = bs.val[1];
		sign = bs.val[2];
		signRecover = bs.val[3];
		wrap = bs.val[4];
		unwrap = bs.val[5];
		verify = bs.val[6];
		verifyRecover = bs.val[7];
		derive = bs.val[8];
		nonRepudiation = bs.val[9];
		
	}
	
	
	/**
	 * This method decodes a KeyUsageFlags.
	 * The encoding must have been previously with a call to encode().
	 * @return true if decoding was successful, false otherwise ( in case that encoding has not been set).
	 */
	public boolean decode(){
	 
		if (bs == null)
			  bs = new BitString();
		
		boolean status = bs.decode();
		
		if (status == false) 
			  return false;
		
		encrypt = bs.val[0];
		decrypt = bs.val[1];
		sign = bs.val[2];
		signRecover = bs.val[3];
		wrap = bs.val[4];
		unwrap = bs.val[5];
		verify = bs.val[6];
		verifyRecover = bs.val[7];
		derive = bs.val[8];
		nonRepudiation = bs.val[9];
		
		return true;
	}

	
}
