package com.pkcs15.applet;

/**
 * This class represents an ASN1 structure of CommonObjectFlags defined in PKCS#15
 * @author Lupascu Alexandru
 */
public class CommonObjectFlags extends ASN1Type {

	
	/*DER TAG for BITSTRING*/
	public final byte TAG = (byte) 0x03;
	
	public boolean privateFlag;
	public boolean modifiableFlag;
	
	private BitString bs = null;
	
	
	/**
	 * Implicit constructor
	 */
	public CommonObjectFlags(){
		
		bs =null;
	}
	
	
	public CommonObjectFlags(boolean privateFl,boolean modifiableFl){
		
		boolean[] bits = new boolean[2];
		
		bits[0] = privateFl;
		bits[1] = modifiableFl;
		
		bs = new BitString(bits);
		
		privateFlag = privateFl;
		modifiableFlag = modifiableFl;
	}
	
	
	
	/**
	 * This method encodes a CommonObjectFlags.
	 * The boolean flag values must have been previously set
	 * using the specific constructor,or a previous call to decode.
	 * After the call, the this.bs.encoding member will contain the encoding of CommonObjectFlags
	 * Warning! It only encodes the values given on constructor or after decode! modification on members are not taken into consideration!
	 * @return Byte array containing the encoding of the CommonObjectFlags. If boolean array has not been set or the length of the array is 0 then null is returned.
	 */
	public byte[] encode(){
		
		return bs.encode();
	}
	
	
	
	/**
	 * This method decodes a CommonObjectFlags with encoding given as parameter
	 * @param enc Byte array containing the encoding of the CommonObjectFlags
	 * @param offset offset in the byte array from where the encoding starts
	 * @param len length of the encoding
	 */
	public void decode(byte[] enc,short offset,short len){
	  
		if (bs == null)
			  bs = new BitString();
		
		bs.decode(enc, offset, len);
		
		privateFlag = bs.val[0];
		modifiableFlag = bs.val[1];
		
	}
	
	
	/**
	 * This method decodes a CommonObjectFlags.
	 * The encoding must have been previously with a call to encode().
	 * @return true if decoding was successful, false otherwise ( in case that encoding has not been set).
	 */
	public boolean decode(){
	 
		if (bs == null)
			  bs = new BitString();
		
		boolean status = bs.decode();
		
		if (status == false) 
			  return false;
		
		privateFlag = bs.val[0];
		modifiableFlag = bs.val[1];
		
		
		return true;
	}
	

}
