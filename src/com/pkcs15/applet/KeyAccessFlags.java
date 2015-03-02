package com.pkcs15.applet;



/**
 * 
 * @author Lupascu Alexandru
 * This class represents an ASN1 structure of KeyAccessFlags as defined in PKCS#15
 */
public class KeyAccessFlags extends ASN1Type{

	/*DER TAG for BITSTRING*/
	public final byte TAG = (byte) 0x03;
	
	public boolean sensitive;
	public boolean extractable;
	public boolean alwaysSensitive;
	public boolean neverExtractable;
	public boolean local;
	
	public BitString bs = null;
	
	/**
	 * Implicit constructor
	 */
	public KeyAccessFlags(){
		
		bs = null;
		
	}
	
	
	/**
	 * Constructor which takes a boolean flags as parameters
	 */
	public KeyAccessFlags(boolean sensitiveFlag,boolean extractableFlag,
						  boolean alwaysSensitveFlag,boolean neverExtractableFlag,
						  boolean localFlag) {
		
		boolean[] bits = new boolean[5];
		
		bits[0] = sensitiveFlag;
		bits[1] = extractableFlag;
		bits[2] = alwaysSensitveFlag;
		bits[3] = neverExtractableFlag;
		bits[4] = localFlag;
		
		bs = new BitString(bits);
				
		sensitive  = sensitiveFlag;
		extractable = extractableFlag;
		alwaysSensitive = alwaysSensitveFlag;
		neverExtractable = neverExtractableFlag;
		local = localFlag;
				
	}
	
	
	
	/**
	 * This method encodes a KeyAccessFlags.
	 * The boolean flag values must have been previously set
	 * using the specific constructor,or a previous call to decode.
	 * After the call, the this.bs.encoding member will contain the encoding of KeyAccessFlags
	 * Warning! It only encodes the values given on constructor or after decode! modification on members are not taken into consideration!
	 * @return Byte array containing the encoding of the KeyAccessFlags. If boolean array has not been set or the length of the array is 0 then null is returned.
	 */
	public byte[] encode(){
		
		return bs.encode();
	}
	
	
	/**
	 * This method decodes a KeyAccessFlags with encoding given as parameter
	 * @param enc Byte array containing the encoding of the KeyAccessFlags
	 * @param offset offset in the byte array from where the encoding starts
	 * @param len length of the encoding
	 */
	public void decode(byte[] enc,short offset,short len){
	  
		if (bs == null)
			  bs = new BitString();
		
		bs.decode(enc, offset, len);
		
		sensitive = bs.val[0];
		extractable = bs.val[1];
		alwaysSensitive = bs.val[2];
		neverExtractable = bs.val[3];
		local = bs.val[4];
		
	}
	
	
	/**
	 * This method decodes a KeyAccessFlags.
	 * The encoding must have been previously with a call to encode().
	 * @return true if decoding was successful, false otherwise ( in case that encoding has not been set).
	 */
	public boolean decode(){
	 
		if (bs == null)
			  bs = new BitString();
		
		boolean status = bs.decode();
		
		if (status == false) 
			  return false;
		
		sensitive = bs.val[0];
		extractable = bs.val[1];
		alwaysSensitive = bs.val[2];
		neverExtractable = bs.val[3];
		local = bs.val[4];
		
		return true;
	}
	
}
