package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * 
 * @author Lupascu Alexandru
 * This class represents a BOOLEAN according to DER
 */
public class Boolean extends ASN1Type{

	/*DER TAG for BOOLEAN*/
	public final byte TAG = (byte) 0x01;
	
	public boolean val;
	
	byte[] encoding =null;
	
	
	public Boolean(){
		
		encoding = null;
	}
	
	/**
	 * Constructor
	 * @param value Boolean value
	 */
	public Boolean(boolean value){
		val = value;
		encoding = new byte[3];
		encoding[0] = this.TAG;
		encoding[1]= (byte) 0x01;
		
	}
	
	
	
    /**
     * This method encodes a BOOLEAN according to DER
     * @return the encoding of the BOOLEAN 	
     */
	public byte[] encode() {
		
		if (val == true)
			  encoding[2] = (byte) 0xFF;
		else 
			  encoding[2] = (byte) 0x00;
		
		return encoding;
	}

	
	
	/**
	 * This method decodes a BOOLEAN with encoding given as parameter.
	 * * After this call, the this.val member will also store the boolean value.
	 * @param enc Byte array containing the encoding of the BOOLEAN
	 * @param offset offset in the byte array from where the encoding starts
	 */
    public boolean decode(byte[] enc,short offset){
		
		encoding = new byte[3];
		
		Util.arrayCopy(enc,	offset, encoding, (short)0,(short)3);
		
		return decode();
	}
	
	/**
	 * This method decodes a BOOLEAN according to DER.
	 * The encoding must have been previously set, by a call to encode, otherwise the result is ambigous
	 * After this call, the this.val member will also store the boolean value
	 * @return boolean value 
	 */
	public boolean decode(){
		
		if (encoding[2] == 0x00)
			  {
			   this.val = false;
			   return false;
			  }
		else 
			{
			this.val = true;
			return true;
			}
	}

	
}
