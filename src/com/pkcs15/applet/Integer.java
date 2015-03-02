package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * 
 * @author Lupascu Alexandru
 * This class represents a ASN1 INTEGER which can be used to encode/decode. 
 */
public class Integer extends ASN1Type {

	/*DER TAG for INTEGER*/
	public final byte TAG = (byte) 0x02;
	
	/* In this byte array it will be stored the value of the integer*/
	public byte[] val = null;
	
	/* In this byte array it ill be stored the DER encoding of the integer*/
	public byte[] encoding = null;
	
	/* In this byte array it will be stored the encoded length of the integer according to DER */
	private byte[] lengthEncoded = null;
	
	
	
	/**
	 * Constructor with short parameter
	 * @param number short value 
	 */
	public Integer(short number){
		
		byte lsb   = (byte) (number & 0xFF);
		byte byte2 = (byte) ((number >> 8) &0xFF);
		byte byte3 = (byte)0x00;// ((number >>16) &0xFF);
		byte msb   = (byte)0x00;// ((number >>24) &0xFF);
		
		short byteslength=4;
		
		if ( msb == (byte) 0x00 )
				{
					byteslength--;
					
					if ( byte3 == (byte)0x00)
							{
							  byteslength--;
							  
							  if (byte2 == (byte) 0x00)
								    byteslength--;
							}
			
				}
		
		val = new byte[byteslength];
		
		if (byteslength == 1)
				{ 
					val[0]=lsb;
				}
		else if (byteslength == 2)
				{
			        val[0]=byte2;
			        val[1]=lsb;
				}
		else if (byteslength == 3)
				{
					val[0]=byte3;
					val[1]=byte2;
					val[2]=lsb;
				}
		else if (byteslength == 4)
				{
			        val[0]=msb;
			        val[1]=byte3;
			        val[2]=byte2;
			        val[3]=lsb;
				}
		
	}
	
	
	
	/**
	 * Constructor with byte array parameter as integer
	 * @param number byte array which represents the integer
	 * @param offset offset in the byte array from where the number starts
	 * @param length length of the number in bytes
	 */
	public Integer(byte[] number,short offset,short length){
		
		val = new byte[length];
		
		Util.arrayCopy(number, (short)offset, val, (short)0, (short) length);
	}
	
	/**
	 * Implicit constructor
	 */
	public Integer(){
		
		val = null;
		lengthEncoded = null;
		encoding = null;
		
	}
	
	/**
	 * This method sets the encoding value. 
	 * @param encodedinteger byte array which contains the INTEGER encoding
	 * @param offset offset in the byte array from where the encoding starts
	 * @param length length of the encoding
	 */
	public void setEncoding(byte[] encodedinteger,short offset,short length){
		
		encoding = new byte[length];
		Util.arrayCopy(encodedinteger, (short)offset, encoding, (short)0,(short) length);
	}
	
	
	/**
	 * This method decodes a INTEGER DER encoding.
	 * The integer value is store in val member.
	 * @param encodedinteger byte array which contains the INTEGER encoding
	 * @param offset offset in the byte array from where the encoding starts
	 * @param length length of the encoding
	 * @return byte array which contains the integer value
	 */
	public byte[] decode(byte[] encodedinteger,short offset,short length) {
		
		val = null;
		setEncoding(encodedinteger, offset, length);
		
		return decode();
		
	}
	
	/**
	 * This method decodes a INTEGER DER.
	 * The integer value is store in this.val member.
	 * The object's encoding must have been previously set with setEncoding method, or a previous encode must have been called.
	 * @return byte array which contains the integer value. If the object's encoding is not set, null is returned
	 */
	public byte[] decode()
	{
		if ( encoding == null)
			  return null;
		
        short vallength = decodeLength(encoding, (short)1);
		
		val = new byte[vallength];
		
		Util.arrayCopy(encoding, (short)(1+findLengthEncodedLength(encoding, (short)1)), val, (short)0, (short)vallength);
		
		return val;
	}
	
	/**
	 * This method encodes the number stored inside as INTEGER according to DER.
	 * After this call, the this.encoding member will store the encoding.
	 * After this call, the this.lengthEncoded will also store the length of the integer encoded according to DER.
	 * @return byte[] which contains the INTEGER encoding. if value has not been set, null is returned.
	 */
	public byte[] encode() {
		
		if (val == null)
			  return null;
		 
		lengthEncoded = encodeLength((short)val.length);
		
		encoding = new byte[(short)( 1 + lengthEncoded.length + val.length)];
		
		encoding[0]=this.TAG;
		
		
		Util.arrayCopy(lengthEncoded,(short)0, encoding,(short)1,(short)lengthEncoded.length);
		Util.arrayCopy(val, (short)0, encoding, (short)(1+lengthEncoded.length), (short)val.length);
		
		return encoding;
	}
 
	
	
	
	
}
