package com.pkcs15.applet;


import javacard.framework.Util;


/**
 * 
 * @author Lupacu Alexandru
 * This class represents a ASN1 BITSTRING type according to DER .
 *
 */
public class BitString extends ASN1Type {

	
	/*DER TAG for BITSTRING*/
	public final byte TAG = (byte)0x03;
	
	
	public boolean[] val = null;
	
	byte[] encoding = null;
	
	byte[] lengthEncoded = null;
	
	
	/**
	 * Implicit constructor.
	 */
	public BitString(){
		val = null;
		encoding = null;
		lengthEncoded = null;
	}
	
	
	
	
	/**
	 * Constructor which takes a boolean array as parameter
	 * @param bits Boolean array which represents the bits to encode
	 */
	public BitString(boolean[] bits){
		val = bits;
	}

	
	

	/**
	 * This method encodes a BITSTRING.The boolean values must have been previously set.
	 * using the specific constructor,or a previous call to decode.
	 * After the call, the this.encoding member will contain the encoding of BITSTRING
	 * @return Byte array containing the encoding of the BITSTRING. If boolean array has not been set or the length of the array is 0 then null is returned.
	 */
	public byte[] encode() {
		
		encoding = null;
		
		if (val == null)
			 return null;
		
		if (val.length == 0)
			 return null;
		
		byte padBitsNr = (byte) (8 -  (val.length % 8)); 
		
		short length = (short) (val.length /8);
		if ( (val.length % 8) != 0x00)
			  length++;
		
		length++;
		
		lengthEncoded = encodeLength((short)length);
		
		encoding = new byte[(short)(1+ lengthEncoded.length + length)];
		
		encoding[0] =this.TAG;
		Util.arrayCopy(lengthEncoded, (short)0, encoding, (short)1,(short)lengthEncoded.length);
		
		short offset = (short) (1 +lengthEncoded.length);
		
		if (padBitsNr == 0x08)
            padBitsNr = 0x00;
		
		encoding[offset++] = padBitsNr; 
		

		short bitoff =0;
		byte value;
		 
		for (short byteoff = 0; byteoff <(short)(val.length/8);byteoff++){
			   value =(byte) 0x00;
			   if ( val[bitoff] == true )
				     value += 128;
			   if ( val[(short)(bitoff+1)] == true )
				     value += 64;
			   if ( val[(short)(bitoff+2)] == true )
				     value += 32;
			   if ( val[(short)(bitoff+3)] == true )
				     value += 16;
			   if ( val[(short)(bitoff+4)] == true )
				     value += 8;
			   if ( val[(short)(bitoff+5)] == true )
				     value += 4;
			   if ( val[(short)(bitoff+6)] == true )
				     value += 2;
			   if ( val[(short)(bitoff+7)] == true )
				     value += 1;
			   
			   encoding[offset++] = value;
				   
			   bitoff += 8;	
	    }
		
		
		if ( (val.length % 8) != 0x00)
				{
				byte power=7;
				value = 0x00;
				for (short bit=bitoff;bit<val.length;bit++){
					 
					byte powOf2 = (byte) (1 << power);
					if (val[bit] == true )
						value += powOf2;
					power--;
				     }
				
				encoding[offset] = value;
				}
		return encoding;
		
	}
	

	
	/**
	 * This method decodes a BITSTRING with encoding given as parameter
	 * @param enc Byte array containing the encoding of the BITSTRING
	 * @param offset offset in the byte array from where the encoding starts
	 * @param len length of the encoding
	 */
	public void decode(byte[] enc,short offset,short len){
		
		encoding = new byte[len];
		
		Util.arrayCopy(enc,	offset, encoding, (short)0,(short)len);
		
		decode();
	}
	
	
	
	
	/**
	 * This method decodes a BITSTRING.
	 * The encoding must have been previously with a call to encode().
	 * @return true if decoding was successful, false otherwise ( in case that encoding has not been set).
	 */
	public boolean decode(){
		
		if (encoding == null)
			  return false;
		
		short encvallength = decodeLength(encoding, (short)1);
		
		short offset = (short) (1+findLengthEncodedLength(encoding, (short)1));
		 
		short nrOfBitsPadded = encoding[offset];
		
		
		short necessaryBits =  (short) (((encvallength-1)*8) - nrOfBitsPadded);
		
		val = new boolean[necessaryBits];
		
		short bitIdx = 0;
		
		offset++;
		
		for (short i=0;i<(short)(encvallength-1);i++)
					{
					   boolean stop = false;
					   
					   byte crtByte = encoding[offset++];
					   
					   for(short j=7;j>=0;j--)
					   		{
						   		byte bit = (byte) ((crtByte >> j) & 0x01);
						   		
						   		if (bit == 0x01)
						   			  val[bitIdx++] = true;
						   		else
						   			  val[bitIdx++] = false;
						   		
						   		if (bitIdx == necessaryBits)		
						   				{
						   					stop = true;
						   					break;
						   				}
					   		}
					   
					   if (stop)
						    break;
					}
		
		return true;
	}
	

	
	
}
