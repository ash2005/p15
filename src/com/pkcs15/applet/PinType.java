package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * This class represents a ASN1 structure of PinType as defined in PKCS#15
 * @author Lupascu Alexandru
 *
 */
public class PinType extends ASN1Type{

	/*Types*/
	public static final byte TYPE_BCD             = (byte)0x00;
	public static final byte TYPE_ASCII_NUMERIC   = (byte)0x01;
	public static final byte TYPE_UTF8			  = (byte)0x02;
	public static final byte TYPE_HALF_NIBBLE_BCD = (byte)0x03;
	public static final byte TYPE_ISO9564_1	      = (byte)0x04;
	
	
	/*DER TAG for ENUMERATED*/
	public final byte TAG = (byte)0x0A;
	
	
	public byte value = (byte)TYPE_ASCII_NUMERIC;
	
	public byte[] encoding =null;
	
	
	
	/**
	 * Implicit constructor
	 */
	public PinType(){}
	
	
	
	/**
	 * Constructor
	 * @param type Byte value with the meaning of type as static members TYPE_* are declared
	 */
	public PinType(byte type){
		value = type;
	}
	
	
	
	/**
	 * This method encodes a PinType structure.
	 * The members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set, null is returned.
	 */
	public byte[] encode() {
		
		encoding = null;
		
		Integer i = new Integer((short)this.value);
		encoding = i.encode();
		i=null;
	
		encoding[0]=this.TAG;
		return encoding;
	}

	
	
	
	/**
	 * This method decodes a PinType structure.
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
    	 * This method decodes a PinType encoding.
    	 * The encoding must have been previously set.
    	 * @return true if successful, and false if encoding was not set.
    	 */
    	public boolean decode(){
    		
    		if (encoding==null)
    			 return false;
    		
    		
    		
    		Integer i = new Integer();
    		encoding[0] = (byte) 0x02;
    		i.decode(encoding,(short)0,(short)encoding.length);
    		
    		value = i.val[0];
    		i=null;
    		
    		return true;
    	}
}
