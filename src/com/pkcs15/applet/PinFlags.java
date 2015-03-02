package com.pkcs15.applet;

/**
 * This class represents a ASN1 structure of PinFlags as defined in PKCS#15
 * @author Lupascu Alexandru
 *
 */
public class PinFlags extends ASN1Type{


	/*DER TAG for BIT STRING*/
	public final byte TAG = (byte)0x03;
	
	public boolean caseSensitive;
	public boolean local;
	public boolean changeDisabled;
	public boolean unblockDisabled;
	public boolean initialized;
	public boolean needsPadding;
	public boolean unblockingPin;
	public boolean soPin;
	public boolean disableAllowed;
	public boolean integrityProtected;
	public boolean confidentialityProtected;
	public boolean exchangeRefData;
	
	
	private BitString bs=null;
	
	/**
	 * Implicit constructor
	 */
	public PinFlags(){bs = new BitString();}

	
	/**
	 * Constructor
	 * @param caseSens Case Sensitive flag
	 * @param isLocal Local flag
	 * @param changeDis changeDisabled flag
	 * @param unblockDis unblockDisabled flag
	 * @param init initialized flag
	 * @param needsPadd needsPadding flag
	 * @param unblockPin unblockingPin flag
	 * @param securitOfficerPin soPin flag
	 * @param disableAllow disableAllowed flag
	 * @param integrityProtect integrityProtected flag
	 * @param confidentialityProtect confidentialityProtected flag
	 * @param exchangeReferenceData exchangeRefData flag
	 */
	public PinFlags(boolean caseSens,boolean isLocal,boolean changeDis,boolean unblockDis,
					boolean init,boolean needsPadd,boolean unblockPin,boolean securitOfficerPin,
					boolean disableAllow,boolean integrityProtect,boolean confidentialityProtect,
					boolean exchangeReferenceData){
		
		caseSensitive = caseSens;
		local = isLocal;
		changeDisabled = changeDis;
		unblockDisabled = unblockDis;
		initialized = init;
		needsPadding = needsPadd;
		unblockingPin = unblockPin;
		soPin = securitOfficerPin;
		disableAllowed = disableAllow;
		integrityProtected = integrityProtect;
		confidentialityProtected = confidentialityProtect;
		exchangeRefData = exchangeReferenceData;
		
		bs= new BitString();
	}
	
	
	/**
	 * This method encodes a PinFlags structure.
	 * The boolean flag values must have been previously set
	 * using the specific constructor,or a previous call to decode.
	 * After the call, the this.bs.encoding member will contain the encoding
	 * @return Byte array containing the encoding of the PinFlags. If boolean array has not been set or the length of the array is 0 then null is returned.
	 */
	public byte[] encode(){
		
       boolean[] bits = new boolean[12];
		
		bits[0]=caseSensitive;
		bits[1]=local;
		bits[2]=changeDisabled;
		bits[3]=unblockDisabled;
		bits[4]=initialized;
		bits[5]=needsPadding;
		bits[6]=unblockingPin;
		bits[7]=soPin;
		bits[8]=disableAllowed;
		bits[9]=integrityProtected;
		bits[10]=confidentialityProtected;
		bits[11]=exchangeRefData;
		
		bs.val = bits;
		return bs.encode();
	}
	
	
	
	/**
	 * This method decodes a PinFlags structure with encoding given as parameter
	 * @param enc Byte array containing the encoding 
	 * @param offset offset in the byte array from where the encoding starts
	 * @param len length of the encoding
	 */
	public void decode(byte[] enc,short offset,short len){
	  
		if (bs == null)
			  bs = new BitString();
		
		bs.decode(enc, offset, len);
		
		caseSensitive = bs.val[0];
		local = bs.val[1];
		changeDisabled = bs.val[2];
		unblockDisabled = bs.val[3];
		initialized = bs.val[4];
		needsPadding = bs.val[5];
		unblockingPin = bs.val[6];
		soPin = bs.val[7];
		disableAllowed = bs.val[8];
		integrityProtected = bs.val[9];
		confidentialityProtected = bs.val[10];
		exchangeRefData = bs.val[11];
	}
	
	
	/**
	 * This method decodes a PinFlags
	 * The encoding must have been previously with a call to encode().
	 * @return true if decoding was successful, false otherwise ( in case that encoding has not been set).
	 */
	public boolean decode(){
	 
		if (bs == null)
			  bs = new BitString();
		
		boolean status = bs.decode();
		
		if (status == false) 
			  return false;
		
		caseSensitive = bs.val[0];
		local = bs.val[1];
		changeDisabled = bs.val[2];
		unblockDisabled = bs.val[3];
		initialized = bs.val[4];
		needsPadding = bs.val[5];
		unblockingPin = bs.val[6];
		soPin = bs.val[7];
		disableAllowed = bs.val[8];
		integrityProtected = bs.val[9];
		confidentialityProtected = bs.val[10];
		exchangeRefData = bs.val[11];
		
		
		return true;
	}
	
	
}
