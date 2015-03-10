package com.pkcs15.applet;

/**
 * This class represents a provider for unique IDs
 * @author Lupascu Alexandru
 */
public class UniqueIDProvider {
	
	private short counter;
	
	private byte len;
	/**
	 * Implicit constructor
	 */
	public UniqueIDProvider(){ counter = (short)1; len = (byte)0x02;}
	
	public byte[] getUniqueID(){
		
		byte[] id = new byte[len];
		
		id[0] = (byte) ((short)((counter & (short)0xFF00)>>8) & (byte)0xFF);
		id[1] = (byte) (counter & (byte)0x00FF);
		
		short idx;
		
		for (idx=2;idx<len;idx++){
			  id[idx]=(byte)len; 
		}
		
		if (counter == (short)32767) {
			  counter = (short)1;
			  len++;
		}
		else 
			 counter++;
		
		return id;
	}
	
}
