package com.pkcs15.applet;

/**
 * This class represents a node of the private key object list
 * @author Lupascu Alexandru
 *
 */
public class PrivateKeyObjectEntry {
      
	public PrivateKeyObject obj =null;
	public PrivateKeyObjectEntry next=null;
	
	public PrivateKeyObjectEntry(){}
	
	public PrivateKeyObjectEntry(PrivateKeyObject object){ obj = object;}
	
	
}
