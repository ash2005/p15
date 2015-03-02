package com.pkcs15.applet;

/**
 * This class represents a node of the Secret Key Object list
 * @author Lupascu Alexandru
 */
public class SecretKeyObjectEntry {

	public SecretKeyObject obj =null;
	public SecretKeyObjectEntry next=null;
	
	public SecretKeyObjectEntry(){}
	
	public SecretKeyObjectEntry(SecretKeyObject object){ obj = object;}
}
