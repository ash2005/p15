package com.pkcs15.applet;

/**
 * This class represents a node of the Public Key Object list
 * @author Lupascu Alexandru
 */
public class PublicKeyObjectEntry {

	public PublicKeyObject obj =null;
	public PublicKeyObjectEntry next=null;
	
	public PublicKeyObjectEntry(){}
	
	public PublicKeyObjectEntry(PublicKeyObject object){ obj = object;}
}
