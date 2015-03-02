package com.pkcs15.applet;

/**
 * This class represents a node of the AuthenticationObject list
 * @author Lupascu Alexandru
 */
public class AuthenticationObjectEntry {

	public AuthenticationObject obj =null;
	public AuthenticationObjectEntry next=null;
	
	public AuthenticationObjectEntry(){}
	
	public AuthenticationObjectEntry(AuthenticationObject object){ obj = object;}
}
