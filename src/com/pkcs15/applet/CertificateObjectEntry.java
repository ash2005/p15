package com.pkcs15.applet;

/**
 * This class represents a node of the Certificate Object list
 * @author Lupascu Alexandru
 */
public class CertificateObjectEntry {

	public CertificateObject obj =null;
	public CertificateObjectEntry next=null;
	
	public CertificateObjectEntry(){}
	
	public CertificateObjectEntry(CertificateObject object){ obj = object;}
}
