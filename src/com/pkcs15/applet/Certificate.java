package com.pkcs15.applet;

import javacard.framework.Util;


/**
 * This class represents a ASN1 structure of Certificate as defined in X509 PKI and CRL Profile
 * @author Lupascu Alexandru
 * 
 */
public class Certificate extends ASN1Type{
	
	public Integer serialNumber = null;
	public Name issuer = null;
	public Name subject = null;
	public RSAPublicKey publicKey = null;
	
	
    byte[] encoding = null;
    
    /**
     * Constructor
     * @param enc Encoding of the certificate
     */
    public Certificate(byte[] enc){
    	encoding = new byte[enc.length];
    	Util.arrayCopy(enc,(short)0,encoding,(short)0,(short)enc.length);
    	
    }
	
    
    
    /**
     * This method returns the encoding of the Certificate 
     */
	public byte[] encode() {
		return encoding;
	}
	
	
	/**
	 * This method decodes a Certificate
	 */
	public void decode(){
		
		
		short offset = 1;
		short memberlen = 0;
		
		
		short len = (short)findLengthEncodedLength(encoding, offset);
		offset = (short) (offset + len);
		len = (short) findLengthEncodedLength(encoding, (short) (offset+1));
		offset = (short)(offset + len+1);
		
		if (encoding[offset] == (byte)0xA0)
				{
					len = (short)findLengthEncodedLength(encoding, (short) (offset+1));
					memberlen = (short)decodeLength(encoding, (short) (offset+1));
					offset = (short)(offset + 1 + len + memberlen);
				}
		
		serialNumber = new Integer();
		memberlen = (short)decodeLength(encoding, (short) (offset+1));
		len = findLengthEncodedLength(encoding, (short)(offset+1));
		serialNumber.decode(encoding, offset, (short)(1+memberlen+len));
		offset = (short) (offset + 1 + len + memberlen);
		
		
		
		memberlen = (short)decodeLength(encoding, (short)(offset+1));
		len = (short) findLengthEncodedLength(encoding, (short)(offset+1));
		offset = (short) (offset + 1 + len + memberlen);
		
		issuer = new Name();
		memberlen = (short) decodeLength(encoding, (short) (offset+1));
		len = (short) findLengthEncodedLength(encoding, (short) (offset+1));
		issuer.decode(encoding, offset, (short)(1+len+memberlen));
		offset = (short) (offset +1 + len +memberlen);
		
		
		
		memberlen = (short)decodeLength(encoding, (short) (offset+1));
		len = (short)findLengthEncodedLength(encoding, (short) (offset+1));
		offset = (short) (offset +1 + len + memberlen);
		
		subject = new Name();
		memberlen = (short) decodeLength(encoding, (short) (offset+1));
		len = (short) findLengthEncodedLength(encoding, (short) (offset+1));
		subject.decode(encoding, offset, (short)(1+len+memberlen));
		offset = (short) (offset +1 + len +memberlen);
		
		
		
		offset = (short) (offset +1);
		len = (short) findLengthEncodedLength(encoding, offset);
		offset = (short) (offset + len);
		memberlen = (short) decodeLength(encoding, (short) (offset+1));
		len = (short) findLengthEncodedLength(encoding, (short) (offset+1));
		offset = (short) (offset +1 + len + memberlen);
		offset = (short) (offset +1);
		len = (short)findLengthEncodedLength(encoding, offset);
		memberlen = (short) decodeLength(encoding, offset);
		offset = (short) (offset +len +1);
		
		
		len = (short)findLengthEncodedLength(encoding, (short) (offset+1));
		memberlen = (short)decodeLength(encoding, (short) (offset+1));
		publicKey = new RSAPublicKey();
		publicKey.decode(encoding, offset, (short)(1+len+memberlen));
		offset = (short) (offset +1 +len+memberlen);
		
		
		
	}
	
}
