package com.pkcs15.applet;



import javacard.framework.Util;

/**
 * This class represents a ASN1 structure of PinAttributes as defined in PKCS#15
 * @author Lupascu Alexandru
 */
public class PinAttributes extends ASN1Type{

	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte)0x30;
	
	public PinFlags pinFlags = null;
	public PinType  pinType = null;
	public Integer minLength = null;
	public Integer storedLength = null;
	public Integer maxLength =null;
	public Integer pinReference = null;
	
	public byte[] encoding =null;
	byte[] lengthEncoded = null;
	
	/**
	 * Implicit constructor
	 */
	public PinAttributes(){}
	
	/**
	 * Constructor
	 * @param flagsPIN PinFlags object
	 * @param typePIN PinType Object
	 * @param minimumLen Integer object which represents the minimum length of the PIN
	 * @param storedLen Integer object which represents the stored length of the PIN
	 * @param maxLen Integer object which represents the maximum length of the PIN
	 * @param ref Integer object which represents the reference to a Card Specific representation of PIN
	 */
	public PinAttributes(PinFlags flagsPIN,PinType typePIN,Integer minimumLen,Integer storedLen,Integer maxLen,Integer ref)
	{
		pinFlags = flagsPIN;
		pinType = typePIN;
		minLength = minimumLen;
		storedLength = storedLen;
		maxLength = maxLen;
		pinReference = ref;
	}
	
	
	

	/**
	 * This method encodes a PinAttributes structure.
	 * The members must have been previously set.
	 * @return byte array which contains the encoding. If members were not set, null is returned.
	 */
	public byte[] encode() {
	
		encoding = null;
		
		if ( (pinFlags == null) || (pinType == null) || (minLength == null) || (storedLength == null) || (maxLength==null) || (pinReference == null))
			     return null;
		
		byte[] flagsEnc = pinFlags.encode();
		byte[] typeEnc = pinType.encode();
		byte[] minLenEnc = minLength.encode();
		byte[] storedLenEnc = storedLength.encode();
	    byte[] maxLenEnc = maxLength.encode();
	    byte[] ctxPinReferenceEnc = null ;
	    
	    if (pinReference.val[0] != (byte) 0x00)
		       ctxPinReferenceEnc = encodeContextSpecificExplicit(pinReference.encode(), (byte)0x00);
	    
	    short length = (short) (flagsEnc.length + typeEnc.length + minLenEnc.length + storedLenEnc.length + maxLenEnc.length);
		
	    if (ctxPinReferenceEnc != null )
			  length += (short) ctxPinReferenceEnc.length;
		
        lengthEncoded = encodeLength((short)length);
		
		encoding = new byte[ (short)( 1 + lengthEncoded.length + length)];
		
		encoding[0] = this.TAG;
		
		short offset=1;
		Util.arrayCopy(lengthEncoded,(short)0, encoding,offset, (short)lengthEncoded.length);
		
		offset += lengthEncoded.length;
		
		Util.arrayCopy(flagsEnc, (short)0, encoding,offset,(short)flagsEnc.length);
		offset += flagsEnc.length;
		
		Util.arrayCopy(typeEnc, (short)0, encoding,offset,(short)typeEnc.length);
		offset += typeEnc.length;
		
		Util.arrayCopy(minLenEnc, (short)0, encoding,offset,(short)minLenEnc.length);
		offset += minLenEnc.length;
		
		Util.arrayCopy(storedLenEnc, (short)0, encoding,offset,(short)storedLenEnc.length);
		offset += storedLenEnc.length;
		
		Util.arrayCopy(maxLenEnc, (short)0, encoding,offset,(short)maxLenEnc.length);
		
		if (ctxPinReferenceEnc != null) {
			  offset += maxLenEnc.length;
			  Util.arrayCopy(ctxPinReferenceEnc, (short)0, encoding,offset,(short)ctxPinReferenceEnc.length);
				
		}
		
		return encoding;
	}

	
	/**
	 * This method decodes a PinAttributes structure.
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
  	 * This method decodes a PinAttributes encoding.
  	 * The encoding must have been previously set.
  	 * @return true if successful, and false if encoding was not set.
  	 */
  	public boolean decode(){
  		
  		if (encoding == null)
  			   return false;
  		
  	     short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
 		 
  	     
  	     
 		 short memberlen = 0;
 		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
 		 pinFlags = new PinFlags();
 		 pinFlags.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
 		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
 		 
 		
 	
 		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
 		 pinType = new PinType();
 		 pinType.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
 		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
 		
 
 		
 		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
 		 minLength = new Integer();
 		 minLength.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
 		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
 
 		 
  		
 		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
 		 storedLength = new Integer();
 		 storedLength.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
 		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
 		
 		 
 		
 		 memberlen = (short) decodeLength(encoding, (short) (offset+1));
 		 maxLength = new Integer();
 		 maxLength.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
 		 offset = (short) (offset + 1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ));
  		
 		
 		 if (offset >= (short)(encoding.length - 1))
 			    pinReference = new Integer((short)0);
 		 else {
 			 //Move offset after the context specific tag and length
 			 offset = (short) (offset + 1 + findLengthEncodedLength(encoding, (short)(offset+1)));
 			 
 			 memberlen = (short) decodeLength(encoding, (short) (offset+1));
 	 		 pinReference = new Integer();
 	 		 pinReference.decode(encoding,offset,(short) (1 + memberlen + findLengthEncodedLength(encoding,(short)( offset+1) ) ) );
 	 		 
 		 }
 		
 		
  	  return true;
  	}
	
}
