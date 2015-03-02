package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * 
 * @author Lupascu Alexandru
 * This is an abstract class which represents any ASN1Type.
 */
public abstract class ASN1Type implements IAsn1Type {

	
	
	
	/**
	 * This method encoded Context Specific explicit by TAG number
	 * @param encoding Encoding to be context specific	
	 * @param tagNumber Tag number
	 * @return byte array containing the context specific explicit encoding
	 */
	public byte[] encodeContextSpecificExplicit(byte[] encoding,byte tagNumber){
		byte[] CSEncoding = null;
		byte[] encLen = null;
		
		tagNumber = (byte) (tagNumber & 0x1F);
		
		encLen = encodeLength((short) encoding.length);
	
		CSEncoding = new byte[(short)( 1 + encLen.length + encoding.length)];
		
		CSEncoding[0] = (byte)( 0xA0 | tagNumber);
		
		Util.arrayCopy(encLen, (short)0,CSEncoding,(short)1, (short)encLen.length);
		Util.arrayCopy(encoding, (short)0,CSEncoding,(short)(1+encLen.length),(short)encoding.length);
		
		return CSEncoding;
	}
	
	
	
	/**
	 * This method decodes a Context specific explicit encoding
	 * @param csEncoding context specific explicit encoding	
	 * @param offset Offset where the encoding starts
	 * @return encoding without the context specific tag and length
	 */
	public byte[] decodeContextSpecificExplicit(byte[] csEncoding,short offset){
		byte[] encoding = null;
		
		short len = (short) decodeLength(csEncoding,(short)(offset+1));
		encoding = new byte[len];
		Util.arrayCopy(csEncoding, (short)(1+offset+ findLengthEncodedLength(csEncoding, (short)(offset+1))),encoding,(short)0,(short)len);
		
		return encoding;
	}
	
/**
 * This method encodes a length given parameter as short to byte array according to DER
 * @param vallength Length to encode
 * @return encoded length as byte[]
 */
public byte[] encodeLength(short vallength){
		
		byte[] lengthEncoded = null;
		
		if (vallength<=127) 
				{
				   lengthEncoded = new byte[1];
				   lengthEncoded[0]= (byte)vallength;
				   
				}
		else {
			       byte[] len = new byte[4];
			   		len[3]= (byte) (vallength & 0xFF);
			   		len[2]= (byte) ((vallength >> 8) &0xFF);
			   		len[1]= (byte) (0x00);//((vallength >>16) &0xFF);
			   		len[0]= (byte) (0x00);//((vallength >>24) &0xFF);
			   		
			   		short bitnr = 0;
			   		for (short i=0;i<=3;i++)
			   				{
			   			 	  boolean stop = false;
			   			      byte crtbyte;
			   			      for (short j=7;j>=0;j--)
			   			      		{
			   			    	      bitnr++;
			   			    	      crtbyte = len[i];
			   			    	      crtbyte = (byte)((crtbyte>>j) & 0x01);
			   			    	      
			   			    	      if (crtbyte == (byte) 0x01)
			   			    	      			{
			   			    	    	  		  stop = true;
			   			    	    	  		  break;
			   			    	      			}
			   			      		}
			   			      
			   			      if (stop)
			   			    	    break;
			   				}
			   		
			   		bitnr = (short) (32 - bitnr + 1);
			   		
			   		short bytesNr = (short) (bitnr /8);
			   		if (( bitnr % 8) != 0)
			   			   bytesNr++;
			   		
			   		byte NrOfBytes = (byte) (bytesNr & 0xFF);
			   		NrOfBytes = (byte)(NrOfBytes | 0x80);
			   		
			   		lengthEncoded = new byte[(short)(1 + bytesNr)];
			   		lengthEncoded[0] = NrOfBytes;
			   		
			   		NrOfBytes = (byte)(NrOfBytes & 0x7F);
			   		
			   		Util.arrayCopy(len, (short)(4-NrOfBytes), lengthEncoded, (short)1, NrOfBytes);
		     }
		
		
		return lengthEncoded;
	}


/**
 * This method decodes a encoded length according to DER
 * @param enclength byte array containing the encoded length 
 * @param offset offset in the byte array from where the encoded length starts
 * @return short value which represents the length
 */
	public short decodeLength(byte[] enclength,short offset) {
		
		short length =0;
		
		 if ( (enclength[(short)(offset+0)] & 0x80) == 0x00)
				{
				   length = (short) (enclength[(short)(offset+0)] & 0x00FF);
				   return length;
				}
		else {
			   byte bytesnr = enclength[(short)(offset+0)];
			   bytesnr = (byte) (bytesnr & 0x7F);
			   
			   if (bytesnr == 1)
			   			{
				   			length = (short) (enclength[(short)(offset+1)] & 0x00FF);
				   			return length;
			   			}
			   else if (bytesnr == 2)
			   			{
				   			short msb,lsb;
				   			
				   			msb = (short) (enclength[(short)(offset+1)] & 0x00FF);
				   			msb = (short) (msb <<8);
				   			msb = (short) (msb& (short)0xFF00);
				   			
				   			lsb = (short) (enclength[(short)(offset+2)] & 0x00FF);
				   			
				   			length = (short) (msb | lsb);
				   			return length;
			   			}
			   // In Java card 2.2.1 there is no int, so there is no point to implement case bytesnr ==3 and ==4
//			   else if (bytesnr == 3)
//			   			{
//				   			int msb,byte2,lsb;
//				   			
//				   			msb = enclength[offset+1];
//				   			msb = msb<< 16;
//				   			msb = msb & 0x00FF0000;
//				   			
//				   			byte2 = enclength[offset+2]; 
//				   			byte2 = byte2 << 8;
//				   			byte2 = byte2 & 0x0000FF00;
//				   			
//				   			lsb = enclength[offset+3];
//				   			lsb = lsb & 0x000000FF;
//				   			
//				   			length = msb | byte2 | lsb;
//				   			return length;
//			   			}
//			   else if (bytesnr == 4)
//			   			{
//						   int msb,byte3,byte2,lsb;
//				   			
//				   			msb = enclength[offset+1];
//				   			msb = msb<< 24;
//				   			msb = msb & 0xFF000000;
//				   			
//				   			byte3 = enclength[offset+2];
//				   			byte3 = byte3 << 16;
//				   			byte3 = byte3 & 0x00FF0000;
//				   			
//				   			byte2 = enclength[offset+3]; 
//				   			byte2 = byte2 << 8;
//				   			byte2 = byte2 & 0x0000FF00;
//				   			
//				   			lsb = enclength[offset+4];
//				   			lsb = lsb & 0x000000FF;
//				   			
//				   			length = msb | byte3 | byte2 | lsb;
//				   			return length;
//			   			}
			 }
		return length;
	}
	
	
	/**
	 * This method finds the encoded length's length
	 * @param enclength byte array containing the encoded length
	 * @param offset offset in the byte array from where the encoded length starts
	 * @return short value which represents the encoded length's length
	 */
	public short findLengthEncodedLength(byte[] enclength,short offset) {
	       
		short length =0;
		
		 if ( (enclength[(short)(offset+0)] & 0x80) == 0x00)
				{
				   length = 1;
				}
		else {
			   byte bytesnr = enclength[(short)(offset+0)];
			   bytesnr = (byte) (bytesnr & 0x7F);
			   length = (short) (bytesnr + 1);
		    }
	
		return length;
	}
}
