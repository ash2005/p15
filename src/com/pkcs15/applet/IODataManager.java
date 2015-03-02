package com.pkcs15.applet;


import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;

/**
 * 
 * @author Lupascu Alexandru
 * This class manages the transfer of data from/into the card.
 */
public class IODataManager {

	
	/* Offset for data sent from the card*/
	 public static short offset_sent = 0;
	 
	 /*Offset for data received by the card*/
	 public static short offset_received =0;
	 
	 /*Data buffer*/
     private static byte[] buffer=null;
     
     
     public static short actualBufferSize = 0;
     
     
     /**
      * This method does realloc the IO buffer if it is not already the size specified by parameter.
      * Reallocation of buffer is atomic. 
      * @param bufferSize Buffer size in bytes
      */
     public static void prepareBuffer(short bufferSize){
    	 	
    	
    	 offset_sent = 0;
    	 offset_received =0;
    	 
    	 
    	 try{
    	      if ( buffer != null)
    	      		{
    	    	     
    	    	  	   if ( buffer.length == bufferSize)
    	    	  		    return;
    	      		}
    	      
    	     
    	      JCSystem.beginTransaction();
    	      
    	     
    	      
    	      byte[] oldBuffer = buffer;
    	      buffer = JCSystem.makeTransientByteArray(bufferSize, JCSystem.CLEAR_ON_RESET);
    	      
    	      if (oldBuffer != null)
    	    	  		oldBuffer = null;
    	     
    	      
    	      actualBufferSize = bufferSize;
    	      JCSystem.commitTransaction();
    	    
    		 
    	 }
    	
    	 catch(Exception e)
    	 {
    		 if (e instanceof SystemException)
    		 		{
    			 		if (((SystemException) e).getReason() == SystemException.NO_TRANSIENT_SPACE)
    			 				{
    			 			      if (JCSystem.isObjectDeletionSupported()){
					    			 				  buffer = new byte[bufferSize];
							    	    	          actualBufferSize = bufferSize;
							    	    	          JCSystem.commitTransaction();
					    			 			      }
    			 			      else ISOException.throwIt(APDUDispatcher.SW_VOLATILE_MEMORY_UNAVAILABLE);
    			 				}
    			 		else
    			 			 JCSystem.abortTransaction();
    		 		}
    		 else
    			 JCSystem.abortTransaction();
    		 
    	 }
    	 
    	 finally{
    		 
    		  if (JCSystem.isObjectDeletionSupported())
    			  	JCSystem.requestObjectDeletion();
    	 }
    	 
     }
     
     
     /**
      * This method resets the offsets and marks the IO buffer as free.
      */
     public static void freeBuffer(){
    	  buffer = null;
    	  offset_sent = 0;
    	  offset_received =0;
    	  actualBufferSize = 0;
     }
     
     
     /**
      * This method puts data in the IO buffer.
      * @param dst_offset Destination offset
      * @param src_data Source byte array
      * @param src_offset Source offset
      * @param len Length
      */
     public static void setData(short dst_offset,byte[] src_data,short src_offset,short len){
    	 
    	 Util.arrayCopy(src_data, src_offset, buffer, dst_offset, len);
    	 
     }
     
     /**
      * This method gets data from the IO buffer.
      * @param dst_data Destination byte array
      * @param dst_offset Destination offset
      * @param src_offset Source offset
      * @param len Length
      */
     public static void getData(byte[] dst_data,short dst_offset,short src_offset,short len){
    	 
    	 Util.arrayCopy(buffer, src_offset, dst_data, dst_offset, len);
     }
     
     
     /**
      * This method receives data and stores it in the IO buffer
      * @param apdu APDU structure
      * @param bytesReceived Number of bytes received with setIncomingAndReceive()
      */
     public static void receiveData(APDU apdu,short bytesReceived){
    	 
    	 byte[] buffer = apdu.getBuffer();
 		
 		 if (offset_received == 0)
 				{
 			        short bufferSize = Util.makeShort(buffer[ISO7816.OFFSET_P1],buffer[ISO7816.OFFSET_P2]);
 					prepareBuffer(bufferSize);
 				}
 		
 		setData(offset_received, buffer,ISO7816.OFFSET_CDATA, bytesReceived);
 		
 		offset_received += bytesReceived;
 		
 		if (offset_received == actualBufferSize)
 					offset_received = 0;
     }

     
     /**
      * This method send data from the IO buffer
      * @param apdu APDU structure
      */
     public static void sendData(APDU apdu){
    	
    	short remain = (short) (actualBufferSize - offset_sent);
 		boolean chain = remain > APDUDispatcher.MAX_APDU_SIZE;
 		short sendlen = chain ? APDUDispatcher.MAX_APDU_SIZE : remain;
 		
 		apdu.setOutgoing();
 		apdu.setOutgoingLength(sendlen);
 		
 		apdu.sendBytesLong(buffer,offset_sent,sendlen);
 		
 		
 		
 		if (chain) {
 			offset_sent +=sendlen;
 			ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00));
 		}
 		else 
 			offset_sent =0;
     }
     
     
     
     
     /**
      * This method gets the IO buffer
      * @return IO buffer
      */
     public static byte[] getBuffer(){
    	 
    	 return buffer;
     }
     
}
