package com.pkcs15.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;

/**
 * This class represents the Public Key Directory File
 * @author Lupascu Alexandru
 */
public class PublicKeyDirectoryFile {

	/*This is the head of the list*/
	public PublicKeyObjectEntry root = null;
	
	public short size=0;
	
	/**
	 * Implicit constructor
	 */
	public PublicKeyDirectoryFile(){}
	
	
	/**
	 * This method adds a PublicKeyObject in the public key directory file
	 * @param obj PublicKeyObject
	 */
	public void addRecord(PublicKeyObject obj){
		
		try {
			    JCSystem.beginTransaction();
		
	    if (root == null)
	    {
	    	  if (obj.isEncoded == false){
	    		   obj.encode();
	    		   obj.freeMembers();
	    	  }
	    		  
			  root = new PublicKeyObjectEntry(obj);
	    }
	    
		else 
				{
					PublicKeyObjectEntry node = root;
					while(node.next != null){
						   node = node.next;
					}
					
					if (obj.isEncoded == false){
						 obj.encode();
						 obj.freeMembers();
					}
					
					PublicKeyObjectEntry newnode = new PublicKeyObjectEntry(obj);
					node.next=newnode;
				}
		size++;	
		JCSystem.commitTransaction();
		}
		catch( SystemException e){
		    JCSystem.abortTransaction();
		    ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);  	
	    }
		
	}
	
	
	/**
	 * This method gets an specific PublicKeyObject from the public key directory file
	 * @param index Index in the public key directory file
	 * @return PublicKeyObject
	 */
	public PublicKeyObject getRecordAtIndex(short index){
		   
		   if ((index >= size) || (index < (short)0))
			     return null;
		   
		   
		   short it = (short)0;
		   PublicKeyObjectEntry node = root;
		   
		   while (node != null){
			   	  if (it == index)
			   		    return node.obj;
			   	  it++;
			   	  node = node.next;
		   }
		   
		   
		   return null;
	}
	
	
	
	/**
	 * This method gets an specific PublicKeyObject from the public key directory file
	 * @param id Unique ID of the public key
	 * @return PublicKeyObject
	 */
	public PublicKeyObject getRecord(byte[] id){
				
		boolean match = false;
		
		if (root == null)
			 return null;
		
		PublicKeyObjectEntry node =root;
		
		while(node != null){
			
			node.obj.decode();
			match = areEqualIds(node.obj.classAtributes.iD.val, id);
			node.obj.encode();
			node.obj.freeMembers();
			
			if (match)
				 return node.obj;
			
			node= node.next;
		}
		
		return null;
	}
	
	
	/**
	 * This method gets the public key directory file content
	 * @return Byte array with the file content
	 */
	public byte[] getFile(){
		
		short totallen = 0;
		PublicKeyObjectEntry node = root;
		while (node != null){
						
			totallen += (short) node.obj.encoding.length;
			node = node.next;
		}
		
		
		byte[] file = new byte[totallen];
		
		short offset=0;
		node = root;
		while (node != null){
			Util.arrayCopy(node.obj.encoding, (short)0, file, offset,(short)node.obj.encoding.length);
			offset += (short) node.obj.encoding.length;
			node = node.next;
		}
		
		return file;
	}

	
	/**
	 * This method deletes a PublicKeyObject from the public key directory file
	 * @param id Unique Id of the public key
	 */
	public void deleteRecord(byte[] id){
		
		if (root == null) 
			return;
		
	    root.obj.decode();
	    boolean match = areEqualIds(root.obj.classAtributes.iD.val, id);
	    root.obj.encode();
	    root.obj.freeMembers();
	    
	   
	    
	    if (match)
	    	{
	    	   try{
	    		   
		    		JCSystem.beginTransaction();
		    		
		    		root.obj=null;
		    		root = root.next;
		    		if (JCSystem.isObjectDeletionSupported())
		    			 JCSystem.requestObjectDeletion();
		    		
		    		size--;
		    		JCSystem.commitTransaction();
	    	   }
	    	   
	    	   catch( SystemException e){
	   		    JCSystem.abortTransaction();
	   			  	
	   	      }
	    	   
	    		return;
	      }
	  
		PublicKeyObjectEntry node = root;
		if (node.next == null)
			 return;
		
		while(node.next !=null){
			 node.next.obj.decode();
			 match = areEqualIds(node.next.obj.classAtributes.iD.val, id);
			 node.next.obj.encode();
			 node.next.obj.freeMembers();
			 
			 if (match == false){
				 node = node.next;
				 continue;
			 }
			 
			 try{
				 JCSystem.beginTransaction();
					 
			     PublicKeyObjectEntry entry = node.next;
				 node.next = entry.next;
				 entry.obj=null;
				 entry=null;
				 if (JCSystem.isObjectDeletionSupported())
					 JCSystem.requestObjectDeletion();
				 
				 size--;
				 JCSystem.commitTransaction();
			 }
			 
			 catch( SystemException e){
				    JCSystem.abortTransaction();
					  	
			 }
			 
			 break;
		}
		
	}
	
	
	/**
	 * This method compares 2 ID
	 * @param reqId First ID
	 * @param id Second ID
	 * @return true if the two IDs are identical, false otherwise
	 */
	private boolean areEqualIds(byte[] reqId,byte[] id){
		
		if (reqId.length != id.length)
				return false;
		
		byte res = Util.arrayCompare(reqId, (short)0, id, (short)0,(short)id.length);
		if (res == (byte)0x00)
			  return true;
		else 
			return false;
	}
	
}
