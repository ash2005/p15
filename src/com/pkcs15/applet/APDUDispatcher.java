package com.pkcs15.applet;



import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;


/**
 * @author Lupascu Alexandru
 * This class represents a dispatcher for APDU commands
 */
public class APDUDispatcher {
		
	
	/* Maximum APDU data size*/
	public static final short MAX_APDU_SIZE = 255;
	
	
	/* ISO7816 status words*/
	public static final short ISO7816_SW_AUTH_BLOCKED = (short)0x6983;
	public static final short ISO7816_SW_AUTH_FAILED  = (short)0x6300;
	public static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;	
	public static final short SW_VOLATILE_MEMORY_UNAVAILABLE = (short)0x6386;
	public static final short SW_LC_INCONSISTENT		     = (short)0x6A85;
	public static final short SW_INCORRECT_PARAMETERS_IN_DATA = (short)0x6A80;
	public static final short SW_SECURITY_NOT_SATISFIED       = (short)0x6982;
	
	
	
	/*PKCS15Applet CLA*/
	public static final byte PKCS15Applet_CLA                  = (byte)0x00;
	public static final byte PKCS15Applet_CLA_COMMAND_CHAINING = (byte) 0x10;
	
	/* ISO7816 instructions bytes*/
	public static final byte INS_VERIFY       = (byte) 0x20;
	public static final byte INS_GET_RESPONSE = (byte) 0xC0;
	
	
	/* Proprietary instructions bytes*/
	public static final byte INS_TRANSFER_DATA_PUT   	   	   = (byte) 0x02;
	public static final byte INS_TRANSFER_DATA_GET   	   	   = (byte) 0x04;
	public static final byte INS_SETUP				       	   = (byte) 0x06;
	public static final byte INS_GET_RANDOM_DATA               = (byte) 0x07;
	public static final byte INS_GENERATE_SECRET_KEY 	   	   = (byte) 0x08;
	public static final byte INS_GENERATE_KEY_PAIR         	   = (byte) 0x09;
	public static final byte INS_SYMMETRIC_ECB_ENCRYPT_DECRPYT = (byte) 0x0A;
	public static final byte INS_ASYMMETRIC_RSA_ENCRYPT_DECRYPT= (byte) 0x0B;
	public static final byte INS_COMPUTE_SIGNATURE             = (byte) 0x0C;
	public static final byte INS_IMPORT_SECRET_KEY			   = (byte) 0x0D;
	public static final byte INS_EXPORT_SECRET_KEY 			   = (byte) 0x0E;
	public static final byte INS_EXPORT_PRIVATE_PUBLIC_KEY	   = (byte) 0x0F;
	
	private static final byte INS_DEBUG = (byte)0xFF;
	private static final byte INS_GET_MEMORY =(byte) 0xFE;
	
	
	private static UniqueIDProvider idProvider = null;
	
	private static RandomData randomGenerator = null;
	
	private static Signature signature = null;
	
	/**
	 * This method calls specific method to handle the APDU command
	 * @param applet PKCS15Applet instance
	 * @param apdu APDU structure
	 */
	public static void dispatch(PKCS15Applet applet,APDU apdu)
	{
		
		        //get the number of received bytes
				short bytesReceived = apdu.setIncomingAndReceive();
				
				//get the APDU buffer
				byte buffer[] = apdu.getBuffer();	
				
				//verify CLA byte
				if (buffer[ISO7816.OFFSET_CLA] != PKCS15Applet_CLA)
					  if (buffer[ISO7816.OFFSET_CLA] != PKCS15Applet_CLA_COMMAND_CHAINING)
						  ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
				
				//get the LC byte
				short LC = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
				
				//get the INS byte
						byte INS = buffer[ISO7816.OFFSET_INS];
				
			   // If first command is not SETUP then return SW = COMMAND NOT ALLOWED.
			   // Only allow SETUP command first time
			   if ((PKCS15Applet.isSetupDone() == false &&  INS != INS_SETUP)
			   		   ||(PKCS15Applet.isSetupDone() == true && INS == INS_SETUP))
			   	   	throw new ISOException(ISO7816.SW_COMMAND_NOT_ALLOWED);
			   
				while (bytesReceived < LC) {
					 bytesReceived +=apdu.receiveBytes(bytesReceived);			
				}
				
				// Verifying that GET_RESPONSE command is sent after part of the data was transfered
				// Verifying that no command is sent until all data was transfered with the GET_RESPONSE command
				if(IODataManager.offset_sent>0 && INS!= INS_GET_RESPONSE)
					 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			    //	else if (INS ==INS_GET_RESPONSE && IODataManager.offset_sent ==0 )
				//	 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				
                switch(INS) {
		
						case INS_VERIFY: 		    verify(applet,apdu,bytesReceived);
										 			               break;
				
						case INS_TRANSFER_DATA_PUT: transferDataPut(apdu,bytesReceived);
										                           break; 
										 
						case INS_TRANSFER_DATA_GET: IODataManager.offset_sent = 0;
						case INS_GET_RESPONSE:      transferDataGet(apdu);
											                       break;
											  
						case INS_SETUP:			   doSetup(applet,apdu);
													               break;
													               
						case INS_GET_RANDOM_DATA:  getRandomData(applet,apdu);
													break;
				        
						case INS_GENERATE_SECRET_KEY: generateSecretKey(applet,apdu);
													  break;
													  
						case INS_GENERATE_KEY_PAIR: generateKeyPair(applet,apdu);
													break;
													
						case INS_SYMMETRIC_ECB_ENCRYPT_DECRPYT: symmetricEcbEncryptDecrypt(applet,apdu);
													break;
													
						case INS_ASYMMETRIC_RSA_ENCRYPT_DECRYPT: asymmetricRSAEncryptDecrypt(applet,apdu);
																  break;
																  
						case INS_COMPUTE_SIGNATURE: computeSignature(applet,apdu);
													break;
								
						case INS_IMPORT_SECRET_KEY: importSecretKey(applet,apdu);
													break;
						
						case INS_EXPORT_SECRET_KEY: exportSecretKey(applet,apdu);
													break;
													
						case INS_EXPORT_PRIVATE_PUBLIC_KEY: exportPrivatePublicKey(applet,apdu);
													break;
													
						case INS_DEBUG: 
																									    
//													Certificate cert = new Certificate(IODataManager.getBuffer());
//													cert.decode();
//													
//													
//													X509CertificateAttributes xca = new X509CertificateAttributes(cert);
//																										
//													CertificateObject co = new CertificateObject(coa, cca, xca);
//													
//														   
												    byte[] data=null;
												   // KeyPair kp = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
												    //kp.genKeyPair();
											
												 //   RSAPublicKey pub = (RSAPublicKey)kp.getPublic();
												   // RSAPrivateKey priv = (RSAPrivateKey)kp.getPrivate();
												    
												   // data = JCSystem.makeTransientByteArray((short)((priv.getSize()/8)+1), JCSystem.CLEAR_ON_RESET);
												    
												   // short len;
												    
												   // len = priv.getModulus(data, (short)0);
												    //len = priv.getExponent(data, (short)0);
												    
												    byte[] id=new byte[2];
												    id[0]= apdu.getBuffer()[ISO7816.OFFSET_P1];
												    id[1]= apdu.getBuffer()[ISO7816.OFFSET_P2];
												    SecretKeyObject sko = applet.secKeyDirFile.getRecord(id);
												    sko.decode();
												    data = sko.typeAttribute.value.val;
												     
												     //pub.getModulus(data,(short)0);
												    //pub.getExponent(data, (short)0);
												    
												   // IODataManager.prepareBuffer((short)len);
													//IODataManager.setData((short)0, data, (short)0,(short)len);
												   
												    
												   
												    
													IODataManager.prepareBuffer((short)data.length);
												    IODataManager.setData((short)0, data, (short)0,(short)data.length);
													
													break;
						case INS_GET_MEMORY:		
													
													byte[] data2 = applet.privKeyDirFile.getFile();
							
													IODataManager.prepareBuffer((short)data2.length);
												    IODataManager.setData((short)0, data2, (short)0,(short)data2.length);
							
							                        //short left = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);
													//buffer[0] = (byte) ((left>>8) & 0x00FF);
													//buffer[1] = (byte) (left & 0x00FF);
													//apdu.setOutgoingAndSend((short)0,(short)2);
												break;
						default:		 			               ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);						 
						}
	}


/**
 * This method handles the EXPORT_PRIVATE_PUBLIC_KEY command
 * @param applet PKCS15Applet instance
 * @param apdu APDU structure
 */
private static void exportPrivatePublicKey(PKCS15Applet applet,APDU apdu){
	
	byte[] buffer = apdu.getBuffer();
	short offset = ISO7816.OFFSET_CDATA;
	
	short idSize = (short) (buffer[ISO7816.OFFSET_P2] & 0x00FF);
	byte[] keyId = null;
	
	try {
		keyId = JCSystem.makeTransientByteArray((short)idSize,JCSystem.CLEAR_ON_RESET);
	    Util.arrayCopy(buffer,offset, keyId, (short)0, idSize);
		}
		catch (SystemException e){
			ISOException.throwIt(SW_VOLATILE_MEMORY_UNAVAILABLE);
		}
	
	
	if ( buffer[ISO7816.OFFSET_P1] == (byte)0x00 ) //public key case
				{
					PublicKeyObject pubKey = applet.pubKeyDirFile.getRecord(keyId);
					if (pubKey == null)
						   ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
					
					pubKey.decode();
					pubKey.typeAttribute.value.encode();
					IODataManager.prepareBuffer((short)pubKey.typeAttribute.value.encoding.length);
					IODataManager.setData((short)0, pubKey.typeAttribute.value.encoding, (short)0, (short)pubKey.typeAttribute.value.encoding.length);
					
					pubKey.typeAttribute.value.decode();							
					pubKey.encode();
					pubKey.freeMembers();
					
					IODataManager.sendData(apdu);
				
				}
	
	else if ( buffer[ISO7816.OFFSET_P1] == (byte)0xFF) //private key case
				{
					if (applet.getPins()[0].isValidated() == false)
				        ISOException.throwIt(SW_SECURITY_NOT_SATISFIED);
	
					PrivateKeyObject privKey = applet.privKeyDirFile.getRecord(keyId);
					if (privKey == null)
						  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
				
					privKey.decode();
					
					if (privKey.classAtributes.accessFlags.extractable == false)
							{
						       privKey.encode();
						       privKey.freeMembers();
						       ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
							}
					
					privKey.typeAttribute.value.encode();
					IODataManager.prepareBuffer((short)privKey.typeAttribute.value.encoding.length);
					IODataManager.setData((short)0, privKey.typeAttribute.value.encoding , (short)0, (short) privKey.typeAttribute.value.encoding.length);
					
					privKey.typeAttribute.value.decode();
					privKey.encode();
				    privKey.freeMembers();
				    
				    IODataManager.sendData(apdu);
					
					
				}
	else 
		ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	
}	
	
	
	
	
/**
 * This method handles the EXPORT_SECRET_KEY command
 * @param applet PKCS15Applet instance
 * @param apdu APDU structure
 */
private static void exportSecretKey(PKCS15Applet applet,APDU apdu){
	
	if (applet.getPins()[0].isValidated() == false)
        ISOException.throwIt(SW_SECURITY_NOT_SATISFIED);
	
	byte[] buffer = apdu.getBuffer();
	short offset = ISO7816.OFFSET_CDATA;
	
	short idSize = (short) (buffer[offset++] & 0x00FF);
	byte[] keyId = null;
	
	try {
		keyId = JCSystem.makeTransientByteArray((short)idSize,JCSystem.CLEAR_ON_RESET);
	    Util.arrayCopy(buffer,offset, keyId, (short)0, idSize);
		}
		catch (SystemException e){
			ISOException.throwIt(SW_VOLATILE_MEMORY_UNAVAILABLE);
		}
	
	SecretKeyObject secretKey = applet.secKeyDirFile.getRecord(keyId);
	if (secretKey == null)
		  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
	
	secretKey.decode();
	
	if (secretKey.classAtributes.accessFlags.extractable == false)
					{
						secretKey.encode();
						secretKey.freeMembers();
						ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		     		}		
	
	IODataManager.prepareBuffer((short)secretKey.typeAttribute.value.val.length);
	IODataManager.setData((short)0, secretKey.typeAttribute.value.val, (short)0, (short)secretKey.typeAttribute.value.val.length);
    secretKey.encode();
    secretKey.freeMembers();
    
    IODataManager.sendData(apdu);
    
    
}	
	
	
/**
 * This method handles the IMPORT_SECRET_KEY command
 * @param applet PKCS15Applet instance
 * @param apdu APDU structure
 */
private static void importSecretKey(PKCS15Applet applet,APDU apdu){
	
	if (applet.getPins()[0].isValidated() == false)
        ISOException.throwIt(SW_SECURITY_NOT_SATISFIED);
	
	byte[] buffer = apdu.getBuffer();
	short offset = ISO7816.OFFSET_CDATA;
	byte[] id = idProvider.getUniqueID();
	short size = (short) (buffer[offset++] & 0x00FF);
	
	//Creating ASN1 structure of SecretKeyObject and adding it to SKDF
	Utf8String label = new Utf8String(buffer, offset,size);
	CommonObjectFlags cof = new CommonObjectFlags(true, false);
	OctetString authId = new OctetString(applet.ownerPinAuthId, (short)0,(short)applet.ownerPinAuthId.length);
	CommonObjectAttributes coa = new CommonObjectAttributes(label, cof, authId);
	
	OctetString keyID = new OctetString(id,(short)0,(short)id.length);
	KeyUsageFlags kuf = new KeyUsageFlags(true, true, false, false, false, false, false, false, false, false);
	Boolean nativ = new Boolean(true);
	offset+=size;
	boolean extractable = (buffer[offset++] == (byte)0xFF);
	KeyAccessFlags kaf = new KeyAccessFlags(false,extractable,false,!extractable,false);
	Integer ref = new Integer((short)0);
	CommonKeyAttributes cka = new CommonKeyAttributes(keyID, kuf, nativ, kaf, ref);
	
	short keyLen=0;;
	switch(buffer[offset++]){
	case 0x01: // AES key case
		    if (buffer[offset] == (byte)0x80) // 128 bit key case
		    		keyLen=(short)128;
		    else if (buffer[offset] == (byte)0xC0) // 192 bit key case
		    	keyLen=(short)192;
		    else if (buffer[offset] == (byte)0x00) // 256 bit key case
		    	keyLen=(short)256;
		    else
		    	ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
			break;
	case 0x02: // DES key case
		    if (buffer[offset] ==(byte)0x40 ) //64 bit key case
		    	keyLen = (short)64;
		    else
		    	ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
			break;
	case 0x03: // 3DES key case
			if (buffer[offset] ==(byte)0x80 ) //128 bit key case
	    		keyLen = (short)128;
	    	else if (buffer[offset] ==(byte)0xC0 ) //192 bit key case
		    	keyLen = (short)192;
		    else 
		    	ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
		    break;
	default: ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);}
	Integer keyLength = new Integer(keyLen);
	CommonSecretKeyAttributes cska = new CommonSecretKeyAttributes(keyLength);
	
	SecretKeyObject secObj = null;
	
	try {
	offset++;
	
	OctetString keyValue = new OctetString();
	keyValue.val = new byte[(short)(keyLen/8)];
	Util.arrayCopy(buffer, offset, keyValue.val, (short)0, (short)keyValue.val.length);
	GenericSecretKeyAttributes gska = new GenericSecretKeyAttributes(keyValue);
    secObj = new SecretKeyObject(coa, cka, cska, gska);
	
	}
	catch (Exception e){
	   ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);	
	}

	applet.secKeyDirFile.addRecord(secObj);
	
	if (JCSystem.isObjectDeletionSupported())
		 JCSystem.requestObjectDeletion();
	
	IODataManager.prepareBuffer((short)id.length);
	IODataManager.setData((short)0,id,(short)0,(short)id.length);
	IODataManager.sendData(apdu);
	
}
	
	
/**
 * This method handles the COMPUTE_SIGNATURE command
 * @param applet PKCS15Applet instance
 * @param apdu APDU structure
 */
private static void computeSignature(PKCS15Applet applet,APDU apdu){
	
	if (applet.getPins()[0].isValidated() == false)
	        ISOException.throwIt(SW_SECURITY_NOT_SATISFIED);
	
	byte[] buffer = apdu.getBuffer();
	short offset = ISO7816.OFFSET_CDATA;
	
	if (buffer[ISO7816.OFFSET_P1] == (byte) 0x00 ) //initialize operation
				{
						
					short idSize = (short) (buffer[ISO7816.OFFSET_P2] & 0x00FF);
					byte[] keyId = null;
					
					try {
						keyId = JCSystem.makeTransientByteArray((short)idSize,JCSystem.CLEAR_ON_RESET);
					    Util.arrayCopy(buffer,offset, keyId, (short)0, idSize);
						}
						catch (SystemException e){
							ISOException.throwIt(SW_VOLATILE_MEMORY_UNAVAILABLE);
						}
					offset+= idSize;
					
					if (buffer[offset] == (byte) 0x00)
						   signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
					else if (buffer[offset] == (byte) 0xFF)
						   signature = Signature.getInstance(Signature.ALG_RSA_MD5_PKCS1, false);
					else 
						 ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
					
					PrivateKeyObject privKeyObj = applet.privKeyDirFile.getRecord(keyId);
					
					if (privKeyObj == null)
						  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
					
					privKeyObj.decode();
					
					short keylen =0;
					if (privKeyObj.typeAttribute.modulusLength.val[0] == (byte) 0x04)
						   keylen = KeyBuilder.LENGTH_RSA_1024;
					else if (privKeyObj.typeAttribute.modulusLength.val[0] == (byte)0x08) 
					 	   keylen = KeyBuilder.LENGTH_RSA_2048;
					else
						 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					
					Key privKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keylen, false);
					((RSAPrivateKey)privKey).setModulus(privKeyObj.typeAttribute.value.modulus.val, (short)0, (short)privKeyObj.typeAttribute.value.modulus.val.length);
					((RSAPrivateKey)privKey).setExponent(privKeyObj.typeAttribute.value.privateExponent.val, (short)0, (short) privKeyObj.typeAttribute.value.privateExponent.val.length );
                    
					signature.init(privKey, Signature.MODE_SIGN);
                    
					privKeyObj.encode();
					privKeyObj.freeMembers();
					
					
				}
	else if (buffer[ISO7816.OFFSET_P1] == (byte) 0x01) //update operation
				{
				    short inputSize = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
				    
				    try{
				    	 signature.update(buffer, (short) ISO7816.OFFSET_CDATA, (short)inputSize);
				    }
				    catch(Exception e){
				    	 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				    }
				}
	else if (buffer[ISO7816.OFFSET_P1] == (byte) 0x02) // final sign operation
	            {
					short inputSize = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
				   
				   
				    try{
				    	 IODataManager.prepareBuffer(signature.getLength());
				    	 signature.sign(buffer, (short)ISO7816.OFFSET_CDATA, inputSize, IODataManager.getBuffer(), (short)0);
				    	 signature=null;
				    	 
				    	 if (JCSystem.isObjectDeletionSupported())
				    		   JCSystem.requestObjectDeletion();
				    	 
				    	 IODataManager.sendData(apdu);
				    }
				    
				    catch(Exception e){
				    	 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				    }
				    
	            }
	else ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	   
}
	
	
	
	
/**
 * This method handles the ASYMMETRIC_RSA_ENCRYPT_DECRYPT command	
 * @param applet PKCS15Applet instance
 * @param apdu APDU structure
 */
private static void asymmetricRSAEncryptDecrypt(PKCS15Applet applet,APDU apdu){
	
	byte[] buffer = apdu.getBuffer();
	short offset = ISO7816.OFFSET_CDATA;
	
	short idSize = (short) (buffer[ISO7816.OFFSET_P2] & 0x00FF);
	byte[] keyId = null;
	byte[] outputData = null;
	
	byte padding = (byte)0x00;
	byte privPub = (byte)0x00;
	
	//Extract parameters from data field
		try {
		keyId = JCSystem.makeTransientByteArray((short)idSize,JCSystem.CLEAR_ON_RESET);
	    Util.arrayCopy(buffer,offset, keyId, (short)0, idSize);
		}
		catch (SystemException e){
			ISOException.throwIt(SW_VOLATILE_MEMORY_UNAVAILABLE);
		}
	offset+= idSize;
	
	padding = buffer[offset++];
	privPub = buffer[offset++];
	
	Cipher asymmetricCipher = null;
	Key rsaKey = null;
	
	if (padding == (byte) 0x00)
		   asymmetricCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD,false);
	else if (padding == (byte) 0xFF)
		   asymmetricCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
	else 
		ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
	
	if (privPub == (byte) 0x00 ) // using public key
			{
				PublicKeyObject pubKey = applet.pubKeyDirFile.getRecord(keyId);
				if (pubKey == null)
					  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
				
				pubKey.decode();
				
				short keylen =0;
				if (pubKey.typeAttribute.modulusLength.val[0] == (byte) 0x04)
					   keylen = KeyBuilder.LENGTH_RSA_1024;
				else if (pubKey.typeAttribute.modulusLength.val[0] == (byte)0x08) 
				 	   keylen = KeyBuilder.LENGTH_RSA_2048;
				else
					 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				
				rsaKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, keylen, false);
				((RSAPublicKey)rsaKey).setModulus(pubKey.typeAttribute.value.modulus.val, (short)0,(short) pubKey.typeAttribute.value.modulus.val.length);
				((RSAPublicKey)rsaKey).setExponent(pubKey.typeAttribute.value.publicExponent.val, (short)0, (short)pubKey.typeAttribute.value.publicExponent.val.length);
				
				pubKey.encode();
				pubKey.freeMembers();
				
				try{
					outputData = JCSystem.makeTransientByteArray((short)(keylen/8), JCSystem.CLEAR_ON_RESET);
				}
				catch(Exception e){
					ISOException.throwIt(SW_VOLATILE_MEMORY_UNAVAILABLE);
				}
			
				
			} 
	else if (privPub == (byte)0xFF ) // using private key
			{
				if (applet.getPins()[0].isValidated() == false)
			     	        ISOException.throwIt(SW_SECURITY_NOT_SATISFIED);
			     		
				PrivateKeyObject privKey = applet.privKeyDirFile.getRecord(keyId);
				if (privKey == null)
					  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
				
				privKey.decode();
				
				short keylen =0;
				if (privKey.typeAttribute.modulusLength.val[0] == (byte) 0x04)
					   keylen = KeyBuilder.LENGTH_RSA_1024;
				else if (privKey.typeAttribute.modulusLength.val[0] == (byte)0x08) 
				 	   keylen = KeyBuilder.LENGTH_RSA_2048;
				else
					 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				
				rsaKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keylen, false);
				((RSAPrivateKey)rsaKey).setModulus(privKey.typeAttribute.value.modulus.val, (short)0, (short)privKey.typeAttribute.value.modulus.val.length);
				((RSAPrivateKey)rsaKey).setExponent(privKey.typeAttribute.value.privateExponent.val, (short)0, (short) privKey.typeAttribute.value.privateExponent.val.length );
				
				
				privKey.encode();
				privKey.freeMembers();
				
				try{
					outputData = JCSystem.makeTransientByteArray((short)(keylen/8), JCSystem.CLEAR_ON_RESET);
				}
				catch(Exception e){
					ISOException.throwIt(SW_VOLATILE_MEMORY_UNAVAILABLE);
				}
				
			}
	else 
		ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
	
	
	 if ( buffer[ISO7816.OFFSET_P1] == (byte) 0x00) // Encrypt operation
 		 asymmetricCipher.init(rsaKey, Cipher.MODE_ENCRYPT);
     else if ( buffer[ISO7816.OFFSET_P1] == (byte) 0xFF) // Decrypt operation
 	    asymmetricCipher.init(rsaKey, Cipher.MODE_DECRYPT);
     else 
 	      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	 
	 short bytesNr = 0;
	 
	 try{
	 bytesNr = asymmetricCipher.doFinal(IODataManager.getBuffer(), (short)0, IODataManager.actualBufferSize, outputData, (short)0);
	 }
	 catch(CryptoException e){
		 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	 }
	 

	 IODataManager.freeBuffer();	 
	 
	 IODataManager.prepareBuffer(bytesNr);
	 IODataManager.setData((short)0, outputData, (short)0, bytesNr);
	 rsaKey.clearKey();
	
	 outputData=null;
	 
	 if (JCSystem.isObjectDeletionSupported())
	      JCSystem.requestObjectDeletion();
	 
	 IODataManager.sendData(apdu);
	 
}	
	
	



	
/**
 * This method handles the SYMMETRIC_ECB_ENCRYPT_DECRYPT command
 * @param applet PKCS15Applet instance
 * @param apdu APDU structure
 */
private static void symmetricEcbEncryptDecrypt(PKCS15Applet applet,APDU apdu){
	
	byte[] buffer = apdu.getBuffer();
	short offset = ISO7816.OFFSET_CDATA;
	
	short idSize = (short) (buffer[ISO7816.OFFSET_P2] & 0x00FF);
	byte[] keyId = null;
	byte alg = (byte)0x00;
	
	//Extract parameters from data field
	try {
	keyId = JCSystem.makeTransientByteArray((short)idSize,JCSystem.CLEAR_ON_RESET);
    Util.arrayCopy(buffer,offset, keyId, (short)0, idSize);
	}
	catch (SystemException e){
		ISOException.throwIt(SW_VOLATILE_MEMORY_UNAVAILABLE);
	}
	
	offset += idSize;
	alg = (byte) buffer[offset++];
	short inputSize = (short) (alg & 0x00FF);
	
	//Search secret key by ID
    SecretKeyObject key = applet.secKeyDirFile.getRecord(keyId);
    if (key == null)
    	   ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    
    //Check if the key is private - protected by PIN and verify that the authentication was previously made
    key.decode();
    if (key.commonObjectAttributes.flags.privateFlag == true)
    		{
    			if (applet.getPins()[0].isValidated() == false)
    				     {
    						key.encode();
    						key.freeMembers();
    				        ISOException.throwIt(SW_SECURITY_NOT_SATISFIED);
    				     }
    		}
    
    Cipher symmetricCipher = null;
    Key symKey = null;
    
    
    if (alg == (byte) 0x10)  // AES 128 bit input block
    	  {
    	      symmetricCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    	      if (key.subClassAttributes.keyLen.val.length == (short)2 )  // check if key length is 256 bits
    	      		{
    	    	  		if ((key.subClassAttributes.keyLen.val[0] != (byte) 0x01) ||
    	    	  			(key.subClassAttributes.keyLen.val[1] != (byte) 0x00))
    	    	  				{
    	    	  				  key.encode();
    	    	  				  key.freeMembers();
    	    	  				  ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    	    	  				}
    	    	  		symKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256, false);
    	    	  		((AESKey)symKey).setKey(key.typeAttribute.value.val,(short)0);
    	    	  		
    	      		}
    	      else if (key.subClassAttributes.keyLen.val.length == (short)1 )
    	      		{
    	    	       if (key.subClassAttributes.keyLen.val[0] == (byte) 0xC0) // check if key length is 192 bits
    	    	    	       symKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_192, false);
    	    	       else if (key.subClassAttributes.keyLen.val[0] == (byte) 0x80) // check if key length is 128 bits
    	    	    	       symKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
    	    	       else 
    	    	       	{
    	    	    	   key.encode();
    	    	    	   key.freeMembers();
    	    	    	   ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    	    	       	}
    	    	       
    	    	        ((AESKey)symKey).setKey(key.typeAttribute.value.val, (short)0);
    	    	       
    	      		}  	      
    	      else 
    	      		{
    	    	      key.encode();
    	    	      key.freeMembers();
    	    	      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    	      		}
    	  }
    else if (alg == (byte) 0x08 )  // DES or 3DES 64 bit input block
    	  {
    	      symmetricCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD,false);
    	      if (key.subClassAttributes.keyLen.val.length == (short) 1) 
    	      		{
    	    	  		if (key.subClassAttributes.keyLen.val[0] == (byte) 0x40) // check if key length is 64 bits
    	    	  			  symKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET, KeyBuilder.LENGTH_DES, false);
    	    	  		else if (key.subClassAttributes.keyLen.val[0] == (byte) 0x80) // check if key length is 128 bits
    	    	  			  symKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET, KeyBuilder.LENGTH_DES3_2KEY, false);
    	    	  		else if  (key.subClassAttributes.keyLen.val[0] == (byte) 0xC0) // check if key length is 192 bits
    	    	  			  symKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET, KeyBuilder.LENGTH_DES3_3KEY, false);
    	    	  		else 
    	    	  				{
    	    	  					key.encode();
    	    	  					key.freeMembers();
    	    	  					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    	    	  				}
    	    	  		
    	    	  		((DESKey) symKey).setKey(key.typeAttribute.value.val, (short)0);
    	      		}
    	      else 
    	      		{
    	    	      key.encode();
    	    	      key.freeMembers();
    	    	      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    	      		}
    	  }
    else 
    	{
    	 key.encode();
    	 key.freeMembers();
    	 ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
    	}
    
    key.encode();
    key.freeMembers();
    
    
    if ( buffer[ISO7816.OFFSET_P1] == (byte) 0x00) // Encrypt operation
    		symmetricCipher.init(symKey, Cipher.MODE_ENCRYPT);
       
    else if ( buffer[ISO7816.OFFSET_P1] == (byte) 0xFF) // Decrypt operation
    	    symmetricCipher.init(symKey, Cipher.MODE_DECRYPT);
    else 
    	  ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    	
    
    IODataManager.prepareBuffer(inputSize);
    symmetricCipher.doFinal(buffer,offset, inputSize, IODataManager.getBuffer(), (short)0);
    symKey.clearKey();
    IODataManager.sendData(apdu);
    

}	
	
	
	
/**
 * This method handles the GENERATE_KEY_PAIR command
 * @param applet PKCS15Applet instance
 * @param apdu APDU structure
 */
private static void generateKeyPair(PKCS15Applet applet,APDU apdu){
	
	if (applet.getPins()[0].isValidated() == false)
		 ISOException.throwIt(SW_SECURITY_NOT_SATISFIED);
	
	try{
		
	byte[] buffer = apdu.getBuffer();
	short offset = ISO7816.OFFSET_CDATA;
	byte[] id = idProvider.getUniqueID();
	short keysize=0;
	short size = (short) (buffer[offset++] & 0x00FF);
	byte[] cn=null;
	byte[] c=null;
	byte[] l=null;
	byte[] s=null;
	byte[] o=null;
	byte[] ou=null;
	
	
	//Extract parameters from data field
	Utf8String labelPrivate = new Utf8String(buffer,offset,size);
	offset+=size;
	size = (short) (buffer[offset++] & 0x00FF);
	Utf8String labelPublic = new Utf8String(buffer,offset,size);
	offset+=size;
	boolean extractable = (buffer[offset++] == (byte)0xFF);
    size = (short) (buffer[offset++] & 0x00FF);
    keysize = size;
    Integer modulusLen = null;
	if (size == (short)0x0010)
		   modulusLen = new Integer((short)1024);
	else if (size == (short)0x0020)
		   modulusLen = new Integer((short)2048);
	else ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
	
	size = (short) (buffer[offset++] & 0x00FF);
	if (size != (short)0x0000){
	cn = new byte[size];
	Util.arrayCopy(buffer, offset, cn, (short)0, size);
	offset+=size;
	}
	
	size = (short) (buffer[offset++] & 0x00FF);
	if (size != (short)0x0000){
	c = new byte[size];
	Util.arrayCopy(buffer, offset, c, (short)0, size);
	offset+=size;
	}
	
	size = (short) (buffer[offset++] & 0x00FF);
	if (size != (short)0x0000){
	l = new byte[size];
	Util.arrayCopy(buffer, offset, l, (short)0, size);
	offset+=size;
	}
	
	size = (short) (buffer[offset++] & 0x00FF);
	if (size != (short)0x0000){
	s = new byte[size];
	Util.arrayCopy(buffer, offset, s, (short)0, size);
	offset+=size;
	}
	
	size = (short) (buffer[offset++] & 0x00FF);
	if (size != (short)0x0000){
	o = new byte[size];
	Util.arrayCopy(buffer, offset, o, (short)0, size);
	offset+=size;
	}
	
	size = (short) (buffer[offset++] & 0x00FF);
	if (size != (short)0x0000){
	ou = new byte[size];
	Util.arrayCopy(buffer, offset, ou, (short)0, size);
	}
	
	//Generate key pair
	 KeyPair kp = null;
	 if (keysize == (short)0x0010)
		 kp = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
	 else kp = new KeyPair(KeyPair.ALG_RSA,KeyBuilder.LENGTH_RSA_2048);
	 kp.genKeyPair();

    RSAPublicKey pub = (RSAPublicKey)kp.getPublic();
    RSAPrivateKey priv = (RSAPrivateKey)kp.getPrivate();
    
    //Creating PrivateKeyObject
    CommonObjectFlags cof = new CommonObjectFlags(true,false);
    OctetString authId = new OctetString(applet.ownerPinAuthId,(short)0,(short)applet.ownerPinAuthId.length);
    CommonObjectAttributes coa = new CommonObjectAttributes(labelPrivate, cof, authId);
    OctetString keyId = new OctetString(id, (short)0,(short)id.length);
    KeyUsageFlags kuf = new KeyUsageFlags(false, true, false, true, false, false, false, false, false, true);		
    Boolean nativ = new Boolean(true);
    KeyAccessFlags kaf = new KeyAccessFlags(false, extractable, false, !extractable, false);
    Integer ref = new Integer((short)0);
    CommonKeyAttributes cka = new CommonKeyAttributes(keyId, kuf, nativ, kaf, ref);
    Name name = new Name(cn,null,c,l,s,o,ou,null,null,null,null,null,null);
    CommonPrivateKeyAttributes cprka = new CommonPrivateKeyAttributes(name);
    byte[] altBuf = JCSystem.makeTransientByteArray((short)((priv.getSize()/8)+1), JCSystem.CLEAR_ON_RESET);
    size = priv.getModulus(altBuf, (short)0);
    Integer modulus = new Integer(altBuf,(short)0,size);
    size = priv.getExponent(altBuf, (short)0);
	Integer privExponent = new Integer(altBuf,(short)0,size);
	RsaPrivateKeyObject rsaprko = new RsaPrivateKeyObject(modulus, privExponent);
	PrivateRsaKeyAttribute prrsaka = new PrivateRsaKeyAttribute(rsaprko, modulusLen);
	PrivateKeyObject privKeyObj = new PrivateKeyObject(coa, cka, cprka, prrsaka); 
	
	//Creating PublicKeyObject
	cof = new CommonObjectFlags(false, false);
	coa = new CommonObjectAttributes(labelPublic, cof, authId);
	kuf = new KeyUsageFlags(true, false, false, false, false, false, false, true, false, false);
	kaf = new KeyAccessFlags(false, true, false, false, false);
	cka = new CommonKeyAttributes(keyId, kuf, nativ, kaf, ref);
	CommonPublicKeyAttributes cpuka = new CommonPublicKeyAttributes(name);
	size = pub.getExponent(altBuf,(short)0);
	Integer pubExponent = new Integer(altBuf,(short)0,size);
	com.pkcs15.applet.RSAPublicKey rsapuk = new com.pkcs15.applet.RSAPublicKey(modulus,pubExponent);
	PublicRSAKeyAttributes pursaka = new PublicRSAKeyAttributes(rsapuk, modulusLen);
	PublicKeyObject pubKeyObj = new PublicKeyObject(coa, cka, cpuka, pursaka);
	
	//Adding PrivateKeyObject to PrKDF
	applet.privKeyDirFile.addRecord(privKeyObj);
	
	//Adding PublicKeyObject to PuKDF
	applet.pubKeyDirFile.addRecord(pubKeyObj);
	
	IODataManager.prepareBuffer((short)id.length);
	IODataManager.setData((short)0,id, (short)0, (short)id.length);
	IODataManager.sendData(apdu);
	}
	
	catch(SystemException e){
		  if (e.getReason() == SystemException.NO_TRANSIENT_SPACE)
			  		ISOException.throwIt(SW_VOLATILE_MEMORY_UNAVAILABLE);
		  else
			  ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
	}
}


	
/**
 * This method handles the GENERATE_SECRET_KEY command
 * @param applet PKCS15Applet instance
 * @param apdu APDU structure
 */
private static void generateSecretKey(PKCS15Applet applet,APDU apdu){
	
	if (applet.getPins()[0].isValidated() == false)
		 ISOException.throwIt(SW_SECURITY_NOT_SATISFIED);
	
	byte[] buffer = apdu.getBuffer();
	short offset = ISO7816.OFFSET_CDATA;
	byte[] id = idProvider.getUniqueID();
	short size = (short) (buffer[offset++] & 0x00FF);
	
	//Creating ASN1 structure of SecretKeyObject and adding it to SKDF
	Utf8String label = new Utf8String(buffer, offset,size);
	CommonObjectFlags cof = new CommonObjectFlags(true, false);
	OctetString authId = new OctetString(applet.ownerPinAuthId, (short)0,(short)applet.ownerPinAuthId.length);
	CommonObjectAttributes coa = new CommonObjectAttributes(label, cof, authId);
	
	OctetString keyID = new OctetString(id,(short)0,(short)id.length);
	KeyUsageFlags kuf = new KeyUsageFlags(true, true, false, false, false, false, false, false, false, false);
	Boolean nativ = new Boolean(true);
	offset+=size;
	boolean extractable = (buffer[offset++] == (byte)0xFF);
	KeyAccessFlags kaf = new KeyAccessFlags(false,extractable,false,!extractable,false);
	Integer ref = new Integer((short)0);
	CommonKeyAttributes cka = new CommonKeyAttributes(keyID, kuf, nativ, kaf, ref);
	
	short keyLen=0;;
	switch(buffer[offset++]){
	case 0x01: // AES key case
		    if (buffer[offset] == (byte)0x80) // 128 bit key case
		    		keyLen=(short)128;
		    else if (buffer[offset] == (byte)0xC0) // 192 bit key case
		    	keyLen=(short)192;
		    else if (buffer[offset] == (byte)0x00) // 256 bit key case
		    	keyLen=(short)256;
		    else
		    	ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
			break;
	case 0x02: // DES key case
		    if (buffer[offset] ==(byte)0x40 ) //64 bit key case
		    	keyLen = (short)64;
		    else
		    	ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
			break;
	case 0x03: // 3DES key case
			if (buffer[offset] ==(byte)0x80 ) //128 bit key case
	    		keyLen = (short)128;
	    	else if (buffer[offset] ==(byte)0xC0 ) //192 bit key case
		    	keyLen = (short)192;
		    else 
		    	ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);
		    break;
	default: ISOException.throwIt(SW_INCORRECT_PARAMETERS_IN_DATA);}
	Integer keyLength = new Integer(keyLen);
	CommonSecretKeyAttributes cska = new CommonSecretKeyAttributes(keyLength);
	
	OctetString keyValue = new OctetString();
	keyValue.val = new byte[(short)(keyLen/8)];
	randomGenerator.generateData(keyValue.val, (short)0, (short)keyValue.val.length);
	GenericSecretKeyAttributes gska = new GenericSecretKeyAttributes(keyValue);
	SecretKeyObject secObj = new SecretKeyObject(coa, cka, cska, gska);		
	
	applet.secKeyDirFile.addRecord(secObj);
	
	if (JCSystem.isObjectDeletionSupported())
		 JCSystem.requestObjectDeletion();
	
	IODataManager.prepareBuffer((short)id.length);
	IODataManager.setData((short)0,id,(short)0,(short)id.length);
	IODataManager.sendData(apdu);
	
}	
	

	
/**
 * This method handles the GET_RANDOM_DATA command	
 * @param applet PKCS15Applet instance	
 * @param apdu APDU structure
 */
private static void getRandomData(PKCS15Applet applet,APDU apdu){
	
	
	short size = (short)(apdu.getBuffer()[ISO7816.OFFSET_P1] & 0x00FF);
	
	try{
		
		IODataManager.prepareBuffer((short)size);
		randomGenerator.generateData(IODataManager.getBuffer(), (short)0,size);
		IODataManager.sendData(apdu);
	}
	catch(SystemException e){
		if (JCSystem.isObjectDeletionSupported())
			 JCSystem.requestObjectDeletion();
		ISOException.throwIt(SW_VOLATILE_MEMORY_UNAVAILABLE);
	}
	catch(NegativeArraySizeException e){
		ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
	}
	
	
}
	
	
/**
 * This method handles the VERIFY command 
 * @param applet PKCS15Applet instance
 * @param apdu APDU structure
 * @param bytesReceived Number of bytes received, obtained with APDU.setIncomingAndReceive().
 */
private static void verify(PKCS15Applet applet,APDU apdu,short bytesReceived){
		
		byte pinBytes = (byte) (bytesReceived & 0x00FF);
		
		OwnerPIN[] pins = applet.getPins();
		
		byte reference = apdu.getBuffer()[ISO7816.OFFSET_P2];
		
		if (reference >= (byte) PKCS15Applet.MAX_PIN_CODES)
			  ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
		
		
		if (pins[reference].check(apdu.getBuffer(),ISO7816.OFFSET_CDATA, pinBytes) == false)
			   if (pins[reference].getTriesRemaining() == 0)
				   	ISOException.throwIt(ISO7816_SW_AUTH_BLOCKED);
			   else
			   		{
				      short sw =  (short) (ISO7816_SW_AUTH_FAILED + pins[reference].getTriesRemaining());
				      ISOException.throwIt(sw);
			   		}
	}




/**
 * This method handles the TRANSFER_DATA_PUT command.
 * Data is placed in IODataManager's buffer 
 * @param apdu APDU structure
 * @param bytesReceived Number of bytes received, obtained with APDU.setIncomingAndReceive().
 */
private static void transferDataPut(APDU apdu,short bytesReceived){
		
		IODataManager.receiveData(apdu, bytesReceived);
	}


/**
 * This method handles the TRANSFER_DATA_GET command.
 * Transfers data from IODataManager's buffer to host
 * @param apdu APDU structure
 */
private static void transferDataGet(APDU apdu){
		
		IODataManager.sendData(apdu);
			
	}
	

/**
 * This method handles the SETUP command.
 * This method creates a instance of ObjectManagerWrapper with memory size encoded in parameter P1,P2 
 * @param applet PKCS15Applet instance
 * @param apdu APDU structure
 */
private static void doSetup(PKCS15Applet applet,APDU apdu){
		
	
		
		try {
			
				
				idProvider = new UniqueIDProvider();
				randomGenerator =  RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
				OwnerPIN[] pins = applet.getPins();
				
				//set Security officer's PIN
				pins[1] = new OwnerPIN(PKCS15Applet.MAX_PIN_TRIES,PKCS15Applet.MAX_PIN_SIZE);
				byte[] soPin = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);
				Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, soPin, (short)0, (short)4);
				pins[1].update(soPin, (short)0,(byte)4);
				soPin=null;
				
				
				applet.setFileSystem(new FileSystem((short)32));
				
				FileSystem fs = applet.getFileSystem();
				fs.fileStructure = FileSystem.pkcs15FileSystemStructure;
				
				
				
			    // EF(ODF) content
			    byte[] efODFContent = new byte[] {
			    		(byte)0xA0,(byte)0x06,(byte)0x30,(byte)0x04,(byte)0x04,(byte)0x02,(byte)0x4D,(byte)0x01, // Path for EF(PrKDF)
			    		(byte)0xA1,(byte)0x06,(byte)0x30,(byte)0x04,(byte)0x04,(byte)0x02,(byte)0x4D,(byte)0x02, // Path for EF(PuKDF)
			    		(byte)0xA3,(byte)0x06,(byte)0x30,(byte)0x04,(byte)0x04,(byte)0x02,(byte)0x4D,(byte)0x03, // Path for EF(SKDF)
			    		(byte)0xA4,(byte)0x06,(byte)0x30,(byte)0x04,(byte)0x04,(byte)0x02,(byte)0x4D,(byte)0x04, // Path for EF(CDF)
			    		(byte)0xA7,(byte)0x06,(byte)0x30,(byte)0x04,(byte)0x04,(byte)0x02,(byte)0x4D,(byte)0x05, // Path for EF(DODF)
			    		(byte)0xA8,(byte)0x06,(byte)0x30,(byte)0x04,(byte)0x04,(byte)0x02,(byte)0x4D,(byte)0x06, // Path for EF(AODF)
			    				    					
			    };
			    
			    
			    // EF(TokenInfo) context
			    byte[] efTokenInfoContent = new byte[] {
			    	    (byte)0x30,(byte)0x15,  //SEQUENCE   
			    	    					(byte)0x02,(byte)0x01, //INTEGER -version V1(0)
			    	    										 (byte)0x00,
			    	    										 
			    	    					(byte)0x04,(byte)0x0C, //OctetString - serialNumber
			    	    										 (byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x00,
			    	    										 (byte)0x63,(byte)0x50,(byte)0x4B,(byte)0x43,
			    	    										 (byte)0x53,(byte)0x2D,(byte)0x31,(byte)0x35,
			    	    					
			    	    					(byte)0x03,(byte)0x02, //BitString - TokenFlags
			    	    										 (byte)0x04,(byte)0x00  
		        };
			    
			    
			    //Create ODF file
			    fs.createFile((short)FileSystem.ODF_FID, (short)efODFContent.length, FileSystem.PERM_FREE);
			    fs.selectEntryAbsolute((short)FileSystem.ODF_FID);
		
		        // Copy EF(ODF) content to file in the filesystem
			    byte[] efODF = fs.getFile(fs.getCurrentIndex());			    
			    Util.arrayCopy(efODFContent, (short)0, efODF, (short)0, (short) efODFContent.length);
			    efODFContent = null;
			    
			    //Create TokenInfo file
			    fs.createFile((short)FileSystem.TokenInfo_FID,(short)efTokenInfoContent.length,FileSystem.PERM_FREE);
			    fs.selectEntryAbsolute((short)FileSystem.TokenInfo_FID); 
			   
			    //Copy EF(TokenInfo) content to file in the filesystem
			    byte[] efTokenInfo = fs.getFile(fs.getCurrentIndex());
			    Util.arrayCopy(efTokenInfoContent,(short)0, efTokenInfo, (short)0,(short)efTokenInfoContent.length);
			    efTokenInfoContent=null;
			    
			    //Create PrKDF file
			    fs.createFileObject((short)FileSystem.PrKDF_FID,applet.privKeyDirFile, FileSystem.PERM_FREE);
			    
			    //Create PuKDF file
			    fs.createFileObject((short)FileSystem.PuKDF_FID,applet.pubKeyDirFile,FileSystem.PERM_FREE);
			     
			    //Create SKDF file
			    fs.createFileObject((short)FileSystem.SKDF_FID,applet.secKeyDirFile, FileSystem.PERM_FREE);
			    
			    //Create CDF file
			    fs.createFileObject((short)FileSystem.CDF_FID,applet.certDirFile,FileSystem.PERM_FREE);
			    
			    //Create DODF file
			    fs.createFile((short)FileSystem.DODF_FID,(short)0, FileSystem.PERM_FREE);
			    
			    //Create AODF file
			    fs.createFileObject((short)FileSystem.AODF_FID,applet.authObjDirFile ,FileSystem.PERM_FREE);
			   
			    
			   			    
			    //Add owner's authentication object to directory file
			    byte[] id = idProvider.getUniqueID();
			    applet.ownerPinAuthId = id;
			    
			    Utf8String label = new Utf8String(new byte[]{ // "Owner PIN"
			    						(byte)0x4f,(byte)0x77,(byte)0x6e,(byte)0x65,
			    						(byte)0x72,(byte)0x20,(byte)0x50,(byte)0x49,
			    						(byte)0x4e},(short)0,(short)9);	
			    
			    CommonObjectFlags cof = new CommonObjectFlags(true, true);
			    OctetString authId = new OctetString(id,(short)0,(short)id.length);
			    CommonObjectAttributes coa = new CommonObjectAttributes(label,cof,authId);
			    
			    CommonAuthenticationObjectAttributes caoa = new CommonAuthenticationObjectAttributes(authId);
			    PinFlags pinFlags = new PinFlags(false, false, false, false, true, false, false, false, false, false, false, false);
			    PinType pinType = new PinType(PinType.TYPE_ASCII_NUMERIC);
			    Integer minMaxStored = new Integer((short)4);
			    Integer ref = new Integer((short)0);
			    PinAttributes pa = new PinAttributes(pinFlags, pinType, minMaxStored, minMaxStored, minMaxStored, ref);
			    AuthenticationObject ownerAO = new AuthenticationObject(coa, caoa, pa);
			    applet.authObjDirFile.addRecord(ownerAO);
			   
			   
			   // Add SO's authentication object to directory file
			    id = idProvider.getUniqueID();
			    label = new Utf8String(new byte[]{ // "SO PIN"
			    					(byte)0x53,(byte)0x4f,(byte)0x20,(byte)0x50,
						            (byte)0x49,(byte)0x4e,},(short)0,(short)6);	
			    authId = new OctetString(id,(short)0,(short)id.length);
			    coa = new CommonObjectAttributes(label,cof,authId);
			    caoa = new CommonAuthenticationObjectAttributes(authId);
			    pinFlags = new PinFlags(false, false, false, false, true, false, false, true, false, false, false, false);
			    ref = new Integer((short)1);
			    pa = new PinAttributes(pinFlags, pinType, minMaxStored, minMaxStored, minMaxStored, ref);
			    AuthenticationObject soAo = new AuthenticationObject(coa, caoa, pa);
			    applet.authObjDirFile.addRecord(soAo);
			    
			    
			    
			    
			    if (JCSystem.isObjectDeletionSupported())
			    	  JCSystem.requestObjectDeletion();

		
	     	}
		catch (Exception e)
				{
				  ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
				}
		
		PKCS15Applet.setSetupDone(true);

	}
}
