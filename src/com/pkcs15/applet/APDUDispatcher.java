package com.pkcs15.applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;


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
	
	/* Proprietary status words*/
	//public static final short SW_OUT_OF_RAM = (short)0x5100;
	
	
	
	/*PKCS15Applet CLA*/
	public static final byte PKCS15Applet_CLA                  = (byte)0x00;
	public static final byte PKCS15Applet_CLA_COMMAND_CHAINING = (byte) 0x10;
	
	/* ISO7816 instructions bytes*/
	public static final byte INS_VERIFY       = (byte) 0x20;
	public static final byte INS_GET_RESPONSE = (byte) 0xC0;
	
	
	/* Proprietary instructions bytes*/
	public static final byte INS_TRANSFER_DATA_PUT   = (byte) 0x02;
	public static final byte INS_TRANSFER_DATA_GET   = (byte) 0x04;
	public static final byte INS_SETUP				 = (byte) 0x06;
	public static final byte INS_GET_RANDOM_DATA     = (byte) 0x07;
	public static final byte INS_GENERATE_SECRET_KEY = (byte) 0x08;
	public static final byte INS_GENERATE_KEY_PAIR   = (byte) 0x09;
	

	private static final byte INS_DEBUG = (byte)0xFF;
	private static final byte INS_GET_MEMORY =(byte) 0xFE;
	
	
	private static UniqueIDProvider idProvider = null;
	
	private static RandomData randomGenerator = null;
	
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
												    
												     
												    data = applet.pubKeyDirFile.getFile();
												     
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