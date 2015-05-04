package com.pkcs15.applet;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;




public class PKCS15Applet extends Applet {

	/*PKCS#15 applet AID*/
   public static final byte[] AID = new byte[]{(byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x63,
	   										   (byte)0x50,(byte)0x4B,(byte)0x43,(byte)0x53,(byte)0x2D,
	   										   (byte)0x31,(byte)0x35};
	
	/* Maximum pin codes */
	public static byte MAX_PIN_CODES = (byte)2;
	
	/* Minimum pin size*/
 	public static final byte MIN_PIN_SIZE = (byte) 4;
	
	/* Maximum pin size*/
	public static final byte MAX_PIN_SIZE = (byte) 4;
	
	/* Maximum failed PIN tries*/
	public static final byte MAX_PIN_TRIES = (byte) 3;
	
	/* Initial Owner's PIN value*/
	private static byte[] INITIAL_OWNER_PIN_VALUE  = {
	(byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, // ASCII: "0000"
	};
	
	public byte[] ownerPinAuthId = null;
	
	/* Authentication Object Directory File*/
	public AuthenticationObjectDirectoryFile authObjDirFile = null;
	
	/* Certificate Directory File*/
	public CertificateDirectoryFile certDirFile = null;
	
	/* Secret Key Directory File*/
	public SecretKeyDirectoryFile secKeyDirFile = null;
	
	/* Private Key Directory File*/
	public PrivateKeyDirectoryFile privKeyDirFile = null;
	
	/* Public Key Directory File*/
	public PublicKeyDirectoryFile pubKeyDirFile = null;
	
	
	/* Boolean value to check if setup has been done*/
	private static boolean setupDone;
	
	
	/* PIN codes.
	 *  pins[0] will be the owner's PIN 
     *  pins[1] will be the security officer's PIN */
	private OwnerPIN[] pins;
	
	/* applet's filesystem*/
	private FileSystem fileSystem = null;
	
	
	
	/**
	 * Applet's constructor.
	 * This method initialises applet's members.
	 */
	private PKCS15Applet() {
		
		authObjDirFile = new AuthenticationObjectDirectoryFile();
		certDirFile    = new CertificateDirectoryFile();
	    secKeyDirFile  = new SecretKeyDirectoryFile();
	    privKeyDirFile = new PrivateKeyDirectoryFile();
	    pubKeyDirFile  = new PublicKeyDirectoryFile();
		
		setupDone = false;
		
		fileSystem = null;
		
		pins = new OwnerPIN[MAX_PIN_CODES];
		
		//Owner's PIN
		pins[0] = new OwnerPIN(MAX_PIN_TRIES, MAX_PIN_SIZE);
		pins[0].update(INITIAL_OWNER_PIN_VALUE,(short)0, (byte) INITIAL_OWNER_PIN_VALUE.length);
		
		
		
	}
    
	
	
	/**
	 * This method installs the  PKCS15 applet
	 * @param bArray
	 * @param bOffset
	 * @param bLength
	 * @throws ISOException
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new PKCS15Applet().register();//AID,(short)0,(byte)AID.length);
		
	}
	
	
	
	/**
	 * This method is invoked when the applet is selected
	 */
	public boolean select(){
		
		short i;
		
		for (i=0;i<MAX_PIN_CODES;i++)
			   pins[0].reset();
		
		IODataManager.freeBuffer();
		
		return true;
	}

	
	/**
	 * This method is invoked when the applet is deselected
	 */
	public void deselect(){
		
		short i;
		
		for (i=0;i<MAX_PIN_CODES;i++)
			  pins[i].reset();
		
		IODataManager.freeBuffer();
	}
	
	
	
	
	/**
	 * This method is processing APDU commands
	 * @param apdu The APDU structure which contains the command
	 * @throws ISOException
	 */
	public void process(APDU apdu) throws ISOException {
		
		/*If the command is select applet, then no processing is made */
		if (this.selectingApplet())
	   			return;
	   			
     
		//dispatch APDU message
		APDUDispatcher.dispatch(this, apdu);
		
		
	}
	
	
	
	
	/**
	 * Getter for setupDone
	 * @return true if setup has been done, false otherwise
	 */
	public static boolean isSetupDone() {
		return setupDone;
	}


    /**
     * Setter for setupDone.
     * Once setupDone is set to true, no more set on setupDone is executed
     * @param done Boolean value
     */
	public static void setSetupDone(boolean done) {
		
		if (setupDone)
			  return;
		setupDone = done;
	}


    /**
     * Getter for PIN codes
     * @return the OwnerPIN array which contains the PIN codes
     */
	public OwnerPIN[] getPins() {
		return pins;
	}


    /**
     * Getter for FileSystem
     * @return the filesystem
     */
	public FileSystem getFileSystem() {
		return fileSystem;
	}


    /**
     * Setter for filesystem.
     * Only first set is valid.
     * @param fileSystem new filesistem 
     */
	public void setFileSystem(FileSystem fileSystem) {
		if (this.fileSystem != null)
			 return;
		this.fileSystem = fileSystem;
	}

    



	
}
