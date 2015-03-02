package com.pkcs15.applet;

import javacard.framework.Util;

/**
 * This class represents a ASN1 structure of Name as defined in InformationFramework
 * @author Lupascu Alexandru
 *
 */
public class Name extends ASN1Type{
	
	/*DER TAG for SEQUENCE*/
	public final byte TAG = (byte) 0x30;

	/*Attribute types defined in RFC5280 - Internet X.509 Public Key Infrastructure Certificate
	 * and Certificate Revocation List (CRL) Profile */
	public final byte ATTRYBUTE_TYPE_CommonName_CN = (byte)0x03;
	public final byte ATTRYBUTE_TYPE_surname_SN = (byte)0x04;
	public final byte ATTRYBUTE_TYPE_countryName_C = (byte)0x06;
	public final byte ATTRYBUTE_TYPE_localityName_L = (byte)0x07;
	public final byte ATTRYBUTE_TYPE_stateOrProvinceName_S = (byte)0x08;
	public final byte ATTRYBUTE_TYPE_organizationName_O = (byte)0x0a;
	public final byte ATTRYBUTE_TYPE_organizationalUnitName_OU = (byte)0x0b;
	public final byte ATTRYBUTE_TYPE_title = (byte)0x0c;
	public final byte ATTRYBUTE_TYPE_name = (byte)0x29;
	public final byte ATTRYBUTE_TYPE_givenName_GN = (byte)0x2a;
	public final byte ATTRYBUTE_TYPE_initials = (byte)0x2b;
	public final byte ATTRYBUTE_TYPE_generationQualifier = (byte)0x2c;
	public final byte ATTRYBUTE_TYPE_dnQualifier = (byte)0x2e;
	
	/* id-at OBJECT IDENTIFIER as defined in RFC 2459*/
	public final byte[] id_at_OID = new byte[]{(byte)0x55,(byte)0x04};
	
	public byte[] commonName_CN = null;
	public byte[] surname_SN = null;
	public byte[] countryName_C = null;
	public byte[] localityName_L = null;
	public byte[] stateOrProvinceName_S = null;
	public byte[] organizationName_O = null;
	public byte[] organizationalUnitName_OU = null;
	public byte[] title = null;
	public byte[] name = null;
	public byte[] givenName_GN = null;
	public byte[] initials = null;
	public byte[] generationQualifier = null;
	public byte[] dnQualifier = null;
	
	
	
	public byte[] encoding =null;
	byte[] lengthEncoded = null;
	
	/*Implicit constructor*/
	public Name(){
		
	}
	
	
	/**
	 * Constructor 
	 * @param _commonName_CN Common Name (CN)
	 * @param _surname_SN Surname (SN)
	 * @param _countryName_C Country Name (C)
	 * @param _localityName_L Locality Name(L)
	 * @param _stateOrProvinceName_S State or Province Name (S)
	 * @param _organizationName_O Organization Name (O)
	 * @param _organizationalUnitName_OU Organizational Unit Name (OU)
	 * @param _title Title
	 * @param _name Name
	 * @param _givenName_GN Given Name (GN)
	 * @param _initials Initials
	 * @param _generationQualifier Generation Qualifier
	 * @param _dnQualifier DN Qualifier
	 */
	public Name(byte[] _commonName_CN,byte[] _surname_SN,byte[] _countryName_C,
				byte[] _localityName_L,byte[] _stateOrProvinceName_S,
				byte[] _organizationName_O,byte[] _organizationalUnitName_OU,
				byte[] _title,byte[] _name,byte[] _givenName_GN,
				byte[] _initials,byte[] _generationQualifier,
				byte[] _dnQualifier) {
		
		commonName_CN = _commonName_CN;
		surname_SN = _surname_SN;
		countryName_C = _countryName_C;
		localityName_L = _localityName_L;
		stateOrProvinceName_S = _stateOrProvinceName_S;
		organizationName_O = _organizationName_O;
		organizationalUnitName_OU = _organizationalUnitName_OU;
		title = _title;
		name = _name;
		givenName_GN = _givenName_GN;
		initials = _initials;
		generationQualifier = _generationQualifier;
		dnQualifier = _dnQualifier;
	}
	
	
	
	/**
	 * This method encodes a ASN1 structure of Name as defined in InformationFramework
	 *  The members must have been previously set.
	 *  @return byte array which contains the encoding. If no member was set, null is returned.
	 */
	public byte[] encode() {
		encoding = null;
				
		if (((commonName_CN == null) && (surname_SN == null ) &&  (countryName_C == null) &&
			 (localityName_L ==null) &&	(stateOrProvinceName_S == null) && (organizationName_O == null) &&
			 (organizationalUnitName_OU ==null) && (title == null) && (name == null) &&
			 (givenName_GN == null) && (initials == null) && (generationQualifier == null) &&
			 (dnQualifier==null)) == true)
					return null;
			 
		short totalLen = (short)0;
		
		
		byte[] CNEncoding = null;
		byte[] SNEncoding = null;
		byte[] CEncoding = null;
		byte[] LEncoding  = null;
		byte[] SEncoding  =null;
		byte[] OEncoding = null;
		byte[] OUEncoding = null;
		byte[] titleEncoding =null;
		byte[] nameEncoding = null;
		byte[] GNEncoding = null;
		byte[] initialsEncoding = null;
		byte[] genQualEncoding = null;
		byte[] dnQualEncoding = null;
		
		OctetString ostr = null;
		
		if (commonName_CN != null)
			   {
				ostr = new OctetString(commonName_CN, (short)0, (short)commonName_CN.length);
				CNEncoding = ostr.encode();
				totalLen += (short)CNEncoding.length+9;
			   }
		if (organizationalUnitName_OU != null)
				{
				ostr = new OctetString(organizationalUnitName_OU, (short)0,(short)organizationalUnitName_OU.length);
				OUEncoding = ostr.encode();
				totalLen += (short) OUEncoding.length+9;
				}
		
		if (organizationName_O != null)
				{
				ostr = new OctetString(organizationName_O,(short)0,(short)organizationName_O.length);
				OEncoding = ostr.encode();
				totalLen += (short) OEncoding.length+9;
				}
		
		if (localityName_L != null)
				{
				ostr = new OctetString(localityName_L,(short)0,(short)localityName_L.length);
				LEncoding = ostr.encode();
				totalLen += (short) LEncoding.length+9;
				}
		
		if (stateOrProvinceName_S != null)
			 	{
				ostr = new OctetString(stateOrProvinceName_S, (short)0,(short)stateOrProvinceName_S.length);
				SEncoding = ostr.encode();
				totalLen += (short) SEncoding.length+9;
			 	}
		
		if (countryName_C != null)
				{
				ostr = new OctetString(countryName_C,(short)0,(short)countryName_C.length);
				CEncoding = ostr.encode();
				totalLen += (short) CEncoding.length+9;
				}
		
		if (surname_SN != null)
				{
				ostr = new OctetString(surname_SN,(short)0,(short)surname_SN.length);
				SNEncoding = ostr.encode();
				totalLen += (short) SNEncoding.length+9;
				}
		
		if (givenName_GN != null)
				{
				ostr = new OctetString(givenName_GN,(short)0,(short)givenName_GN.length);
				GNEncoding = ostr.encode();
				totalLen += (short) GNEncoding.length+9;
				}
		
		if (initials != null)
				{
				ostr = new OctetString(initials,(short)0,(short)initials.length);
				initialsEncoding = ostr.encode();
				totalLen += (short) initialsEncoding.length+9;
				}
		
		if (title != null)
				{
				ostr = new OctetString(title,(short)0,(short)title.length);
				titleEncoding = ostr.encode();
				totalLen += (short) titleEncoding.length+9;
				}
		
		if (name  != null)
				{
				ostr = new OctetString(name,(short)0,(short)name.length);
				nameEncoding = ostr.encode();
				totalLen += (short) nameEncoding.length+9;
				}
		
		if (generationQualifier !=null)
				{
				ostr = new OctetString(generationQualifier,(short)0,(short)generationQualifier.length);
				genQualEncoding = ostr.encode();
				totalLen += (short) genQualEncoding.length+9;
				}
		
		if (dnQualifier != null)
				{
				ostr = new OctetString(dnQualifier,(short)0,(short)dnQualifier.length);
				dnQualEncoding = ostr.encode();
				totalLen += (short) dnQualEncoding.length+9;
				}
		
		lengthEncoded = encodeLength(totalLen);
		
		encoding = new byte[(short)(1 + lengthEncoded.length + totalLen)];
		
		encoding[0] = this.TAG;
		short offset = 1;
		
		Util.arrayCopy(lengthEncoded, (short)0, encoding, (short)offset,(short) lengthEncoded.length);
		offset += (short)lengthEncoded.length;
		
		if (CNEncoding != null)
		   {
			  encoding[offset++] = (byte)0x31; // SET TAG
			  encoding[offset++] = (byte) (CNEncoding.length+7);
			  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
			  encoding[offset++] = (byte) (CNEncoding.length+5);
			  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
			  encoding[offset++] = (byte) 0x03; 
			  encoding[offset++] = id_at_OID[0];
			  encoding[offset++] = id_at_OID[1];
			  encoding[offset++] = this.ATTRYBUTE_TYPE_CommonName_CN;
			  Util.arrayCopy(CNEncoding, (short)0, encoding,offset,(short)CNEncoding.length);
			  offset += (short) CNEncoding.length;
		   }
	   if (OUEncoding != null)
			{
		      encoding[offset++] = (byte)0x31; // SET TAG
			  encoding[offset++] = (byte) (OUEncoding.length+7);
			  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
			  encoding[offset++] = (byte) (OUEncoding.length+5);
			  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
			  encoding[offset++] = (byte) 0x03; 
			  encoding[offset++] = id_at_OID[0];
			  encoding[offset++] = id_at_OID[1];
			  encoding[offset++] = this.ATTRYBUTE_TYPE_organizationalUnitName_OU;
			  Util.arrayCopy(OUEncoding, (short)0, encoding,offset,(short)OUEncoding.length);
			  offset += (short) OUEncoding.length;
			}
	
	   if (OEncoding != null)
			{
		      encoding[offset++] = (byte)0x31; // SET TAG
			  encoding[offset++] = (byte) (OEncoding.length+7);
			  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
			  encoding[offset++] = (byte) (OEncoding.length+5);
			  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
			  encoding[offset++] = (byte) 0x03; 
			  encoding[offset++] = id_at_OID[0];
			  encoding[offset++] = id_at_OID[1];
			  encoding[offset++] = this.ATTRYBUTE_TYPE_organizationName_O;
			  Util.arrayCopy(OEncoding, (short)0, encoding,offset,(short)OEncoding.length);
			  offset += (short) OEncoding.length;
			}
	
	  if (LEncoding != null)
			{
		  encoding[offset++] = (byte)0x31; // SET TAG
		  encoding[offset++] = (byte) (LEncoding.length+7);
		  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
		  encoding[offset++] = (byte) (LEncoding.length+5);
		  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
		  encoding[offset++] = (byte) 0x03; 
		  encoding[offset++] = id_at_OID[0];
		  encoding[offset++] = id_at_OID[1];
		  encoding[offset++] = this.ATTRYBUTE_TYPE_localityName_L;
		  Util.arrayCopy(LEncoding, (short)0, encoding,offset,(short)LEncoding.length);
		  offset += (short) LEncoding.length;
			}
	
	 if (SEncoding != null)
		 	{
		 encoding[offset++] = (byte)0x31; // SET TAG
		  encoding[offset++] = (byte) (SEncoding.length+7);
		  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
		  encoding[offset++] = (byte) (SEncoding.length+5);
		  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
		  encoding[offset++] = (byte) 0x03; 
		  encoding[offset++] = id_at_OID[0];
		  encoding[offset++] = id_at_OID[1];
		  encoding[offset++] = this.ATTRYBUTE_TYPE_stateOrProvinceName_S;
		  Util.arrayCopy(SEncoding, (short)0, encoding,offset,(short)SEncoding.length);
		  offset += (short) SEncoding.length;
		 	}
	
	 if (CEncoding != null)
			{
		 encoding[offset++] = (byte)0x31; // SET TAG
		  encoding[offset++] = (byte) (CEncoding.length+7);
		  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
		  encoding[offset++] = (byte) (CEncoding.length+5);
		  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
		  encoding[offset++] = (byte) 0x03; 
		  encoding[offset++] = id_at_OID[0];
		  encoding[offset++] = id_at_OID[1];
		  encoding[offset++] = this.ATTRYBUTE_TYPE_countryName_C;
		  Util.arrayCopy(CEncoding, (short)0, encoding,offset,(short)CEncoding.length);
		  offset += (short) CEncoding.length;
			}
	
	if (SNEncoding != null)
			{
		encoding[offset++] = (byte)0x31; // SET TAG
		  encoding[offset++] = (byte) (SNEncoding.length+7);
		  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
		  encoding[offset++] = (byte) (SNEncoding.length+5);
		  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
		  encoding[offset++] = (byte) 0x03; 
		  encoding[offset++] = id_at_OID[0];
		  encoding[offset++] = id_at_OID[1];
		  encoding[offset++] = this.ATTRYBUTE_TYPE_surname_SN;
		  Util.arrayCopy(SNEncoding, (short)0, encoding,offset,(short)SNEncoding.length);
		  offset += (short) SNEncoding.length;
			}
	
	if (GNEncoding != null)
			{
		encoding[offset++] = (byte)0x31; // SET TAG
		  encoding[offset++] = (byte) (GNEncoding.length+7);
		  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
		  encoding[offset++] = (byte) (GNEncoding.length+5);
		  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
		  encoding[offset++] = (byte) 0x03; 
		  encoding[offset++] = id_at_OID[0];
		  encoding[offset++] = id_at_OID[1];
		  encoding[offset++] = this.ATTRYBUTE_TYPE_givenName_GN;
		  Util.arrayCopy(GNEncoding, (short)0, encoding,offset,(short)GNEncoding.length);
		  offset += (short) GNEncoding.length;
			}
	
	if (initialsEncoding != null)
			{
		  encoding[offset++] = (byte)0x31; // SET TAG
		  encoding[offset++] = (byte) (initialsEncoding.length+7);
		  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
		  encoding[offset++] = (byte) (initialsEncoding.length+5);
		  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
		  encoding[offset++] = (byte) 0x03; 
		  encoding[offset++] = id_at_OID[0];
		  encoding[offset++] = id_at_OID[1];
		  encoding[offset++] = this.ATTRYBUTE_TYPE_initials;
		  Util.arrayCopy(initialsEncoding, (short)0, encoding,offset,(short)initialsEncoding.length);
		  offset += (short) initialsEncoding.length;
			}
	
	if (titleEncoding != null)
			{
		encoding[offset++] = (byte)0x31; // SET TAG
		  encoding[offset++] = (byte) (titleEncoding.length+7);
		  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
		  encoding[offset++] = (byte) (titleEncoding.length+5);
		  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
		  encoding[offset++] = (byte) 0x03; 
		  encoding[offset++] = id_at_OID[0];
		  encoding[offset++] = id_at_OID[1];
		  encoding[offset++] = this.ATTRYBUTE_TYPE_title;
		  Util.arrayCopy(titleEncoding, (short)0, encoding,offset,(short)titleEncoding.length);
		  offset += (short) titleEncoding.length;
			}
	
	if (nameEncoding  != null)
			{
		encoding[offset++] = (byte)0x31; // SET TAG
		  encoding[offset++] = (byte) (nameEncoding.length+7);
		  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
		  encoding[offset++] = (byte) (nameEncoding.length+5);
		  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
		  encoding[offset++] = (byte) 0x03; 
		  encoding[offset++] = id_at_OID[0];
		  encoding[offset++] = id_at_OID[1];
		  encoding[offset++] = this.ATTRYBUTE_TYPE_name;
		  Util.arrayCopy(nameEncoding, (short)0, encoding,offset,(short)nameEncoding.length);
		  offset += (short) nameEncoding.length;
			}
	
	if (genQualEncoding !=null)
			{
		encoding[offset++] = (byte)0x31; // SET TAG
		  encoding[offset++] = (byte) (genQualEncoding.length+7);
		  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
		  encoding[offset++] = (byte) (genQualEncoding.length+5);
		  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
		  encoding[offset++] = (byte) 0x03; 
		  encoding[offset++] = id_at_OID[0];
		  encoding[offset++] = id_at_OID[1];
		  encoding[offset++] = this.ATTRYBUTE_TYPE_generationQualifier;
		  Util.arrayCopy(genQualEncoding, (short)0, encoding,offset,(short)genQualEncoding.length);
		  offset += (short) genQualEncoding.length;
			}
	
	if (dnQualEncoding != null)
			{
		encoding[offset++] = (byte)0x31; // SET TAG
		  encoding[offset++] = (byte) (dnQualEncoding.length+7);
		  encoding[offset++] = (byte) 0x30; //SEQUENCE TAG
		  encoding[offset++] = (byte) (dnQualEncoding.length+5);
		  encoding[offset++] = (byte) 0x06; // OBJECT ID TAG
		  encoding[offset++] = (byte) 0x03; 
		  encoding[offset++] = id_at_OID[0];
		  encoding[offset++] = id_at_OID[1];
		  encoding[offset++] = this.ATTRYBUTE_TYPE_dnQualifier;
		  Util.arrayCopy(dnQualEncoding, (short)0, encoding,offset,(short)dnQualEncoding.length);
		  offset += (short) dnQualEncoding.length;
			}
		
		
		return encoding;
	}

	
	/**
	 * This method decodes a Name structure.
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
  	 * This method decodes a Name encoding.
  	 * The encoding must have been previously set.
  	 * @return true if successful, and false if encoding was not set.
  	 */
  	public boolean decode(){
  		
  		if (encoding == null)
  			 return false;
  		

		 short offset =(short)( 1 + findLengthEncodedLength(encoding, (short)1));
		 
		 OctetString ostr = new OctetString();
		 
		 while (offset < encoding.length)
		 	{
			 	offset++;
			 	byte size = (byte)(encoding[offset++]-7);
			 	offset += (short) 6;
			 	byte type = encoding[offset++];
			 	if (type == this.ATTRYBUTE_TYPE_CommonName_CN)
			 			{
			 				ostr.decode(encoding, offset,(short)size);
			 				commonName_CN = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_countryName_C)
			 			{	
					 		ostr.decode(encoding, offset,(short)size);
			 				countryName_C = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_dnQualifier)
			 			{
					 		ostr.decode(encoding, offset,(short)size);
			 				dnQualifier = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_generationQualifier)
			 			{
					 		ostr.decode(encoding, offset,(short)size);
			 				generationQualifier = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_givenName_GN)
			 			{
					 		ostr.decode(encoding, offset,(short)size);
			 				givenName_GN = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_initials)
			 			{
					 		ostr.decode(encoding, offset,(short)size);
			 				initials = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_localityName_L)
			 			{
					 		ostr.decode(encoding, offset,(short)size);
			 				localityName_L = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_name)
			 			{
					 		ostr.decode(encoding, offset,(short)size);
			 				name  = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_organizationalUnitName_OU)
			 			{
					 		ostr.decode(encoding, offset,(short)size);
			 				organizationalUnitName_OU = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_organizationName_O)
			 			{
					 		ostr.decode(encoding, offset,(short)size);
			 				organizationName_O = ostr.val;
			 			}
			 	
			 	if (type == this.ATTRYBUTE_TYPE_stateOrProvinceName_S)
			 			{
			 				ostr.decode(encoding, offset,(short)size);
			 				stateOrProvinceName_S = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_surname_SN)
			 			{
			 				ostr.decode(encoding, offset,(short)size);
			 				surname_SN = ostr.val;
			 			}
			 	
			 	
			 	if (type == this.ATTRYBUTE_TYPE_title)
			 			{
			 				ostr.decode(encoding, offset,(short)size);
			 				title = ostr.val;
			 			}
			 	
			 	
			 	offset += (short)size;
		 	}
  		
  		return true;
  	}
	
}
