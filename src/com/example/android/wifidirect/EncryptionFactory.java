package com.example.android.wifidirect;

import javax.crypto.spec.*;
import javax.crypto.*;
import java.io.*;

public class EncryptionFactory 
{
	public PBEKeySpec pbeKeySpec;
	public PBEParameterSpec pbeParamSpec;
	public SecretKeyFactory keyFac;
	public byte[] salt = {
		(byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c, (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
	};
	public int iterationCount = 10;
	public SecretKey pbeKey;
	public Cipher pbeEncryptCipher;

	public EncryptionFactory(String password) {
	try {
		pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
		pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
		
		keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		pbeKey = keyFac.generateSecret(pbeKeySpec);
		
		pbeEncryptCipher = Cipher.getInstance("PBEWithMD5AndDES");
		
		pbeEncryptCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
	} catch(Exception e) {
		System.out.println(e.getMessage());
		System.out.println(e.toString());
	}
	}

	public InputStream encrypt(InputStream is) throws Exception {
		byte[] bytes = makeByteArray(is);
		bytes = pbeEncryptCipher.doFinal(bytes);
		return new ByteArrayInputStream(bytes);
	}
	
	public InputStream decrypt(InputStream is) throws Exception {
		Cipher pbeDecryptCipher = Cipher.getInstance("PBEWithMD5AndDES");
		pbeDecryptCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
		byte[] bytes = makeByteArray(is);
		bytes = pbeDecryptCipher.doFinal(bytes); 
		return new ByteArrayInputStream(bytes);
	}
	
	public static byte[] makeByteArray(InputStream input) throws IOException
	{
	    byte[] buffer = new byte[8192];
	    int bytesRead;
	    ByteArrayOutputStream output = new ByteArrayOutputStream();
	    while ((bytesRead = input.read(buffer)) != -1)
	    {
	        output.write(buffer, 0, bytesRead);
	    }
	    return output.toByteArray();
	}
}