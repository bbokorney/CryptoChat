package com.example.android.wifidirect;

import javax.crypto.spec.*;
import javax.crypto.*;

public class EncryptionFactory {
	public PBEKeySpec pbeKeySpec;
	public PBEParameterSpec pbeParamSpec;
	public SecretKeyFactory keyFac;
	public byte[] salt = {
		(byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c, (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
	};
	public int iterationCount = 10;
	public SecretKey pbeKey;
	public Cipher pbeEncryptCipher;

	public EncryptionFactory(char[] password) {
	try {
		pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
		pbeKeySpec = new PBEKeySpec(password, salt, iterationCount);
		
		keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		pbeKey = keyFac.generateSecret(pbeKeySpec);
		
		pbeEncryptCipher = Cipher.getInstance("PBEWithMD5AndDES");
		
		pbeEncryptCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
	} catch(Exception e) {
		System.out.println(e.getMessage());
	}
	}

	public byte[] encrypt(byte[] cleartext) throws Exception {
		return pbeEncryptCipher.doFinal(cleartext);
	}
	
	public byte[] decrypt(byte[] ciphertext) throws Exception {
		Cipher pbeDecryptCipher = Cipher.getInstance("PBEWithMD5AndDES");
		pbeDecryptCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
		return pbeDecryptCipher.doFinal(ciphertext);
	}
}
