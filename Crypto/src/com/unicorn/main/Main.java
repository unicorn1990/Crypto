package com.unicorn.main;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.unicorn.des.DES;

public class Main {

	static String key="12345678";
	
	static String text="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	
	
	public static void main(String[] args) {
		
		
		try {
			String encryptResult=DES.encryptDES(text, key);
			String decryptResult=DES.decryptDES(encryptResult, key);
			
			System.out.println("encryptResult:"+encryptResult);
			System.out.println("decryptResult:"+decryptResult);
			
			
			String encryptResult2=DES.encryptDES2(text, key);
			String decryptResult2=DES.decryptDES2(encryptResult2, key);
			
			System.out.println("encryptResult2:"+encryptResult2);
			System.out.println("decryptResult2:"+decryptResult2);
			
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}