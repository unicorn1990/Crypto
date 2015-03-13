package com.unicorn.main;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Observable;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.unicorn.crypto.AES;

public class MainAES {
	static String key="xfxg!~#$&unicorn";
	static String text="ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
	
	public static void main(String[] args) {
		
		
		try {
			String encryptResult=AES.encrypt( key,text);
			String decryptResult=AES.decrypt( key,encryptResult);
			
			System.out.println("encryptResult:"+encryptResult+" length:"+encryptResult.length());
			System.out.println("decryptResult:"+decryptResult+" length:"+decryptResult.length());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}

}
