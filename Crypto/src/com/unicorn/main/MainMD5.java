package com.unicorn.main;

import java.security.NoSuchAlgorithmException;

import com.unicorn.crypto.MD5;

public class MainMD5 {

	public static void main(String[] args) {
		
		try {
			System.out.println(MD5.toMd5("Android"));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

}
