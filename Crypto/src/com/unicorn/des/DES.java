package com.unicorn.des;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class DES {

	// 初始化向量，必须八位
	private static byte[] iv = { 1, 2, 3, 4, 5, 6, 7, 8 };

	public static String encryptDES(String encryptString, String encryptKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeySpecException {
		// 实例化IvParameterSpec对象，使用指定的初始化向量
		IvParameterSpec zeroIv = new IvParameterSpec(iv);
		// 实例化DESKeySpec类，根据字节数组来构造DESKeySpec
		DESKeySpec key = new DESKeySpec(encryptKey.getBytes());
		// 用密匙工厂获取DES密匙工厂实例，并根据keySpec生成secretKey
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey secretKey = keyFactory.generateSecret(key);

		// 创建密码器
		Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		// 用密匙初始化Cipher对象
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, zeroIv);

		// 执行des加密操作
		byte[] encryptedData = cipher.doFinal(encryptString.getBytes());
		// Base64.encode(encryptedData);

		// base64加密后返回
		return new BASE64Encoder().encode(encryptedData);
	}

	public static String decryptDES(String decryptString, String decryptKey) throws IOException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeySpecException {
		// 实例化IvParameterSpec对象，使用指定的初始化向量
		IvParameterSpec zeroIv = new IvParameterSpec(iv);
		// 实例化DESKeySpec类，根据字节数组来构造DESKeySpec
		DESKeySpec keySpec = new DESKeySpec(decryptKey.getBytes());
		// 用密匙工厂获取DES密匙工厂实例，并根据keySpec生成secretKey
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey secretKey = keyFactory.generateSecret(keySpec);
		// 创建密码器
		Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		// 用密匙初始化Cipher对象
		cipher.init(Cipher.DECRYPT_MODE, secretKey, zeroIv);

		// 用Base64解密
		byte[] byteMi = new BASE64Decoder().decodeBuffer(decryptString);

		// 执行des解密操作
		byte[] encryptedData = cipher.doFinal(byteMi);

		return new String(encryptedData);
	}
}
