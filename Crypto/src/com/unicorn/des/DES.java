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

	/**
	 * {@link DES}加密
	 * 
	 * @param encryptString
	 *            要加密的字符串
	 * @param encryptKey
	 *            必须长度为8 加密密钥
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encryptDES(String encryptString, String encryptKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeySpecException {
		// 实例化IvParameterSpec对象，使用指定的初始化向量
		IvParameterSpec zeroIv = new IvParameterSpec(iv);
		// 实例化SecretKeySpec类，根据字节数组来构造SecretKey
		SecretKeySpec key = new SecretKeySpec(encryptKey.getBytes(), "DES");

		// 创建密码器
		Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		// 用密匙初始化Cipher对象
		cipher.init(Cipher.ENCRYPT_MODE, key, zeroIv);

		// 执行des加密操作
		byte[] encryptedData = cipher.doFinal(encryptString.getBytes());
		// Base64.encode(encryptedData);

		// base64加密后返回
		return new BASE64Encoder().encode(encryptedData);
	}

	/**
	 * {@link DES}解密
	 * 
	 * @param decryptString
	 * @param decryptKey 长度不小于8，否则会抛{@link InvalidKeyException}
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String decryptDES(String decryptString, String decryptKey) throws IOException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// 实例化IvParameterSpec对象，使用指定的初始化向量
		IvParameterSpec zeroIv = new IvParameterSpec(iv);
		// 实例化SecretKeySpec类，根据字节数组来构造SecretKey
		SecretKeySpec key = new SecretKeySpec(decryptKey.getBytes(), "DES");
		// 创建密码器
		Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		// 用密匙初始化Cipher对象
		cipher.init(Cipher.DECRYPT_MODE, key, zeroIv);

		// 用Base64解密
		byte[] byteMi = new BASE64Decoder().decodeBuffer(decryptString);

		// 执行des解密操作
		byte[] encryptedData = cipher.doFinal(byteMi);

		return new String(encryptedData);
	}

	public static String encryptDES2(String encryptString, String encryptKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeySpecException {
		// 实例化IvParameterSpec对象，使用指定的初始化向量
		IvParameterSpec zeroIv = new IvParameterSpec(iv);
		// 实例化SecretKeySpec类，根据字节数组来构造SecretKey
		DESKeySpec key = new DESKeySpec(encryptKey.getBytes());
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

	public static String decryptDES2(String decryptString, String decryptKey) throws IOException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeySpecException {
		// 实例化IvParameterSpec对象，使用指定的初始化向量
		IvParameterSpec zeroIv = new IvParameterSpec(iv);
		// 实例化SecretKeySpec类，根据字节数组来构造SecretKey
		DESKeySpec key = new DESKeySpec(decryptKey.getBytes());
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey secretKey = keyFactory.generateSecret(key);
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
