package com.unicorn.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES工具类
 * 
 * @author unicorn
 * @version @2015年3月11日上午10:13:56
 */
public class AES {

	private static final String HEX = "0123456789ABCDEF";

	/**
	 * AES加密
	 * @param seed 加密密钥
	 * @param cleartext 待加密内容
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static String encrypt(String seed,String cleartext) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		//对密钥进行编码
		byte[] rawKey=getRawKey(seed.getBytes());
		
		//加密数据
		byte[] result=encrypt(rawKey, cleartext.getBytes());
		
		//将十进制数转换为十六进制数
		return toHex(result);
	}
	
	
	/**
	 * AES解密
	 * @param seed 加密密钥
	 * @param encrypted 待解密内容
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 */
	public static String decrypt(String seed, String encrypted) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		// 对密钥进行编码
		byte[] rawKey = getRawKey(seed.getBytes());
		byte[] enc = toByte(encrypted);
		byte[] result = decrypt(rawKey, enc);
		return new String(result);
	}

	/**
	 * 对密钥进行编码
	 * 
	 * @param seed
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static byte[] getRawKey(byte[] seed) throws NoSuchAlgorithmException {
		// 获取密钥生成器
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(seed);

		// 生成128位的AES密码生成器
		kgen.init(128, sr);
		// 生成密匙
		SecretKey skey = kgen.generateKey();

		// 编码格式
		byte[] raw = skey.getEncoded();
		return raw;
	}

	/**
	 * 加密
	 * 
	 * @param raw
	 *            密钥字节
	 * @param clear
	 *            待加密字节
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private static byte[] encrypt(byte[] raw, byte[] clear) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {
		// 生成一组拓展密钥，并放入一个数组之中
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance("AES");

		// 用DECRYPT_MODE模式，用skeySpec密码组，生成AES解密方法
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

		// 得到 加密数据
		byte[] encrypted = cipher.doFinal(clear);
		
//		System.out.println("clear length:"+clear.length);
//		System.out.println("encrypted length:"+encrypted.length);
		return encrypted;
	}

	/**
	 * 解密
	 * 
	 * @param raw
	 *            密钥字节
	 * @param encrypted
	 *            已加密字节
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	private static byte[] decrypt(byte[] raw, byte[] encrypted) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {
		// 生成一组拓展密钥，并放入一个数组之中
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance("AES");

		// 用DECRYPT_MODE模式，用skeySpec密码组，生成AES解密方法
		cipher.init(Cipher.DECRYPT_MODE, skeySpec);

		// 得到解密数据
		byte[] decrypted = cipher.doFinal(encrypted);
		return decrypted;
	}

	/**
	 * 将十进制字符串转换为十六进制字符串
	 * 
	 * @param txt
	 * @return
	 */
	public static String toHex(String txt) {
		return toHex(txt.getBytes());
	}

	/**
	 * 将十六进制字符串转换为十进制字符串
	 * 
	 * @param hex
	 * @return
	 */
	public static String fromHex(String hex) {
		return new String(toByte(hex));
	}

	/**
	 * hexString转成byte[]
	 * 
	 * @param hexString
	 * @return
	 */
	public static byte[] toByte(String hexString) {
		int len = hexString.length() / 2;
		byte[] result = new byte[len];
		for (int i = 0; i < len; i++)
			result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2), 16).byteValue();
		return result;
	}

	/**
	 * byte[]转成16位String
	 * 
	 * @param buf
	 * @return
	 */
	public static String toHex(byte[] buf) {
		if (buf == null)
			return "";
		StringBuffer result = new StringBuffer(2 * buf.length);

		for (int i = 0; i < buf.length; i++) {
			appendHex(result, buf[i]);
		}
		return result.toString();
	}

	/**
	 * 将b转成两位String，放到sb中
	 * 
	 * @param sb
	 * @param b
	 */
	private static void appendHex(StringBuffer sb, byte b) {
		sb.append(HEX.charAt((b >> 4) & 0x0f)).append(HEX.charAt(b & 0x0f));
	}
}
