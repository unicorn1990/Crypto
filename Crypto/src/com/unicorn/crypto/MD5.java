package com.unicorn.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD5工具类
 * @author unicorn
 * @version @2015年3月13日下午4:55:01
 */
public class MD5 {

	/**
	 * to{@link MD5}
	 * @param text
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	public static String toMd5(String text) throws NoSuchAlgorithmException
	{
		return toMd5(text.getBytes());
	}
	
	
	/**
	 * MD5加密
	 * @param bytes
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	
	
	private static String toMd5(byte[] bytes) throws NoSuchAlgorithmException
	{
		
		//实例化一个指定摘要算法为MD5的MessageDigest对象
		MessageDigest algorithm=MessageDigest.getInstance("MD5");
		
		//重置摘要以供再次使用
		algorithm.reset();
		//使用bytes 更新摘要
		algorithm.update(bytes);
		
		//使用指定的byte数组对摘要进行最后更新，然后完成摘要计算
		
		return toHexString(algorithm.digest(),"");
		
		
	}

	/**
	 * 将字符串中的每个字符转换为十六进制
	 * @param digest 加密比特
	 * @param separator 分隔符
	 * @return
	 */
	private static String toHexString(byte[] digest, String separator) {
		StringBuffer hexString=new StringBuffer();
		for(byte b:digest)
		{
			String hex=Integer.toHexString(0xff&b);
			if(hex.length()==1)
			{
				hexString.append("0");
			}
			hexString.append(hex).append(separator);
			
		}
		return hexString.toString();
	}
	
	
}
