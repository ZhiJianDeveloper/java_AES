package com.zhijian.util;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.util.Base64Utils;

public class AES {
	private static String charset = "UTF-8";

	private static String encrypt_type = "AES/CBC/PKCS5Padding";

	/**
	 * 使用原始秘钥解密
	 * 
	 * @author yuanzc
	 * @time 2017-6-14
	 * @param content
	 * @return
	 * @throws Exception
	 */
	public static String dencryptDefault(String content) throws Exception {
		String ivp = PropertiesLoader.getProperty("Ivp");
		System.out.println(PropertiesLoader.getProperty("AscKey").length());
		String ascKey = PropertiesLoader.getProperty("AscKey");

		return dencrypt(content, ivp, ascKey);
	}

	/**
	 * 默认密钥加密
	 * 
	 * @author yuanzc
	 * @time 2017-6-14
	 * @param content
	 * @return
	 * @throws Exception
	 */
	public static String encryptDefault(String content) throws Exception {
		String ivp = PropertiesLoader.getProperty("Ivp");
		System.out.println(PropertiesLoader.getProperty("AscKey").length());
		String ascKey = PropertiesLoader.getProperty("AscKey");

		return encrypt(content, ivp, ascKey);
	}

	/**
	 * 使用自定义加密
	 * 
	 * @param content
	 * @param ivp
	 * @param ascKey
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String content, String ivp, String ascKey) throws Exception {
		if (ascKey == null) {
			throw new RuntimeException("ascKey不能为空");
		}
		// 判断Key是否为16位
		if (ascKey.length() != 16) {
			throw new RuntimeException("ascKey长度不是16位");
		}
		byte[] raw = ascKey.getBytes(charset);
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance(encrypt_type);// "算法/模式/补码方式"
		IvParameterSpec ips = new IvParameterSpec(ivp.getBytes(charset));// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ips);
		byte[] encrypted = cipher.doFinal(content.getBytes(charset));
		String encrypt_content = Base64Utils.encodeToString(encrypted);// 此处使用BASE64做转码功能，同时能起到2次加密的作用。
		encrypt_content = encrypt_content.replaceAll("\\r", "").replaceAll("\\n", "");
		return encrypt_content;
	}

	/**
	 * 使用自定义解密
	 * 
	 * @param content
	 * @param ivp
	 * @param ascKey
	 * @return
	 * @throws Exception
	 */
	public static String dencrypt(String content, String ivp, String ascKey) throws Exception {
		// 判断Key是否正确
		if (ascKey == null) {
			throw new RuntimeException("ascKey不能为空");
		}
		// 判断Key是否为16位
		if (ascKey.length() != 16) {
			throw new RuntimeException("ascKey长度不是16位");
		}
		byte[] raw = ascKey.getBytes(charset);
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance(encrypt_type);
		IvParameterSpec ips = new IvParameterSpec(ivp.getBytes(charset));
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ips);
		byte[] encrypted1 = Base64Utils.decodeFromString(content);// 先用base64解密
		byte[] original = cipher.doFinal(encrypted1);
		String originalString = new String(original, charset);
		return originalString;
	}

	public static String format(int n) {
		String str = Integer.toHexString(n);
		return str;
	}

}
