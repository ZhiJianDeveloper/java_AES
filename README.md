# java_AES
java AES加密解密示例代码

package com.zhijian.util;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.util.Base64Utils;

public class AES {
	private static String charset = "UTF-8";

	private static String encrypt_type = "AES/CBC/PKCS5Padding";

	/**
	 *  π”√‘≠ º√ÿ‘øΩ‚√‹
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
	 * ƒ¨»œ√‹‘øº”√‹
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
	 *  π”√◊‘∂®“Âº”√‹
	 * 
	 * @param content
	 * @param ivp
	 * @param ascKey
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String content, String ivp, String ascKey) throws Exception {
		if (ascKey == null) {
			throw new RuntimeException("ascKey≤ªƒ‹Œ™ø’");
		}
		// ≈–∂œKey «∑ÒŒ™16Œª
		if (ascKey.length() != 16) {
			throw new RuntimeException("ascKey≥§∂»≤ª «16Œª");
		}
		byte[] raw = ascKey.getBytes(charset);
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance(encrypt_type);// "À„∑®/ƒ£ Ω/≤π¬Î∑Ω Ω"
		IvParameterSpec ips = new IvParameterSpec(ivp.getBytes(charset));//  π”√CBCƒ£ Ω£¨–Ë“™“ª∏ˆœÚ¡øiv£¨ø…‘ˆº”º”√‹À„∑®µƒ«ø∂»
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ips);
		byte[] encrypted = cipher.doFinal(content.getBytes(charset));
		String encrypt_content = Base64Utils.encodeToString(encrypted);// ¥À¥¶ π”√BASE64◊ˆ◊™¬Îπ¶ƒ‹£¨Õ¨ ±ƒ‹∆µΩ2¥Œº”√‹µƒ◊˜”√°£
		encrypt_content = encrypt_content.replaceAll("\\r", "").replaceAll("\\n", "");
		return encrypt_content;
	}

	/**
	 *  π”√◊‘∂®“ÂΩ‚√‹
	 * 
	 * @param content
	 * @param ivp
	 * @param ascKey
	 * @return
	 * @throws Exception
	 */
	public static String dencrypt(String content, String ivp, String ascKey) throws Exception {
		// ≈–∂œKey «∑Ò’˝»∑
		if (ascKey == null) {
			throw new RuntimeException("ascKey≤ªƒ‹Œ™ø’");
		}
		// ≈–∂œKey «∑ÒŒ™16Œª
		if (ascKey.length() != 16) {
			throw new RuntimeException("ascKey≥§∂»≤ª «16Œª");
		}
		byte[] raw = ascKey.getBytes(charset);
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance(encrypt_type);
		IvParameterSpec ips = new IvParameterSpec(ivp.getBytes(charset));
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ips);
		byte[] encrypted1 = Base64Utils.decodeFromString(content);// œ»”√base64Ω‚√‹
		byte[] original = cipher.doFinal(encrypted1);
		String originalString = new String(original, charset);
		return originalString;
	}

	public static String format(int n) {
		String str = Integer.toHexString(n);
		return str;
	}

}

