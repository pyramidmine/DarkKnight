package endec;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RsaTest {

	public static void main(String[] args) throws Exception {

		//
		// RSA 키 생성 및 암호화/복호화 테스트
		//
		
		// RSA 키 쌍 생성
		KeyPair keyPair = genRSAKeyPair();
		
		// 암호화 할 문자열
		String plainText = "배달 문화를 선도하는 오투오시스";
		System.out.println("Plain text: " + plainText);
		
		// 공개키로 암호화
		String encrypted = encrypt(plainText, keyPair.getPublic());
		System.out.println("Encrypted: " + encrypted);
		
		// 개인키로 복호화
		String decrypted = decrypt(encrypted, keyPair.getPrivate());
		System.out.println("Decrypted: " + decrypted);
		
		//
		// 공개키를 Base64 인코딩 해서 전달 및 복원
		//
		{
			// 공개키를 Base64 인코딩
			byte[] encodedBytes = keyPair.getPublic().getEncoded();
			String encoded = Base64.getEncoder().encodeToString(encodedBytes);
			System.out.println("Base64ed public key: " + encoded);
			
			// Base64 인코딩된 키를 복원
			byte[] decoded = Base64.getDecoder().decode(encoded);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey deliveredPublicKey = keyFactory.generatePublic(keySpec);
			
			// 복원된 공개키로 암호화
			String deliveredEncrypted = encrypt(plainText, deliveredPublicKey);
			System.out.println("Delivered encrypted: " + deliveredEncrypted);
			
			// 개인키로 복호화
			String deliveredDecrypted = decrypt(deliveredEncrypted, keyPair.getPrivate());
			System.out.println("Delivered decrypted: " + deliveredDecrypted);
		}
		
		//
		// 개인키를 Base64 인코딩 해서 전달 및 복원
		//
		{
			// 개인키를 Base64 인코딩
			byte[] encodedBytes = keyPair.getPrivate().getEncoded();
			String encoded = Base64.getEncoder().encodeToString(encodedBytes);
			System.out.println("Base64ed private key: " + encoded);
			
			// Base64 인코딩된 키를 복원
			byte[] decoded = Base64.getDecoder().decode(encoded);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey deliveredPrivateKey = keyFactory.generatePrivate(keySpec);
			
			// 공개키로 암호화
			String deliveredEncrypted = encrypt(plainText, keyPair.getPublic());
			System.out.println("Delivered encrypted: " + deliveredEncrypted);
			
			// 복원된 개인키로 복호화
			String deliveredDecrypted = decrypt(deliveredEncrypted, deliveredPrivateKey);
			System.out.println("Delivered decrypted: " + deliveredDecrypted);
		}
		
		//
		// 가짜 키로 시도
		//
		try
		{
			System.out.println("Try faking public key...");
			KeyPair fakeKeyPair = genRSAKeyPair();
			String fakeEncrypted = encrypt(plainText, fakeKeyPair.getPublic());
			String fakeDecrypted = decrypt(fakeEncrypted, keyPair.getPrivate());
			System.out.println("Fake decrypted: " + fakeDecrypted);		
		}
		catch (BadPaddingException ex)
		{
			System.out.println("BadPaddingException: " + ex.getMessage());
		}
		
		//
		// 엉뚱한 코드 전달
		//
		try
		{
			System.out.println("Try faking data...");
			String fakeEncrypted = Base64.getEncoder().encodeToString(plainText.getBytes(StandardCharsets.UTF_8));
			String fakeDecrypted = decrypt(fakeEncrypted, keyPair.getPrivate());
			System.out.println("Fake decrypted: " + fakeDecrypted);		
		}
		catch (BadPaddingException ex)
		{
			System.out.println("BadPaddingException: " + ex.getMessage());
		}
	}

	static KeyPair genRSAKeyPair() throws NoSuchAlgorithmException {
		SecureRandom sr = new SecureRandom();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024, sr);
		KeyPair keyPair = keyGen.genKeyPair();
		return keyPair;
	}
	
	static String encrypt(String plainText, PublicKey publicKey) throws
			BadPaddingException,
			IllegalBlockSizeException,
			InvalidKeyException,
			NoSuchAlgorithmException,
			NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
		String encoded = Base64.getEncoder().encodeToString(encrypted);
		return encoded;
	}
	
	static String decrypt(String encoded, PrivateKey privateKey) throws
			BadPaddingException,
			IllegalBlockSizeException,
			InvalidKeyException,
			NoSuchAlgorithmException,
			NoSuchPaddingException,
			UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("RSA");
		byte[] decoded = Base64.getDecoder().decode(encoded.getBytes(StandardCharsets.UTF_8));
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decrypted = cipher.doFinal(decoded);
		String plainText = new String(decrypted, "UTF-8");
		return plainText;
	}

}
