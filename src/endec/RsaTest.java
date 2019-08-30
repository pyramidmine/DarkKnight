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
		// RSA Ű ���� �� ��ȣȭ/��ȣȭ �׽�Ʈ
		//
		
		// RSA Ű �� ����
		KeyPair keyPair = genRSAKeyPair();
		
		// ��ȣȭ �� ���ڿ�
		String plainText = "��� ��ȭ�� �����ϴ� �������ý�";
		System.out.println("Plain text: " + plainText);
		
		// ����Ű�� ��ȣȭ
		String encrypted = encrypt(plainText, keyPair.getPublic());
		System.out.println("Encrypted: " + encrypted);
		
		// ����Ű�� ��ȣȭ
		String decrypted = decrypt(encrypted, keyPair.getPrivate());
		System.out.println("Decrypted: " + decrypted);
		
		//
		// ����Ű�� Base64 ���ڵ� �ؼ� ���� �� ����
		//
		{
			// ����Ű�� Base64 ���ڵ�
			byte[] encodedBytes = keyPair.getPublic().getEncoded();
			String encoded = Base64.getEncoder().encodeToString(encodedBytes);
			System.out.println("Base64ed public key: " + encoded);
			
			// Base64 ���ڵ��� Ű�� ����
			byte[] decoded = Base64.getDecoder().decode(encoded);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey deliveredPublicKey = keyFactory.generatePublic(keySpec);
			
			// ������ ����Ű�� ��ȣȭ
			String deliveredEncrypted = encrypt(plainText, deliveredPublicKey);
			System.out.println("Delivered encrypted: " + deliveredEncrypted);
			
			// ����Ű�� ��ȣȭ
			String deliveredDecrypted = decrypt(deliveredEncrypted, keyPair.getPrivate());
			System.out.println("Delivered decrypted: " + deliveredDecrypted);
		}
		
		//
		// ����Ű�� Base64 ���ڵ� �ؼ� ���� �� ����
		//
		{
			// ����Ű�� Base64 ���ڵ�
			byte[] encodedBytes = keyPair.getPrivate().getEncoded();
			String encoded = Base64.getEncoder().encodeToString(encodedBytes);
			System.out.println("Base64ed private key: " + encoded);
			
			// Base64 ���ڵ��� Ű�� ����
			byte[] decoded = Base64.getDecoder().decode(encoded);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey deliveredPrivateKey = keyFactory.generatePrivate(keySpec);
			
			// ����Ű�� ��ȣȭ
			String deliveredEncrypted = encrypt(plainText, keyPair.getPublic());
			System.out.println("Delivered encrypted: " + deliveredEncrypted);
			
			// ������ ����Ű�� ��ȣȭ
			String deliveredDecrypted = decrypt(deliveredEncrypted, deliveredPrivateKey);
			System.out.println("Delivered decrypted: " + deliveredDecrypted);
		}
		
		//
		// ��¥ Ű�� �õ�
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
		// ������ �ڵ� ����
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
