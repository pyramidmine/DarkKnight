package endec;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import common.Statistics;

public class Aes256 {
	
	static final int SESSION_DATA_SIZE = 512;
	
	public static void main(String[] args) {
		String sessionData = "edward;2019-09-03T13:00:00;2019-09-03T13:35:27;Mobile;O2OSYS";
		System.out.println("Session data: " + sessionData);
		SecretKey key = generateKey();
		try {
			byte[] encoded = sessionData.getBytes(StandardCharsets.UTF_8);
			byte[] encrypted = encrypt(encoded, key);
			byte[] decrypted = decrypt(encrypted, key);

			if (Arrays.equals(encoded, decrypted)) {
				System.out.println("Encrypt / decrypt succeeded.");
			}
			else {
				System.out.println("Encrypt / decrypt failed.");
			}
		}
		catch (Exception ex) {
			System.out.println("main failed: " + ex.getMessage());
		}
		
		//
		// 성능테스트
		//
		System.out.println("--- Performance test ---");
		loopTest(key, 1000);
		loopTest(key, 10000);
		loopTest(key, 50000);
		loopTest(key, 100000);
	}
	
	static void loopTest(SecretKey key, int testCount) {
		Statistics stat = new Statistics();
		byte[] sample = new byte[512];
		Random random = new Random();
		for (int i = 0; i < testCount; i++) {
			try {
				random.nextBytes(sample);
				long timeBegin = System.nanoTime();
				byte[] encrypted = encrypt(sample, key);
				long timeEncrypt = System.nanoTime();
				byte[] decrypted = decrypt(encrypted, key);
				long timeDecrypt = System.nanoTime();
				
				if (!Arrays.equals(sample, decrypted)) {
					System.out.println("Text mismatch!");
					break;
				}
				
				stat.encryptCount++;
				stat.encryptLength = encrypted.length;
				stat.encryptTime += (timeEncrypt - timeBegin);
				stat.encodeCount++;
				stat.encodeLength = decrypted.length;
				stat.encodeTime += (timeDecrypt - timeEncrypt);
			}
			catch (Exception ex) {
				System.out.println("Performance test failed: " + ex.getMessage());
				break;
			}
		}
		
		System.out.printf("Encrypt{EC:%d, EL:%d, Ave.ET:%.6fms}, Decrypt{EC:%d, EL:%d, Ave.ET:%.6fms}%n",
				stat.encryptCount,
				stat.encryptLength,
				stat.encryptTime / Math.max(1, stat.encryptCount) / 1000000.0,
				stat.encodeCount,
				stat.encodeLength,
				stat.encodeTime / Math.max(1, stat.encodeCount) / 1000000.0);
	}
	
	static SecretKey generateKey() {
		SecureRandom random = new SecureRandom();
		byte[] randomData = new byte[32];
		random.nextBytes(randomData);
		SecretKey secretKey = new SecretKeySpec(randomData, "AES");
		return secretKey;
	}
	
	static byte[] encrypt(byte[] message, SecretKey key) throws
			BadPaddingException,
			IllegalBlockSizeException,
			InvalidKeyException,
			NoSuchAlgorithmException,
			NoSuchPaddingException {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encrypted = cipher.doFinal(message);
			return encrypted;
		}
		catch (Exception ex) {
			System.out.println("encrypt() failed: " + ex.getMessage());
			return null;
		}
	}
	
	static byte[] decrypt(byte[] encrypted, SecretKey key) throws
			BadPaddingException,
			IllegalBlockSizeException,
			InvalidKeyException,
			NoSuchAlgorithmException,
			NoSuchPaddingException {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] decrypted = cipher.doFinal(encrypted);
			return decrypted;
		}
		catch (Exception ex) {
			System.out.println("decrypt() failed: " + ex.getMessage());
			return null;
		}
	}
}
