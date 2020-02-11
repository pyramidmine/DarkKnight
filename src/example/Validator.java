package example;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Validator {
	//
	// ���� ������
	//
	static final String SAMPLE_FILENAME = "sample.txt";
	static String SAMPLE_TEXT = "��� ��ȭ�� �����ϴ� �����÷���, (C) Manna Planet 2020";
	static byte[] SAMPLE_ENCODED_DATA = SAMPLE_TEXT.getBytes(StandardCharsets.UTF_8);

	//
	// HMAC
	//
	static final String HMAC_ALGORITHM_NAME = "HmacSHA256";
	static final int HMAC_KEY_SIZE = 64;
	static final String JAVA_HMAC_KEY_FILENAME = "java.hmac.key";
	static final String JAVA_HMAC_HASH_FILENAME = "java.hmac.hash";
	static final String CS_HMAC_KEY_FILENAME = "cs.hmac.key";
	
	//
	// AES
	//
	static final String AES_ALGORITHM_NAME = "AES/CBC/PKCS5Padding";
	static final int AES_KEY_SIZE = 32;
	static final int AES_IV_SIZE = 16;
	static final int AES_PASSWORD_SIZE = 32;
	static final int AES_SALT_SIZE = 32;
	static final int AES_ITERATION_COUNT = 1;
	static class AesFiles
	{
		public AesFiles(String language, String keyFile, String ivFile, String encryptedFile) {
			Language = language;
			KeyFile = keyFile;
			IvFile = ivFile;
			EncryptedFile = encryptedFile;
		}
		public String Language;
		public String KeyFile;
		public String IvFile;
		public String EncryptedFile;
	}
	static List<AesFiles> aesFiles = new ArrayList<AesFiles>();
	
	static final int BUFFER_SIZE = 1024;
	
	public static void main(String[] args) {
		prepareSampleData();
		prepareLanguageData();
//		testHMAC();
		testAES();
	}
	
	private static void prepareLanguageData() {
		// AES ���� �غ�
		aesFiles.add(new AesFiles("java", getKeyDirectory() + File.separator + "java.aes.key", getKeyDirectory() + File.separator + "java.aes.iv", getKeyDirectory() + File.separator + "java.aes.data"));
		aesFiles.add(new AesFiles("cs", getKeyDirectory() + File.separator + "cs.aes.key", getKeyDirectory() + File.separator + "cs.aes.iv", getKeyDirectory() + File.separator + "cs.aes.data"));
	}
	
	private static void prepareSampleData() {
		File sampleFile = new File(getKeyDirectory() + File.separator + SAMPLE_FILENAME);
		if (sampleFile.exists()) {
			// ���� ������ ������ �ε�
			SAMPLE_ENCODED_DATA = Base64.getDecoder().decode(readAllText(sampleFile));
			SAMPLE_TEXT = new String(SAMPLE_ENCODED_DATA, StandardCharsets.UTF_8);
		} else {
			// ���� ������ ������ �����ϰ� ����
			writeAllText(sampleFile, Base64.getEncoder().encodeToString(SAMPLE_ENCODED_DATA));
		}
	}

	private static void testHMAC() {
		byte[] keyData = new byte[HMAC_KEY_SIZE];

		// Ű ����
		File keyFile = new File(getKeyDirectory() + File.separator + JAVA_HMAC_KEY_FILENAME);
		if (keyFile.exists()) {
			// Ű ������ �����ϸ� Ű ���� �ε�
			keyData = Base64.getDecoder().decode(readAllText(keyFile));
		}
		else {
			// Ű ������ ������ Ű ���� �� ����
			try {
				KeyGenerator keyGen = KeyGenerator.getInstance(HMAC_ALGORITHM_NAME);
				keyGen.init(new SecureRandom());
				keyData = keyGen.generateKey().getEncoded();
				writeAllText(keyFile, Base64.getEncoder().encodeToString(keyData));
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
		
		// �ؽ�
		byte[] hashedData = null;
		try {
			SecretKeySpec key = new SecretKeySpec(keyData, HMAC_ALGORITHM_NAME);
			Mac mac = Mac.getInstance(HMAC_ALGORITHM_NAME);
			mac.init(key);
			hashedData = mac.doFinal(SAMPLE_ENCODED_DATA);
			
			File hashFile = new File(getKeyDirectory() + File.separator + JAVA_HMAC_HASH_FILENAME);
			writeAllText(hashFile, Base64.getEncoder().encodeToString(hashedData));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	
		// �ؽ� ����
		byte[] verifyingKeyData = Base64.getDecoder().decode(readAllText(keyFile));
		byte[] verifyingHashedData = null;
		try {
			SecretKeySpec key = new SecretKeySpec(verifyingKeyData, HMAC_ALGORITHM_NAME);
			Mac mac = Mac.getInstance(HMAC_ALGORITHM_NAME);
			mac.init(key);
			verifyingHashedData = mac.doFinal(SAMPLE_ENCODED_DATA);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		// ��� ���
		System.out.println("---------- Java HMAC ----------");
		System.out.println("Original Hash: " + Base64.getEncoder().encodeToString(hashedData));
		System.out.println("Verified Hash: " + Base64.getEncoder().encodeToString(verifyingHashedData));
		
		// �ٸ� ��� Ű ���� �о ����
		File otherKeyFile = new File(getKeyDirectory() + File.separator + CS_HMAC_KEY_FILENAME);
		if (otherKeyFile.exists()) {
			try {
				byte[] otherKeyData = Base64.getDecoder().decode(readAllText(otherKeyFile));
				SecretKeySpec key = new SecretKeySpec(otherKeyData, HMAC_ALGORITHM_NAME);
				Mac mac = Mac.getInstance(HMAC_ALGORITHM_NAME);
				mac.init(key);
				byte[] otherHashedData = mac.doFinal(SAMPLE_ENCODED_DATA);
				
				// ��� ���
				System.out.println("---------- Verify C# HMAC ----------");
				System.out.println("Original Hash: " + Base64.getEncoder().encodeToString(hashedData));
				System.out.println("Verified Hash: " + Base64.getEncoder().encodeToString(otherHashedData));
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
	}
	
	private static String getKeyDirectory() {
		return System.getProperty("user.dir");
	}

	/**
	 * ������ �о String Ÿ������ ����
	 */
	static String readAllText(File file) {
		String result = null;
		
		try (FileReader fr = new FileReader(file)) {
			StringBuilder sb = new StringBuilder(BUFFER_SIZE);
			try (BufferedReader br = new BufferedReader(fr)) {
				String line = null;
				while ((line = br.readLine()) != null) {
					sb.append(line);
				}
			}
			result = sb.toString();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		
		return result;
	}
	
	/**
	 * String�� ���Ͽ� ���
	 * @param file ����
	 * @param text �ؽ�Ʈ
	 */
	static void writeAllText(File file, String text) {
		try (FileWriter fw = new FileWriter(file)) {
			try (BufferedWriter bw = new BufferedWriter(fw)) {
				bw.write(text);
			}
		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}
	
	private static void testAES() {
		AesFiles files = aesFiles.get(0);
		
		byte[] keyData = null;
		File keyFile = new File(files.KeyFile);
		if (keyFile.exists()) {
			// Ű ������ �����ϸ� Ű ���� �ε�
			keyData = Base64.getDecoder().decode(readAllText(keyFile));
		} else {
			// Ű ������ ������ Ű ���� �� ����
			keyData = createAesKey(AES_KEY_SIZE);
			writeAllText(keyFile, Base64.getEncoder().encodeToString(keyData));
		}
		
		byte[] ivData = null;
		File ivFile = new File(files.IvFile);
		if (ivFile.exists()) {
			// IV ������ �����ϸ� IV ���� �ε�
			ivData = Base64.getDecoder().decode(readAllText(ivFile));
		} else {
			// IV ������ ������ IV ���� �� ���Ͽ� ����
			ivData = createAesKey(AES_IV_SIZE);
			writeAllText(ivFile, Base64.getEncoder().encodeToString(ivData));
		}
		
		// ��ȣȭ ��ü�� ������ �� ����� Ű�� IV ����
		SecretKeySpec key = new SecretKeySpec(keyData, "AES");
		AlgorithmParameterSpec iv = new IvParameterSpec(ivData);

		// ��ȣȭ ��ü ���� �� ��ȣȭ
		byte[] encryptedData = null;
		Cipher encryptor = null;
		try {
			encryptor = Cipher.getInstance(AES_ALGORITHM_NAME);	// PKCS5Padding in Java == PKCS7Padding in C#
			encryptor.init(Cipher.ENCRYPT_MODE, key, iv);
			encryptedData = encryptor.doFinal(SAMPLE_ENCODED_DATA);
			
			File encryptedFile = new File(files.EncryptedFile);
			writeAllText(encryptedFile, Base64.getEncoder().encodeToString(encryptedData));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		if (encryptedData == null) {
			return;
		}
		
		// ��ȣȭ ��ü ���� �� ��ȣȭ
		byte[] decryptedData = decryptAes(encryptedData, keyData, ivData);
		
		if (decryptedData == null) {
			return;
		}
		
		// ��� ���
		System.out.println("---------- Java AES ----------");
		System.out.println("Original Data:  " + Base64.getEncoder().encodeToString(SAMPLE_ENCODED_DATA));
		System.out.println("Decrypted Data: " + Base64.getEncoder().encodeToString(decryptedData));
		
		//
		// �ٸ� ���� ���� Ű�� IV�� �̿��ؼ� ��ȣȭ
		//
		for (int i = 1; i < aesFiles.size(); i++)
		{
			AesFiles otherFiles = aesFiles.get(i);
			
			File otherKeyFile = new File(otherFiles.KeyFile);
			File otherIvFile = new File(otherFiles.IvFile);
			File otherEncryptedFile = new File(otherFiles.EncryptedFile);
			
			if (!otherKeyFile.exists() || !otherIvFile.exists() || !otherEncryptedFile.exists()) {
				continue;
			}
			
			byte[] otherKeyData = Base64.getDecoder().decode(readAllText(otherKeyFile));
			byte[] otherIvData = Base64.getDecoder().decode(readAllText(otherIvFile));
			byte[] otherEncryptedData = Base64.getDecoder().decode(readAllText(otherEncryptedFile));
			byte[] otherDecryptedData = decryptAes(otherEncryptedData, otherKeyData, otherIvData);
			
			System.out.println("---------- AES, Language: " + otherFiles.Language + " ----------");
			System.out.println("Original Data:  " + Base64.getEncoder().encodeToString(SAMPLE_ENCODED_DATA));
			System.out.println("Decrypted Data: " + Base64.getEncoder().encodeToString(otherDecryptedData));
		}
	}
	
	/**
	 * AES Ű �Ǵ� IV ����
	 * @param size ������ Ű �Ǵ� IV ����� byte ������ ����
	 * @return ������ Ű �Ǵ� IV ������
	 */
	private static byte[] createAesKey(int size) {
		// Ű ������ �� ����� �н������ ��Ʈ�� �����ϰ� ����
		SecureRandom random = new SecureRandom();
		byte[] password = new byte[AES_PASSWORD_SIZE];
		byte[] salt = new byte[AES_SALT_SIZE];
		random.nextBytes(password);
		random.nextBytes(salt);

		byte[] result = null;
		
		// Ű ����
		try {
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			PBEKeySpec keySpec = new PBEKeySpec(Base64.getEncoder().encodeToString(password).toCharArray(), salt, AES_ITERATION_COUNT, size * 8);
			SecretKey key = keyFactory.generateSecret(keySpec);
			result = key.getEncoded();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return result;
	}
	
	private static byte[] decryptAes(byte[] data, byte[] keyData, byte[] ivData) {
		byte[] result = null;
		SecretKeySpec key = new SecretKeySpec(keyData, "AES");
		AlgorithmParameterSpec iv = new IvParameterSpec(ivData);
		try {
			Cipher decryptor = Cipher.getInstance(AES_ALGORITHM_NAME);
			decryptor.init(Cipher.DECRYPT_MODE, key, iv);
			result = decryptor.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return result;
	}
}
