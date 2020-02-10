package example;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Validator {
	//
	// 샘플 데이터
	//
	static final String SAMPLE_TEXT = "배달 문화를 선도하는 만나플러스, (C) Manna Planet 2020";
	static final byte[] SAMPLE_ENCODED_DATA = SAMPLE_TEXT.getBytes(StandardCharsets.UTF_8);

	//
	// HMAC
	//
	static final String HMAC_ALGORITHM_NAME = "HmacSHA256";
	static final int HMAC_KEY_SIZE = 64;
	static final String JAVA_HMAC_KEY_FILENAME = "java.hmac.key";
	static final String JAVA_HMAC_HASH_FILENAME = "java.hmac.hash";
	static final String CS_HMAC_KEY_FILENAME = "cs.hmac.key";
	
	static final int BUFFER_SIZE = 1024;
	
	public static void main(String[] args) {
		testHMAC();
		

	}

	private static void testHMAC() {
		byte[] keyData = new byte[HMAC_KEY_SIZE];

		// 키 파일
		File keyFile = new File(getKeyDirectory() + File.separator + JAVA_HMAC_KEY_FILENAME);
		if (keyFile.exists()) {
			// 키 파일이 존재하면 키 파일 로드
			keyData = Base64.getDecoder().decode(readAllText(keyFile));
		}
		else {
			// 키 파일이 없으면 키 생성 및 저장
			try {
				KeyGenerator keyGen = KeyGenerator.getInstance(HMAC_ALGORITHM_NAME);
				keyGen.init(new SecureRandom());
				keyData = keyGen.generateKey().getEncoded();
				writeAllText(keyFile, Base64.getEncoder().encodeToString(keyData));
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
		
		// 해쉬
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
	
		// 해쉬 검증
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
		
		// 결과 출력
		System.out.println("---------- Java HMAC ----------");
		System.out.println("Original Hash: " + Base64.getEncoder().encodeToString(hashedData));
		System.out.println("Verified Hash: " + Base64.getEncoder().encodeToString(verifyingHashedData));
		
		// 다른 언어 키 파일 읽어서 검증
		File otherKeyFile = new File(getKeyDirectory() + File.separator + CS_HMAC_KEY_FILENAME);
		if (otherKeyFile.exists()) {
			try {
				byte[] otherKeyData = Base64.getDecoder().decode(readAllText(otherKeyFile));
				SecretKeySpec key = new SecretKeySpec(otherKeyData, HMAC_ALGORITHM_NAME);
				Mac mac = Mac.getInstance(HMAC_ALGORITHM_NAME);
				mac.init(key);
				byte[] otherHashedData = mac.doFinal(SAMPLE_ENCODED_DATA);
				
				// 결과 출력
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

	/*
	 * 파일을 읽어서 String 타입으로 리턴
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
	
	/*
	 * String을 파일에 기록
	 * @param file 파일
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

}
