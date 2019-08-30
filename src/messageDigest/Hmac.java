package messageDigest;
import common.*;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Hmac {
	static final String ALGORITHM_NAME = "HmacSHA256";
	static final int LOOP_COUNT = 100000;

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
		String data = "배달 문화를 선도하는 오투오시스";
		System.out.println("Data: " + data);
		
		byte[] encodedKey = new byte[16];

		//
		// 키를 SecureRandom + KeyGenerator를 이용해서 생성
		//
		try
		{
			SecureRandom randomNumber = new SecureRandom();
			KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_NAME);
			keyGen.init(randomNumber);
			SecretKey signingKey = keyGen.generateKey();
			encodedKey = signingKey.getEncoded();
			Mac mac = Mac.getInstance(ALGORITHM_NAME);
			mac.init(signingKey);
			byte[] encrypted = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
			String encoded = Base64.getEncoder().encodeToString(encrypted);
			System.out.println("--- SecureRandom + KeyGenerator ---");
			System.out.println("Encoded: " + encoded);
		}
		catch (Exception ex)
		{
			System.out.println(ex.getMessage());
			return;
		}
		
		//
		// 키를 SecretKeySpec을 이용해서 생성 (키 데이터를 받아올 때)
		//
		try
		{
			SecretKeySpec signingKey = new SecretKeySpec(encodedKey, ALGORITHM_NAME);
			Mac mac = Mac.getInstance(ALGORITHM_NAME);
			mac.init(signingKey);
			byte[] encrypted = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
			String encoded = Base64.getEncoder().encodeToString(encrypted);
			System.out.println("--- SecretKeySpec ---");
			System.out.println("Encoded: " + encoded);
		}
		catch (Exception ex)
		{
			System.out.println(ex.getMessage());
			return;
		}
		
		//
		// 성능 테스트
		//
		System.out.println("--- Performance test ---");
		ArrayList<Statistics> stat = new ArrayList<Statistics>();
		for (int i = 0; i < SampleData.messages.length; i++)
		{
			stat.add(new Statistics());
		}
		
		try
		{
			SecretKeySpec signingKey = new SecretKeySpec(encodedKey, ALGORITHM_NAME);
			Mac mac = Mac.getInstance(ALGORITHM_NAME);
			mac.init(signingKey);
			
			for (int i = 0; i < LOOP_COUNT; i++)
			{
				for (int j = 0; j < stat.size(); j++)
				{
					long timeBegin = System.nanoTime();
					byte[] encrypted = mac.doFinal(SampleData.messages[j].getBytes(StandardCharsets.UTF_8));
					long timeEncrypt = System.nanoTime();
					String encoded = Base64.getEncoder().encodeToString(encrypted);
					long timeEncode = System.nanoTime();
					
					stat.get(j).encryptLength = encrypted.length;
					stat.get(j).encryptCount++;
					stat.get(j).encryptTime += (timeEncrypt - timeBegin);
					stat.get(j).encodeLength = encoded.length();
					stat.get(j).encodeCount++;
					stat.get(j).encodeTime += (timeEncode - timeEncrypt);
				}
			}
			
			for (int i = 0; i < stat.size(); i++)
			{
				System.out.printf("Message{Id:%d, Length:%d}, Encrypting{Length:%d, Count:%d, Time:%dns, Ave.Time:%.6fms}, Encoding{Length:%d, Count:%d, Time:%dns, Ave.Time:%.6fms}%n",
						i,
						SampleData.messages[i].length(),
						stat.get(i).encryptLength,
						stat.get(i).encryptCount,
						stat.get(i).encryptTime,
						stat.get(i).encryptTime / (double)Math.max(1, stat.get(i).encryptCount) / 1000000,
						stat.get(i).encodeLength,
						stat.get(i).encodeCount,
						stat.get(i).encodeTime,
						stat.get(i).encodeTime / (double)Math.max(1, stat.get(i).encodeCount) / 1000000);
			}
		}
		catch (Exception ex)
		{
			System.out.println(ex.getMessage());
			return;
		}
	}
}
