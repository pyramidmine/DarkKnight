package compress;
import common.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class Gzip {
	
	static final int LOOP_COUNT = 1000;

	public static void main(String[] args) throws UnsupportedEncodingException {
		String message = "배달 문화를 선도하는 오투오시스";
		System.out.println("Message: " + message);
		
		//
		// 압축 / 압축 해제 테스트
		//
		{
			System.out.println("--- Compress / Decompress ---");
			byte[] compressed = compress(message);
			String decompressed = decompressToString(compressed);
			System.out.println("Decompressed message: " + decompressed);
		}
		
		//
		// 성능 테스트
		//
		System.out.println("--- Performance for String ---");
		
		ArrayList<Statistics> stat = new ArrayList<Statistics>();
		for (int i = 0; i < SampleData.messages.length; i++)
		{
			stat.add(new Statistics());
		}
		
		for (int i = 0; i < LOOP_COUNT; i++)
		{
			for (int j = 0; j < stat.size(); j++)
			{
				long timeBegin = System.nanoTime();
				byte[] compressed = compress(SampleData.messages[j]);
				long timeCompress = System.nanoTime();
				String decompressed = decompressToString(compressed);
				long timeDecompress = System.nanoTime();
				
				stat.get(j).encryptLength = compressed.length;
				stat.get(j).encryptCount++;
				stat.get(j).encryptTime += (timeCompress - timeBegin);
				stat.get(j).encodeLength = decompressed.length();
				stat.get(j).encodeCount++;
				stat.get(j).encodeTime += (timeDecompress - timeCompress);
			}
		}
		
		for (int i = 0; i < stat.size(); i++)
		{
			System.out.printf("Message{Id:%d, Length:%d}, Compress{Length:%d, Count:%d, Time:%dms, Ave.Time:%.6fms}, Decompress{Length:%d, Count:%d, Time:%dms, Ave.Time:%.6fms}%n",
					i,
					SampleData.messages[i].length(),
					stat.get(i).encryptLength,
					stat.get(i).encryptCount,
					stat.get(i).encryptTime / 1000000,
					stat.get(i).encryptTime / (double)Math.max(1, stat.get(i).encryptCount) / 1000000,
					stat.get(i).encodeLength,
					stat.get(i).encodeCount,
					stat.get(i).encodeTime / 1000000,
					stat.get(i).encodeTime / (double)Math.max(1, stat.get(i).encodeCount) / 1000000);
		}
		
		System.out.println("--- Performance for byte array ---");
		ArrayList<byte[]> byteMessages = new ArrayList<byte[]>();
		for (int i = 0; i < SampleData.messages.length; i++)
		{
			stat.get(i).reset();
			byteMessages.add(SampleData.messages[i].getBytes(StandardCharsets.UTF_8));
		}
		
		for (int i = 0; i < LOOP_COUNT; i++)
		{
			for (int j = 0; j < stat.size(); j++)
			{
				long timeBegin = System.nanoTime();
				byte[] compressed = compress(byteMessages.get(j));
				long timeCompress = System.nanoTime();
				byte[] decompressed = decompress(compressed);
				long timeDecompress = System.nanoTime();
				
				stat.get(j).encryptLength = compressed.length;
				stat.get(j).encryptCount++;
				stat.get(j).encryptTime += (timeCompress - timeBegin);
				stat.get(j).encodeLength = decompressed.length;
				stat.get(j).encodeCount++;
				stat.get(j).encodeTime += (timeDecompress - timeCompress);
			}
		}
		
		for (int i = 0; i < stat.size(); i++)
		{
			System.out.printf("Message{Id:%d, Length:%d}, Compress{Length:%d, Count:%d, Time:%dms, Ave.Time:%.6fms}, Decompress{Length:%d, Count:%d, Time:%dms, Ave.Time:%.6fms}%n",
					i,
					byteMessages.get(i).length,
					stat.get(i).encryptLength,
					stat.get(i).encryptCount,
					stat.get(i).encryptTime / 1000000,
					stat.get(i).encryptTime / (double)Math.max(1, stat.get(i).encryptCount) / 1000000,
					stat.get(i).encodeLength,
					stat.get(i).encodeCount,
					stat.get(i).encodeTime / 1000000,
					stat.get(i).encodeTime / (double)Math.max(1, stat.get(i).encodeCount) / 1000000);
		}
	}
	
	static byte[] compress(final String message) {
		if (message == null || message.length() == 0) {
			return null;
		}
		
		return compress(message.getBytes(StandardCharsets.UTF_8));
	}
	
	static byte[] compress(final byte[] data) {
		if (data == null || data.length == 0) {
			return null;
		}
		
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
			GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
			gzos.write(data);
			gzos.finish();
			return baos.toByteArray();
		}
		catch (IOException ex) {
			throw new UncheckedIOException("Compression error!", ex);
		}
	}
	
	static String decompressToString(final byte[] compressed) throws UnsupportedEncodingException {
		if (compressed == null || compressed.length == 0) {
			return null;
		}
		
		return new String(decompress(compressed), "UTF-8");
	}

	static byte[] decompress(final byte[] compressed) {
		if (compressed == null || compressed.length == 0) {
			return null;
		}
		
		try (GZIPInputStream gzis = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
			byte[] decompressed = gzis.readAllBytes();
			return decompressed;
		}
		catch (IOException ex)
		{
			throw new UncheckedIOException("Decompression error!", ex);
		}
	}
}
