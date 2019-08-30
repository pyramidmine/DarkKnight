package codec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CodecTest {

	public static void main(String[] args) {
		String eng = "AaZz019";
		String kor = "¾È³ç";
		byte[] engEncodedUtf8 = eng.getBytes(StandardCharsets.UTF_8);
		byte[] engEncodedCurr = eng.getBytes();
		byte[] korEncodedUtf8 = kor.getBytes(StandardCharsets.UTF_8);
		byte[] korEncodedCurr = kor.getBytes();
		
		System.out.println("Press any key to exit...");
	}

}
