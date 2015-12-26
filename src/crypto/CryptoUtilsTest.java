package crypto;

import java.io.File;

/**
 * A tester for the CryptoUtils class.
 *
 */
public class CryptoUtilsTest {
	public static void main(String[] args) {
		String key = "Mary has one cat1";
		File inputFile = new File("document.txt");
		File encryptedFile = new File("document.encrypted");
		
		try {
			CryptoUtils.encrypt(key, inputFile, encryptedFile);
		} catch (CryptoException ex) {
			System.err.println(ex.getMessage());
			ex.printStackTrace();
		}
	}
}
