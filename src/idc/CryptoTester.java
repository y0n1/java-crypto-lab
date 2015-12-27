package idc;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class CryptoTester {

	public static void main(String[] args) throws Exception {
		// Input parameters
		String INPUT_FILE = "./tmp/document.txt";
		String OUTPUT_FILE = INPUT_FILE + ".encrypted";
		String DEFAULT_KEYSTORE_LOCATION = "./keystores/";  
		String KEYSTORE_NAME = "alice.jks";
		String KEYSTORE_PASSWORD = "4l1c3=k3y5t0r3";
		String KEYSTORE_ALIAS_PASSWORD = "4l1c3=";
		String KEYSTORE_ALIAS = "alice";
				
		// Load the KeyStore
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(new FileInputStream(DEFAULT_KEYSTORE_LOCATION + KEYSTORE_NAME), KEYSTORE_PASSWORD.toCharArray());
		
		// Load the key pair for the given user (Private and Public Keys) 
		KeyPair keyPair = null;
		Key key = keystore.getKey(KEYSTORE_ALIAS, KEYSTORE_ALIAS_PASSWORD.toCharArray());		
		if (key instanceof PrivateKey) {
	      // Get certificate of public key
	      Certificate cert = keystore.getCertificate(KEYSTORE_ALIAS);

	      // Get public key
	      PublicKey publicKey = cert.getPublicKey();

	      // Create the key pair
	      keyPair = new KeyPair(publicKey, (PrivateKey) key);
	    }
		
		/*
		 *  Step 1. Generate an AES key using KeyGenerator.
		 *         Initialize the key size to 128 bits (16 bytes)
		 */
		final int AES_KEYLENGTH = 128;	// change this as desired for the security level you want
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(AES_KEYLENGTH);
		SecretKey secretKey = keyGen.generateKey(); // TODO: must encrypt later with RSA and appended to the configuration file.

		/*
		 * Step 2. Generate a random Initialization Vector (IV) 
		 * 		a. Use SecureRandom to generate random bits
		 * 		   The size of the IV matches the blocksize of the cipher (128 bits for AES)
		 * 		b. Construct the appropriate IvParameterSpec object for the data to pass to Cipher's init() method
		 */
		byte[] ivByteBuffer = new byte[AES_KEYLENGTH / 8];  // TODO: Save the IV bytes to the configuration file later 
		SecureRandom prng = new SecureRandom();
		prng.nextBytes(ivByteBuffer);
		IvParameterSpec iv = new IvParameterSpec(ivByteBuffer);
		
		/*
		 * Step 3. Create a Cipher by specifying the following parameters
		 * 		a. Algorithm name - here it is AES 
		 * 		b. Mode - here it is CBC mode 
		 * 		c. Padding - e.g. PKCS7 or PKCS5
		 */
		Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/NoPadding"); // Must specify the mode explicitly as most JCE providers default to ECB mode!!

		/*
		 * Step 4. Initialize the Cipher for Encryption
		 */
		aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey, iv);

		/*
		 * Step 5. Read the input file and encrypt it
		 */		
		FileInputStream fis = new FileInputStream(INPUT_FILE);
		FileOutputStream fos = new FileOutputStream(OUTPUT_FILE);
		CipherOutputStream cos = new CipherOutputStream(fos, aesCipherForEncryption);
		byte[] buffer = new byte[8];
		int numBytesRead = fis.read(buffer);
		while (numBytesRead != -1) {
			cos.write(buffer, 0, numBytesRead);
			numBytesRead = fis.read(buffer);
		}
		cos.flush();
				
	    /*
	     * TODO: Step 7. Digital Signature
	     */
		
		/*
		 * TODO: Step 8. Create the configuration file
		 *      a. Add the Digital Signature
		 *      b. Add the Secret Key
		 *      b. Add the IV (TODO: as Plaintext?) 
		 */
		
		

	    
		

	}

}
