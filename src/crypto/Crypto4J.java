package crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 *
 * @author JKILZI
 */
public class Crypto4J {

    private static final Logger LOGGER = Logger.getLogger(Crypto4J.class.getName());
    private static final String KEYSTORES_DIR = "keystores";
    private static final String OUTPUT_DIR = "output";
    private static final String INPUT_DIR = "input";

    private static FileInputStream fileInputStream;
    private static FileOutputStream fileOutputStream;

    public static byte[] encrypt() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public static String decrypt() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public static byte[] sign() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public static boolean verify() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private static byte[] readFile(File fileName, InputStream inputStream) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private static int writeFile(File fileName, OutputStream OutputStream) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private static KeyStore loadKeyStore(File keyStoreFileName, char[] keyStorePassword) throws IllegalArgumentException,
            NoSuchAlgorithmException, FileNotFoundException, KeyStoreException, IOException, CertificateException {

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        fileInputStream = new FileInputStream(keyStoreFileName);
        keystore.load(fileInputStream, keyStorePassword);
        fileInputStream.close();

        return keystore;
    }

    private static KeyPair retrieveKeyPair(String alias, char[] keyPass, File keyStoreFile, char[] keyStorePassword) throws IllegalArgumentException,
            NoSuchAlgorithmException, KeyStoreException, IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException {

        KeyStore keyStore = loadKeyStore(keyStoreFile, keyStorePassword);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPass);
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static void main(String[] args) {
        /* Setup the very specific details for the entities inside the keystores that we'll be using.
         * REMARK:
         *     This is the only sensitive information that I won't force it to be deleted immediately after being used.
         *     Should this was not just an exercise, I wouldn't never leave this data in memory.
         */
        final Map<String, Map> defaultEntities = new HashMap(2);
        defaultEntities.put("alice", new HashMap<>());
        defaultEntities.get("alice").put("keystore", Paths.get(KEYSTORES_DIR, "alice.jks").toFile());
        defaultEntities.get("alice").put("passphrase", "123456".toCharArray());
        defaultEntities.put("bob", new HashMap<>());
        defaultEntities.get("bob").put("keystore", Paths.get(KEYSTORES_DIR, "bob.jks").toFile());
        defaultEntities.get("bob").put("passphrase", "123456".toCharArray());

        final String usageMessage = "Crypto4J -[h|d|p]";
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        Options options = new Options();

        // Define cli arguments
        boolean hasArg = true;
        options.addOption("h", "help", !hasArg, "This help message");
        options.addOption("d", "debug", !hasArg, "Shows stack traces when an error is found");
        options.addOption("p", "password", hasArg, "The password used to protect the integrity of the keystore contents");

        boolean hasDebug = false;
        try {
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("help")) {
                formatter.printHelp(usageMessage, options);
                System.exit(0);
            }

            hasDebug = (cmd.hasOption("debug"));

            char[] keyStorePassword = null;
            if (cmd.hasOption("password")) {
                keyStorePassword = cmd.getOptionValue("password").toCharArray();
            }

            /* Schedule unnecesssary instance references for garbage collection.
             * The main reason is that these objects may contain a copy of the plain
             * text password passed by in the cli arguments.
             * 
             * QUESTION FOR THE GRADER: Is this the best solution Java has to offer?               
             */
            formatter = null;
            options = null;
            parser = null;
            cmd = null;
            System.gc(); // This is CPU intensive... but I had no choice... did I? Well ask James Gosling :)~

            // Retrieve the key pairs
            File aliceKeyStoreFile = (File) defaultEntities.get("alice").get("keystore");
            char[] alicePassPharse = (char[]) defaultEntities.get("alice").get("passphrase");
            KeyPair aliceKeyPair = retrieveKeyPair("alice", alicePassPharse, aliceKeyStoreFile, keyStorePassword);
            
            File bobKeyStoreFile = (File) defaultEntities.get("bob").get("keystore");
            char[] bobPassPharse = (char[]) defaultEntities.get("bob").get("passphrase");
            KeyPair bobKeyPair = retrieveKeyPair("bob", bobPassPharse, bobKeyStoreFile, keyStorePassword);
            
            // Zero the keystore password
            Arrays.fill(keyStorePassword, '\u0000');
            
            /*
            TODO: 
                1. Read the plaintext
                2. PRNG: IV and SecretKey (for AES)
                3. encrypt plaintext with "AES/ECB/PKCS5Padding"
                4. produce the Digital Signature of the plaintext (use "SHA256withRSA")
                5. write to file (XML?)
            */ 

        } catch (ParseException ex) {
            System.err.println(ex.getLocalizedMessage());
            formatter.printHelp(usageMessage, options);
            System.exit(1);
        } catch (IllegalArgumentException | KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | UnsupportedOperationException ex) {
            if (hasDebug) {
                LOGGER.log(Level.SEVERE, ex.getLocalizedMessage(), ex);
            } else {
                LOGGER.log(Level.SEVERE, ex.getLocalizedMessage());
            }
            System.exit(1);
        }
    }

}
