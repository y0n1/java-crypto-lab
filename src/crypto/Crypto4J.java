package crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
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
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/**
 *
 * @author JKILZI
 */
public class Crypto4J {

    private static final Logger LOGGER = Logger.getLogger(Crypto4J.class.getName());
    private static final Map<String, File> defaultKeystoreFiles = new HashMap(2);
    private static final String KEYSTORES_DIR = "keystores";
    private static final String OUTPUT_DIR = "output";
    private static final String INPUT_DIR = "input";
    
    /**
     * For the sake of simplicity, both keystores have the same password.
     */
    private static char[] keyStoresPassword;
    private static FileInputStream fileInputStream;
    private static FileOutputStream fileOutputStream;
    
    
    public static byte[] encrypt() {
        throw new NotImplementedException();
    } 
    
    public static String decrypt() {
        throw new NotImplementedException();
    }
    
    public static byte[] sign() {
        throw new NotImplementedException();
    }
    
    public static boolean verify() {
        throw new NotImplementedException();
    }
    
    private static byte[] readFile(File fileName, InputStream inputStream) {
        throw new NotImplementedException();
    }
    
    private static int writeFile(File fileName, OutputStream OutputStream) {
        throw new NotImplementedException();
    }
    
    private static byte[] readFileSecure(File fileName, InputStream inputStream) {
        throw new NotImplementedException();
    }
    
    private static int writeFileSecure(File fileName, OutputStream OutputStream) {
        throw new NotImplementedException();
    }
    
    private static KeyStore loadKeyStore(String name) throws IllegalArgumentException,
            NoSuchAlgorithmException, FileNotFoundException, KeyStoreException,
            IOException, CertificateException {
        
        if (!name.matches("(alice|bob)")) {
            throw new IllegalArgumentException("Arguments allowed are: 'alice' or 'bob'");
        }
        
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        File keyStoreFile = defaultKeystoreFiles.get(name);
        fileInputStream = new FileInputStream(keyStoreFile);
        keystore.load(fileInputStream, keyStoresPassword);
        
        return keystore;
    }
        
    public static void main(String[] args) {
        // Setup the default keystores that we'll be using
        defaultKeystoreFiles.put("alice", Paths.get(KEYSTORES_DIR, "alice.jks").toFile());
        defaultKeystoreFiles.put("bob", Paths.get(KEYSTORES_DIR, "bob.jks").toFile());
                
        Options options = new Options();
        
        // Definition Stage
        boolean hasArg = true;
        options.addOption("p", "password", hasArg, "The password used to protect the integrity of the keystore contents");
        options.addOption("h", "help", !hasArg, "This help message");
        
        // Automatically generate the Usage + Help message
        HelpFormatter formatter = new HelpFormatter();        
        
        // Parsing Stage
        CommandLineParser parser = new DefaultParser();
        try {
            // Interrogation Stage
            CommandLine cmd = parser.parse(options, args);           
                        
            // Display Help message and exit
            if (cmd.hasOption("help")) {
                formatter.printHelp(Crypto4J.class.getName(), options);
                System.exit(0);
            }            
            
            if (cmd.hasOption("password")) {
                final String KS_DEFAULT_PASSWD = "k3y5t0r3";
                keyStoresPassword = cmd.getOptionValue("password", KS_DEFAULT_PASSWD).toCharArray();
                KeyStore aliceKeyStore = loadKeyStore("alice");
                KeyStore bobKeyStore = loadKeyStore("bob");
            }         
            
        } catch (ParseException ex) {
            System.err.println(ex.getLocalizedMessage());
            formatter.printHelp(Crypto4J.class.getName(), options);
            System.exit(1);
        } catch (IllegalArgumentException | KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(Crypto4J.class.getName()).log(Level.SEVERE, null, ex);
            System.exit(1);
        }       
        
    }
    
}
