package crypto;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
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

    private static final Path INPUT_DIR_PATH = Paths.get("input/");
    private static final Path OUTPUT_DIR_PATH = Paths.get("output/");
    private static final Path KEYSTORES_DIR_PATH = Paths.get("keystores/");
    
    /**
     * For the sake of simplicity, both keystores have the same password.
     */
    private static char[] keyStoresPassword;
    
    private static final Logger logger = Logger.getLogger(Crypto4J.class.getName());
    
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
        
    public static void main(String[] args) {
        Options options = new Options();
        
        // Definition Stage
        boolean hasArg = true;
        options.addOption("p", "keystorepass", hasArg, "The password used to protect the integrity of the keystore contents");
        options.addOption("h", "help", !hasArg, "This help message");
        
        // Automatically generate the Usage + Help message
        HelpFormatter formatter = new HelpFormatter();        
        
        // Parsing Stage
        CommandLineParser parser = new DefaultParser();
        try {
            // Interrogation Stage
            CommandLine cmd = parser.parse(options, args);           
                        
            // Display Help message if proper option was provided and exit
            if (cmd.hasOption("help")) {
                formatter.printHelp("Crypto4J", options);
                System.exit(0);
            }            
            
            if (cmd.hasOption("kstorepass")) {
                String defaultValue = "k3y5t0r3";
                keyStoresPassword = cmd.getOptionValue("kstorepass", defaultValue).toCharArray();
                
                
            }
            
        } catch (ParseException ex) {
            System.err.println(ex.getLocalizedMessage());
            formatter.printHelp("Crypto4J", options);
            System.exit(1);
        }       
        
    }
    
}
