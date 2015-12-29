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

    private static Path INPUT_DIR_PATH = Paths.get("input/");
    private static Path OUTPUT_DIR_PATH = Paths.get("output/");
    private static Path KEYSTORES_DIR_PATH = Paths.get("keystores/");
    private static byte[] KS_PASSWORD_BYTES;
    
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
                KS_PASSWORD_BYTES = cmd.getOptionValue("kstorepass", defaultValue).
                
                
            }
            
        } catch (ParseException ex) {
            System.err.println(ex.getLocalizedMessage());
            formatter.printHelp("Crypto4J", options);
            System.exit(1);
        }       
        
    }
    
}
