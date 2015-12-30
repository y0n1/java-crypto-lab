package crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.jdom2.Attribute;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

/**
 *
 * @author JKILZI
 */
public class Crypto4J {

    private static final Logger LOGGER = Logger.getLogger(Crypto4J.class.getName());
    private static final String KEYSTORES_DIR_NAME = "keystores";
    private static final String OUTPUT_DIR_NAME = "output";

    private static FileInputStream fileInputStream;
    private static FileOutputStream fileOutputStream;

    private static Map<String, Object> encryptAndSign(String transformation, String provider, File inputFile,
            File outputFile, File configFile, String signatureAlgorithm, PrivateKey privateKey)
            throws NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            FileNotFoundException,
            IOException,
            SignatureException {
        Cipher cipher = Cipher.getInstance(transformation, provider);

        // Generate the secret key
        KeyGenerator keygen = KeyGenerator.getInstance(transformation.split("/")[0]);
        keygen.init(cipher.getBlockSize() * 8);
        SecretKey secretKey = keygen.generateKey();

        // Initialize the cipher
        cipher.init(Cipher.ENCRYPT_MODE, secretKey); // IV is automatically generated...

        // Initialize the digital signature
        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(privateKey);

        fileInputStream = new FileInputStream(inputFile);
        fileOutputStream = new FileOutputStream(outputFile);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, cipher);
        byte[] buffer = new byte[cipher.getBlockSize() * 8];
        int numBytesRead = fileInputStream.read(buffer);
        signer.update(buffer);
        while (numBytesRead != -1) {
            cipherOutputStream.write(buffer, 0, numBytesRead);
            numBytesRead = fileInputStream.read(buffer);
            if (numBytesRead > 0) {
                signer.update(buffer);
            }
        }

        byte[] digitalSignature = signer.sign();
        cipherOutputStream.flush();

        Map<String, Object> map = new HashMap<>(2);
        map.put("signature", digitalSignature);
        map.put("secretKey", secretKey);

        return map;
    }

    public static boolean decryptAndVerify(File encryptedFile, File configFile) throws JDOMException, IOException {
        Document config = readConfigFile(configFile);
        // TODO: Decrypt
        // TODO: Verify Signature
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private static Document readConfigFile(File file) throws FileNotFoundException, JDOMException, IOException {
        FileReader fileReader = new FileReader(file);
        return new SAXBuilder().build(fileReader);
    }

    private static void writeConfigFile(File fileName, byte[] digitalSignature, String signatureAlgorithm,
            SecretKey secretKey, PublicKey publicKey)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        // Encrypt the secret key first
        Cipher rsaCipher = Cipher.getInstance(ECipherAlgorithmNames.RSA.name());
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);        
        
        Element configuration = new Element("configuration");
        Document doc = new Document(configuration);

        Element signature = new Element("signature");
        signature.setAttribute(new Attribute("algorithm", signatureAlgorithm));
        signature.setText(new String(Base64.getEncoder().encode(digitalSignature), StandardCharsets.UTF_8)); // FIXME
        doc.getRootElement().addContent(signature);

        Element key = new Element("key");
        key.setAttribute(new Attribute("algorithm", ECipherAlgorithmNames.RSA.name()));
        key.setText(new String(Base64.getEncoder().encode(secretKey.getEncoded()), StandardCharsets.UTF_8));
        doc.getRootElement().addContent(key);

        // Pretty print
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());
        xmlOutput.output(doc, new FileWriter(fileName));
        // xmlOutput.output(doc, System.out);
    }

    private static KeyStore loadKeyStore(File keyStoreFileName, char[] keyStorePassword)
            throws IllegalArgumentException,
            NoSuchAlgorithmException,
            FileNotFoundException,
            KeyStoreException,
            IOException,
            CertificateException {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        fileInputStream = new FileInputStream(keyStoreFileName);
        keystore.load(fileInputStream, keyStorePassword);
        fileInputStream.close();

        return keystore;
    }

    private static Map<String, Object> retrieveAliasData(String alias, char[] keyPass, File keyStoreFile, char[] keyStorePassword)
            throws IllegalArgumentException,
            NoSuchAlgorithmException,
            KeyStoreException,
            IOException,
            FileNotFoundException,
            CertificateException,
            UnrecoverableKeyException,
            UnrecoverableEntryException {
        KeyStore keyStore = loadKeyStore(keyStoreFile, keyStorePassword);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPass);
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
        
        // Find the alias for whose entry type is 'trustedCertEntry'
        KeyStore.TrustedCertificateEntry trustedCertificateEntry = null;
        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String nextAlias = aliases.nextElement();
            if (keyStore.entryInstanceOf(nextAlias, KeyStore.TrustedCertificateEntry.class)) {
                trustedCertificateEntry = (KeyStore.TrustedCertificateEntry) keyStore.getEntry(nextAlias, null);
            }
        }
        
        if (trustedCertificateEntry == null) {
            throw new UnrecoverableEntryException("No Trusted Certificates could be found for the given keystore.");
        }
                
        Map<String, Object> map = new HashMap<>(2);
        map.put("keypair", new KeyPair(publicKey, privateKey));
        map.put("trustedCertPubKey", trustedCertificateEntry.getTrustedCertificate().getPublicKey());
        return map;
    }

    public static void main(String[] args) {
        // Setup the very specific details for the entities inside the keystores that we'll be using.
        final Map<String, Map> defaultEntities = new HashMap(2);
        defaultEntities.put("alice", new HashMap<>());
        defaultEntities.get("alice").put("keystore", Paths.get(KEYSTORES_DIR_NAME, "alice.jks").toFile());
        defaultEntities.get("alice").put("passphrase", "123456".toCharArray());
        defaultEntities.put("bob", new HashMap<>());
        defaultEntities.get("bob").put("keystore", Paths.get(KEYSTORES_DIR_NAME, "bob.jks").toFile());
        defaultEntities.get("bob").put("passphrase", "123456".toCharArray());

        // Automatically generate the help statement
        HelpFormatter formatter = new HelpFormatter();
        final String usageMessage = "java -jar Crypto4J.jar [OPTIONS]";

        // Define cli arguments
        Options options = new Options();
        options.addOption(Option.builder("d").longOpt("debug").hasArg(false).required(false).numberOfArgs(0)
                .desc("Shows stack traces when an error is found").build());
        options.addOption(Option.builder("h").longOpt("help").hasArg(false).required(false).numberOfArgs(0)
                .desc("Shows this help message").build());
        options.addOption(Option.builder("s").longOpt("sign_algo").hasArg(true).required(false).numberOfArgs(1)
                .desc("The algorithm used for the Digital Signature. Default is SHA256withRSA").build());
        options.addOption(Option.builder("algo").hasArg(true).required(false).numberOfArgs(1)
                .desc("The algorithm to be used. Default is AES").build());
        options.addOption(Option.builder("cipher_opmode").hasArg(true).required(false).numberOfArgs(1)
                .desc("The cipher operation mode. Default is CBC").build());
        options.addOption(Option.builder("padding_scheme").hasArg(true).required(false).numberOfArgs(1)
                .desc("The padding technique used by the cipher. Default is PKCS5Padding").build());
        options.addOption(Option.builder("provider").hasArg(true).required(false).numberOfArgs(1)
                .desc("The cryptographic provider implementation to be used. Default is SunJCE").build());
        options.addOption(Option.builder("o").longOpt("output_file").hasArg(true).required(false).numberOfArgs(1)
                .desc("The path to the output file. Default is the current working directory.").build());
        options.addOption(Option.builder("c").longOpt("config_file").hasArg(true).required(false).numberOfArgs(1)
                .desc("The path to the config file. Default is the current working directory.").build());
        options.addOption(Option.builder("i").longOpt("input_file").hasArg(true).required().numberOfArgs(1)
                .desc("The path to the input file.").build());
        options.addOption(Option.builder("k").longOpt("keystore_password").hasArg(true).required().numberOfArgs(1)
                .desc("The password for the keystore.").build());
        options.addOption(Option.builder("m").longOpt("mode").hasArg(true).required().numberOfArgs(1)
                .desc("The mode of operation: {encrypt|decrypt}.").build());

        // Create the cli args parser
        CommandLineParser parser = new DefaultParser();
        boolean debugFlagOn = false;
        try {
            // Parse CLI arguments
            CommandLine cli = parser.parse(options, args);

            debugFlagOn = cli.hasOption("debug");

            if (cli.hasOption("help")) {
                formatter.printHelp(usageMessage, options);
                System.exit(0);
            }

            char[] keyStorePassword = cli.getOptionValue("keystore_password").toCharArray();

            int mode = 0;
            if (cli.getOptionValue("mode").matches("encrypt")) {
                mode = Cipher.ENCRYPT_MODE;
            } else if (cli.getOptionValue("mode").matches("decrypt")) {
                mode = Cipher.DECRYPT_MODE;
            } else {
                throw new ParseException("Invalid operation mode!\n"
                        + "Should be {encrypt|decrypt}.");
            }

            String signatureAlgorithm = (cli.hasOption("sign_algo"))
                    ? cli.getOptionValue("sign_algo")
                    : ESignatureAlgorithms.SHA256withRSA.name();
            signatureAlgorithm = ESignatureAlgorithms.valueOf(signatureAlgorithm).name();

            String algorithm = (cli.hasOption("algo"))
                    ? cli.getOptionValue("algo")
                    : ECipherAlgorithmNames.AES.name();
            algorithm = ECipherAlgorithmNames.valueOf(algorithm).name();

            String cipherOpmode = (cli.hasOption("cipher_opmode"))
                    ? cli.getOptionValue("cipher_opmode")
                    : ECipherAlgorithmModes.CBC.name();
            cipherOpmode = ECipherAlgorithmModes.valueOf(cipherOpmode).name();

            String paddingScheme = (cli.hasOption("padding_scheme"))
                    ? cli.getOptionValue("padding_scheme")
                    : ECipherAlgorithmPadding.PKCS5Padding.name();
            paddingScheme = ECipherAlgorithmPadding.valueOf(paddingScheme).name();

            String provider = (cli.hasOption("provider")) ? cli.getOptionValue("provider") : "SunJCE";

            File inputFile = Paths.get(cli.getOptionValue("input_file")).toFile();
            File outputFile = (cli.hasOption("output_file"))
                    ? Paths.get(cli.getOptionValue("output_file")).toFile()
                    : Paths.get(OUTPUT_DIR_NAME, String.format("%s.enc", inputFile.getName())).toFile();
            File configFile = (cli.hasOption("config_file"))
                    ? Paths.get(cli.getOptionValue("config_file")).toFile()
                    : Paths.get(OUTPUT_DIR_NAME, "config.xml").toFile();

            // Retrieve the key pairs
            File aliceKeyStoreFile = (File) defaultEntities.get("alice").get("keystore");
            char[] alicePassPharse = (char[]) defaultEntities.get("alice").get("passphrase");
            Map aliceData = retrieveAliasData("alice", alicePassPharse, aliceKeyStoreFile, keyStorePassword);
            File bobKeyStoreFile = (File) defaultEntities.get("bob").get("keystore");
            char[] bobPassPharse = (char[]) defaultEntities.get("bob").get("passphrase");
            Map bobData = retrieveAliasData("bob", bobPassPharse, bobKeyStoreFile, keyStorePassword);

            // Zero the keystore password
            Arrays.fill(keyStorePassword, '\u0000');

            switch (mode) {
                case Cipher.ENCRYPT_MODE:
                    String transformation = String.format("%s/%s/%s", algorithm, cipherOpmode, paddingScheme);
                    Map output = encryptAndSign(
                            transformation,
                            provider,
                            inputFile,
                            outputFile,
                            configFile,
                            signatureAlgorithm,
                            ((KeyPair) aliceData.get("keypair")).getPrivate());
                    writeConfigFile(configFile,
                            (byte[]) output.get("signature"),
                            signatureAlgorithm,
                            (SecretKey) output.get("secretKey"),
                            ((PublicKey) aliceData.get("trustedCertPubKey")));
                    break;
                case Cipher.DECRYPT_MODE:
                    // TODO: decryptAndVerify();
                    break;
            }

        } catch (ParseException ex) {
            System.err.println(ex.getLocalizedMessage());
            formatter.printHelp(usageMessage, options);
            System.exit(1);
        } catch (NoSuchPaddingException |
                NoSuchProviderException |
                InvalidKeyException |
                IllegalArgumentException |
                KeyStoreException |
                IOException |
                NoSuchAlgorithmException |
                CertificateException |
                UnrecoverableEntryException |
                SignatureException |
                UnsupportedOperationException ex) {
            if (debugFlagOn) {
                LOGGER.log(Level.SEVERE, ex.getLocalizedMessage(), ex);
            } else {
                LOGGER.log(Level.SEVERE, ex.getLocalizedMessage());
            }
            System.exit(1);
        }
    }
}
