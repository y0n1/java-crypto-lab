package crypto;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
import sun.security.x509.X509CertImpl;

/**
 * CS3536: Building Secure Applications Lab1 - Java Crypto API (JCA & JCE)
 *
 * @author Jonathan Kilzi & Ben Avner
 */
public class Crypto4J {

    private static final Logger LOGGER = Logger.getLogger(Crypto4J.class.getName());
    private static final String KEYSTORES_DIR_NAME = "keystores";
    private static final String OUTPUT_DIR_NAME = "output";

    private static Provider fDsProvider = Security.getProviders()[1];
    private static Provider fAlgoProvider = Security.getProviders()[4];
    private static String fAlgorithm = ECipherAlgorithmNames.AES.name();
    private static String fSignatureAlgorithm = ESignatureAlgorithms.SHA256withRSA.name();
    private static String fCipherOpmode = ECipherAlgorithmModes.CBC.name();
    private static String fPaddingScheme = ECipherAlgorithmPadding.PKCS5Padding.name();
    private static File fOutputFile = Paths.get(OUTPUT_DIR_NAME, "output.enc").toFile();
    private static File fConfigFile = Paths.get(OUTPUT_DIR_NAME, "config.xml").toFile();
    private static File fInputFile;

    public static Map<String, byte[]> encryptAndSign(PrivateKey alicePrivateKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
            FileNotFoundException, IOException, SignatureException, InvalidAlgorithmParameterException {
        String transformation = String.format("%s/%s/%s", fAlgorithm, fCipherOpmode, fPaddingScheme);
        Cipher encryptCipher = Cipher.getInstance(transformation, fAlgoProvider);

        // Generate the secret key
        KeyGenerator keygen = KeyGenerator.getInstance(fAlgorithm);
        keygen.init(encryptCipher.getBlockSize() * 8);
        SecretKey secretKey = keygen.generateKey();

        // Initialize the cipher with random IV
        byte[] iv = new byte[encryptCipher.getBlockSize()];
        SecureRandom prng = new SecureRandom();
        prng.nextBytes(iv);
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Initialize the digital signature
        Signature signer = Signature.getInstance(fSignatureAlgorithm, fDsProvider);
        signer.initSign(alicePrivateKey);

        // Encrypt and sign
        InputStream is = Files.newInputStream(fInputFile.toPath());
        OutputStream os = Files.newOutputStream(fOutputFile.toPath());
        try (CipherOutputStream cipherOutputStream = new CipherOutputStream(os, encryptCipher)) {
            byte[] buffer = new byte[encryptCipher.getBlockSize()];
            int numBytesRead = is.read(buffer);
            while (numBytesRead != -1) {
                signer.update(buffer, 0, numBytesRead);
                cipherOutputStream.write(buffer, 0, numBytesRead);
                numBytesRead = is.read(buffer);
            }
            
            cipherOutputStream.flush();
        }
        
        byte[] digitalSignature = signer.sign();

        Map<String, byte[]> outputVault = new HashMap<>(3);
        outputVault.put("digitalSignature", digitalSignature);
        outputVault.put("secretKey", secretKey.getEncoded());
        outputVault.put("iv", iv);

        return outputVault;
    }

    public static boolean decryptAndVerify(PrivateKey bobPrivateKey, PublicKey alicePublicKey)
            throws JDOMException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException,
            SignatureException {
        // Parse the XML configFile
        Document xml = readConfigFile(fConfigFile);
        Element configurationElement = xml.getRootElement();

        Element digitalSignatureElement = configurationElement.getChild("DigitalSignature");
        Attribute algorithm = digitalSignatureElement.getAttribute("algorithm");
        Attribute dsProvider = digitalSignatureElement.getAttribute("provider");
        String digitalSignatureElementText = digitalSignatureElement.getText();

        Element secretKeyElement = configurationElement.getChild("SecretKey");
        Attribute encryptedWith = secretKeyElement.getAttribute("encrypted-with");
        String secretKeyElementText = secretKeyElement.getText();

        Element encryptedDataParamsElement = configurationElement.getChild("EncryptedDataParams");
        Attribute transformation = encryptedDataParamsElement.getAttribute("transformation");
        Attribute provider = encryptedDataParamsElement.getAttribute("provider");
        Attribute initVector = encryptedDataParamsElement.getAttribute("init-vector");
        Attribute location = encryptedDataParamsElement.getAttribute("location");

        // Get the DS, SecretKey and IV
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] digitalSignature = decoder.decode(digitalSignatureElementText.getBytes());
        byte[] encryptedSecretKey = decoder.decode(secretKeyElementText.getBytes());
        byte[] iv = decoder.decode(initVector.getValue().getBytes());

        // Decrypt the SecretKey with bobPrivateKey.
        Cipher secretKeyDecipher = Cipher.getInstance(encryptedWith.getValue());
        secretKeyDecipher.init(Cipher.DECRYPT_MODE, bobPrivateKey);
        byte[] decryptedSecretKey = secretKeyDecipher.doFinal(encryptedSecretKey);

        // Initialize the decipher
        String[] transParts = transformation.getValue().split("/");
        SecretKeySpec secretKey = new SecretKeySpec(decryptedSecretKey, transParts[0]);
        Cipher decipher = Cipher.getInstance(transformation.getValue(), provider.getValue());
        decipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Decrypt the file and Verify its Signature using alicePublicKey.
        Signature verifier = Signature.getInstance(algorithm.getValue(), dsProvider.getValue());
        verifier.initVerify(alicePublicKey);

        // Check that input and output paths are different
        fInputFile = Paths.get(location.getValue()).toFile();
        if (fInputFile.toPath() == fOutputFile.toPath()) {
            throw new IllegalArgumentException("Input and output path are the same!\nPlease specify a different output path.");
        }

        InputStream is = Files.newInputStream(fInputFile.toPath());
        BufferedWriter writer = Files.newBufferedWriter(fOutputFile.toPath());
        CipherInputStream cipherInputStream = new CipherInputStream(is, decipher);
        byte[] buffer = new byte[decipher.getBlockSize()];
        int numBytesRead = cipherInputStream.read(buffer);
        while (numBytesRead != -1) {
            String part = new String(buffer, 0, numBytesRead);
            writer.write(part);
            verifier.update(buffer, 0, numBytesRead);
            numBytesRead = cipherInputStream.read(buffer);
        }

        writer.flush();
        writer.close();
        cipherInputStream.close();

        return verifier.verify(digitalSignature);
    }

    private static Document readConfigFile(File file) throws FileNotFoundException, JDOMException, IOException {
        FileReader fileReader = new FileReader(file);
        return new SAXBuilder().build(fileReader);
    }

    private static void writeConfigFile(Map<String, Object> params) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Unpack the parameters
        byte[] iv = (byte[]) params.get("iv");
        byte[] secretKey = (byte[]) params.get("secretKey");
        byte[] digitalSignature = (byte[]) params.get("digitalSignature");
        PublicKey bobPublicKey = ((X509CertImpl) params.get("aliceTrustedCertEntry")).getPublicKey();

        // Encrypt the secret key first
        Cipher rsaCipher = Cipher.getInstance(ECipherAlgorithmNames.RSA.name());
        rsaCipher.init(Cipher.ENCRYPT_MODE, bobPublicKey);
        byte[] encryptedSecretKey = rsaCipher.doFinal(secretKey);

        // Setup the XML configuration document
        Base64.Encoder encoder = Base64.getEncoder();
        Element configuration = new Element("Configuration");
        Document xml = new Document(configuration);

        Element signature = new Element("DigitalSignature");
        signature.setAttribute(new Attribute("algorithm", fSignatureAlgorithm));
        signature.setAttribute(new Attribute("provider", fDsProvider.getName()));
        signature.setText(new String(encoder.encode(digitalSignature), StandardCharsets.UTF_8));
        xml.getRootElement().addContent(signature);

        Element key = new Element("SecretKey");
        key.setAttribute(new Attribute("encrypted-with", ECipherAlgorithmNames.RSA.name()));
        key.setText(new String(encoder.encode(encryptedSecretKey), StandardCharsets.UTF_8));
        xml.getRootElement().addContent(key);

        Element data = new Element("EncryptedDataParams");
        String transformation = String.format("%s/%s/%s", fAlgorithm, fCipherOpmode, fPaddingScheme);
        data.setAttribute(new Attribute("transformation", transformation));
        data.setAttribute(new Attribute("provider", fAlgoProvider.getName()));
        data.setAttribute(new Attribute("init-vector", new String(encoder.encode(iv))));
        data.setAttribute(new Attribute("location", fOutputFile.getAbsolutePath()));
        xml.getRootElement().addContent(data);

        // Pretty print the XML
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());
        xmlOutput.output(xml, new FileWriter(fConfigFile));
    }

    public static KeyStore loadKeyStore(File keyStoreFile, char[] keyStorePassword) throws IllegalArgumentException,
            NoSuchAlgorithmException, FileNotFoundException, KeyStoreException, IOException, CertificateException {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream is = Files.newInputStream(keyStoreFile.toPath());
        keystore.load(is, keyStorePassword);
        is.close();

        return keystore;
    }

    private static Map<String, Object> retrieveAliasData(String alias, char[] keyPass, File keyStoreFile,
            char[] keyStorePassword) throws IllegalArgumentException, NoSuchAlgorithmException, KeyStoreException,
            IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException,
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
        map.put("trustedCertEntry", trustedCertificateEntry);
        
        return map;
    }

    public static void main(String[] args) {
        // Setup the info for the entities inside the keystores.
        final Map<String, Map<String, Object>> defaultEntities = new HashMap<>(2);
        defaultEntities.put("alice", new HashMap<>());
        defaultEntities.get("alice").put("keystore", Paths.get(KEYSTORES_DIR_NAME, "alice.jks").toFile());
        defaultEntities.get("alice").put("passphrase", "123456".toCharArray());
        defaultEntities.put("bob", new HashMap<>());
        defaultEntities.get("bob").put("keystore", Paths.get(KEYSTORES_DIR_NAME, "bob.jks").toFile());
        defaultEntities.get("bob").put("passphrase", "123456".toCharArray());

        // Automatically generate the help statement
        HelpFormatter formatter = new HelpFormatter();
        final String usageMessage = "java -jar JavaCryptoLab.jar [OPTIONS]\n\nOptions:";

        // Define the command-line arguments
        Options options = new Options();
        options.addOption(Option.builder("d").longOpt("debug").hasArg(false).required(false).numberOfArgs(0)
                .desc("Shows stack traces when an error is found").build());
        options.addOption(Option.builder("h").longOpt("help").hasArg(false).required(false).numberOfArgs(0)
                .desc("Shows this help message").build());
        options.addOption(Option.builder("s").longOpt("sign").hasArg(true).required(false).numberOfArgs(1)
                .desc("The algorithm used for the Digital Signature. Default is " + fSignatureAlgorithm).build());
        options.addOption(Option.builder("a").longOpt("algo").hasArg(true).required(false).numberOfArgs(1)
                .desc("The algorithm to be used. Default is AES").build());
        options.addOption(Option.builder("opmode").hasArg(true).required(false).numberOfArgs(1)
                .desc("The cipher operation mode. Default is CBC").build());
        options.addOption(Option.builder("padding").hasArg(true).required(false).numberOfArgs(1)
                .desc("The padding technique used by the cipher. Default is " + fPaddingScheme).build());
        options.addOption(Option.builder("p").longOpt("provider").hasArg(true).required(false).numberOfArgs(1)
                .desc("The provider to be used. Default is " + fAlgoProvider).build());
        options.addOption(Option.builder("x").longOpt("dsprovider").hasArg(true).required(false).numberOfArgs(1)
                .desc("The provider to be used for the digital signature. Default is " + fDsProvider).build());
        options.addOption(Option.builder("o").longOpt("output").hasArg(true).required(false).numberOfArgs(1)
                .desc("The path to the output file. Default is the current working directory.").build());
        options.addOption(Option.builder("c").longOpt("config").hasArg(true).required(false).numberOfArgs(1)
                .desc("The path to the config file. Default is the current working directory.").build());
        options.addOption(Option.builder("i").longOpt("input").hasArg(true).required(false).numberOfArgs(1)
                .desc("The path to the input file.").build());
        options.addOption(Option.builder("k").longOpt("keystore_password").hasArg(true).required().numberOfArgs(1)
                .desc("The password for the keystore.").build());
        options.addOption(Option.builder("m").longOpt("mode").hasArg(true).required().numberOfArgs(1)
                .desc("The mode of operation: {encrypt|decrypt}.").build());

        // Create the command-line arguments parser
        CommandLineParser parser = new DefaultParser();
        boolean debugFlagOn = false;
        try {
            // Parse CLI arguments
            CommandLine cli = parser.parse(options, args);

            debugFlagOn = cli.hasOption("debug");

            if (debugFlagOn) {
                System.out.printf("Intalled Providers: %s%n", Arrays.toString(Security.getProviders()));
                System.out.printf("Using Provider: %s%n", fAlgoProvider.getName());
                System.out.printf("Provider Info: %s%n", fAlgoProvider.getInfo());
                System.out.printf("Using DS Provider: %s%n", fDsProvider.getName());
                System.out.printf("Provider Info: %s%n", fDsProvider.getInfo());
            }

            if (cli.hasOption("help")) {
                formatter.printHelp(usageMessage, options);
                System.exit(0);
            }

            char[] keyStorePassword = cli.getOptionValue("keystore_password").toCharArray();

            int mode = 0;
            if (cli.getOptionValue("mode").matches("encrypt")) {
                mode = Cipher.ENCRYPT_MODE;
                if (!cli.hasOption("input")) {
                    throw new ParseException("Input file path must be specified! Use -i or --input option to set.");
                }
                
            } else if (cli.getOptionValue("mode").matches("decrypt")) {
                mode = Cipher.DECRYPT_MODE;
                if (cli.hasOption("input")) {
                    throw new ParseException("Invalid option --input when in mode 'decrypt'!");
                }

                if (!cli.hasOption("output")) {
                    throw new ParseException("Output file path must be specified! Use -o or --output option to set.");
                }

            } else {
                throw new ParseException("Invalid operation mode!\n" + "Should be {encrypt|decrypt}.");
            }

            fSignatureAlgorithm = (cli.hasOption("sign")) ? cli.getOptionValue("signo") : fSignatureAlgorithm;
            fSignatureAlgorithm = ESignatureAlgorithms.valueOf(fSignatureAlgorithm).name();

            fAlgorithm = (cli.hasOption("algo")) ? cli.getOptionValue("algo") : fAlgorithm;
            fAlgorithm = ECipherAlgorithmNames.valueOf(fAlgorithm).name();

            fCipherOpmode = (cli.hasOption("opmode")) ? cli.getOptionValue("opmode") : fCipherOpmode;
            fCipherOpmode = ECipherAlgorithmModes.valueOf(fCipherOpmode).name();

            fPaddingScheme = (cli.hasOption("padding")) ? cli.getOptionValue("padding") : fPaddingScheme;
            fPaddingScheme = ECipherAlgorithmPadding.valueOf(fPaddingScheme).name();

            String name = (cli.hasOption("provider")) ? cli.getOptionValue("provider") : fAlgoProvider.getName();
            fAlgoProvider = Security.getProvider(name);
            name = (cli.hasOption("dsprovider")) ? cli.getOptionValue("dsprovider") : fDsProvider.getName();
            fDsProvider = Security.getProvider(name);

            fOutputFile = (cli.hasOption("output")) ? Paths.get(cli.getOptionValue("output")).toFile() : fOutputFile;
            fConfigFile = (cli.hasOption("config")) ? Paths.get(cli.getOptionValue("config")).toFile() : fConfigFile;
            fInputFile = mode == Cipher.DECRYPT_MODE ? null : Paths.get(cli.getOptionValue("input")).toFile();

            // Retrieve the key pairs
            File aliceKeyStoreFile = (File) defaultEntities.get("alice").get("keystore");
            char[] alicePassPharse = (char[]) defaultEntities.get("alice").get("passphrase");
            Map<String, Object> aliceData = retrieveAliasData("alice", alicePassPharse, aliceKeyStoreFile,
                    keyStorePassword);
            File bobKeyStoreFile = (File) defaultEntities.get("bob").get("keystore");
            char[] bobPassPharse = (char[]) defaultEntities.get("bob").get("passphrase");
            Map<String, Object> bobData = retrieveAliasData("bob", bobPassPharse, bobKeyStoreFile, keyStorePassword);

            // Zero the keystore password
            Arrays.fill(keyStorePassword, '\u0000');

            String msg = null;
            switch (mode) {
                case Cipher.ENCRYPT_MODE:
                    Map<String, byte[]> encryptOutput = encryptAndSign(((KeyPair) aliceData.get("keypair")).getPrivate());
                    Map<String, Object> writeConfigParams = new HashMap<>(encryptOutput);
                    writeConfigParams.put("aliceTrustedCertEntry",
                            ((KeyStore.TrustedCertificateEntry) aliceData.get("trustedCertEntry")).getTrustedCertificate());
                    writeConfigFile(writeConfigParams);
                    msg = String.format("Done! checkout your files at: " + fOutputFile.getAbsolutePath());
                    break;
                case Cipher.DECRYPT_MODE:
                    PrivateKey bobPrivateKey = ((KeyPair) bobData.get("keypair")).getPrivate();
                    PublicKey alicePublicKey = ((KeyStore.TrustedCertificateEntry) bobData.get("trustedCertEntry"))
                            .getTrustedCertificate().getPublicKey();
                    boolean verificationSucceeded = decryptAndVerify(bobPrivateKey, alicePublicKey);
                    msg = String.format("Digital Signature Verification Status: %s", verificationSucceeded ? "OK" : "FAIL");
                    break;
            }

            LOGGER.info(msg);
        } catch (ParseException ex) {
            System.err.println(ex.getLocalizedMessage());
            formatter.printHelp(usageMessage, options);
            System.exit(1);
        } catch (NoSuchPaddingException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | IllegalArgumentException | KeyStoreException | IOException | CertificateException | UnrecoverableEntryException | SignatureException | JDOMException | IllegalBlockSizeException | BadPaddingException | UnsupportedOperationException | InvalidAlgorithmParameterException ex) {
            if (debugFlagOn) {
                LOGGER.log(Level.SEVERE, ex.getLocalizedMessage(), ex);
            } else {
                LOGGER.log(Level.SEVERE, ex.getLocalizedMessage());
            }

            System.exit(1);
        }
    }
}
