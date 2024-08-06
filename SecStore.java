import java.io.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.PBEParameterSpec;

import iaik.security.cipher.PBEKeyBMP;
import iaik.security.provider.IAIK;
import iaik.utils.Base64InputStream;

public class SecStore {
    static String banner = 
        "==================================================================================================\n" +
        "    ____           ______                    \n" +
        "   / __ \\___  ____/ / __ \\____ ___  _______  \n" +
        "  / /_/ / _ \\/ __  / /_/ / __ `/ / / / ___/  \n" +
        " / _, _/  __/ /_/ / _, _/ /_/ / /_/ (__  )   \n" +
        "/_/ |_|\\___/\\__,_/_/ |_|\\__,_/\\__, /____/    \n" +
        "                             /____/          \n" +
        "==================================================================================================\n";

    private static String keyPhrase;
    private static String sid;
    private static int verNum = 0;
    private static PBEParameterSpec pbeParamSpec;
    private static Properties contents;

    public static void main(String[] args) {
        if (args.length < 3 || isHelpCommand(args[0])) {
            printUsage();
            System.exit(1);
        }

        if ("-s".equals(args[0])) {
            if (args[1].length() < 3) {
                printUsage();
                System.exit(1);
            }
            sid = args[1];
        }

        try {
            if ("-a".equals(args[2])) {
                processAutomatic(args.length == 5 ? args[3] : "SecStore.properties", 
                     args.length == 5 ? args[4] : "SecStore.key");
            } else if ("-m".equals(args[2])) {
                if (args.length < 4) {
                    printUsage();
                    System.exit(1);
                }
                processManual(args.length == 6 ? args[4] : "SecStore.properties", 
                       args.length == 6 ? args[5] : "SecStore.key", 
                       args[3]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean isHelpCommand(String arg) {
        return arg.equals("help") || arg.equals("-help") || arg.equals("h") || 
               arg.equals("-h") || arg.equals("?") || arg.equals("-?");
    }

    private static void processAutomatic(String propFile, String secFile) throws Exception {
        System.out.print(banner);
        keyPhrase = decryptKeyFromFile(secFile);
        System.out.println("SID = " + sid);
        System.out.println("KeyPhrase = " + keyPhrase);
        Security.addProvider(new IAIK());
        loadProperties(propFile);
        contents.remove("$internal/version");
        contents.remove("$internal/mode");
        for (String key : contents.stringPropertyNames()) {
            processKey(key);
        }
    }

    private static void processManual(String propFile, String secFile, String param) throws Exception {
        keyPhrase = decryptKeyFromFile(secFile);
        System.out.println("SID = " + sid);
        System.out.println("KeyPhrase = " + keyPhrase );
        Security.addProvider(new IAIK());
        loadProperties(propFile);
        processKey(param);
    }

    private static void processKey(String key) throws Exception {
        byte[] decryptedBytes = decryptValue(key);
        String decryptedValue = new String(decryptedBytes, "UTF-8");
        if (decryptedValue.contains("|")) {
            String[] parts = decryptedValue.split("\\|");
            System.out.println(key + " = " + parts[2].substring(0, Integer.parseInt(parts[1])) );
        } else {
            System.out.println(key + " = " + decryptedValue );
        }
    }

    private static String decryptKeyFromFile(String file) throws IOException {
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file))) {
            byte[] bytes = in.readAllBytes();
            int delimIndex = findIndexOf(bytes, (byte) 124);
            String version = new String(bytes, 0, delimIndex, "UTF-8");
            if (version.startsWith("7.00.000")) {
                verNum = 1;
            }
            return decryptKey(Arrays.copyOfRange(bytes, delimIndex + 1, bytes.length));
        }
    }

    private static int findIndexOf(byte[] array, byte target) {
        for (int i = 0; i < array.length; i++) {
            if (array[i] == target) return i;
        }
        return -1;
    }

    private static String decryptKey(byte[] ciphertext) {
        byte[] plaintext = xorBytes(ciphertext);
        try {
            return new String(plaintext, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    private static byte[] xorBytes(byte[] array) {
        byte[] hash = {43, -74, -113, -6, -106, -20, -74, 16, 36, 71, -110, 101, 23, -80, 9, -60, 62, 10, -41, -67};
        for (int i = 0; i < array.length; i++) {
            array[i] ^= hash[i % 20];
            if ((i + 1) % 20 == 0 && i < array.length - 1) {
                try {
                    hash = MessageDigest.getInstance("SHA").digest(hash);
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("SHA algorithm not found");
                }
            }
        }
        return array;
    }

    private static byte[] decryptValue(String value) throws Exception {
        byte[] ciphertext = getPropertyValue(value);
        Cipher cipher = Cipher.getInstance("PbeWithSHAAnd3_KeyTripleDES_CBC", "IAIK");
        String rawKey = verNum == 1 ? keyPhrase : keyPhrase + sid;
        PBEKeyBMP key = new PBEKeyBMP(rawKey);
        byte[] salt = new byte[16];
        pbeParamSpec = new PBEParameterSpec(salt, 0);
        cipher.init(Cipher.DECRYPT_MODE, key, pbeParamSpec);
        return cipher.doFinal(ciphertext);
    }

    private static byte[] getPropertyValue(String key) {
        String stringValue = contents.getProperty(key);
        if (stringValue == null) {
            System.out.println("[!] key '" + key + "' not found in properties file");
            System.exit(1);
        }
        return decodeBase64(stringValue);
    }

    private static void loadProperties(String file) throws IOException {
        contents = new Properties();
        try (FileInputStream fis = new FileInputStream(file)) {
            contents.load(fis);
        }
    }

    private static byte[] decodeBase64(String encodedString) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(encodedString.getBytes());
             Base64InputStream b64is = new Base64InputStream(bais)) {
            return b64is.readAllBytes();
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    private static void printUsage() {
        String helpText = 
            "Usage: java -jar SecStore_Cr.jar -s <SID> [-a | -m <parameter>] [/path/to/propertiesfile /path/to/keyfile]\n\n" +
            "Options:\n" +
            "  -s <SID>         Specify the SID (System ID)\n" +
            "  -a               Automatic decode\n" +
            "  -m <parameter>   Manual decode. Requires parameter name\n\n" +
            "File paths (optional):\n" +
            "  propertiesfile   Full path to the SecStore.properties file\n" +
            "                   Default: 'SecStore.properties' in current directory\n" +
            "  keyfile          Full path to the SecStore.key file\n" +
            "                   Default: 'SecStore.key' in current directory\n\n" +
            "Examples:\n" +
            "  1. Decrypt specific key for SID 'J01':\n" +
            "     java -jar SecStore_Cr.jar -s J01 -m jdbc/pool/SID\n\n" +
            "  2. Automatic decrypt all for SID 'J01':\n" +
            "     java -jar SecStore_Cr.jar -s J01 -a\n\n" +
            "  3. Automatic decrypt with custom file locations:\n" +
            "     java -jar SecStore_Cr.jar -s J01 -a /tmp/SecStore.properties /tmp/SecStore.key\n" +
            "==================================================================================================";

        System.out.println(banner + helpText);
    }
}
