import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;

public class JwtUtil {


    public static void main(String[] args) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        System.out.println(generateToken());
    }

    public static String generateToken() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {

        Properties props = getProperties();
        String encryptedSecret = props.getProperty(CitrusConstants.ENCRYPTED_SECRET_KEY_PROPERTY_NAME);
        String encryptionKey = System.getProperty(CitrusConstants.ENCRYPTION_KEY_PROPERTY_NAME);

        String secret = decryptAES(encryptedSecret, encryptionKey);
        String jwt = JwtGenerator.generate(secret);

        return jwt;
    }

    public static String decryptAES(String encrypted, String aesEncryptionKey) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException {

            IvParameterSpec iv = new IvParameterSpec(new byte[16]);
            SecretKeySpec skeySpec = new SecretKeySpec(aesEncryptionKey.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(decrypted);
    }


    public static Properties getProperties() throws IOException {

        InputStream input = new FileInputStream("src/main/resources/config.properties");
        if (input == null) {
            System.err.println("Unable to find config.properties");
            return null;
        }
        Properties props = new Properties();

        // load a properties file
        props.load(input);


        return props;
    }



}
