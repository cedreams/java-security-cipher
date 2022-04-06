import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

/**
 * Cipher example (JCA - Java Crypto Architecture)
 * 
 * @author Cédric Thonus
 */
public class MainApp {

    public static void main(String[] args) {
        try {
            //Cipher asymmetric
            KeyPair keyPair = generateKeyPair("RSA", 2048); //Min 512
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            //Cipher symmetric
            SecretKey secretKey = generateKey("AES"); //Session key

            //Wrap secretkey with public key
            Cipher cipherWrap = Cipher.getInstance("RSA");
            cipherWrap.init(Cipher.WRAP_MODE, publicKey);
            byte[] byteSecretKeyWrap = cipherWrap.wrap(secretKey);

            //Unwrap secretkey with private key
            Cipher cipherUnwrap = Cipher.getInstance("RSA");
            cipherUnwrap.init(Cipher.UNWRAP_MODE, privateKey);
            Key key = cipherUnwrap.unwrap(byteSecretKeyWrap, "AES", Cipher.SECRET_KEY);


            String text = "Hello World";

            //Encrypt text with secret key who have unwrap by private key
            Cipher cipherEncrypt = Cipher.getInstance("AES");
            cipherEncrypt.init(Cipher.ENCRYPT_MODE, key);
            byte[] textEncrypted = cipherEncrypt.doFinal(text.getBytes());

            //Decrypt with secret key who have unwrap by private key
            Cipher cipherDecrypt = Cipher.getInstance("AES");
            cipherDecrypt.init(Cipher.DECRYPT_MODE, key);
            byte[] textDecrypt = cipherDecrypt.doFinal(textEncrypted);

            System.out.println("Decrypt with secretkey: " + new String(textDecrypt));


            System.out.println("-----------------------------------------");

            //Encrypt a text with public key in selead object
            Cipher cipherEncryptWithPublicKey = Cipher.getInstance("RSA");
            cipherEncryptWithPublicKey.init(Cipher.ENCRYPT_MODE, publicKey);
            String secretText = "i love java";
            SealedObject sealed  = new SealedObject(secretText, cipherEncryptWithPublicKey);

            //Decrypt a text with private key in sealed object
            Cipher cipherDecryptWithPrivateKey = Cipher.getInstance("RSA");
            cipherDecryptWithPrivateKey.init(Cipher.DECRYPT_MODE, privateKey);
            String decryptSecretText = (String) sealed.getObject(cipherDecryptWithPrivateKey);

            System.out.println("Decrypt with privatekey : " + decryptSecretText);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("Hello".getBytes());
            System.out.println(String.valueOf(md.digest()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(algorithm);
        SecureRandom random = new SecureRandom();
        keygen.init(random);
        return keygen.generateKey();
    }

    public static KeyPair generateKeyPair(String algorithm, int size) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        kpg.initialize(size);
        return kpg.genKeyPair();
    }

}