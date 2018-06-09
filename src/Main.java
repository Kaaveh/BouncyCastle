import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.*;


/**
 * Created by kaaveh on 4/25/18.
 */
public class Main {

    private static final String text = "It's example of Bouncy Castle";

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        //RSA
        System.out.println("-----------------RSA----------------");
        KeyPair RSAkeyPair = RSAgenerateKey();
        byte[] RSAcipherText = RSAencrypt(text.getBytes(), RSAkeyPair.getPublic());
        System.out.println(new sun.misc.BASE64Encoder().encode(RSAcipherText));

        System.out.println("**************************************************************");
        byte[] RSAdectyptedText = RSAdecrypt(RSAcipherText, RSAkeyPair.getPrivate());
        System.out.println(new String(RSAdectyptedText));

        System.out.println("**************************************************************");
        byte[] RSAsingedText = RSAsignature(text.getBytes(), RSAkeyPair.getPrivate());
        System.out.println(new sun.misc.BASE64Encoder().encode(RSAsingedText));

        if (RSAsignatureVerify(RSAsingedText, RSAkeyPair.getPublic())){
            System.out.println("Validation successful!");
        }else {
            System.out.println("Validation failed!");
        }

        //DES
        System.out.println("-----------------DES----------------");
        Key DESkey = DESKeyGenerator();
        byte[] DEScipherText = DESencrypt(text.getBytes(), DESkey);
        System.out.println(new sun.misc.BASE64Encoder().encode(DEScipherText));

        System.out.println("**************************************************************");

        byte[] DESdectyptedText = DESdencrypt(DEScipherText, DESkey);
        System.out.println(new String(DESdectyptedText));

        //AES
        System.out.println("-----------------AES----------------");
        Key AESkey = AESKeyGenerator();
        byte[] AEScipherText = AESencrypt(text.getBytes(), AESkey);
        System.out.println(new sun.misc.BASE64Encoder().encode(AEScipherText));

        System.out.println("**************************************************************");

        byte[] AESdectyptedText = AESdencrypt(AEScipherText, AESkey);
        System.out.println(new String(AESdectyptedText));


        //HASH
        System.out.println("-----------------HASH----------------");
        System.out.println(Hash(text));

        // ECC
        System.out.println("-----------------ECC----------------");
        KeyPair ECCkeyPair = ECCgenerateKey();
        byte[] ECCsingedText = ECCsignature(text.getBytes(), ECCkeyPair.getPrivate());
        System.out.println(new sun.misc.BASE64Encoder().encode(ECCsingedText));

        if (ECCsignatureVerify(ECCsingedText, ECCkeyPair.getPublic())){
            System.out.println("Validation successful!");
        }else {
            System.out.println("Validation failed!");
        }
    }

    // HASH
    private static String Hash(String text) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        return new String(Hex.encode(hash));
    }

    // RSA
    private static KeyPair RSAgenerateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(1024);
        KeyPair key = keyGen.generateKeyPair();
        return key;
    }

    private static byte[] RSAencrypt(byte[] text, PublicKey key) throws Exception
    {
        byte[] cipherText = null;

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text);
        return cipherText;
    }

    private static byte[] RSAdecrypt(byte[] text, PrivateKey key) throws Exception
    {
        byte[] dectyptedText = null;
        // decrypt the text using the private key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        dectyptedText = cipher.doFinal(text);
        return dectyptedText;

    }

    private static byte[] RSAsignature(byte[] text, PrivateKey privateKey) throws Exception
    {
        Signature signature = Signature.getInstance("SHA1withRSA", "BC");
        signature.initSign(privateKey, new SecureRandom());
        signature.update(text);
        return signature.sign();
    }

    private static boolean RSAsignatureVerify(byte[] sigText, PublicKey publicKey) throws Exception
    {
        Signature signature1 = Signature.getInstance("SHA1withRSA", "BC");
        signature1.initVerify(publicKey);
        signature1.update(text.getBytes());
        return signature1.verify(sigText);
    }

    // DES
    private static Key DESKeyGenerator() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES", "BC");
        keyGen.init(56);
        return keyGen.generateKey();
    }

    private static byte[] DESencrypt(byte[] text, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(text);
    }

    private static byte[] DESdencrypt(byte[] text, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(text);
    }

    // AES
    private static Key AESKeyGenerator() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static byte[] AESencrypt(byte[] text, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(text);
    }

    private static byte[] AESdencrypt(byte[] text, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(text);
    }

    // ECC
    private static KeyPair ECCgenerateKey() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECIES", "BC");
        keyGen.initialize(384);

        return keyGen.genKeyPair();
    }

    private static byte[] ECCsignature(byte[] text, PrivateKey privateKey) throws Exception
    {
        Signature signature = Signature.getInstance("SHA1withECDSA", "BC");
        signature.initSign(privateKey);
        signature.update(text);
        return signature.sign();
    }

    private static boolean ECCsignatureVerify(byte[] sigText, PublicKey publicKey) throws Exception
    {
        Signature signature1 = Signature.getInstance("SHA1withECDSA", "BC");
        signature1.initVerify(publicKey);
        signature1.update(text.getBytes());
        return signature1.verify(sigText);
    }
}