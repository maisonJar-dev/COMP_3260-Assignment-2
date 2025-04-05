
// Maison Gulyas T00722026 
// 2023-10-23
// COMP 3260 - Assignment 2
// MARK: Import Libraries
import java.security.*;
import java.security.spec.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;

import java.util.Base64;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;

public class Create_RSA_Keys {
    public static void main(String[] args) {
        PrivateKey Alices_privateKey = null;
        PublicKey Alices_publicKey = null;

        PrivateKey Bobs_privateKey = null;
        PublicKey Bobs_publicKey = null;
        try {
            // MARK: Genrate Key Pair
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048); // Key size in bits
            KeyPair keyPair = generator.generateKeyPair();

            Alices_privateKey = keyPair.getPrivate();
            Alices_publicKey = keyPair.getPublic();

            Bobs_privateKey = keyPair.getPrivate();
            Bobs_publicKey = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        
        // MARK: Part 1
        System.out.println("||PART 1: RSA Key Generation||");
        System.out.println("=============Alice's Public Key=============");
        System.out.println(Base64.getEncoder().encodeToString(Alices_publicKey.getEncoded()));
        System.out.println("=============End of Public Key=============");
        System.out.println("=============Alice's Private Key=============");
        System.out.println("Alice's Private Key: " + Base64.getEncoder().encodeToString(Alices_privateKey.getEncoded()));
        System.out.println("=============End of Private Key=============\n");
        System.out.println("=============Bob's Public Key=============");
        System.out.println(Base64.getEncoder().encodeToString(Bobs_publicKey.getEncoded()));
        System.out.println("=============End of Public Key=============");
        System.out.println("=============Bob's Private Key=============");
        System.out.println("Alice's Private Key: " + Base64.getEncoder().encodeToString(Bobs_privateKey.getEncoded()));
        System.out.println("=============End of Private Key=============");


        // MARK: Part 2
        System.out.println("\n||PART 2: DES Key Generation||");

        // NOTE: Generate DES Key
        SecretKey desKey = null;
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            SecureRandom secRandom = new SecureRandom();
            keyGen.init(secRandom); // Key size in bits
            desKey = keyGen.generateKey();
           
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        String generatedDESKey = Base64.getEncoder().encodeToString(desKey.getEncoded());
        System.out.println("Alice: The DES key is: " + generatedDESKey);

        // MARK: Part 3
        System.out.println("\n||PART 3:Message  DES Encryption||");
    
        String pt = "Protect your network as if it would be a hotel not as if it would be a castle.";
        System.out.println("Alice: Plaintext is: " + pt);
        System.out.println("DES Key: " + generatedDESKey);
        byte[] desEncrypted = encryptWihDES(pt, desKey);
        String desEncryptedString = converteByteArray(desEncrypted);
        System.out.println("Cipher text is: " + desEncryptedString);

        // MARK: Part 4
        System.out.println("\n||PART 4: MAC Algorithm & Signature||");
        byte[] alice_signauture = signWithMac(pt, Alices_privateKey);
        String alice_signautureString = converteByteArray(alice_signauture);
        System.out.println("Alice: Digitally signed message is:  " + alice_signautureString);

        // MARK: Part 5
        System.out.println("\n||PART 5: DES Key Encryption||");
        byte[] encryptedDESKey = encryptDESKey(desKey, Bobs_publicKey);
        String encryptedDESKeyString = converteByteArray(encryptedDESKey);
        System.out.println("Alice: Encrypted DES key is: " + encryptedDESKeyString);


        // MARK: Part 6
        System.out.println("\n||PART 6: MAC Verification||");
        String verified = verifyWithMac(pt, alice_signauture, Alices_publicKey) ? "Bob: Message is signed by Alice!" : "Bob: Message is not signed by Alice!"; 
        System.out.println(verified);

        // MARK: Part 7
        System.out.println("\n||PART 7: DES Key Decryption||");
        byte[] decryptedDESKey = desDecrypt(encryptedDESKey, Bobs_privateKey);
        String decryptedDESKeyString = converteByteArray(decryptedDESKey);
        //Assuming you meant to to print the decoded key here instead of the encrypted one?
        System.out.println("Bob: The decrypted DES key is: " + decryptedDESKeyString);

        // MARK: Part 8
        System.out.println("\n||PART 8: Message Decryption||");
        String decryptedMessage = decryptMessage(desEncrypted, decryptedDESKey);
        
        System.out.println(pt.equals(decryptedMessage) ? "The Decrypted Message is: \n" + decryptedMessage + "!" : "Error In Decryption"); 
    }





    // MARK: Encryption W/ DES
    protected static byte[] encryptWihDES(String pt, SecretKey key) {
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted = cipher.doFinal(pt.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    // MARK: MAC Algorithm
    //User Private key to generate MAC
    protected static byte[] signWithMac(String pt, PrivateKey alicePrivateKey) {
        byte[] digiSig = null;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(alicePrivateKey);
            signature.update(pt.getBytes());
            digiSig = signature.sign();
            return digiSig;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return digiSig;
    }

    // MARK: DES Key Encrypt
    protected static byte[] encryptDESKey(SecretKey desKey, PublicKey bobsPublicKey) {
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, bobsPublicKey);
            encrypted = cipher.doFinal(desKey.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    // MARK: MAC Vaerifcation
    protected static boolean verifyWithMac(String pt, byte[] signature, PublicKey alicePublicKey) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(alicePublicKey);
            sig.update(pt.getBytes());
            return sig.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // MARK: DES Key Decrypt
    protected static byte[] desDecrypt(byte[] encryptedDES, PrivateKey bobsPrivateKey) {
        byte[] decrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, bobsPrivateKey);
            String stringDES = converteByteArray(encryptedDES);
            decrypted = cipher.doFinal(Base64.getDecoder().decode(stringDES));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decrypted;
    }
    // MARK: Message Decryption
    protected static String decryptMessage(byte[] encryptedMessage, byte[] desKeyBytes) {
        byte[] decrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("DES");
            SecretKey desKey = new SecretKeySpec(desKeyBytes, "DES");
            cipher.init(Cipher.DECRYPT_MODE, desKey);
            decrypted = cipher.doFinal(encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new String(decrypted, StandardCharsets.UTF_8);
    }
    // Converting Byte[] to String
    public static String converteByteArray(byte[] input){
        return Base64.getEncoder().encodeToString(input);
    }
}