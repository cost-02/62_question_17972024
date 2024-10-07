package com.example;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.UnsupportedEncodingException;
import java.security.Security;

public class Test {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final String UTF8 = "utf-8";
    public static final String KEY = "CLp4j13gADa9AmRsqsXGJ";  // Assicurati che la chiave abbia la lunghezza corretta

    public static byte[] encrypt(String inputString) throws UnsupportedEncodingException, CryptoException {
        final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CAST6Engine());
        byte[] keyBytes = KEY.getBytes(UTF8);
        byte[] inputBytes = inputString.getBytes(UTF8);

        // Assicurati che la chiave sia della lunghezza adeguata, o troncala/espandila secondo necessità
        KeyParameter key = new KeyParameter(keyBytes);

        cipher.init(true, key);
        byte[] cipherText = new byte[cipher.getOutputSize(inputBytes.length)];
        int outputLen = cipher.processBytes(inputBytes, 0, inputBytes.length, cipherText, 0);
        cipher.doFinal(cipherText, outputLen); // Gestisci l'eccezione CryptoException qui

        return cipherText;
    }

    public static void main(String[] args) {
        try {
            final String toEncrypt = "hola";
            final String encrypted = new String(Base64.encode(encrypt(toEncrypt)), UTF8);
            System.out.println("Encrypted: " + encrypted);
        } catch (Exception e) {
            System.err.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
