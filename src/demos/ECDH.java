package demos;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ECDH {
    public static final String ENC_ALG = "ECDH";

    public static KeyPair generate()
            throws Exception {
//        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");

        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        ECParameterSpec ecSpec =
                new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ENC_ALG, "BC");
        keyGen.initialize(ecSpec);
        return keyGen.generateKeyPair();
    }

    public static void encrypt(Reader in, Writer out, PublicKey publicKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(ENC_ALG, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] redData = getBase64Bytes(in);
        byte[] blackData = cipher.doFinal(redData);
        out.write(Base64.toBase64String(blackData));
    }

    public static void decrypt(Reader in, Writer out, PrivateKey privateKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(ENC_ALG, "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] blackData = getBase64Bytes(in);
        byte[] redData = cipher.doFinal(blackData);
        out.write(Base64.toBase64String(redData));
    }

    public static void main(String[] args)
            throws Exception {
        if (args.length == 0) {
            System.out.println("gen key_file");
            System.out.println("encrypt file key_file");
            System.out.println("decrypt file key_file");
            System.out.println("  key_file: base64");
            System.out.println("  encrypt: base64 -> base64");
            System.out.println("  decrypt: base64 -> base64");
            System.exit(1);
        }

        Setup.BC();

        String command = args[0];
        if (command.equalsIgnoreCase("gen")) {
            KeyPair keyPair = generate();

            String filename = args[1];
            PrintWriter pubWriter = new PrintWriter(filename + ".pub");
            PublicKey publicKey = keyPair.getPublic();
            pubWriter.println(Base64.toBase64String(publicKey.getEncoded()));
            pubWriter.close();

            PrintWriter secWriter = new PrintWriter(filename + ".sec");
            PrivateKey privateKey = keyPair.getPrivate();
            secWriter.println(Base64.toBase64String(privateKey.getEncoded()));
            secWriter.close();

            ECPublicKey ecPub = (ECPublicKey) publicKey;
            System.out.println("public:");
            System.out.println("  curve: " + ecPub.getParams().getCurve().toString());
            System.out.println("  w: " + ecPub.getW().toString());

            ECPrivateKey ecSec = (ECPrivateKey) privateKey;
            System.out.println("private:");
            System.out.println("  s: " + ecSec.getS().toString(16));
        }

        if (command.equalsIgnoreCase("encrypt")) {
            PublicKey publicKey = getPubKey(args[2]);
            File file = new File(args[1]);
            File blackFile = new File(args[1] + ".enc");
            Reader red_in = new FileReader(file);
            Writer black_out = new FileWriter(blackFile);
            encrypt(red_in, black_out, publicKey);
            red_in.close();
            black_out.close();
        }

        if (command.equalsIgnoreCase("decrypt")) {
            PrivateKey privateKey = getSecKey(args[2]);
            File file = new File(args[1]);
            File redFile = new File(args[1] + ".dec");
            Reader black_in = new FileReader(file);
            Writer red_out = new FileWriter(redFile);
            decrypt(black_in, red_out, privateKey);
            black_in.close();
            red_out.close();
        }
    }

    private static PrivateKey getSecKey(String filename)
            throws Exception {
        Reader secReader = new FileReader(filename + ".sec");
        byte[] encoded = getBase64Bytes(secReader);
        KeyFactory keyFactory = KeyFactory.getInstance(ENC_ALG, "BC");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    private static PublicKey getPubKey(String filename)
            throws Exception {
        Reader secReader = new FileReader(filename + ".pub");
        byte[] encoded = getBase64Bytes(secReader);
        KeyFactory keyFactory = KeyFactory.getInstance(ENC_ALG, "BC");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static byte[] getBase64Bytes(Reader reader)
            throws IOException {
        StringBuilder builder = new StringBuilder();
        char[] buffer = new char[1024];
        while (true) {
            int n = reader.read(buffer);
            if (n < 0)
                break;
            builder.append(buffer, 0, n);
        }
        return Base64.decode(builder.toString());
    }
}
