package demos;

import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class DSA {
    public static final String SIGN_ALG = "SHA256withDSA";

    public static KeyPair generate(int size)
            throws Exception {
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
        dsaKpg.initialize(size);
        return dsaKpg.generateKeyPair();
    }

    public static void sign(InputStream in, Writer out, PrivateKey privateKey)
            throws Exception {
        Signature signer = Signature.getInstance(SIGN_ALG, "BC");
        signer.initSign(privateKey);
        byte[] buffer = new byte[1024];
        while (true) {
            int n = in.read(buffer);
            if (n < 0)
                break;
            signer.update(buffer, 0, n);
        }
        byte[] signature = signer.sign();
        out.write(Base64.toBase64String(signature));
    }

    public static boolean verify(InputStream in, byte[] signature, PublicKey publicKey)
            throws Exception {
        Signature signer = Signature.getInstance(SIGN_ALG, "BC");
        signer.initVerify(publicKey);
        byte[] buffer = new byte[1024];
        while (true) {
            int n = in.read(buffer);
            if (n < 0)
                break;
            signer.update(buffer, 0, n);
        }
        return signer.verify(signature);
    }

    public static void main(String[] args)
            throws Exception {
        if (args.length == 0) {
            System.out.println("gen size key_file");
            System.out.println("sign file key_file");
            System.out.println("verify file key_file");
            System.out.println("  key_file: base64");
            System.out.println("  file: bytes");
            System.out.println("  sign: bytes -> base64");
            System.out.println("  signature: base64");
            System.exit(1);
        }

        Setup.BC();

        String command = args[0];
        if (command.equalsIgnoreCase("gen")) {
            KeyPair keyPair = generate(Integer.parseInt(args[1]));

            String filename = args[2];
            PrintWriter pubWriter = new PrintWriter(filename + ".pub");
            PublicKey publicKey = keyPair.getPublic();
            pubWriter.println(Base64.toBase64String(publicKey.getEncoded()));
            pubWriter.close();

            PrintWriter secWriter = new PrintWriter(filename + ".sec");
            PrivateKey privateKey = keyPair.getPrivate();
            secWriter.println(Base64.toBase64String(privateKey.getEncoded()));
            secWriter.close();

            DSAPublicKey dsaPub = (DSAPublicKey) publicKey;
            System.out.println("public:");
            System.out.println("  p: " + dsaPub.getParams().getP().toString(16));
            System.out.println("  q: " + dsaPub.getParams().getQ().toString(16));
            System.out.println("  g: " + dsaPub.getParams().getG().toString(16));
            System.out.println("  y: " + dsaPub.getY().toString(16));

            DSAPrivateKey dsaSec = (DSAPrivateKey) privateKey;
            System.out.println("private:");
            System.out.println("  x: " + dsaSec.getX().toString(16));
        }

        if (command.equalsIgnoreCase("sign")) {
            PrivateKey privateKey = getSecKey(args[2]);
            InputStream in = new FileInputStream(args[1]);
            Writer sigWriter = new FileWriter(args[1] + ".sig");
            sign(in, sigWriter, privateKey);
            sigWriter.close();
        }

        if (command.equalsIgnoreCase("verify")) {
            PublicKey publicKey = getPubKey(args[2]);
            InputStream in = new FileInputStream(args[1]);
            Reader sigReader = new FileReader(args[1] + ".sig");
            byte[] signature = getBase64Bytes(sigReader);
            boolean ok = verify(in, signature, publicKey);
            System.out.println("verification: " + ok);
        }
    }

    private static PrivateKey getSecKey(String filename)
            throws Exception {
        Reader secReader = new FileReader(filename + ".sec");
        byte[] encoded = getBase64Bytes(secReader);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA", "BC");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    private static PublicKey getPubKey(String filename)
            throws Exception {
        Reader secReader = new FileReader(filename + ".pub");
        byte[] encoded = getBase64Bytes(secReader);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA", "BC");
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
