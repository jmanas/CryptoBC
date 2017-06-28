package demos;

import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ElGamal {
    public static final String ENC_ALG = "ElGamal";

    // plain prime generation is very slow because
    // the algorithm needs to find a prime p for which (p-1)/2 is a safe prime

    // RFC 5996 Internet Key Exchange Protocol Version 2 (IKEv2)
    // RFC 3526 More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)
    private static MODP modp1024 = new MODP(2,
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08" +
                    "        8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B" +
                    "        302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9" +
                    "        A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6" +
                    "        49286651 ECE65381 FFFFFFFF FFFFFFFFF");
    private static MODP modp1536 = new MODP(2,
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" +
                    "      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD" +
                    "      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" +
                    "      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED" +
                    "      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" +
                    "      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F" +
                    "      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" +
                    "      670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF");
    private static MODP modp2048 = new MODP(2,
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" +
                    "      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD" +
                    "      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" +
                    "      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED" +
                    "      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" +
                    "      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F" +
                    "      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" +
                    "      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B" +
                    "      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" +
                    "      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" +
                    "      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF");

    private static MODP modp3072 = new MODP(2,
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" +
                    "      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD" +
                    "      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" +
                    "      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED" +
                    "      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" +
                    "      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F" +
                    "      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" +
                    "      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B" +
                    "      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" +
                    "      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" +
                    "      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64" +
                    "      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7" +
                    "      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B" +
                    "      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C" +
                    "      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31" +
                    "      43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF");


    public static KeyPair generate()
            throws Exception {
        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance(ENC_ALG, "BC");
        BigInteger p = modp3072.p;
        BigInteger g = modp3072.g;
        ElGamalParameterSpec elgParams = new ElGamalParameterSpec(p, g);
        elgKpg.initialize(elgParams);
        return elgKpg.generateKeyPair();
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
            System.out.println("gen key_file (fixed size: 3072 bits)");
            System.out.println("encrypt file key_file");
            System.out.println("decrypt file key_file");
            System.out.println("  file: bytes");
            System.out.println("  key_file: base64");
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

            ElGamalPublicKey elgPub = (ElGamalPublicKey) publicKey;
            System.out.println("public:");
            System.out.println("  p: " + elgPub.getParameters().getP().toString(16));
            System.out.println("  g: " + elgPub.getParameters().getG().toString(16));
            System.out.println("  y: " + elgPub.getY().toString(16));

            ElGamalPrivateKey elgSec = (ElGamalPrivateKey) privateKey;
            System.out.println("private:");
            System.out.println("  x: " + elgSec.getX().toString(16));
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

    private static class MODP {
        final BigInteger g;
        final BigInteger p;

        MODP(int g, String p) {
            this.g = BigInteger.valueOf(g);
            this.p = new BigInteger(p.replaceAll(" ", ""), 16);
        }

        public int size() {
            return p.bitLength();
        }

        public BigInteger[] getParams() {
            return new BigInteger[]{p, g};
        }
    }
}
