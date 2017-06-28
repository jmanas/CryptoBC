package demos;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Created by jose on 07-Jun-17.
 */
public class Digester {
    // uncomment as needed
//    public static final String ALGORITHM = "MD2";
//    public static final String ALGORITHM = "MD3";
//    public static final String ALGORITHM = "MD5";
//    public static final String ALGORITHM = "RIPEMD128";
//    public static final String ALGORITHM = "RIPEMD160";
//    public static final String ALGORITHM = "RIPEMD256";
//    public static final String ALGORITHM = "RIPEMD320";
//    public static final String ALGORITHM = "SHA-1";
//    public static final String ALGORITHM = "SHA224";
    public static final String ALGORITHM = "SHA256";
//    public static final String ALGORITHM = "SHA384";
//    public static final String ALGORITHM = "SHA512";
//    public static final String ALGORITHM = "SHA3-224";
//    public static final String ALGORITHM = "SHA3-256";
//    public static final String ALGORITHM = "SHA3-384";
//    public static final String ALGORITHM = "SHA3-512";
//    public static final String ALGORITHM = "Whirlpool";

    private final String algorithm;

    public Digester(String algorithm) {
        this.algorithm = algorithm;
    }

    public byte[] hash(File file)
            throws IOException, NoSuchAlgorithmException {
        byte[] buffer = new byte[1024];
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        try (
                InputStream is = new FileInputStream(file);
        ) {
            while (true) {
                int n = is.read(buffer);
                if (n < 0)
                    break;
                messageDigest.update(buffer, 0, n);
            }
        }
        return messageDigest.digest();
    }

    // smoke test
    public static void main(String[] args)
            throws Exception {
        Setup.BC();

        Digester hashFile = new Digester(ALGORITHM);

        File file = new File(args[0]);
        byte[] digest = hashFile.hash(file);
        System.out.println(DatatypeConverter.printHexBinary(digest));
    }
}
