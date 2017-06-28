package demos;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

/**
 * PBE - Password based encryption.
 *
 * @author jose a manas
 * @version 10-Jun-17
 */
public class PBE_key {
    public static byte[] mkKey(int keyBits, String password, byte[] salt)
            throws Exception {
        int iterations = 1000;

        PKCS5S2ParametersGenerator parametersGenerator =
                new PKCS5S2ParametersGenerator();
        parametersGenerator.init(password.getBytes("UTF-8"), salt, iterations);

        KeyParameter keyParameter =
                (KeyParameter) parametersGenerator.generateDerivedParameters(keyBits);
        return keyParameter.getKey();
    }

    public static void main(String[] args)
            throws Exception {
        if (args.length == 0) {
            System.out.println("key_bits password [salt]");
            System.out.println("  key_bits: dec");
            System.out.println("  password: string");
            System.out.println("  salt: hex");
            System.exit(1);
        }

        byte[] salt = new byte[0];
        if (args.length > 2)
            salt = Hex.decode(args[2]);

        int keyBits = Integer.parseInt(args[0]);
        byte[] key = mkKey(keyBits, args[1], salt);
        System.out.println(Hex.toHexString(key));
    }
}
