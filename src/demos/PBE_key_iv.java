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
public class PBE_key_iv {

    public static byte[][] mkKeyIv(int keyBits, int ivBits, String password, byte[] salt)
            throws Exception {
        int iterations = 1000;

        PKCS5S2ParametersGenerator parametersGenerator =
                new PKCS5S2ParametersGenerator();
        parametersGenerator.init(password.getBytes("UTF-8"), salt, iterations);

        ParametersWithIV params = (ParametersWithIV) parametersGenerator.generateDerivedParameters(keyBits, ivBits);
        CipherParameters cipherParameters = params.getParameters();
        KeyParameter keyParameter = (KeyParameter) cipherParameters;
        byte[] key = keyParameter.getKey();
        byte[] iv = params.getIV();
        return new byte[][]{key, iv};
    }

    public static void main(String[] args)
            throws Exception {
        if (args.length == 0) {
            System.out.println("key_bits iv_bits password [salt]");
            System.out.println("  key_bits: dec");
            System.out.println("  iv_bits: dec");
            System.out.println("  password: string");
            System.out.println("  salt: hex");
            System.exit(1);
        }

        byte[] salt = new byte[0];
        if (args.length > 3)
            salt = Hex.decode(args[3]);

        int keyBits = Integer.parseInt(args[0]);
        int ivBits = Integer.parseInt(args[1]);
        byte[][] params = mkKeyIv(keyBits, ivBits, args[2], salt);
        System.out.println("key: " + Hex.toHexString(params[0]));
        System.out.println("iv:  " + Hex.toHexString(params[1]));
    }
}
