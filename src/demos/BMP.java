package demos;

import java.io.*;

/**
 * Encrypt the pixels in a BPM file.
 * 1. remove bpm header
 * 2. encrypt pixels
 * 3. recover header
 *
 * Example:
 * 0. $PRG demos/AES_ECB gen 256 key_256
 * 1. $PRG demos/BMP remove duck.bmp
 * 2. $PRG demos/AES_ECB encrypt duck.bmp.img key_256
 * 3. $PRG demos/BMP recover duck.bmp duck_enc.bmp
 */
public class BMP {
    public static void main(String[] args)
            throws Exception {
        if (args.length == 0) {
            System.out.println("remove source.bmp");
            System.out.println("recover source.bmp destination.bmp");
            System.exit(1);
        }

        String command = args[0];

        if (command.equalsIgnoreCase("remove")) {
            File srcFile = new File(args[1]);
            File strippedFile = new File(args[1] + ".img");
            InputStream in = new FileInputStream(srcFile);
            OutputStream out = new FileOutputStream(strippedFile);
            byte[] header = new byte[54];
            in.read(header);
            byte[] buffer = new byte[1024];
            while (true) {
                int n = in.read(buffer);
                if (n < 0)
                    break;
                out.write(buffer, 0, n);
            }
            in.close();
            out.close();
        }

        if (command.equalsIgnoreCase("recover")) {
            File srcFile = new File(args[1]);
            File encFile = new File(args[1] + ".img.enc");
            File dstFile = new File(args[2]);
            InputStream srcIn = new FileInputStream(srcFile);
            InputStream imgIn = new FileInputStream(encFile);
            OutputStream out = new FileOutputStream(dstFile);
            byte[] header = new byte[54];
            srcIn.read(header);
            out.write(header);
            byte[] buffer = new byte[1024];
            while (true) {
                int n = imgIn.read(buffer);
                if (n < 0)
                    break;
                out.write(buffer, 0, n);
            }
            srcIn.close();
            imgIn.close();
            out.close();
        }
    }
}
