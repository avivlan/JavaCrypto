import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Decrypt {

    public static void main(String[] args) {


        try
        {
            if (args.length != 6)
            {
                System.out.println("Usage: keyStorePassword keyStoreBName sideAAlias sideBAlias encrypted.txt decrypted.txt");
            }
            // get information from keystore
            char[] keyStorePassword = args[0].toCharArray();
            String keyStoreBName = args[1];
            String sideAAlias = args[2];
            String sideBAlias = args[3];
            String encryptedTextName = args[4];
            String decryptedTextName = args[5];

            FileInputStream keyStoreFile = new FileInputStream(keyStoreBName);
            KeyStore keyStoreB = KeyStore.getInstance("JKS");
            keyStoreB.load(keyStoreFile, keyStorePassword);
            Certificate sideACert = keyStoreB.getCertificate(sideAAlias);
            // decrypt AES key from conf file using our private key and gather information from conf file
            PrivateKey privKey = (PrivateKey)keyStoreB.getKey(sideBAlias, keyStorePassword);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            byte[] encryptedKey;
            byte[] decodedAlgParams;
            byte[] sig;
            FileReader fr = new FileReader("conf.txt");
            try (BufferedReader reader = new BufferedReader(fr))
            {
                encryptedKey = Base64.getDecoder().decode(reader.readLine());
                decodedAlgParams = Base64.getDecoder().decode(reader.readLine());
                sig = Base64.getDecoder().decode(reader.readLine());
            }

            byte[] decryptedKey = cipher.doFinal(encryptedKey);
            SecretKey sKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
            AlgorithmParameters algParams = AlgorithmParameters.getInstance("AES");
            algParams.init(decodedAlgParams);
            // decrypt encrypted message
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, sKey, algParams);
            FileInputStream fis = new FileInputStream(encryptedTextName);
            CipherInputStream cis = new CipherInputStream(fis, cipher);
            FileOutputStream fos = new FileOutputStream(decryptedTextName);
            byte[] b = new byte[8];
            int i = cis.read(b);
            while (i != -1) {
                fos.write(b, 0, i);
                i = cis.read(b);
            }
            fos.close();
            // gather plain text
            Scanner in = new Scanner(new FileReader(decryptedTextName));
            StringBuilder sb = new StringBuilder();
            while(in.hasNext()) {
                sb.append(in.nextLine());
                if (in.hasNextLine()) {sb.append(System.getProperty("line.separator")); }

            }
            // verify digital signature
            String data = sb.toString();
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(sideACert.getPublicKey());
            sign.update(data.getBytes());
            boolean verifies = sign.verify(sig);

            in.close();
            if (!verifies)
            {
                System.out.println("Signature failed to verify!");
                PrintWriter writer = new PrintWriter(fos);
                writer.println("Signature failed to verify!");
                writer.flush();
                writer.close();
            }

            System.out.println(data);

            try {
                if (fis != null) { fis.close();}
                if (fos != null) { fos.close();}
                if (cis != null) { cis.close();}
                if (keyStoreFile != null) { keyStoreFile.close();}
            }

            catch (Exception ex)
            {
                ex.printStackTrace();
            }

        }

        catch (Exception ex)
        {
            ex.printStackTrace();
        }
    }

}
