
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class Encrypt {

    public static void main(String[] args) {

        try {
            if (args.length != 5)
            {
                System.out.println("Usage: keyStorePassword keyStoreAName sideAAlias sideBAlias plaintext.txt");
            }
            // get information from keystore
            char[] keyStorePassword = args[0].toCharArray();
            String keyStoreAName = args[1];
            String sideAAlias = args[2];
            String sideBAlias = args[3];
            String plainTextName = args[4];
            FileInputStream keyStoreFile = new FileInputStream(keyStoreAName);
            KeyStore keyStoreA = KeyStore.getInstance("JKS");
            keyStoreA.load(keyStoreFile, keyStorePassword);
            Certificate sideBCert = keyStoreA.getCertificate(sideBAlias);

            // create key
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            SecretKey sKey = kg.generateKey();
            // create IV
            byte[] iv= new byte[16];
            SecureRandom secRand = new SecureRandom();
            secRand.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            // create cipher
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, sKey, ivSpec);
            // encrypt
            FileInputStream fis = new FileInputStream(plainTextName);
            FileOutputStream fos = new FileOutputStream("encrypted.txt");
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);
            byte[] b = new byte[8];
            int i = fis.read(b);
            while (i != -1)
            {
                cos.write(b,0, i);
                i = fis.read(b);
            }
            AlgorithmParameters algParams = cipher.getParameters();
            byte[] encodedAlgParams = algParams.getEncoded();
            // save plain text
            Scanner in = new Scanner(new FileReader(plainTextName));
            StringBuilder sb = new StringBuilder();
            while(in.hasNext()) {
                sb.append(in.nextLine());
                if (in.hasNextLine()) {sb.append(System.getProperty("line.separator")); }
            }
            in.close();
            String data = sb.toString();
            // sign
            Signature sign = Signature.getInstance("SHA256withRSA");
            PrivateKey privKey = (PrivateKey)keyStoreA.getKey(sideAAlias, keyStorePassword);
            sign.initSign(privKey);
            sign.update(data.getBytes());
            byte[] sig = sign.sign();
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sideBCert.getPublicKey());
            byte[] encryptedKey = cipher.doFinal(sKey.getEncoded());
            // create configuration file
            FileWriter fw = new FileWriter("conf.txt");
            PrintWriter writer = new PrintWriter(fw);
            writer.println(new String(Base64.getEncoder().encode(encryptedKey)));
            writer.println(new String(Base64.getEncoder().encode(encodedAlgParams)));
            writer.println(new String(Base64.getEncoder().encode(sig)));

            fw.flush();
            writer.flush();
            fw.close();
            writer.close();
            System.out.println(data);
            try
            {
                if (fis != null) { fis.close();}
                if (fos != null) { fos.close();}
                if (cos != null) { cos.close();}
                if (keyStoreFile != null) { keyStoreFile.close();}

            }
            catch (Exception ex)
            {
                ex.printStackTrace();
            }

        }
        catch (Exception ex) {
            ex.printStackTrace();

        }



    }


}
