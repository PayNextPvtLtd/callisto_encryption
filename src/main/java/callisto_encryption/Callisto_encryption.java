package callisto_encryption;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author abhishekmukhopadhyay
 */
public class Callisto_encryption
{
    public  byte[] string2Hex(String data)
    {
        byte[] result;

        result = new byte[data.length() / 2];
        for (int i = 0; i < data.length(); i += 2)
        {
            result[i / 2] = (byte) (Integer.parseInt(data.substring(i, i + 2), 16));
        }

        return result;
    }

    /**
     * 
     * @param plainText
     * @param dataencrypt_key
     * @return
     * @throws Exception 
     */
    public String encryptAESGCMData(String plainText, byte[] dataencrypt_key) throws Exception
    {
        if (null == plainText)
        {
            return "NA";
        }

        byte[] clean = plainText.getBytes();

        int ivSize = 12;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(dataencrypt_key);
        byte[] keyBytes = new byte[16];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);

        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

        String encryptedData = Base64.getEncoder().encodeToString(encryptedIVAndText);

        return encryptedData;
    }
    
        /**
     * 
     * @param encryptedText
     * @param dataencrypt_key
     * @return
     * @throws Exception 
     */
    public String decryptAESGCMData(String encryptedText, byte[] dataencrypt_key) throws Exception
    {
        int ivSize = 12;
        int keySize = 16;

        if (null == encryptedText)
        {
            return "NA";
        }

        byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);

        byte[] iv = new byte[ivSize];
        System.arraycopy(encryptedTextBytes, 0, iv, 0, iv.length);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

        int encryptedSize = encryptedTextBytes.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedTextBytes, ivSize, encryptedBytes, 0, encryptedSize);

        byte[] keyBytes = new byte[keySize];
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(dataencrypt_key);
        System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

        return new String(decrypted);
    }

    /**
     *
     * @param key
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private PrivateKey loadPrivateKey(String key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] privateKeyBytes = Base64.getDecoder().decode(key);

        KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = privateKeyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }

    /**
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public String decryptRSA(String data, String key) throws Exception
    {
        PrivateKey privateKey = loadPrivateKey(key);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(bytes);
    }

    /**
     *
     * @param args
     */
    public static void main(String[] args)
    {
        String data = "jVG2vNCBkX8MWIhQL5OoWvvUMMgN+raiEcQfpNxZlwNO8iIbzAT0rQ2XNlCWox8LqT8dTslWswqYEz+56g8L5+n8Dg8ZjQW/KuYbed1xSOR59z/JjrBcJzYVsHJyQ2wORojtTdoQw4tQHvbKS4mBvVyeu7Nr6l2Tusz/uzGnpds7yXv+k4qbSodd7GDp6jsali2GXvk0ocgq4lYhFWT+JLH9YWuLYpCannC2Y2xAfB0tVNCstIf97XQCfpIV0lp1My0A9pmQR5ROUbpEmWn++9CC83R2/ggSY2JJhzOovm+oNTH6H3fD01akhHPH6xpph5TARq9ie66A0RyqfiLQlw==";
        String key = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCSvivjpOIDflqGVwkmDPDm7ZJN\n"
                + "FCbScCfwD6+cCNh1dU9zpdHhc1mD9sdlWu0JlIc5sKJ5pqzm0VRJiL3s6Qn5aHJzWThgQfZo7WUf\n"
                + "3lFZvwKQ5RJesIFwbk1HLFWEyL+TCs15nQ/coHqS56kI6p62sX8JWQRW/BoBy+MrEkALNP+X1FT4\n"
                + "bGmYiXdMwX8SVCrThgRrBNIQN3PGqQZUjUg5+bK/QL7uoyzXEeKDy4DSK/DmIpjfYsHScep28MbB\n"
                + "oYEEtBPTu1PyjN+/bA9AtFTzZqBIvxB5oNwl7GBuNahoJvp8oNeSDwvIhaEUj/Jq9c3D9+JrNcUy\n"
                + "RMom8Vsx7iHBAgMBAAECgf9ldRbjThz2TWZJe+PXaxskjx2YLVaqKOF0GWRRfcwrafCFBSEXv6kk\n"
                + "lHtImJVLCmZ0fKvZcGQbMqAUN3cZVgaPaqe3GPjhlLnJ0lkYr52Pb4FWrQsGbQMRuTG1A/Ic3K+X\n"
                + "+uAWNYHCCTK2X3V/tLgHmLE8xU861RMmKtHl9bhSBj5ajXDr8sODTFOPQoEzpEYFGmvpEz/gqa1/\n"
                + "tJiOHbytQK72QXgjGagqx+iwOKJ+AV+4juFablWWBTKJl9aiTtI9hMgfqsjwA5RLmqahiwivU0vW\n"
                + "FEGcWl7Rs+gBxmvaBKSbJSn9Oap0gQaVv75mdV9yOCKQhvU/zGPQES7+A8ECgYEA+IS/k8IXJO3J\n"
                + "TMwa+lbTk7wVOS64NUg5xzruQ1yqwITVxbRIbYchOZd5h+quxar0cBv3WZemU87+3xJncB/kGjG/\n"
                + "6o8O9IKNnCijCDhi0yWulvIpDrHOTuDrfJpUxy4p2twlLvTi+7Yz1T3Fx3ssb0Tng8g+6iUV91H9\n"
                + "Pa35W/kCgYEAlykSKKl54aZSekGcTRq/ipBjI3EYUDGzG63jHygHtkoggyaJxf0aHM4l++h41Ce8\n"
                + "wkU0gH4/DRW9HtWnKunYOTHrc4xXK/EC2wGMXAaXalUnbljvi6FWMebi6ghoNxmIs7IlNijnI1YN\n"
                + "H5jsZ3dy6u2TJRia+zGxg9ihrg/2lgkCgYEAviXT71oyGy9VNk101tZYTFE8a+QzTZFVo/qTEzdz\n"
                + "7pm0dvDZ+fPKmCYt9rC5yMRlAuJi/0npGXbnzAZo3oGIJgKqtO2Ao9TARRtSopeCBcxvKU9f2r5w\n"
                + "/ClcBJqRA1Vu8OZADQ2SHsXqIt6A1YCJHxm5ijtM6Bo4FGPHP8o9YQECgYBYBvXpMhClRKthQNYZ\n"
                + "3MrQkZb6K8FB6j9ojhHmsfQTxwU5+vZeky9iuPZLxayft+hnpc+WSG7FWvSAgWFRT064uAZqir60\n"
                + "+yxzh2pKqRgCN0a4LxiI0tKUSuW37l9qPvdp1gNvj9BStqj7zp1U/62ve9ylzLdsMxsyMbSt3eP2\n"
                + "qQKBgQDyg5sn3b8aBuWHgVUjcWlj8y+KYZB8KnVBe3ybzpM5X4CfzD995D9NqHV2a9t7YADTQs13\n"
                + "7YKlCz4QcqLtzV7ciFBh5+I2ZwewWquhtcPAfvH2nSwwb7GcoLM43plLfR8w8JCDt+GbeiDrE65u\n"
                + "BS2qdIy4uec9o2+PurRzgn00+A==";

        key = key.replaceAll("\n", "");

        Callisto_encryption rsad = new Callisto_encryption();
        try
        {
            String clear_aes_key = rsad.decryptRSA(data, key);

            System.out.println(clear_aes_key);
            
            String v_req = "{\"requestid\": \"IPG000061\",\"mid\": \"107201000064586\",\"tid\": \"10003183\",\"amount\": \"12000\",\"merchanturl\": \"http://paynext.co.in\",\"pan\": \"4111111111111111\",\"authenticationindicator\": \"01\",\"messagecategory\": \"01\",\"devicechannel\": \"02\",\"expirydate\": \"202310\",\"billAddrCity\": \"MUMBAI\",\"billAddrCountryCode\": \"356\",\"billAddrLine1\": \"MUMBAI\",\"billAddrPostalCode\": \"400066\",\"billAddrState\": \"Maharashtra\",\"cardholdername\": \"PayNext Card\",\"browseracceptheader\": \"*/*\",\"browseripaddress\": \"127.0.0.1\",\"notificationurl\": \"https://europa-uat.paynext.co.in/pnmpi/v2/notify\",\"browserlanguage\": \"en\",\"browserjavaenabledval\": false,\"browserscreencolordepth\": \"24\",\"browserscreenheight\": \"768\",\"browserscreenwidth\": \"1366\",\"browsertimezone\": \"-330\",\"browseruseragent\": \"mozilla/5.0+(x11;+ubuntu;+linux+x86_64;+rv:72.0)+gecko/20100101+firefox/72.0\",\"browserjavascriptenabledval\": false,\"accounttype\": \"00\",\"authenticatorindicator\": \"01\",\"cvv2\":\"999\",\"isDCC\":false,\"tran_currency\":\"356\"}";
            
            System.out.println(v_req);
            
            String enc_data = rsad.encryptAESGCMData(v_req, rsad.string2Hex(clear_aes_key));
            
            System.out.println(enc_data);
            
            String v_resp = "QekDNT688JceiCHtbpgueGk3d/jsW1wK5eVp7bWg2cfRSeSNigAr7m6N/bERdYp0yv6Ol2UCSK1JMXaCgWPT9BRkVAgvI5AfsCiguWm5GUtEEmwPtaCqrPAKWEYrp9M8DXIryGGaWhHLxYVFRKs5BTXgsHYqKg5Z0KYxGFfvwbSVoMR1fmvikD9XDHZkCGTtBz1IzuF1VKcIb6uTifk7izTMTqp2yLNxG1iYlwnc5pb52YbSpNgYBflay6krSqawJM30lGmlzsFjNTHGgwzrf39gQiItIfTd4rhIholxRSnRrKr7sj5MRYf4mUN2N9VHp5ENZBjG43OxCzxs9kXxinFv7uwM0OVsy04+b8DfKNrJayhdqfrxgMA0MzndZROQpRhuX92U01zdljnCT21001XfxZ0eCV0QCUIPWiB4oaYxKiZ78sQb3u/r+gvH+fnoV5FvhGI/jQGd1JiR0NjyHcnrdykwxb1rw4HHssDZSVKuNWSwi+/ma9F1XyyDV/fJyWoBbiylTNFXM1W2I8EEh6QyDYA9C2trDr6bIuCuqidd+lhvH3PUlN2k7GZpm9vJ0clHL8thjaiZxyIctsUWzC9inPLemsQWp8CwUdRv2wCAvYOSBTOWUdCyhu9UrPqxhgZbF8/AWGi5Hh1GbZ1m1181KnZBgZaDe7yliPvoDKW51xmb1M3F1IaDesKfZ/Cytb4kvb3P1q/YzkmSUk/IPb9mf7wPkCgLfWK5rYTMWKHlQpcEVaAHXH3DLfqOT+OLnRTLk0sJhmrH3YdcEtASF3OksAU4SZwtgP0ztTVmrmJgB4BY7D8irH/+cTnwO9sxptR0Jo5n+jo8KbxfTOgxf/3mvxOAlVIS3c9+xwsFk8aRJ5hMI1i7NOL7v46/nYBd/tHc0MdAC4Dz9FGi92PJlFSiEhq4zkbc0WehdSHqoasu/TKeK8p0WSIcRiVae/8diC28MMVanaRk666nFJSp/K/ifdEv17EuDAnEc9GMx3UsYAxR5kYGtkJ4p59n";

            System.out.println(rsad.decryptAESGCMData(v_resp, rsad.string2Hex(clear_aes_key)));
        } catch (Exception ex)
        {
            Logger.getLogger(Callisto_encryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
