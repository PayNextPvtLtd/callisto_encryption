package callisto_encryption;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
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

    public byte[] string2Hex(String data)
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

        System.out.println(Base64.getEncoder().encodeToString(bytes));
        return new String(bytes);
    }

    /**
     *
     * @param args
     */
    public static void main(String[] args)
    {
        //String data = "jVG2vNCBkX8MWIhQL5OoWvvUMMgN+raiEcQfpNxZlwNO8iIbzAT0rQ2XNlCWox8LqT8dTslWswqYEz+56g8L5+n8Dg8ZjQW/KuYbed1xSOR59z/JjrBcJzYVsHJyQ2wORojtTdoQw4tQHvbKS4mBvVyeu7Nr6l2Tusz/uzGnpds7yXv+k4qbSodd7GDp6jsali2GXvk0ocgq4lYhFWT+JLH9YWuLYpCannC2Y2xAfB0tVNCstIf97XQCfpIV0lp1My0A9pmQR5ROUbpEmWn++9CC83R2/ggSY2JJhzOovm+oNTH6H3fD01akhHPH6xpph5TARq9ie66A0RyqfiLQlw==";

        //String data="bjF3fw93w1jrEz2MCbux/aT299LbRuqtSQMwy4HerWrpzEm3XIRYyAFd2OhTtWt8lQ83hXVYAI0m4lgN2HI9S8v9UXvrHq7ODso2x4osFHBMAr6gvchH8/niwx5f65GDHwXok2JMfHTzXFJQ4Erh6cemAgVh+P6k0YK0zIuZ8M2pjrfFfKL3qiDGoXa0XcshM1o0hGdCwwWcIuWDT3URX2JG+BjqYyr4owN80uOlJ49IAmVfdcJF56QmlGCl0k4ohBgrD2wIdtQViZ/FtP4DkEdlD/fxuxTbG92xBerSTHIEmKv7rj6h3E9wi8WKpJKyXCpnYVqMgsBMRTSr8wFBuA";
        String data = "QCcyc6SmhlJeZdQ6A5rB28vwgIdFwb1kZvSZ958lUkEVZdI7JH+XkXi7qqh7fsvZAezNhrKjCxqqmUOBFObwB2mFcllNVGxO+L+jSDpxVzO55BJ85211Idjxqis7WcpXC3/hysdU3AOZTJB9sieeRlik78H7jY0jjXKFU7wUPsHZGtC6rysH33jiPGxNO8eyXow+qxjUpffvIsghBZ9CtV3tquaez3Pf0/PgQhCO408EP20uls7iLEiw6uF6RnOR+PSMQ4q6kMsFTfZXMnRAVIckUtxl3yD6JEB8rvVkBllq92gdPGhaf5upnWo+Y06hYX481asubyITYqIx5V/5ug";
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

            System.out.println("Clear AES Key = " + clear_aes_key);

            String v_req = "{\"requestid\": \"IPG000061\",\"mid\": \"107463000232369\",\"tid\": \"10084171\",\"amount\": \"12000\",\"merchanturl\": \"http://paynext.co.in\",\"pan\": \"4216210000000023\",\"authenticationindicator\": \"01\",\"messagecategory\": \"01\",\"devicechannel\": \"02\",\"expirydate\": \"202310\",\"billAddrCity\": \"MUMBAI\",\"billAddrCountryCode\": \"356\",\"billAddrLine1\": \"MUMBAI\",\"billAddrPostalCode\": \"400066\",\"billAddrState\": \"Maharashtra\",\"cardholdername\": \"PayNext Card\",\"browseracceptheader\": \"*/*\",\"browseripaddress\": \"127.0.0.1\",\"notificationurl\": \"https://europa-uat.paynext.co.in/pnmpi/v2/notify\",\"browserlanguage\": \"en\",\"browserjavaenabledval\": false,\"browserscreencolordepth\": \"24\",\"browserscreenheight\": \"768\",\"browserscreenwidth\": \"1366\",\"browsertimezone\": \"-330\",\"browseruseragent\": \"mozilla/5.0+(x11;+ubuntu;+linux+x86_64;+rv:72.0)+gecko/20100101+firefox/72.0\",\"browserjavascriptenabledval\": false,\"accounttype\": \"00\",\"authenticatorindicator\": \"01\",\"cvv2\":\"999\",\"isDCC\":false,\"tran_currency\":\"356\"}";
//            String v_req = "{\n"
//                    + "\"mid\":\"107753000214052\",\n"
//                    + "\"tid\":\"10275103\",\n"
//                    + "\"referenceid\":\"33630000000000781746\",\n"
//                    + "\"requestid\":\"T100-18cb608ab48\",\n"
//                    + "\"pares\":\"eyJ0aHJlZURTU2VydmVyVHJhbnNJRCI6IjJmYmUzYzgzLTc2OTUtNGRjNC1iN2UyLWJiMGUyMzM2MmE2MSIsImFjc1RyYW5zSUQiOiJhYjk2MzVkZS1hNjcwLTExZWUtYTY4ZC00NWRlMmQ1MjYzOGMiLC\n"
//                    + "JtZXNzYWdlVHlwZSI6IkNSZXMiLCJtZXNzYWdlVmVyc2lvbiI6IjIuMi4wIiwiY2hhbGxlbmdlQ29tcGxldGlvbkluZCI6IlkiLCJ0cmFuc1N0YXR1cyI6IlkifQ\"\n"
//                    + "}";

            System.out.println(v_req);

            String enc_data = rsad.encryptAESGCMData(v_req, rsad.string2Hex(clear_aes_key));

            System.out.println(enc_data);

            String v_resp = "SKgNT4TJ2DBzQVk2pBfIinAhWzax4QgelB6kaiHVZ7x7UySPVenw5ZNXwvEcpV6IDMwTu61w%2Fa%2BoLXiEdmej0n7oln9aDshqIjTxBP14jzTJVQG5s%2FbYhggkq00G0e%2FMRsG1lx41ZyPJXHguIbgxYFAvZmekYtqVyWBySksehBeqO9gGq5SPm3EsghJ7ZUU%2FOU74hI2wJNOPSwhwA4D3xxq4Izp44d%2Fu2KY6b%2FBKW9wbC9AMgCYlP30lxmIigi%2BTA9nCb2qczpWkrBlbb0PwPIz50d3bLHh7ndmzgkzEs9wCVbFQBfyCWWE4WDWFy59gutrzsfsBPEheDsIru95QW052AvTPZiIqFIObRsr9%2FDTmuMOhk2Dp3xwKkjwwqvKK3pXKSqX6p3QkY%2F6x%2FFibHsjKYN8QEU4CNo9b%2BXzZl3wQqZQlycjOrdCKhxqArTA7l%2FHmdUfoJl0IMPvGOngYtkq%2Bpv3ak89UgJRVPOmw0ljFIyhPRMw5%2BPsfa1f0JYzSKIyugPQJSvrMboitYr1Zk8qYPpAFO43uRQzJXZSKvxhsfSGCDeV0e9AbLEwOUGThBngukhqc5MYMPbYC4jP3s1ee9vcOfMz0g%2FWWBsa4hK3BgrVczd0FkPv65Ds5QtdvoYZvvU5fCuyaw1Em2kDa6cbvbVT%2BOIpxniXW5pVyqXpQVUmDWhB2aUQkuqo9v3acXjE%2Bpmh7wqJ86DRnsTl1gIHT0kDG7W3hHURV%2BQMvMvu2PPdma7daXxnrR1vvf8Rjw5F5LLrg07qA3IhZ1L3BtLZJKXT%2FewJ4azD5LJAQVn2MpVRN0Z0AoZ4vTAv97Ani3Rp7QaWdm6d%2FN%2BQhoU4n7qDWmPtQOlYqOfCLoOAl7dapO6vQ1oh0tp%2FgtbLhrVdoSUt5ZLgRU%2B6OTQq%2BJEEFPeTVa4OGa3kpsUCpUxFq0%2B22Goyb%2FfA9Jx%2BahP6KIk2HoyTQxIJRTPTI4XXDh9N6tLEbkW9Eso3Z8TVn%2BBVQRLKcS5Rd6x%2BAGttmkkXhkHCvUKs%2FYa7kVh99gq3JpuQaSHG3OQoOI9lVdYNEe1SXpZ67YI0c%2BKLy%2F%2BIwCm%2FBeRY2NzInoyjoFQxONti8mdGyAyY%2BE80dAVBJpjqHfvL0W45llbGCpz7gVPnKkC8GrxHGlNoID2GTYUSwmffE5kEM99ACkWc%3D";
            v_resp = URLDecoder.decode(v_resp, Charset.defaultCharset());
            //String v_resp = "1BXyrIobD5ZAv485kemrEOwz4rO17X0xaCgRco1YzAiuW3GrCeLYs7A3oxzmsiRRNQDX4uYTNLZDg5jTpQ66erxoCpXqli+SJip/p0VElZTTtzG1jRKZ9+T4tJB4j1tjM5vAEGrKiB0GDG7sHzp5NJDZTjkzChh7MB51KiJrLZH+8dMPYNFczgY5rovRScNMJW+GNP8cQ/GBaFKa/15gvP8/0uyjh+2TX0sggujFAmLtQcn6vWR3nbYJQ2RePjt2gI5UwPu9sZ5N9xpxpFjN296vXa5db+DmGR6CSSOebobVr9XS8SYl49J1kidBopGYSqTzOiLW4txGz4ICDG0QoBAY4E08Fb3UMEyfT0FPExsaO9GRJDrTkgWaHqXZ8QScgQrxQ066U1Pn2xW6MqRhf2xAymu7aybXlT3Ibb+td83SzIiTbvvjsyPKtDxKKTKuRrPb7xOGcovZJwYFZ0SPIfLVzNmYo+KoXr5IRPLtp5Hy6d+0tFsovIwbTmuBbKvbxmhuLIgmBdTOfgdE8l+A4/kpcdSZg29V8ufRiQA+TWP1exdfLOamyqDRXaYY2pa2sIKCEdcWJIH1FpOJLn6vKUJqfdt1axrjXzuruYxJBE/5Fgni5Jxrp8bmfiTiVtFXt9GZqik7PG2kD/IOeilEuvW6vXWwr+FJCCYxgog5ClVXrEXjuKDCPIRPvv5IUu3iMqMUvmHMdNZYUqVA/CIrskLYD918An/ETUYmqLlPrk7y26VllKHJ5Tb/ByWNw+X6IfQJzFx27ZiMp3VkDn3JvxktW99UcAGaN+ZnIfHi6P0ZBNpLDF63H27jvkbtnjtzDc3TlcK/b1tG5LygI+HX4Myyws5SmAjV0BGtm+bCxADd19gZO1gqcSGhOSaL5iuVa04YCDNIYppA1XHHtmagDiJaqH+MxrihhEAg0oE15D5A6dxHMhBVbJnXFlsfHHl9uMonlWNmAGDoQeQVo1/G/iae+pfBcU3SGiiDn1YirHY=";
            System.out.println(rsad.decryptAESGCMData(v_resp, rsad.string2Hex(clear_aes_key)));
        } catch (Exception ex)
        {
            Logger.getLogger(Callisto_encryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
