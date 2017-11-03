import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Created by wailm.yousif on 11/3/17.
 */
public class PuzzleTest
{
    public static final String HMAC_SHA512_ALGORITHM = "HmacSHA512";
    public static final String UTF_8 = "UTF-8";

    private static String serverNonce;

    static class ServerDeliverables
    {
        class NonceRange
        {
            public long minNumber;
            public long maxNumber;
            public NonceRange() { }
        }

        public String hash;
        public String key;
        public NonceRange nonceRange;
        public ServerDeliverables()
        {
            nonceRange = new NonceRange();
        }
    }

    private static String generateNonce(long min, long max)
    {
        Random rand = new Random();
        //int randomNum = rand.nextInt((max - min) + 1) + min;
        long randomNum = min + (long)(rand.nextDouble()*(max - min));
        return String.valueOf(randomNum);
    }

    public static void main(String[] args)
    {
        ServerDeliverables serverDeliverables = getPuzzleDeliverablesFromServer();
        String clientSolution = solvePuzzleByClient(serverDeliverables);
        System.out.println("clientSolution = " + clientSolution);
        if (clientSolution.equals(serverNonce))
        {
            System.out.println("Nonce is correct");
        }
        else
        {
            System.out.println("Incorrect nonce");
        }
    }

    private static ServerDeliverables getPuzzleDeliverablesFromServer()
    {
        ServerDeliverables serverDeliverables = new ServerDeliverables();
        serverDeliverables.nonceRange.minNumber = 1000000L;
        serverDeliverables.nonceRange.maxNumber = 7999999L;
        serverNonce = generateNonce(serverDeliverables.nonceRange.minNumber, serverDeliverables.nonceRange.maxNumber);
        //serverNonce = "7999999";
        System.out.println("Server nonce = " + serverNonce);


        try {
            /*
            String uuid = UUID.randomUUID().toString();
            String keyString = uuid.replace("-", "");
            keyString = keyString.substring(0, 15);
            */
            KeyGenerator keyGenerator = KeyGenerator.getInstance(HMAC_SHA512_ALGORITHM);
            keyGenerator.init(1024);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] keyBytes = secretKey.getEncoded();
            //String keyString = new String(keyBytes, UTF_8);
            String keyString = Base64.getEncoder().encodeToString(keyBytes);
            serverDeliverables.key = keyString;
            System.out.println("Server key = " + keyString);

            String hash = getHmacSHA(serverNonce, serverDeliverables.key, HMAC_SHA512_ALGORITHM);
            serverDeliverables.hash = hash;
            System.out.println("Server hash = " + hash);
        }
        catch (Exception ex)
        {
            System.out.println("Exception in getPuzzleDeliverables: " + ex.getMessage());
        }
        return serverDeliverables;
    }

    private static String solvePuzzleByClient(ServerDeliverables serverDeliverables)
    {
        long startTime = System.nanoTime();

        System.out.println("Client finding the nonce...");
        long min = serverDeliverables.nonceRange.minNumber;
        long max = serverDeliverables.nonceRange.maxNumber;
        String key = serverDeliverables.key;
        String serverHash = serverDeliverables.hash;
        String solution = "";
        for (long k=min; k <= max; k++)
        {
            solution = String.valueOf(k);
            String clientHash = getHmacSHA(solution, key, HMAC_SHA512_ALGORITHM);
            if (clientHash.equals(serverHash))
            {
                break;
            }
        }

        long duration = System.nanoTime() - startTime;
        System.out.println("Time needed by client = " + TimeUnit.NANOSECONDS.toSeconds(duration) + " seconds.");
        return solution;
    }


    private static String getHmacSHA(String strToHash, String hmacKeyB64, String algorithm)
    {
        String hash = null;
        try {
            //byte[] hmacKeyBytes = hmacKeyStr.getBytes(UTF_8);
            byte[] hmacKeyBytes = Base64.getDecoder().decode(hmacKeyB64);
            Mac macInstance = Mac.getInstance(algorithm);
            SecretKeySpec keySpec = new SecretKeySpec(hmacKeyBytes, algorithm);
            macInstance.init(keySpec);
            byte[] hashBytes = macInstance.doFinal(strToHash.getBytes(UTF_8));
            hash = Base64.getEncoder().encodeToString(hashBytes);
        } catch (Exception ex) {
            System.out.println("Exception:" + ex.getMessage());
        }
        return hash;
    }
}
