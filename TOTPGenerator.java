import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
 
public class TOTPGenerator {

    // TOTP parameters
    private static final int TIME_STEP = 30; // Time step in seconds (default is 30)
    private static final int CODE_DIGITS = 6; // Number of digits in the OTP (default is 6)
    private static final String HMAC_ALGORITHM = "HmacSHA1"; // HMAC algorithm
    
    
    public TOTPGenerator() {
    }

    public static String generateTOTP(String secret) {
        try {
            // Decode the base32 secret key
            byte[] keyBytes = Base32.decode(secret);

            // Get the current time in seconds and divide by the time step
            long timeCounter = System.currentTimeMillis() / 1000 / TIME_STEP;

            // Convert the time counter to a byte array (big-endian)
            byte[] timeBytes = new byte[8];
            for (int i = 7; i >= 0; i--) {
                timeBytes[i] = (byte) (timeCounter & 0xFF);
                timeCounter >>= 8;
            }

            // Generate HMAC-SHA1 hash
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(keyBytes, HMAC_ALGORITHM));
            byte[] hash = mac.doFinal(timeBytes);

            // Dynamic truncation to get the OTP
            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);

            // Generate the OTP (6 or 8 digits)
            int otp = binary % (int) Math.pow(10, CODE_DIGITS);
            return String.format("%0" + CODE_DIGITS + "d", otp);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Error generating TOTP", e);
        }
    }

    private static String generateTOTPForTimeStep(String secret, long timeStep) {
        try {
            byte[] keyBytes = Base32.decode(secret);
            byte[] timeBytes = new byte[8];
            for (int i = 7; i >= 0; i--) {
                timeBytes[i] = (byte) (timeStep & 0xFF);
                timeStep >>= 8;
            }

            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(keyBytes, HMAC_ALGORITHM));
            byte[] hash = mac.doFinal(timeBytes);

            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);

            int otp = binary % (int) Math.pow(10, CODE_DIGITS);
            return String.format("%0" + CODE_DIGITS + "d", otp);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Error generating TOTP", e);
        }
    }

    public static boolean verifyTOTP(String secret, String userTOTP, int timeWindow) {
        long timeCounter = System.currentTimeMillis() / 1000 / TIME_STEP;

        // Check the TOTP for the current time step and adjacent steps (to account for clock skew)
        for (int i = -timeWindow; i <= timeWindow; i++) {
            String generatedTOTP = generateTOTPForTimeStep(secret, timeCounter + i);
            if (generatedTOTP.equals(userTOTP)) {
                return true; // TOTP is valid
            }
        }

        return false; // TOTP is invalid
    }
    // public static void main(String[] args) {
    //     // Example secret key (base32 encoded)
    //     String secret = "JBSWY3DPEHPK3PXP";

    //     // Generate a TOTP
    //     String totp = generateTOTP(secret);
    //     System.out.println("Generated TOTP: " + totp);

    //     // Verify the TOTP
    //     boolean isValid = verifyTOTP(secret, totp, 1); // Allow ±1 time step (30 seconds)
    //     System.out.println("Is TOTP valid? " + isValid);
    // }
}