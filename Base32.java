import java.util.HashMap;
import java.util.Map;
 
public class Base32 {
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final Map<Character, Integer> BASE32_CHAR_MAP = new HashMap<>();

    static {
        for (int i = 0; i < BASE32_CHARS.length(); i++) {
            BASE32_CHAR_MAP.put(BASE32_CHARS.charAt(i), i);
        }
    }

    public static byte[] decode(String input) {
        input = input.replaceAll("=", "").toUpperCase(); // Remove padding and convert to uppercase
        byte[] output = new byte[input.length() * 5 / 8]; // Calculate output size
        int buffer = 0;
        int bitsRemaining = 0;
        int index = 0;

        for (char c : input.toCharArray()) {
            buffer = (buffer << 5) | BASE32_CHAR_MAP.get(c); // Shift and add the current character's value
            bitsRemaining += 5;
            if (bitsRemaining >= 8) {
                output[index++] = (byte) (buffer >> (bitsRemaining - 8)); // Extract a byte
                bitsRemaining -= 8;
            }
        }
        return output;
    }
}