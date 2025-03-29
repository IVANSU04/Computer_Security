import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
 
public class Server {
    private static final int PORT = 12345; // Port number for the server

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server is listening on port " + PORT);
            while (true) {
                Socket socket = serverSocket.accept();
                //System.out.println("\nNew client connected");
                handleClient(socket);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket) {
        try (ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
                PrintWriter output = new PrintWriter(socket.getOutputStream(), true)) {

            // Read command from the client
            String command = (String) input.readObject();

            if ("LOGIN".equals(command)) {
                // Handle login
                String DateTime = (String) input.readObject();
                Integer accNo = (Integer) input.readObject();
                String accName = (String) input.readObject();
                String accEmail = (String) input.readObject();
                String accHash = (String) input.readObject();
                Integer accPhoneNo = (Integer) input.readObject();
                Integer accStatus = (Integer) input.readObject();
                Integer accRight = (Integer) input.readObject();

                System.out.printf("\nLOGIN by(%s), accNo:%s, accName:%s, accEmail:%s, accHash:%s, accPhoneNo:%s, accStatus:%s accRight:%s",DateTime, accNo+"", accName,accEmail,accHash,accPhoneNo+"",accStatus+"",accRight+"");
            } else if ("REGISTER".equals(command)) {
                // Handle register
                String DateTime = (String) input.readObject();
                String accName = (String) input.readObject();
                String accHash = (String) input.readObject();
                String accEmail = (String) input.readObject();
                Integer accPhone = (Integer) input.readObject();
                System.out.printf("\nREGISTER by(%s), accName:%s, accHash:%s, accEmail:%s, accPhone%s",DateTime, accName, accHash,accEmail,accPhone);

            } else if ("LOGOUT".equals(command)) {
                // Handle logout
                String DateTime = (String) input.readObject();
                Integer accNo = (Integer) input.readObject();
                String accName = (String) input.readObject();
                String accEmail = (String) input.readObject();
                System.out.printf("\nLOGOUT by(%s), accNo:%s, accName:%s, accEmail:%s",DateTime, accNo,accName,accEmail);

            } else if ("UPLOADFILE".equals(command)) {
                // Handle file upload
                String DateTime = (String) input.readObject();
                Integer accNo = (Integer) input.readObject();
                String accName = (String) input.readObject();
                String accEmail = (String) input.readObject();
                String fileName = (String) input.readObject();
                byte[] fileContent = (byte[]) input.readObject();
                
                System.out.printf("\nUPLOADFILE by(%s), accNo:%s, accName:%s, accEmail:%s fileName:%s, fileContent:%s",DateTime, accNo,accName,accEmail,fileName,""+fileContent);

                String keyFilePath = "encryption_key.key";
                SecretKey secretKey = loadOrGenerateKey(keyFilePath);
                byte[] encryptedFileData = fileContent;
                byte[] decryptedFileData = decryptFile(encryptedFileData, secretKey);

                
                if(fileName.contains(".txt")){
                    String decryptedContent = new String(decryptedFileData, StandardCharsets.UTF_8);
                    System.out.printf("\n  ->SYSTEM Decrypt file(%s): %s -> %s",DateTime,  "(ENC,"+fileContent+")", "(DEC,"+decryptedContent+")");
                }else{
                    System.out.printf("\n  ->SYSTEM Decrypt file(%s): %s -> %s",DateTime,  "(ENC,"+fileContent+")", "(DEC,"+decryptedFileData+")");
                }
 
            } else if ("DOWNLOADFILE".equals(command)) {
                // Handle file download
                String DateTime = (String) input.readObject();
                Integer accNo = (Integer) input.readObject();
                String accName = (String) input.readObject();
                String accEmail = (String) input.readObject();
                String fileName = (String) input.readObject();
                byte[] fileContent = (byte[]) input.readObject();
                
                System.out.printf("\nDOWNLOADFILE by(%s), accNo:%s, accName:%s, accEmail:%s fileName:%s, fileContent:%s",DateTime, accNo,accName,accEmail,fileName,""+fileContent);

                String keyFilePath = "encryption_key.key";
                SecretKey secretKey = loadOrGenerateKey(keyFilePath);
                byte[] encryptedFileData = fileContent;
                byte[] decryptedFileData = decryptFile(encryptedFileData, secretKey);

                
                if(fileName.contains(".txt")){
                    // Convert the decrypted byte array to a String
                    String decryptedContent = new String(decryptedFileData, StandardCharsets.UTF_8);
                    System.out.printf("\n  ->SYSTEM Decrypt file(%s): %s -> %s",DateTime, "(ENC,"+fileContent+")", "(DEC,"+decryptedFileData+"):"+decryptedContent);
                }else{
                    System.out.printf("\n  ->SYSTEM Decrypt file(%s): %s -> %s",DateTime, "(ENC,"+fileContent+")", "(DEC,"+decryptedFileData+"):");
                }

            } else {
                output.println("Unknown command");
            }

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private static SecretKey loadOrGenerateKey(String keyFilePath) {
        File keyFile = new File(keyFilePath);
        SecretKey secretKey = null;
    
        if (keyFile.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(keyFile))) {
                secretKey = (SecretKey) ois.readObject();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        } else {
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256); // Use 256-bit AES
                secretKey = keyGen.generateKey();
    
                try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(keyFile))) {
                    oos.writeObject(secretKey);
                }
            } catch (NoSuchAlgorithmException | IOException e) {
                e.printStackTrace();
            }
        }
    
        return secretKey;
    }

    private static byte[] decryptFile(byte[] encryptedFileData, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(encryptedFileData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}