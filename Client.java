import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
 
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import java.io.*;
import java.lang.reflect.Parameter;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class Client {
    //Datetime
    private static Timestamp currentTimestamp = new Timestamp(System.currentTimeMillis());
    private static LocalDate currentDate = LocalDate.now();
    private static DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MMM-yy");
    private static String formattedDate = currentDate.format(formatter);

    //Hash
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 128; // in bits

    //TOTP
    private static String TOTP_secret = "COMP3334";

    // DB connection
    private static final String db_acc_name = "\"12345678d\""; // e.g. "98765432d" Your Oracle Account (SID) or demo user: 22027226d
    private static final String db_pwd = String.valueOf("PWD"); // Your Oracle PWD or demo PWD: ohayrsfs

    public static void main(String[] args)
            throws NoSuchAlgorithmException, SQLException, IOException, InterruptedException {
        // System Value
        Console console = System.console();
        String acc_name;
        String pwd;
        int cmd = -1;
        String salt;
        String hashedPassword;
        boolean sysLoop = true;

        // DB connection
        String sql = "";
        PreparedStatement pstmt;
        ResultSet rset;

        // account value
        Account acc = new Account();

        // Testing OTP
        TOTPGenerator totp = new TOTPGenerator();

        // Connection
        DriverManager.registerDriver(new oracle.jdbc.driver.OracleDriver());
        Connection conn = DriverManager.getConnection("jdbc:oracle:thin:@studora.comp.polyu.edu.hk:1521:dbms",
                db_acc_name, db_pwd);
        clearScreen();

        // ---Start of the loing and register---
        while (!(cmd >= 0 && cmd <= 2)) {
            try {

                clearScreen();
                topView();
                System.out.println("=================================================================");
                System.out.println("** Command List **");
                System.out.print("[0]:Exit    \n[1]:Login Comp3334_CSS    \n[2]:Register Account \n\nEnter CMD:");
                cmd = Integer.parseInt(console.readLine());
                // 0 = exit
                if (cmd == 0) {
                    sysLoop = false;
                    // 1 = login
                } else if (cmd == 1) {
                    System.out.print("\nEnter your account:");
                    acc_name = console.readLine();
                    while (!isValidString(acc_name)) {
                        System.out.print(
                                "\nCan't including any invalid symbol like \"',!%-+`~><$/\\|&*()[]{};:?#^\nEnter your account:");
                                acc_name = console.readLine();
                    }

                    System.out.print("Enter your password:");
                    pwd = console.readLine();
                    while (!isValidString(pwd)) {
                        System.out.print(
                                "\nCan't including any invalid symbol like \"',!%-+`~><$/\\|&*()[]{};:?#^\nEnter your password:");
                                pwd = console.readLine();
                    }

                    if (acc_name.contains("@")) {
                        sql = "SELECT password FROM Comp3334_CSSAccount WHERE email = ?";
                        pstmt = conn.prepareStatement(sql);
                        pstmt.setString(1, acc_name); // if the inputed acc_name contains("@"), that it is email
                        rset = pstmt.executeQuery();

                    } else {
                        sql = "SELECT password FROM Comp3334_CSSAccount WHERE loginName = ? ";
                        //System.out.print("\n\n" + sql);
                        pstmt = conn.prepareStatement(sql);
                        pstmt.setString(1, acc_name); // if not, that it is loginName
                        rset = pstmt.executeQuery();
                    }
                    boolean cc = false ;
                    if (rset.next()) {
                        System.out.flush();
                        String storedhash = rset.getString(1);
                        cc = verifyPassword(pwd, storedhash);

                        //if verify, set pwd = hash and store TOTP_secret = "COMP3334" + Upper Cased & validChars of hash
                        if(cc) {
                            pwd = storedhash; 


                            String[] parts = storedhash.split(":");
                            //System.out.println("\nT:"+TOTP_secret+":PK"); //COMP3334
                            TOTP_secret += toTOTPKEY(parts[1]); //client TOTP key = individual SK
                            //System.out.println("\nT:"+TOTP_secret+":SK"); //COMP3334 + hash
                        }
                    }else{
                        System.out.println("acccount_Name/email is incorrect... ");
                        System.out.println("Please press <enter> to continue\n\n");
                        console.readLine();
                        clearScreen();
                        cmd = -1;
                    }
                    //pwd = hashPassword(pwd);
                    
                    if (cc && acc_name.contains("@")) {
                        sql = "SELECT accNo,loginName,email,phoneNo,userStatus,userRight FROM Comp3334_CSSAccount WHERE email = ? AND password = ? ";
                        pstmt = conn.prepareStatement(sql);
                        pstmt.setString(1, acc_name); // if the inputed acc_name contains("@"), that it is email
                        pstmt.setString(2, pwd);
                        rset = pstmt.executeQuery();

                    } else {
                        sql = "SELECT accNo,loginName,email,phoneNo,userStatus,userRight FROM Comp3334_CSSAccount WHERE loginName = ? AND password = ? ";
                        //System.out.print("\n\n" + sql);
                        pstmt = conn.prepareStatement(sql);
                        pstmt.setString(1, acc_name);
                        pstmt.setString(2, pwd);
                        rset = pstmt.executeQuery();
                    }
                    //System.out.println(acc_name+":"+pwd);

                    if (rset.next()) {
                        
                        //String totpString = totp.generateTOTP(TOTP_secret);
                        String totpString = totp.generateTOTP(TOTP_secret);
                        storeTOTP(totpString, "phone.txt");
                        System.out.print("\nEnter your password:");
                        totpString = console.readLine();
                        
                        //if(totp.verifyTOTP(TOTP_secret, totpString, 1)){
                        if(totp.verifyTOTP(TOTP_secret, totpString, 1)){
                            System.out.flush();
                            acc.setAccNo(rset.getInt(1));
                            acc.setLoginName(rset.getString(2));
                            acc.setEmail(rset.getString(3));
                            acc.setPhoneNo(rset.getInt(4));
                            acc.setUserStatus(rset.getInt(5));
                            acc.setUserRight(rset.getInt(6));
                            System.out.println("login successful");

                            sql = "INSERT INTO Comp3334_LogCSS VALUES (null, ? , 'login' , ? )";
                            pstmt = conn.prepareStatement(sql);
                            pstmt.setInt(1, acc.getAccNo()); // if the inputed acc_name contains("@"), that it is email
                            pstmt.setString(2, formattedDate);
                            rset = pstmt.executeQuery();

                            System.out.println("Please press <enter> to continue\n\n");
                            console.readLine();
                            clearScreen();

                            // Inside the login section of Client.java
                            try (Socket socket = new Socket("localhost", 12345);
                                    ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream())) {

                                output.writeObject("LOGIN"); // Send command
                                output.writeObject(currentTimestamp+"");
                                output.writeObject(acc.getAccNo());
                                output.writeObject(acc.getLoginName());
                                output.writeObject(acc.getEmail());
                                output.writeObject(pwd);
                                output.writeObject(acc.getPhoneNo());
                                output.writeObject(acc.getUserStatus());
                                output.writeObject(acc.getUserRight());

                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }else{
                            System.out.println("\nTOTP is expired / invaild \n");
                            System.out.println("Please press <enter> to continue\n\n");
                            console.readLine();
                            clearScreen();
                            cmd = -1;
                        }

                    } else {
                        System.out.println("acccount_Name/email or password is incorrect... ");
                        System.out.println("Please press <enter> to continue\n\n");
                        console.readLine();
                        clearScreen();
                        cmd = -1;
                    }

                    // 2 = register
                } else if (cmd == 2) {
                    // Account info
                    // -> Check input format is it valid
                    // -> check is it registered
                    // -> if all valid, hash pwd & regisiter account

                    // -> Check input format is it valid
                    // accName, loginName
                    System.out.print("Enter your account_Name:");
                    String nc_name = console.readLine();

                    while (!isValidString(nc_name) || (nc_name == null || nc_name.isEmpty())
                            || ((nc_name.length() > 20 || nc_name.length() < 1)
                                    || Character.isDigit(nc_name.charAt(0)))) {
                        System.out.print(
                                "\nUser_name can't start with digit & lenght must be 1 to 20\nCan't including any invalid symbol like \"',!%-+`~><$/\\|&*()[]{};:?#^\nEnter your account_Name:");
                        nc_name = console.readLine();
                    }

                    // accPws, password
                    System.out.print("Enter your password:");
                    String nc_pwd = console.readLine();

                    while (!isValidString(nc_pwd) || (nc_name == null || nc_name.isEmpty())
                            || (nc_pwd.length() > 15 || nc_pwd.length() < 1)) {
                        System.out.print(
                                "\nPassword length must be 1-15\nCan't including any invalid symbol like \"',!%-+`~><$/\\|&*()[]{};:?#^\nEnter your password:");
                        nc_pwd = console.readLine();
                    }
                    // pwd = hash pwd, which including 2 part, 1:salt 2:hashed pwd
                    nc_pwd = hashPassword(nc_pwd); 
                    //System.out.print("\nhash:"+nc_pwd+"\n");

                    // accEmail, email
                    System.out.print("Enter your email:");
                    String nc_email = console.readLine();

                    while (!isValidString(nc_email) || (nc_name == null || nc_name.isEmpty())
                            || !(nc_email.contains("@"))) {
                        System.out.print(
                                "\nEmail must be contains '@' \nCan't including any invalid symbol like \"',!%-+`~><$/\\|&*()[]{};:?#^\nEnter your email:");
                        nc_email = console.readLine();
                    }

                    // accPhone, phoneNo
                    System.out.print("Enter your phoneNo:");
                    String str_phoneNo = console.readLine();

                    while (!isValidNumber(str_phoneNo) || (nc_name == null || nc_name.isEmpty())
                            || !(str_phoneNo.length() == 8)) {
                        System.out.print(
                                "\nPhoneNo must be 8 number, e.g, 28879643\nOnly Numner <0-9> \nEnter your phoneNo:");
                        str_phoneNo = console.readLine();
                    }

                    int nc_phoneNo = Integer.parseInt(str_phoneNo);

                    // checking email is it registered
                    // -> check is it registered
                    sql = "SELECT accNo FROM Comp3334_CSSAccount WHERE email = ?";
                    pstmt = conn.prepareStatement(sql);
                    pstmt.setString(1, nc_email);
                    rset = pstmt.executeQuery();

                    boolean cc = true;
                    if (rset.next()) {
                        System.out.print("\nThis email has been registered");
                        cc = false;
                    }
                    ResultSet rset2;
                    // checking loginName is it registered
                    sql = "SELECT accNo FROM Comp3334_CSSAccount WHERE loginName = ?";
                    pstmt = conn.prepareStatement(sql);
                    pstmt.setString(1, nc_name);
                    rset2 = pstmt.executeQuery();

                    if (rset2.next()) {
                        System.out.print("\nThis account_Name has been registered");
                        cc = false;
                    }

                    // if valid, INSERT DATA
                    // -> if all valid, hash pwd & regisiter account
                    if (cc) {
                        sql = "INSERT INTO Comp3334_CSSAccount VALUES (null, ?, ?, ?, ?,0,0) ";
                        pstmt = conn.prepareStatement(sql);
                        pstmt.setString(1, nc_name);
                        pstmt.setString(2, nc_pwd);
                        pstmt.setString(3, nc_email);
                        pstmt.setInt(4, nc_phoneNo);
                        rset2 = pstmt.executeQuery();

                        System.out.println("\nRegister Account Successfully");
                        // Inside the REGISTER section of Client.java
                        try (Socket socket = new Socket("localhost", 12345);
                        ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream())) {

                            output.writeObject("REGISTER"); // Send command
                            output.writeObject(currentTimestamp+"");
                            output.writeObject(nc_name);
                            output.writeObject(nc_pwd);
                            output.writeObject(nc_email);
                            output.writeObject(nc_phoneNo);

                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    } else {
                        System.out.println("\nRegister Account Unsuccessfully");
                    }

                    

                    System.out.println("Please Enter <enter> to next...");
                    console.readLine();
                    clearScreen();
                    cmd = -1;
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.out.print("System: Input Error");
            }
        }

        // --- End of the loing and register ---

        // --- Start of the loing and register ---
        // If UserStatus == 1 , account locked
        if (acc.getUserStatus() == 1) {
            topView();
            displayAccData(acc);
            System.out.print(
                    "\nOpss! you account has be locked! \nPlease contact with 'COPM3334@connect.polyu.hk' or call '28879227' to get more details, Bye! \n");
            System.out.println("Please press <enter> to continue\n\n");
            console.readLine();
        }

        // If UserStatus == 0, login
        while (acc.getUserStatus() != 1 && sysLoop) {
            // UserRight == 0 , normal user
            if (acc.getUserRight() == 0 || acc.getUserRight() == 1) {
                clearScreen();
                cssView(acc);
                
                int icount=1;
                String icount_str="";
                //store the fileno in list --> (index)list
                List<Integer> fileno = new ArrayList<>();

                // --Start of displaying the owner files--
                // Select all files & owner == accNo
                sql = "SELECT a.fileNo, a.fileName, owner.loginName AS ownerName, " +
                        "LISTAGG(shared.loginName, ', ') WITHIN GROUP (ORDER BY shared.loginName) AS shareName " +
                        "FROM Comp3334_AccFile a " +
                        "JOIN Comp3334_CSSAccount owner ON a.accNo = owner.accNo " +
                        "LEFT JOIN Comp3334_ShareFile s ON a.fileNo = s.fileNo " +
                        "LEFT JOIN Comp3334_CSSAccount shared ON s.accNo = shared.accNo " +
                        "WHERE a.accNo = ? " +
                        "GROUP BY a.fileNo, a.fileName, owner.loginName";

                pstmt = conn.prepareStatement(sql);
                pstmt.setInt(1, acc.getAccNo()); // Set the accNo parameter
                rset = pstmt.executeQuery();

                System.out.println("\n\n** Files List: **");
                String testmsg = "-Empty list-";
                icount = 1;

                while (rset.next()) {
                    testmsg = "";//reset testmsg
                    int fileNo = rset.getInt("fileNo");
                    String fileName = rset.getString("fileName");
                    String ownerName = rset.getString("ownerName");
                    String shareName = rset.getString("shareName");
                    fileno.add(fileNo);

                    // Handle null shareName (no shared accounts)
                    if (shareName == null) {
                        shareName = "";
                    }

                    System.out.printf("\n[Index:%s] [Owner:%s] [File:%s] [ShareTo:%s]",
                                (icount <= 9 ? "0" + icount++ : "" + icount++),
                                ownerName, 
                                fileName, 
                                shareName);
                }

                //--end of displaying the owner files--

                //--start of displaying the share file by other user--
                sql = "SELECT a.fileNo, c.loginName, c.email, a.fileName " +
                        "FROM Comp3334_AccFile a " +
                        "JOIN Comp3334_ShareFile s ON a.fileNo = s.fileNo " +
                        "JOIN Comp3334_CSSAccount c ON a.accNo = c.accNo " +
                        "WHERE s.accNo = ?";
                        pstmt = conn.prepareStatement(sql);
                        pstmt.setInt(1, acc.getAccNo()); 
                        rset = pstmt.executeQuery();
                
                while(rset.next()){
                    testmsg = "";//reset testmsg
                    fileno.add(rset.getInt(1));
                    System.out.printf("\n[Index:%s] [Owner:%s] [File:%s]",
                                            (icount_str=(icount<=9)?"0"+icount++:""+icount++),
                                            rset.getString(2),
                                            rset.getString(4));
                
                }
                if(!fileno.isEmpty()){
                    testmsg+="fileList:"+fileno;
                    testmsg+= ", fileList[0]:"+fileno.get(0);
                }

                // Load the encryption key
                String keyFilePath = "encryption_key.key";
                SecretKey secretKey = loadOrGenerateKey(keyFilePath);
                byte[] encryptedFileData;

                // Get the current working directory
                String currentPath = System.getProperty("user.dir");

                // Define paths for upload and download folders
                Path uploadPath = Paths.get(currentPath, "uploads");
                Path downloadPath = Paths.get(currentPath, "downloads");

                // Create the folders if they don't exist
                try {
                    if (!Files.exists(uploadPath)) {
                        Files.createDirectories(uploadPath);
                        System.out.println("Created uploads folder: " + uploadPath);
                    }
                    if (!Files.exists(downloadPath)) {
                        Files.createDirectories(downloadPath);
                        System.out.println("Created downloads folder: " + downloadPath);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    System.out.println("Failed to create upload/download folders.");
                }
                
                System.out.print("\n"+testmsg);
                boolean validInput = false;

                // ensure cmd is number not string
                while (!validInput) {
                    System.out.print("\n\nEnter CMD:");
                    String input = console.readLine();

                    try {
                        cmd = Integer.parseInt(input); // Try to parse the input as an integer
                        validInput = true; // If successful, exit the loop
                    } catch (NumberFormatException e) {
                        System.out.println("Invalid input! Please enter a valid number.");
                    }
                }

                switch (cmd) {
                    case 0:
                        sysLoop = false;
                        // Inside the LOGOUT section of Client.java
                        sql = "INSERT INTO Comp3334_LogCSS VALUES (null, ? , 'logout' , ? )";
                            pstmt = conn.prepareStatement(sql);
                            pstmt.setInt(1, acc.getAccNo()); // if the inputed acc_name contains("@"), that it is email
                            pstmt.setString(2, formattedDate);
                            rset = pstmt.executeQuery();

                        try (Socket socket = new Socket("localhost", 12345);
                        ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream())) {

                            output.writeObject("LOGOUT"); // Send command
                            output.writeObject(currentTimestamp+"");
                            output.writeObject(acc.getAccNo());
                            output.writeObject(acc.getLoginName());
                            output.writeObject(acc.getEmail());

                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        break;
                    case 1:
                        System.out.print("*Please ensure the file is store in 'uploads' folder*\n*E.g: abcd.txt*\nEnter the file name to upload to DB : ");
                        String filename = console.readLine();
                        while (!isValidString(filename)) {
                            System.out.print(
                                    "\nCan't including any invalid symbol like \"',!%-+`~><$/\\|&*()[]{};:?#^\nEnter the file name to upload to DB :");
                                    filename = console.readLine();
                        }

                        Path filePath = uploadPath.resolve(filename);
                        File file = filePath.toFile();
                    
                        if (!file.exists()) {
                            System.out.println("File does not exist in the uploads folder: " + filePath);
                            System.out.println("Please press <enter> to EXIT\n\n");
                            console.readLine();
                            break;
                        }
                    
                        // Encrypt the file
                        encryptedFileData = encryptFile(file, secretKey);
                    
                        if (encryptedFileData == null) {
                            System.out.println("File encryption failed.");
                            System.out.println("Please press <enter> to EXIT\n\n");
                            console.readLine();
                            break;
                        }
                    
                        // Insert the encrypted file into the database
                        try {
                            sql = "INSERT INTO Comp3334_AccFile (accNo, fileName, fileData) VALUES (?, ?, ?)";
                            pstmt = conn.prepareStatement(sql);
                            pstmt.setInt(1, acc.getAccNo());
                            pstmt.setString(2, file.getName());
                            pstmt.setBytes(3, encryptedFileData);
                            int rowsInserted = pstmt.executeUpdate();

                            String logSQL = "INSERT INTO Comp3334_LogCSS VALUES (null, ? , 'upload_file' , ? )";
                            PreparedStatement pstmtLOG = conn.prepareStatement(logSQL);
                            pstmtLOG.setInt(1, acc.getAccNo()); // if the inputed acc_name contains("@"), that it is email
                            pstmtLOG.setString(2, formattedDate);
                            ResultSet rsetLOG = pstmtLOG.executeQuery();

                            // Inside the UPLOADFILE section of Client.java
                            try (Socket socket = new Socket("localhost", 12345);
                            ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream())) {

                                output.writeObject("UPLOADFILE"); // Send command
                                output.writeObject(currentTimestamp+"");
                                output.writeObject(acc.getAccNo());
                                output.writeObject(acc.getLoginName());
                                output.writeObject(acc.getEmail());
                                output.writeObject(file.getName());
                                output.writeObject(encryptedFileData);

                            } catch (IOException e) {
                                e.printStackTrace();
                            }

                            if (rowsInserted > 0) {
                                System.out.println("File uploaded successfully.");
                            } else {
                                System.out.println("File upload failed.");
                            }
                        } catch (SQLException e) {
                            e.printStackTrace();
                            System.out.println("Database error during file upload.");
                        }
                        System.out.println("Please press <enter> to EXIT\n\n");
                        console.readLine();
                        break;
                    case 2:
                        if (fileno.isEmpty()) {
                            System.out.println("No files available to download.");
                            break;
                        }
                    
                        int fileIndex=-1;
                        validInput = false;

                        // ensure cmd is number not string
                        while (!validInput) {
                            System.out.print("Enter the index of the file to download: ");
                            String input = console.readLine();

                            try {
                                // Try to parse the input as an integer
                                fileIndex = Integer.parseInt(input) -1;  // Convert to 0-based index
                                validInput = true; // If successful, exit the loop
                            } catch (NumberFormatException e) {
                                System.out.println("Invalid input! Please enter a valid number.");
                            }
                        }

                        if (fileIndex < 0 || fileIndex >= fileno.size()) {
                            System.out.println("Invalid file index.");
                            break;
                        }
                    
                        int selectedFileNo = fileno.get(fileIndex);
                    
                        // Retrieve the encrypted file from the database
                        try {
                            sql = "SELECT fileName, fileData FROM Comp3334_AccFile WHERE fileNo = ?";
                            pstmt = conn.prepareStatement(sql);
                            pstmt.setInt(1, selectedFileNo);
                            rset = pstmt.executeQuery();

                            String logSQL = "INSERT INTO Comp3334_LogCSS VALUES (null, ? , 'download_file' , ? )";
                            PreparedStatement pstmtLOG = conn.prepareStatement(logSQL);
                            pstmtLOG.setInt(1, acc.getAccNo()); // if the inputed acc_name contains("@"), that it is email
                            pstmtLOG.setString(2, formattedDate);
                            ResultSet rsetLOG = pstmtLOG.executeQuery();
                    
                            if (rset.next()) {
                                String fileName = rset.getString("fileName");
                                encryptedFileData = rset.getBytes("fileData");
                    
                                if (secretKey == null) {
                                    System.out.println("Failed to load encryption key.");
                                    break;
                                }
                    
                                // Decrypt the file
                                byte[] decryptedFileData = decryptFile(encryptedFileData, secretKey);
                    
                                if (decryptedFileData == null) {
                                    System.out.println("File decryption failed.");
                                    break;
                                }
                    
                                // Save the decrypted file to the downloads folder
                                Path outputFilePath = downloadPath.resolve(fileName); // Save to downloads folder
                                try (FileOutputStream fos = new FileOutputStream(outputFilePath.toFile())) {
                                    fos.write(decryptedFileData);
                                    System.out.println("File downloaded and decrypted successfully: " + outputFilePath);

                                    // Inside the DOWNLOADFILE section of Client.java
                                    try (Socket socket = new Socket("localhost", 12345);
                                    ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream())) {

                                        output.writeObject("DOWNLOADFILE"); // Send command
                                        output.writeObject(currentTimestamp+"");
                                        output.writeObject(acc.getAccNo());
                                        output.writeObject(acc.getLoginName());
                                        output.writeObject(acc.getEmail());
                                        output.writeObject(fileName);
                                        output.writeObject(encryptedFileData);

                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                } catch (IOException e) {
                                    e.printStackTrace();
                                    System.out.println("Failed to save the decrypted file.");
                                }
                            } else {
                                System.out.println("File not found in the database.");
                            }
                        } catch (SQLException e) {
                            e.printStackTrace();
                            System.out.println("Database error during file download.");
                        }
                        break;
                    case 3:
                        break;
                    case 4:
                        break;
                    case 5:
                        break;
                    case 6:
                        break;
                    case 7:
                        break;
                    case 8:
                        if(acc.getUserRight()==1){

                        }
                        break;
                }

            }
        }
        
        // Exit the program
        conn.close();
        endView();
        System.out.println("Please press <enter> to EXIT\n\n");
        console.readLine();
    }

    // --- functional method, not main logic ---

    // clearScreen function -- clear screen
    public static void clearScreen() throws IOException, InterruptedException {
        if (System.getProperty("os.name").contains("Windows"))
            new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
        else
            System.out.print("\033[H\033[2J");
    }


    public static void topView() {
        System.out.println("\n=================================================================");
        System.out.println("COMPUTER SYSTEMS SECURITY (Comp3334_CSS)");
        System.out.println("Date: " + currentTimestamp);
    }

    public static void cssView(Account acc) {
        topView();
        displayAccData(acc);
        System.out.println("** Command List **");
        //upload logout download sharing editing
        System.out.print(
                            "[0]:Logout & Exit          [1]:Upload File      [2]:Download File"
                        + "\n[3]:ReUpload File(Edit)    [4]:File ShareTo     [5]:File UnshareTo   "
                        + "\n[6]:Delete File            [7]:Reset PWD          ");
        if(acc.getUserRight()==1){
            System.out.print("\n** Admin Func **"
                         +"\n[8]:View COMP3334_DB_LOG");
        }
    }
    
    public static int endView() {
        System.out.println("\n\nExit...");
        System.out.println("\n                         *Thinks for using*                      ");
        System.out.println("=================================================================");
        return 0;
    }

    public static void displayAccData(Account acc) {
        System.out.printf("\nAccNo:%s | Name:%s | Email:%s | PhoneNo:%s", acc.getAccNo() + "",
                acc.getLoginName() + "", acc.getEmail() + "", acc.getPhoneNo() + "");
        System.out.println("\n=================================================================");
    }


    public static boolean isValidString(String input) {
        // Define the set of invalid characters
        String invalidCharacters = "\"',!%-+`~><$/\\|&*()[]{};:?#^";

        // Iterate through each character in the input string
        for (char c : input.toCharArray()) {
            // Check if the character is in the invalid characters set
            if (invalidCharacters.indexOf(c) != -1) {
                return false; // Invalid character found
            }
        }

        return true; // No invalid characters found
    }

    public static boolean isValidNumber(String input) {
        // Check if the input is null or empty
        if (input == null || input.isEmpty()) {
            return false;
        }

        // Iterate through each character in the input string
        for (char c : input.toCharArray()) {
            // Check if the character is not a digit (0-9)
            if (!Character.isDigit(c)) {
                return false; // Invalid character found
            }
        }

        return true; // All characters are valid digits
    }

    public static boolean verifyPassword(String inputPassword, String storedHash) {
        // Define hashpwd to 2 part, first part = salt, sec part = hashed pwd
        String[] parts = storedHash.split(":");
        String salt = parts[0];
        String hash = parts[1];
        // hash the inputed pwd
        String inputHash = hashPasswordWithPBKDF2(inputPassword, salt);
        // if h(hash_inputed_pwd) == h(stored_hash), = ture = verify = login
        return inputHash.equals(hash);
    }

    public static String hashPassword(String password) {
        // gen salt and use salt to hash function
        String salt = generateSalt();
        String hash = hashPasswordWithPBKDF2(password, salt);
        return salt + ":" + hash; // Store salt and hash together
    }

    public static String hashPasswordWithPBKDF2(String password, String salt) {
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // 128 bits
        random.nextBytes(salt);
        return new String(salt); // You may want to convert to hex or base64
    }

    public static void storeTOTP(String totp, String fileName) {
        File file = new File(fileName); // Create a file object for the current directory

        try (FileWriter writer = new FileWriter(file)) {
            writer.write(totp); // Write the TOTP to the file
            System.out.println("TOTP successfully stored in " + fileName+" (Please Use it within 30s)");
        } catch (IOException e) {
            System.err.println("Error writing TOTP to file: " + e.getMessage());
        }
    }

    public static String toTOTPKEY(String input) {
        String validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        // Filter the hash to only include valid characters
        StringBuilder filteredinput = new StringBuilder();
        for (char c : input.toUpperCase().toCharArray()) {
            if (validChars.indexOf(c) != -1) { // Check if the character is valid
                filteredinput.append(c);
            }
        }

        String result = filteredinput.toString();
        //System.out.println(result);
        return result;
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
    
    private static byte[] encryptFile(File file, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    
            byte[] fileData = Files.readAllBytes(file.toPath());
            return cipher.doFinal(fileData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
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