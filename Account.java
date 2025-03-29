 
public class Account {
    private int accNo;
    private String loginName;
    private String email;
    private int phoneNo;
    private int userStatus;
    private int userRight;

    public Account() {
        this(-1, "", "", -1, -1, -1);
    }

    public Account(int accNo, String loginName, String email, int phoneNo, int userStatus, int userRight) {
        this.accNo = accNo;
        this.loginName = loginName;
        this.email = email;
        this.phoneNo = phoneNo;
        this.userStatus = userStatus;
        this.userRight = userRight;
    }

    public int getAccNo() {
        return accNo;
    }

    public String getLoginName() {
        return loginName;
    }

    public String getEmail() {
        return email;
    }

    public int getPhoneNo() {
        return phoneNo;
    }

    public int getUserStatus() {
        return userStatus;
    }

    public int getUserRight() {
        return userRight;
    }


    public void setAccNo(int accNo) {
        this.accNo = accNo;
    }

    public void setLoginName(String loginName) {
        this.loginName = loginName;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setPhoneNo(int phoneNo) {
        this.phoneNo = phoneNo;
    }

    public void setUserStatus(int userStatus) {
        this.userStatus = userStatus;
    }

    public void setUserRight(int userRight) {
        this.userRight = userRight;
    }

}