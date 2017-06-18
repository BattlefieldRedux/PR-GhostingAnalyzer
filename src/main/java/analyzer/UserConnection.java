package analyzer;

import user.RecordBuildingException;
import user.UserAlias;
import user.UserRecords;

public class UserConnection {

    private String name;
    private String ip;
    private UserAlias strongUserObject;
    private UserAlias weakUserObject;

    private int configLevel;

    public UserConnection(String name, String ip, int configLevel) {
        this.name = name;
        this.ip = ip;
        this.configLevel = configLevel;
    }

    // Levels 0 and 1
    public void attachUserObjects(UserRecords strongRecords) throws RecordBuildingException {
        strongUserObject = strongRecords.findByName(name);

        if (strongUserObject == null) {
            throw new RecordBuildingException("User object was not found, although the user records should have been built with the same data. Are you using logs from or before PR v1.4.11.0? (Enable --bad-strings flag or check --help for more info)");
        }
    }

    // Level 2
    public void attachUserObjects(UserRecords strongRecords, UserRecords weakRecords) throws RecordBuildingException {
        strongUserObject = strongRecords.findByName(name);
        weakUserObject = weakRecords.findByName(name);

        if (weakUserObject == null || strongUserObject == null) {
            throw new RecordBuildingException("User object was not found, although the user records should have been built with the same data. Are you using logs from or before PR v1.4.11.0? (Enable --bad-strings flag or check --help for more info)");
        }
    }

    public int checkGhosting(UserConnection other) {
        if (configLevel >= 0) {
            if (this.getIp().equals(other.getIp())) {
                return 0;
            }
        }

        if (configLevel >= 1) {
            if (this.getStrongUserObject().equals(other.getStrongUserObject())) {
                return 1;
            }
        }

        if (configLevel >= 2) {
            if (this.getWeakUserObject().equals(other.getWeakUserObject())) {
                return 2;
            }
        }

        return -1;
    }

    public String getName() {
        return name;
    }

    public String getIp() {
        return ip;
    }

    public UserAlias getWeakUserObject() {
        return weakUserObject;
    }

    public UserAlias getStrongUserObject() {
        return strongUserObject;
    }

    @Override
    public String toString() {
        return "UserConnection{" +
                "name='" + name + '\'' +
                ", ip='" + ip + '\'' +
                '}';
    }
}
