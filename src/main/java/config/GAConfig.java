package config;

import java.io.File;

public class GAConfig {

    private String weakPath;
    private String strongPath;
    private int level;
    private boolean badStringMatching;

    private File cdHashFile;
    private File connectionFile;

    public GAConfig() {
        this.level = 0;
        this.badStringMatching = false;
    }
    public String getWeakPath() {
        return weakPath;
    }

    public void setWeakPath(String weakPath) {
        this.weakPath = weakPath;
    }

    public String getStrongPath() {
        return strongPath;
    }

    public void setStrongPath(String strongPath) {
        this.strongPath = strongPath;
    }

    public Integer getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

    public Boolean getBadStringMatching() {
        return badStringMatching;
    }

    public void setBadStringMatching(boolean badStringMatching) {
        this.badStringMatching = badStringMatching;
    }

    public File getCdHashFile() {
        return cdHashFile;
    }

    public void setCdHashFile(File cdHashFile) {
        this.cdHashFile = cdHashFile;
    }

    public File getConnectionFile() {
        return connectionFile;
    }

    public void setConnectionFile(File connectionFile) {
        this.connectionFile = connectionFile;
    }

    @Override
    public String toString() {
        return "GAConfig{" +
                "weakPath='" + weakPath + '\'' +
                ", strongPath='" + strongPath + '\'' +
                ", level=" + level +
                ", badStringMatching=" + badStringMatching +
                ", cdHashFile=" + cdHashFile.getAbsolutePath() +
                ", connectionFile=" + connectionFile.getAbsolutePath() +
                '}';
    }
}
