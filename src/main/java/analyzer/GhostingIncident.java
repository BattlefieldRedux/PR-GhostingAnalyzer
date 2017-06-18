package analyzer;

import java.util.ArrayList;
import java.util.List;

public class GhostingIncident {

    private List<UserConnection> connections;
    private int level;
    private String timestamp;

    public GhostingIncident(UserConnection primary, UserConnection secondary, int level, String timestamp) {
        this.connections = new ArrayList<>();
        connections.add(primary);
        connections.add(secondary);

        this.level = level;
        this.timestamp = timestamp;
    }

    @Override
    public String toString() {

        List<String> connString = new ArrayList<>();

        for (UserConnection conn : connections) {
            connString.add("(" + conn.getName() + ", " + conn.getIp() + ")");
        }

        return "GhostingIncident{" +
                "connections=[" + String.join(", ", connString) +
                "], level=" + level +
                ", timestamp='" + timestamp + '\'' +
                '}';
    }
}
