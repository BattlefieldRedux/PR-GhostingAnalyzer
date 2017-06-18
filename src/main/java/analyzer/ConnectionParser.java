package analyzer;

import config.GAConfig;
import user.RecordBuildingException;
import user.UserRecords;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConnectionParser {

    private GAConfig config;
    private List<GhostingIncident> incidents;

    private UserRecords strongRecords;
    private UserRecords weakRecords;

    public ConnectionParser(GAConfig config, UserRecords strongRecords, UserRecords weakRecords) {
        this.config = config;
        this.incidents = new ArrayList<>();
        this.strongRecords = strongRecords;
        this.weakRecords = weakRecords;
    }

    public List<GhostingIncident> parse() throws RecordBuildingException {

        /*
            Keep a map of concurrent users on the server.
            If a new join ID doesn't match the number of players on the server, the server must have crashed.

            Joining regex: "\[([^\s]{26})]\sNHACK\sAdded\s"([^\s]{1,16})"\son\s((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\s\[([0-9]{1,3})]\."
            Groups:
                1) Timestamp
                2) Name
                3) IP
                4-7) IP sub-parts
                8) nth player on the server (needed to check for server crashes)

            Leaving regex: "\[([^\s]{26})]\sNACK\sDeleted\s"([^\s]{1,20})"\."
            Groups:
                1) Timestamp
                2) Name
         */

        Map<String, UserConnection> connected = new HashMap<>();

        try (BufferedReader br = new BufferedReader(new FileReader(config.getConnectionFile()))) {
            Pattern conPat = Pattern.compile("\\[([^\\s]{26})]\\sNHACK\\sAdded\\s\"([^\\s]{1,20})\"\\son\\s((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\\s\\[([0-9]{1,3})]\\.");
            Pattern discPat = Pattern.compile("\\[([^\\s]{26})]\\sNACK\\sDeleted\\s\"([^\\s]{1,20})\"\\.");

            String line;
            while ((line = br.readLine()) != null) {

                Matcher matcher = conPat.matcher(line);
                if (matcher.find() && matcher.groupCount() >= 8) {
                    String timestamp = matcher.group(1);

                    // Check for server crash
                    if (Integer.valueOf(matcher.group(8))-1 != connected.size()) {
                        // Server must have crashed, empty out the connection list
                        connected = new HashMap<>();
                    }

                    String name = matcher.group(2);
                    UserConnection newConnection = new UserConnection(name, matcher.group(3), config.getLevel());

                    // Load in the UserAlias objects
                    if (config.getLevel() < 2) {
                        newConnection.attachUserObjects(strongRecords);
                    } else {
                        newConnection.attachUserObjects(strongRecords, weakRecords);
                    }

                    for (UserConnection existingConnection : connected.values()) {
                        int incidentLevel = existingConnection.checkGhosting(newConnection);

                        if (incidentLevel != -1) {
                            incidents.add(new GhostingIncident(existingConnection, newConnection, incidentLevel, timestamp));
                        }
                    }

                    connected.put(name, newConnection);

                } else {
                    // Joining was not found, now check for disconnect
                    matcher = discPat.matcher(line);
                    if (matcher.find() && matcher.groupCount() >= 2) {
                        connected.remove(matcher.group(2));
                    }
                }
            }

        } catch (IOException e) {
            throw new RecordBuildingException("An error occurred while the user record map was being built: " + e.getMessage());
        }

        return incidents;
    }

}
