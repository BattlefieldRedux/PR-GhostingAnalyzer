package user;

import config.GAConfig;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UserRecords {

    /*
        User alias object is made up of a set of hashes, usernames and IPs
        One username could have multiple hashes and one hash could have multiple names linked to it, so it is a n to m mapping
     */

    // Check whether we want to join user records by IP or not (might be overkill in some instances, i.e. dynamic IP)
    // On the other hand it might help against people who spoof HWID's or otherwise connect from the same IP
    // When this is true, the user records will also be updated as the namehack log is parsed
    private final boolean matchByIP;

    private final boolean badNameMatching;

    private Map<String, UserAlias> usersByHash;
    private Map<String, UserAlias> usersByName;
    private Map<String, UserAlias> usersByIP;

    private Set<String> notFound;

    public UserRecords(boolean matchByIP, boolean badNameMatching) {
        this.matchByIP = matchByIP;

        this.badNameMatching = badNameMatching;

        this.usersByHash = new HashMap<>();
        this.usersByName = new HashMap<>();
        this.usersByIP = new HashMap<>();

        this.notFound = new HashSet<>();
    }

    /**
     * Up to and including PR v1.4.11.0 (as of writing this program), the user name strings were matched with log.contains(hash + " " + name),
     * which meant that if you had the same CD hash, but your name was one character shorter than an entry already in the cd hash log,
     * it would still find an entry and not add a new one with the shorter name.
     *
     * However if the bad string matching has been set to true in the config, we will try to mimic it here.
     * A set is returned, because multiple matches for the name might be found, we will combine them all into one user.
     *
     * The result of this search is only relevant for updating an already parsed CD hash log's user records with the Namehack user records.
     *
     * @param name Username to be searched for in the map keys.
     * @return Set of UserAlias objects found. Multiple matches for a name could be found.
     */
    public Set<UserAlias> doBadStringMatching(String name) {

        Set<UserAlias> found = new HashSet<>();

        for (String key : usersByName.keySet()) {
            if (key.startsWith(name)) {
                found.add(usersByName.get(key));
            }
        }

        return found;
    }

    public void addRecord (String hash, String username, String ip) {

        // Create new user object
        UserAlias newUser = new UserAlias();
        newUser.addRecord(hash, username, ip);

        // Join the new object with existing records, that have a correlation with this one
        newUser.join(usersByHash.get(hash))
                .join(usersByName.get(username));

        // If we want to also correlate by IP, we can do that here
        if (matchByIP) {
            newUser.join(usersByIP.get(ip));

            // This map is only relevant when we do want to match join stuff by IP and later use that map
            for (String uIP : newUser.getIPs()) {
                usersByIP.put(uIP, newUser);
            }
        }

        // Update all references for searching
        for (String uHash : newUser.getHashes()) {
            usersByHash.put(uHash, newUser);
        }

        for (String uAlias : newUser.getAliases()) {
            usersByName.put(uAlias, newUser);
        }
    }

    public void addConnectionRecord(String username, String ip) {

        UserAlias user = usersByName.get(username);

        // Read the doBadStringMatching(..) method comment for more information
        if (user == null && badNameMatching) {
            for (UserAlias similarUser : doBadStringMatching(username)) {

                // If no user was previously found, then use the first one possible
                if (user == null) {
                    user = similarUser;
                    // Make sure this name is added too
                    user.addAlias(username);
                    continue;
                }

                user.join(similarUser);
            }
        }

        if (user == null) {
            notFound.add(username);

            // Even though the user was not found, lets retain the limited user data without the CD hash
            user = new UserAlias();
            user.addAlias(username);
        }

        user.addIP(ip);

        // Join by ip
        if (matchByIP) {
            user.join(usersByIP.get(ip));
        }

        // If joined by IP or if bad name searching is active, update references
        if (matchByIP || badNameMatching) {
            // We did a join and should update all references now
            for (String uHash : user.getHashes()) {
                usersByHash.put(uHash, user);
            }

            for (String uAlias : user.getAliases()) {
                usersByName.put(uAlias, user);
            }

            for (String uIP : user.getIPs()) {
                usersByIP.put(uIP, user);
            }
        }

    }

    public static UserRecords build(GAConfig config, boolean joinByIP) throws RecordBuildingException {

        /*
            Regex: "\[([^\s]{8,10}\s[^\s]{5})]\s([a-z0-9]{32})\s([^\s]{1,6})?\s([^\s]{1,20})\s((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
            Capture groups:
                1) Timestamp (first join)
                2) Hash
                3) Tag (optional)
                4) Username
                5) IP
                6-9) IP sub-parts
         */

        UserRecords records = new UserRecords(joinByIP, config.getBadStringMatching());

        try (BufferedReader br = new BufferedReader(new FileReader(config.getCdHashFile()))) {

            Pattern pat = Pattern.compile("\\[([^\\s]{8,10}\\s[^\\s]{5})]\\s([a-z0-9]{32})\\s([^\\s]{1,6})?\\s([^\\s]{1,20})\\s((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))");

            String line;
            while ((line = br.readLine()) != null) {
                Matcher matcher = pat.matcher(line);

                if (matcher.find() && matcher.groupCount() >= 5) {
                    records.addRecord(matcher.group(2), matcher.group(4), matcher.group(5));
                }
            }

        } catch (IOException e) {
            throw new RecordBuildingException("An error occurred while the user record map was being built: " + e.getMessage());
        }

        records.updateUserRecordsWithConnections(config.getConnectionFile(), joinByIP);

        return records;
    }

    private UserRecords updateUserRecordsWithConnections(File connectionFile, boolean joinByIP) throws RecordBuildingException {

        /*
            Joining regex: "\[([^\s]{26})]\sNHACK\sAdded\s"([^\s]{1,16})"\son\s((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\s\[([0-9]{1,3})]\."
            Groups:
                1) Timestamp
                2) Name
                3) IP
                4-7) IP sub-parts
                8) nth player on the server (needed to check for server crashes)

            Leaving regex: \[([^\s]{26})]\sNACK\sDeleted\s"([^\s]{1,20})"\.
            Groups:
                1) Timestamp
                2) Name
         */

        try (BufferedReader br = new BufferedReader(new FileReader(connectionFile))) {

            Pattern pat = Pattern.compile("\\[([^\\s]{26})]\\sNHACK\\sAdded\\s\"([^\\s]{1,20})\"\\son\\s((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\\s\\[([0-9]{1,3})]\\.");

            String line;
            while ((line = br.readLine()) != null) {
                Matcher matcher = pat.matcher(line);

                if (matcher.find() && matcher.groupCount() >= 4) {
                    this.addConnectionRecord(matcher.group(2), matcher.group(3));
                }
            }

        } catch (IOException e) {
            throw new RecordBuildingException("An error occurred while the user record map was being built: " + e.getMessage());
        }

        return this;
    }

    @Override
    public String toString() {

        Set<String> userStrings = new HashSet<>();
        for (UserAlias user : usersByName.values()) {
            userStrings.add(user.toString());
        }

        return String.join(",\n", userStrings);
    }

    public Collection<UserAlias> getAllUserAliases() {

        Set<UserAlias> unique = new HashSet<>();

        for (UserAlias user : usersByName.values()) {
            unique.add(user);
        }

        return unique;
    }

    public void outWarnings() {

        if (notFound.size() > 0) {
            System.err.println("Warning: The following usernames (" + notFound.size() + ") from the Namehack log were not found in the CD Hash log:");
            System.err.println(String.join(", ", notFound));
            if (!badNameMatching) {
                System.err.println("If you are using logs before or including PR v1.4.11.0, then you might want to enable bad name string checking (-b or --bad-strings). Check --help for more info.");
            }
            notFound = new HashSet<>();
        }

    }

    public UserAlias findByName(String name) {
        return usersByName.get(name);
    }

    public UserAlias findByHash(String hash) {
        return usersByHash.get(hash);
    }

    public UserAlias findByIP(String ip) {
        return usersByIP.get(ip);
    }
}
