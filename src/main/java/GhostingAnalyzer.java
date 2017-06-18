import analyzer.ConnectionParser;
import analyzer.GhostingIncident;
import config.GAConfig;
import user.RecordBuildingException;
import user.UserRecords;

import java.io.*;
import java.util.Collection;
import java.util.List;

public class GhostingAnalyzer {

    public static void main(String[] args) {

        if (args.length == 0) {
            System.out.println("You must specify correct arguments! Use --help or -h to see parameters.");
        } else if (args.length == 1) {
            if (args[0].equals("--help") || args[0].equals("-h")) {
                System.out.println("GhostingAnalyzer v0.0.1");
                System.out.println("Author: Kristjan Vedler (NP vedler)");
                System.out.println("https://github.com/vedler/");
                System.out.println("This project is licensed under the GNU General Public License v3.0");
				
                System.out.println("Used to look for correlations between user records (hashes, IP's, usernames) and concurrently online players to help detect ghosting incidents.");

                System.out.println();

                System.out.println("Arguments:");
                System.out.println("\t\"java -jar GhostingAnalyzer-x.x.x.jar [--help|-h]\" to see this dialogue.");
                System.out.println("\t\"java -jar GhostingAnalyzer-x.x.x.jar [options] {CD Hash log path} {Namehack log path}\" to run the application.");

                System.out.println();

                System.out.println("Options:");
                System.out.println("\t[-l|--level] {0-2} - Specify the user record building level. Default is 0. Every higher level also includes the lower levels for search criteria.");
                System.out.println("\t\t0 - Check if there are two concurrent players playing from one IP.");
                System.out.println("\t\t1 - Check if a player is online on two of his accounts at the same time, matched by name and CD Hash (i.e. this user has logged in with the same account on two computers and both of those computers are connected to the server at the same time)");
                System.out.println("\t\t2 - Check if there are two players on the server, who have at some point in the past both used the same IP at any given time.");

                System.out.println("\t[-s|--output-strong] {path} - Output all user records separately matched by names and hashes.");
                System.out.println("\t[-w|--output-weak] {path} - Output all user records separately matched by names, hashes and every IP used.");

                System.out.println("\t[-b|--bad-strings] - Use bad username string matching for PR versions up to and including v1.4.11.0.");
                System.out.println("\t\tExtra characters at the end of the username were not accounted for in the CD hash log, i.e. searching for \"vedler\" was also matched to \"vedlerr\" if they both had the same CD hash.");

                System.out.println();

                System.out.println("\tExample 1: java -jar GhostingAnalyzer-0.0.1.jar \"/var/prbf2/1/admin/logs/cdhash.log\" \"/var/prbf2/1/namehack.log\"");
                System.out.println("\tExample 2: java -jar GhostingAnalyzer-0.0.1.jar --level 1 \"/var/prbf2/1/admin/logs/cdhash.log\" \"/var/prbf2/1/namehack.log\"");
                System.out.println("\tExample 3: java -jar GhostingAnalyzer-0.0.1.jar -s \"userrecords_strong.txt\" -l 2 --output-weak \"userrecords_weak.txt\" \"/var/prbf2/1/admin/logs/cdhash.log\" \"/var/prbf2/1/namehack.log\" > ghosting_incidents.txt");
            }
        } else if (args.length >= 2) {

            GAConfig config = new GAConfig();

            // Last two arguments reserved for CD hash path and namehack path
            for (int i = 0; i < args.length-2; i++) {
                switch (args[i]) {

                    case "-l":
                    case "--level":

                        // Check if there enough room for option value and two paths
                        if (i >= args.length-3) {
                            System.out.println("Incorrect arguments. Check \"java -jar GhostingAnalyzer-x.x.x.jar --help\" for more info.");
                            return;
                        }

                        try {
                            config.setLevel(Integer.valueOf(args[i+1]));
                            i++;
                        } catch (NumberFormatException e) {
                            System.out.println("Incorrect arguments. Check \"java -jar GhostingAnalyzer-x.x.x.jar --help\" for more info.");
                            return;
                        }

                        break;
                    case "-w":
                    case "--output-weak":

                        if (i >= args.length-3) {
                            System.out.println("Incorrect arguments. Check \"java -jar GhostingAnalyzer-x.x.x.jar --help\" for more info.");
                            return;
                        }

                        config.setWeakPath(args[i+1]);
                        i++;
                        break;
                    case "-s":
                    case "--output-strong":

                        if (i >= args.length-3) {
                            System.out.println("Incorrect arguments. Check \"java -jar GhostingAnalyzer-x.x.x.jar --help\" for more info.");
                            return;
                        }

                        config.setStrongPath(args[i+1]);
                        i++;
                        break;
                    case "-b":
                    case "--bad-strings":
                        config.setBadStringMatching(true);
                        break;
                    default:
                        System.out.println("Incorrect arguments. Check \"java -jar GhostingAnalyzer-x.x.x.jar --help\" for more info.");
                        return;
                }
            }

            File hashes = new File(args[args.length-2]);
            File connections = new File(args[args.length-1]);

            // Check if files exist and have read access
            if (!hashes.exists() || !hashes.canRead()) {
                System.out.println("The specified CD Hash log file doesn't exist or the current user doesn't have read access to it.");
                return;
            } else if (!connections.exists()  || !connections.canRead()) {
                System.out.println("The specified Namehack log file doesn't exist or the current user doesn't have read access to it.");
                return;
            }

            config.setCdHashFile(hashes);
            config.setConnectionFile(connections);

            // Execute the Ghosting Analyzer with the created config
            execute(config);

        } else {
            System.out.println("Incorrect arguments. Check \"java -jar GhostingAnalyzer-x.x.x.jar --help\" for more info.");
        }
    }

    public static void execute(GAConfig config) {
        try {
            UserRecords strongRecords = UserRecords.build(config, false);
            UserRecords weakRecords = null;

            if (config.getLevel() >= 2 || (config.getWeakPath() != null && config.getWeakPath().length() > 0)) {
                weakRecords = UserRecords.build(config, true);
            }

            strongRecords.outWarnings();

            // This automatically outputs to std output
            writeLinesToStdOut(analyzeConnectionList(config, strongRecords, weakRecords));

            if (config.getWeakPath() != null && config.getWeakPath().length() > 0) {
                writeLinesToFile(weakRecords.getAllUserAliases(), config.getWeakPath());
            }

            if (config.getStrongPath() != null && config.getStrongPath().length() > 0) {
                writeLinesToFile(strongRecords.getAllUserAliases(), config.getStrongPath());
            }
        } catch (RecordBuildingException e) {
            System.err.println(e.getMessage());
            return;
        } catch (IOException e) {
            System.err.println("An error occurred while trying to write to the strong records file: " + e.getMessage());
        }
    }

    public static void writeLinesToFile(Collection<?> objects, String path) throws IOException {
        File res = new File(path);

        res.createNewFile();

        FileWriter fw = new FileWriter(res);

        for (Object obj : objects) {
            fw.write(obj.toString() + ",\n");
        }

        fw.close();
    }

    public static void writeLinesToStdOut(Collection<?> objects) {
        for (Object obj : objects) {
            System.out.println(obj.toString() + ", ");
        }
    }

    public static List<GhostingIncident> analyzeConnectionList(GAConfig config, UserRecords strongRecords, UserRecords weakRecords) throws RecordBuildingException {
        ConnectionParser parser = new ConnectionParser(config, strongRecords, weakRecords);
        return parser.parse();
    }

}
