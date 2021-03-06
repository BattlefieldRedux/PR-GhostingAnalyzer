# PR Ghosting Analyzer

Project Reality: BF2 Ghosting Detection Tool. Uses _CD Hash_ and _Namehack_ logs to determine ghosting incidents using 3 different techniques. This project is licensed under the GNU General Public License v3.0.

So far only compatible with the Linux IP tables namehack solution. Not too difficult to write the regex and the result parsing around to work with other log formats.

The _CD Hash_ log can usually be found at `admin/logs/cdhash.log`

The _Namehack_ log can usually be found in the server root directory as `namehack.log`

This tool should be used in conjunction with other gameplay analysis tools such as the Realitytracker, as any output from it is not definitive proof of ghosting. For example with level 0 incidents, the players could be playing together behind the same router and unless they are sitting on different teams and acting suspiciously, it is most likely a false-positive.

## Installation

Download the latest version from the [releases page](https://github.com/vedler/PR-GhostingAnalyzer/releases).

Alternatively you can clone or download the source code as ZIP and run `gradlew fatJar` in the project directory. The resulting _.jar_ file will be located at `build/libs/GhostingAnalyzer-0.0.1.jar`

[Java 8 is required.](http://www.oracle.com/technetwork/java/javase/downloads/jre8-downloads-2133155.html)

## Usage

This usage information can also be found by running `java -jar GhostingAnalyzer-x.x.x.jar [--help|-h]`

The tool is ran from the command-line terminal, using the following syntax: `java -jar GhostingAnalyzer-x.x.x.jar [options] {CD Hash log path} {Namehack log path}`

### Options

* `[-l|--level] {0-2}` - Specify the user record building level. Default is 0. Every level also includes the prior levels for search criteria.
  * Level 0: Check if there are two concurrent players playing from one IP.
  * Level 1: Check if a player is online on two of his accounts at the same time, matched by name and CD Hash (i.e. this user has logged in with the same account (username) on two computers (CD Hash) and both of those computers are connected to the server at the same time)
  * Level 2: Check if there are two players on the server, who have at some point in the past both used the same IP at any given time.

* `[-s|--output-strong] {path}` - Output all user records separately matched by names and hashes.
* `[-w|--output-weak] {path}` - Output all user records separately matched by names, hashes and every IP used.

* `[-b|--bad-strings]` - Use bad username string matching for PR versions up to and including v1.4.11.0.
  * Extra characters at the end of the username were not accounted for in the CD hash log, i.e. searching for "vedler" was also matched to "vedlerr" if they both had the same CD hash.

### Examples

`java -jar GhostingAnalyzer-0.0.1.jar "/var/prbf2/1/admin/logs/cdhash.log" "/var/prbf2/1/namehack.log"`

`java -jar GhostingAnalyzer-0.0.1.jar --level 1 "/var/prbf2/1/admin/logs/cdhash.log" "/var/prbf2/1/namehack.log"`

`java -jar GhostingAnalyzer-0.0.1.jar -b -s "userrecords_strong.txt" -l 2 --output-weak "userrecords_weak.txt" "/var/prbf2/1/admin/logs/cdhash.log" "/var/prbf2/1/namehack.log" > ghosting_incidents.txt`
