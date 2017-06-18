package user;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class UserAlias {

    private Set<String> hashes;
    private Set<String> aliases;
    private Set<String> IPs;

    public UserAlias() {
        this.hashes = new HashSet<>();
        this.aliases = new HashSet<>();
        this.IPs = new HashSet<>();
    }

    public void addRecord(String hash, String name, String ip) {
        this.addHash(hash);
        this.addAlias(name);
        this.addIP(ip);
    }

    // A copy of the respective set will be returned, so that the object here could not be altered
    public Set<String> getHashes() {
        return new HashSet<>(hashes);
    }

    public Set<String> getAliases() {
        return new HashSet<>(aliases);
    }

    public Set<String> getIPs() {
        return new HashSet<>(IPs);
    }

    public void addHash(String hash) {
        hashes.add(hash);
    }

    public void addAlias(String alias) {
        aliases.add(alias);
    }

    public void addIP(String ip) {
        IPs.add(ip);
    }

    // Return this object for method chaining
    public UserAlias join(UserAlias other) {
        if (other == null || this.equals(other)) {
            return this;
        }

        hashes.addAll(other.hashes);
        aliases.addAll(other.aliases);
        IPs.addAll(other.IPs);

        return this;
    }

    @Override
    public int hashCode() {
        return Objects.hash(hashes, aliases, IPs);
    }

    @Override
    public boolean equals(Object o) {

        if (o == this) return true;
        if (!(o instanceof UserAlias)) {
            return false;
        }
        UserAlias other = (UserAlias) o;
        return Objects.equals(hashes, other.hashes) &&
                Objects.equals(aliases, other.aliases) &&
                Objects.equals(IPs, other.IPs);
    }

    @Override
    public String toString() {
        return "UserAlias{" +
                "hashes=[" + String.join(", ", hashes) +
                "], aliases=[" + String.join(", ", aliases) +
                "], IPs=[" + String.join(", ", IPs) +
                "]}";
    }
}
