package com.ebremer.lws.server.core;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creating files and directories that only their owner can read.
 *
 * <p>Every long-lived secret this server keeps on disk goes through here: the webhook signing seed
 * (finding M36) and the ACME account and TLS domain private keys (finding M26). Both were written
 * with {@code Files.newBufferedWriter}, which takes the process umask — mode 0644 on a typical host,
 * so any local user could read the storage's TLS private key or forge notification signatures that
 * verify against its published JWKS.
 *
 * <p>Two properties matter and neither is free:
 * <ul>
 *   <li><b>The permission is set before the bytes are.</b> A file created world-readable and
 *       {@code chmod}ed afterwards is readable for the window in between, which is exactly when a
 *       key is being written into it. The POSIX path passes the mode as a creation attribute; the
 *       Windows path cannot, so it restricts an <em>empty</em> temp file first and writes into it
 *       after.</li>
 *   <li><b>The file appears complete or not at all.</b> The content is written to a temp file in the
 *       same directory and moved into place with {@link StandardCopyOption#ATOMIC_MOVE}, so a kill
 *       in the middle leaves the old file (or no file), never a truncated key.</li>
 * </ul>
 *
 * <p>Not every filesystem can express owner-only (a FAT volume cannot), so a failure to restrict is
 * logged rather than fatal: refusing to start because the volume cannot hold a permission bit would
 * be worse than starting with a warning an operator can act on.
 *
 * @author Erich Bremer
 */
public final class SecureFiles {

    private static final Logger log = LoggerFactory.getLogger(SecureFiles.class);

    private static final String FILE_MODE = "rw-------";
    private static final String DIR_MODE = "rwx------";

    private SecureFiles() {
    }

    /** Writes into a {@link Writer} that {@link #writeOwnerOnly} supplies. */
    @FunctionalInterface
    public interface WriterBody {
        void writeTo(Writer writer) throws IOException;
    }

    /**
     * Create {@code file} owner-only and atomically, with content produced by {@code body}.
     *
     * <p>The move deliberately does <em>not</em> replace an existing file: these are keys, and if
     * another process won the race then that process's key is the one the world will verify against.
     * That is enforced by a check immediately before the move as well as by the move itself, because
     * only Windows fails an {@code ATOMIC_MOVE} onto an existing name — a POSIX {@code rename()}
     * replaces silently. The residual window is one instruction wide and both callers generate their
     * key once, at startup.
     *
     * @return {@code true} if this call created the file, {@code false} if it already existed (in
     *         which case nothing was written and the caller should read what is there)
     */
    public static boolean writeOwnerOnly(Path file, WriterBody body) throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        if (!Files.isDirectory(dir)) {
            createDirectoriesOwnerOnly(dir);
        }
        Path tmp = Files.createTempFile(dir, file.getFileName().toString() + "-", ".tmp");
        try {
            restrictToOwner(tmp);
            try (Writer writer = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                body.writeTo(writer);
            }
            if (Files.exists(file)) {
                Files.deleteIfExists(tmp);
                return false;
            }
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE);
            return true;
        } catch (FileAlreadyExistsException alreadyThere) {
            Files.deleteIfExists(tmp);
            return false;
        } catch (IOException | RuntimeException e) {
            Files.deleteIfExists(tmp);
            throw e;
        }
    }

    /**
     * Create {@code dir} and any missing parents, owner-only where the filesystem can say so.
     *
     * <p>On POSIX the mode is a creation attribute, so the directory is never briefly world-readable.
     * Existing directories are restricted too: an operator upgrading from a version that created
     * {@code tls/} as 0755 should not have to find and fix it by hand.
     */
    public static void createDirectoriesOwnerOnly(Path dir) throws IOException {
        if (Files.isDirectory(dir)) {
            restrictDirectoryToOwner(dir);
            return;
        }
        if (isPosix(dir)) {
            Files.createDirectories(dir,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(DIR_MODE)));
            return;
        }
        Files.createDirectories(dir);
        restrictDirectoryToOwner(dir);
    }

    /** Make an existing file readable only by its owner. */
    public static void restrictToOwner(Path file) {
        restrict(file, FILE_MODE, false);
    }

    /** Make an existing directory readable and traversable only by its owner. */
    public static void restrictDirectoryToOwner(Path dir) {
        restrict(dir, DIR_MODE, true);
    }

    /**
     * POSIX permissions where they exist, a replacement Windows ACL where they do not.
     *
     * <p>The {@link java.io.File} permission calls are deliberately <em>not</em> the Windows path.
     * {@code File.setReadable(false, false)} — "take read away from everybody but the owner" — is
     * documented to return {@code false} when the platform cannot do it, and Windows cannot: there is
     * no world bit to clear, and the inherited ACL granting {@code Users} and {@code Administrators}
     * stays exactly where it was. The previous implementation therefore logged a warning and left the
     * key readable on every Windows host, which is the platform this is developed on. Replacing the
     * ACL with a single ALLOW entry for the file's owner is the real equivalent of {@code 0600}: it
     * drops inheritance along with every other principal.
     */
    private static void restrict(Path path, String posixMode, boolean directory) {
        try {
            if (isPosix(path)) {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(posixMode));
                return;
            }
            AclFileAttributeView acl = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (acl != null) {
                // The principal is the one this process runs as, not the one that happens to own the
                // file. They are usually the same and, when they are not, using the file's owner
                // would replace the ACL with a single entry naming somebody else — locking the
                // server out of the key store it was trying to protect, on the path that exists to
                // tighten a directory an operator created earlier.
                java.nio.file.attribute.UserPrincipal self = path.getFileSystem()
                        .getUserPrincipalLookupService()
                        .lookupPrincipalByName(System.getProperty("user.name"));
                AclEntry.Builder entry = AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(self)
                        .setPermissions(EnumSet.allOf(AclEntryPermission.class));
                if (directory) {
                    // So files created inside inherit the same single-principal ACL rather than
                    // picking the parent's up again from further out.
                    entry.setFlags(EnumSet.of(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT));
                }
                acl.setAcl(List.of(entry.build()));
                return;
            }
            warnOnce(path, "this filesystem supports neither POSIX permissions nor ACLs");
        } catch (IOException | UnsupportedOperationException | SecurityException e) {
            warnOnce(path, e.toString());
        }
    }

    /**
     * Say once per path that a secret could not be protected.
     *
     * <p>Once, because the condition is a property of the filesystem rather than of the attempt: it
     * fails identically every time, and these paths are touched on a startup path that can run
     * repeatedly. One line an operator can act on is worth more than a stream of identical ones.
     */
    private static void warnOnce(Path path, String why) {
        if (warned.add(path.toString())) {
            log.warn("Could not restrict {} to owner-only ({}); any local user can read it. "
                    + "This file or directory holds a private key.", path, why);
        }
    }

    private static final Set<String> warned = ConcurrentHashMap.newKeySet();

    private static boolean isPosix(Path path) {
        return Files.getFileAttributeView(path, PosixFileAttributeView.class) != null;
    }
}
