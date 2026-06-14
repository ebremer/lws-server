package com.ebremer.lws.server.storage;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * A {@link BinaryStore} that mirrors blob keys onto a directory tree on the local filesystem.
 * Writes are atomic (write-to-temp then move). Keys are constrained to stay within the base
 * directory.
 *
 * @author Erich Bremer
 */
public final class FileSystemBinaryStore implements BinaryStore {

    private final Path base;

    public FileSystemBinaryStore(Path base) {
        try {
            Files.createDirectories(base);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot create blob directory: " + base, e);
        }
        this.base = base.toAbsolutePath().normalize();
    }

    private Path resolve(String key) {
        Path p = base.resolve(key).toAbsolutePath().normalize();
        if (!p.startsWith(base)) {
            throw new IllegalArgumentException("Key escapes binary store root: " + key);
        }
        return p;
    }

    @Override
    public boolean exists(String key) {
        return Files.isRegularFile(resolve(key));
    }

    @Override
    public InputStream read(String key) throws IOException {
        return Files.newInputStream(resolve(key));
    }

    @Override
    public StoredBlob write(String key, InputStream data) throws IOException {
        Path target = resolve(key);
        Files.createDirectories(target.getParent());
        Path tmp = Files.createTempFile(target.getParent(), ".lws-", ".tmp");
        long size;
        String hex;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (OutputStream out = new DigestOutputStream(Files.newOutputStream(tmp), md)) {
                size = data.transferTo(out);
            }
            hex = HexFormat.of().formatHex(md.digest());
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        } finally {
            Files.deleteIfExists(tmp);
        }
        return new StoredBlob(size, hex);
    }

    @Override
    public void delete(String key) throws IOException {
        Files.deleteIfExists(resolve(key));
    }

    @Override
    public long size(String key) throws IOException {
        return Files.size(resolve(key));
    }
}
