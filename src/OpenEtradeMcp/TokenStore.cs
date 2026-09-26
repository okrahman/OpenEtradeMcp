using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;

namespace OpenEtradeMcp;

public sealed record OAuthCredentials(string Token, string Secret, DateTimeOffset IssuedAt,
    DateTimeOffset RenewedAt, DateTimeOffset ExpiresAt);

public interface ITokenStore
{
    Task<OAuthCredentials?> LoadAsync();
    Task SaveAsync(OAuthCredentials credentials);
    Task DeleteAsync();
}

// Unix deployments only: refuse platforms where POSIX permission checks cannot be enforced.
public sealed class EncryptedFileTokenStore : ITokenStore, IDisposable
{
    private readonly string path;
    private readonly byte[] key;
    private readonly byte[] binding;
    private readonly FileStream storeLock;
    private const UnixFileMode FileMode600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode DirectoryMode700 = FileMode600 | UnixFileMode.UserExecute;

    public EncryptedFileTokenStore(ETradeConfig config)
    {
        FileStream? acquired = null;
        try
        {
            if (OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(config.TokenDirectory) ||
                !Path.IsPathFullyQualified(config.TokenKeyFile)) throw new IOException();
            CheckParents(config.TokenDirectory);
            CheckParents(config.TokenKeyFile);
            Check(config.TokenKeyFile, FileMode600);
            key = File.ReadAllBytes(config.TokenKeyFile);
            if (key.Length != 32) throw new IOException();
            if (!Directory.Exists(config.TokenDirectory)) Directory.CreateDirectory(config.TokenDirectory, DirectoryMode700);
            Check(config.TokenDirectory, DirectoryMode700);
            path = Path.Combine(config.TokenDirectory, "credentials.json");
            var lockPath = Path.Combine(config.TokenDirectory, "store.lock");
            if (File.Exists(lockPath)) Check(lockPath, FileMode600);
            acquired = new FileStream(lockPath, new FileStreamOptions { Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite, Share = FileShare.None, UnixCreateMode = FileMode600 });
            // FileShare.None obtains a nonblocking exclusive flock on Unix, released only on close.
            storeLock = acquired;
            binding = Encoding.UTF8.GetBytes("OpenEtradeMcp:v1:" + config.BaseUrl + ":" +
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(config.ConsumerKey))));
        }
        catch { acquired?.Dispose(); throw new EtradeOperationException("Token storage configuration, permissions, or exclusive lock is invalid."); }
    }

    private static void CheckParents(string value)
    {
        var current = Path.GetFullPath(value);
        while (current != null)
        {
            if (File.Exists(current) || Directory.Exists(current))
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new IOException();
            current = Path.GetDirectoryName(current);
        }
    }

    private static void Check(string value, UnixFileMode maximum)
    {
        if (OperatingSystem.IsWindows()) throw new IOException();
        CheckParents(value);
        if ((File.GetUnixFileMode(value) & ~maximum) != 0) throw new IOException();
    }

    public async Task<OAuthCredentials?> LoadAsync()
    {
        try
        {
            if (!File.Exists(path)) return null;
            Check(path, FileMode600);
            var envelope = JsonSerializer.Deserialize<Envelope>(await File.ReadAllBytesAsync(path)) ?? throw new IOException();
            if (envelope.Version != 1) throw new IOException();
            var plaintext = new byte[envelope.Ciphertext.Length];
            try
            {
                using var aes = new AesGcm(key, 16);
                aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, binding);
                var credentials = JsonSerializer.Deserialize<OAuthCredentials>(plaintext) ?? throw new IOException();
                if (string.IsNullOrEmpty(credentials.Token) || string.IsNullOrEmpty(credentials.Secret) ||
                    credentials.RenewedAt < credentials.IssuedAt || credentials.ExpiresAt <= credentials.IssuedAt ||
                    credentials.RenewedAt >= credentials.ExpiresAt) throw new IOException();
                return credentials;
            }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }
        catch { throw new EtradeOperationException("Stored OAuth credentials are insecure, invalid, or cannot be decrypted."); }
    }

    public async Task SaveAsync(OAuthCredentials credentials)
    {
        if (OperatingSystem.IsWindows()) throw new EtradeOperationException("Unix token storage is required.");
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(credentials);
        try
        {
            Check(Path.GetDirectoryName(path)!, DirectoryMode700);
            if (File.Exists(path)) Check(path, FileMode600);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];
            using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plaintext, ciphertext, tag, binding);
            await using (var file = new FileStream(temporary, new FileStreamOptions { Mode = FileMode.CreateNew,
                Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = FileMode600, Options = FileOptions.WriteThrough }))
            {
                await file.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(new Envelope(1, nonce, ciphertext, tag)));
                file.Flush(true);
            }
            File.Move(temporary, path, true);
            FlushDirectory();
        }
        catch { throw new EtradeOperationException("OAuth credential persistence failed."); }
        finally { CryptographicOperations.ZeroMemory(plaintext); if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public Task DeleteAsync()
    {
        try { if (File.Exists(path)) { Check(path, FileMode600); File.Delete(path); FlushDirectory(); } return Task.CompletedTask; }
        catch { throw new EtradeOperationException("OAuth credentials cleared locally, but stored credential deletion failed."); }
    }

    // Persist the rename/unlink itself so a host reboot does not lose an acknowledged transition.
    private void FlushDirectory()
    {
        var descriptor = Open(Path.GetDirectoryName(path)!, 0);
        if (descriptor < 0) throw new IOException();
        try { if (Fsync(descriptor) != 0) throw new IOException(); }
        finally { Close(descriptor); }
    }
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int descriptor);
    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int descriptor);

    public void Dispose() { storeLock.Dispose(); CryptographicOperations.ZeroMemory(key); }
    private sealed record Envelope(int Version, byte[] Nonce, byte[] Ciphertext, byte[] Tag);
}
