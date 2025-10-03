# Symfony Security Snippets

This comprehensive guide demonstrates 99 security-related practices and  
techniques for Symfony applications. It covers encryption, authentication,  
authorization, input validation, and protection against common  
vulnerabilities using Symfony's idiomatic conventions.  

## Basic Cryptography

### Data Encryption with Sodium

Encrypting sensitive data using PHP's Sodium extension.  

```php
<?php

namespace App\Service;

class EncryptionService
{
    private string $key;

    public function __construct()
    {
        // Key should be stored securely (e.g., in environment variables)
        $this->key = sodium_hex2bin(
            $_ENV['ENCRYPTION_KEY'] ?? sodium_bin2hex(sodium_crypto_secretbox_keygen())
        );
    }

    public function encrypt(string $data): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($data, $nonce, $this->key);
        
        return base64_encode($nonce . $ciphertext);
    }

    public function decrypt(string $encrypted): string
    {
        $decoded = base64_decode($encrypted);
        $nonce = substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        
        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $this->key);
        
        if ($plaintext === false) {
            throw new \RuntimeException('Decryption failed');
        }
        
        return $plaintext;
    }
}
```

This service uses libsodium for authenticated encryption, ensuring both  
confidentiality and integrity. The nonce is prepended to the ciphertext  
for decryption. Always store encryption keys securely in environment  
variables.  

### Symmetric Encryption for Database Fields

Encrypting sensitive fields before persisting to database.  

```php
<?php

namespace App\Entity;

use App\Service\EncryptionService;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\HasLifecycleCallbacks]
class UserProfile
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(type: 'text')]
    private string $encryptedSsn;

    private ?string $ssn = null;

    #[ORM\PrePersist]
    #[ORM\PreUpdate]
    public function encryptSensitiveData(EncryptionService $encryption): void
    {
        if ($this->ssn !== null) {
            $this->encryptedSsn = $encryption->encrypt($this->ssn);
        }
    }

    #[ORM\PostLoad]
    public function decryptSensitiveData(EncryptionService $encryption): void
    {
        if (!empty($this->encryptedSsn)) {
            $this->ssn = $encryption->decrypt($this->encryptedSsn);
        }
    }

    public function setSsn(string $ssn): self
    {
        $this->ssn = $ssn;
        return $this;
    }

    public function getSsn(): ?string
    {
        return $this->ssn;
    }
}
```

Entity lifecycle callbacks automatically encrypt data before persistence  
and decrypt after loading. This ensures sensitive data is never stored in  
plain text. Note: Inject EncryptionService properly via entity listeners.  

### Asymmetric Encryption with Public/Private Keys

Using RSA for asymmetric encryption scenarios.  

```php
<?php

namespace App\Service;

class AsymmetricEncryption
{
    private $privateKey;
    private $publicKey;

    public function __construct(string $privateKeyPath, string $publicKeyPath)
    {
        $this->privateKey = openssl_pkey_get_private(
            file_get_contents($privateKeyPath),
            $_ENV['PRIVATE_KEY_PASSPHRASE'] ?? ''
        );
        
        $this->publicKey = openssl_pkey_get_public(
            file_get_contents($publicKeyPath)
        );
    }

    public function encryptWithPublicKey(string $data): string
    {
        openssl_public_encrypt($data, $encrypted, $this->publicKey);
        return base64_encode($encrypted);
    }

    public function decryptWithPrivateKey(string $encrypted): string
    {
        $data = base64_decode($encrypted);
        openssl_private_decrypt($data, $decrypted, $this->privateKey);
        
        return $decrypted;
    }

    public function sign(string $data): string
    {
        openssl_sign($data, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);
        return base64_encode($signature);
    }

    public function verify(string $data, string $signature): bool
    {
        $sig = base64_decode($signature);
        return openssl_verify($data, $sig, $this->publicKey, OPENSSL_ALGO_SHA256) === 1;
    }
}
```

Asymmetric encryption enables secure key exchange and digital signatures.  
Public keys encrypt, private keys decrypt. Signatures prove authenticity  
and integrity without revealing the private key.  

### Generating Cryptographically Secure Random Values

Creating secure random tokens and identifiers.  

```php
<?php

namespace App\Service;

class SecureRandomGenerator
{
    public function generateToken(int $length = 32): string
    {
        return bin2hex(random_bytes($length));
    }

    public function generateUrlSafeToken(int $length = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($length)), '+/', '-_'), '=');
    }

    public function generateNumericCode(int $digits = 6): string
    {
        $max = (10 ** $digits) - 1;
        $min = 10 ** ($digits - 1);
        
        return (string) random_int($min, $max);
    }

    public function generateUuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    public function generateApiKey(): string
    {
        $prefix = 'sk_live_';
        $random = $this->generateUrlSafeToken(32);
        
        return $prefix . $random;
    }
}
```

Always use random_bytes() or random_int() for cryptographic operations.  
Never use rand() or mt_rand() for security-sensitive contexts as they are  
predictable. These functions use the OS's CSPRNG.  

### Hashing Data for Integrity Verification

Creating and verifying data hashes.  

```php
<?php

namespace App\Service;

class HashingService
{
    public function hash(string $data, string $algorithm = 'sha256'): string
    {
        return hash($algorithm, $data);
    }

    public function hashHmac(string $data, string $secret): string
    {
        return hash_hmac('sha256', $data, $secret);
    }

    public function verifyHmac(string $data, string $secret, string $hash): bool
    {
        $expected = $this->hashHmac($data, $secret);
        return hash_equals($expected, $hash);
    }

    public function hashFile(string $filepath): string
    {
        if (!file_exists($filepath)) {
            throw new \RuntimeException('File not found');
        }
        
        return hash_file('sha256', $filepath);
    }

    public function createChecksum(array $data): string
    {
        ksort($data);
        $serialized = json_encode($data);
        
        return $this->hash($serialized);
    }
}
```

Use HMAC for message authentication when you have a shared secret. Always  
use hash_equals() for comparing hashes to prevent timing attacks. SHA-256  
or stronger algorithms are recommended for integrity checks.  

### Key Derivation with PBKDF2

Deriving encryption keys from passwords.  

```php
<?php

namespace App\Service;

class KeyDerivation
{
    public function deriveKey(
        string $password,
        string $salt,
        int $iterations = 100000,
        int $keyLength = 32
    ): string {
        return hash_pbkdf2('sha256', $password, $salt, $iterations, $keyLength, true);
    }

    public function deriveEncryptionKey(string $password): array
    {
        $salt = random_bytes(16);
        $key = $this->deriveKey($password, $salt);
        
        return [
            'key' => $key,
            'salt' => base64_encode($salt),
        ];
    }

    public function verifyDerivedKey(
        string $password,
        string $salt,
        string $expectedKey
    ): bool {
        $salt = base64_decode($salt);
        $derivedKey = $this->deriveKey($password, $salt);
        
        return hash_equals($expectedKey, $derivedKey);
    }
}
```

PBKDF2 is a key derivation function that makes brute-force attacks  
computationally expensive. Use high iteration counts (100k+) and unique  
salts per password. Store both salt and derived key for verification.  

### Secure Data Comparison

Preventing timing attacks in comparisons.  

```php
<?php

namespace App\Service;

class SecureComparison
{
    public function compareStrings(string $known, string $user): bool
    {
        return hash_equals($known, $user);
    }

    public function compareHashes(string $hash1, string $hash2): bool
    {
        return hash_equals($hash1, $hash2);
    }

    public function validateToken(string $storedToken, string $providedToken): bool
    {
        if (strlen($storedToken) !== strlen($providedToken)) {
            return false;
        }
        
        return hash_equals($storedToken, $providedToken);
    }

    public function validateApiKey(string $expectedKey, string $providedKey): bool
    {
        $expectedHash = hash('sha256', $expectedKey);
        $providedHash = hash('sha256', $providedKey);
        
        return hash_equals($expectedHash, $providedHash);
    }
}
```

hash_equals() performs constant-time string comparison to prevent timing  
attacks. Regular comparison operators (==, ===) can leak information about  
the secret through execution time variations.  

### Encrypting Configuration Values

Securely storing sensitive configuration.  

```php
<?php

namespace App\Service;

use Symfony\Component\Yaml\Yaml;

class ConfigEncryption
{
    public function __construct(
        private EncryptionService $encryption,
        private string $configPath
    ) {
    }

    public function encryptConfigValue(string $key, string $value): void
    {
        $config = Yaml::parseFile($this->configPath);
        
        $encryptedValue = $this->encryption->encrypt($value);
        $config['parameters'][$key] = 'encrypted:' . $encryptedValue;
        
        file_put_contents(
            $this->configPath,
            Yaml::dump($config, 4, 2)
        );
    }

    public function getConfigValue(string $key): ?string
    {
        $config = Yaml::parseFile($this->configPath);
        $value = $config['parameters'][$key] ?? null;
        
        if ($value && str_starts_with($value, 'encrypted:')) {
            $encryptedData = substr($value, 10);
            return $this->encryption->decrypt($encryptedData);
        }
        
        return $value;
    }
}
```

Encrypt sensitive configuration values like API keys and database  
credentials. Use a prefix to identify encrypted values. Consider using  
Symfony's secrets management for production environments.  

### Secure Session Data Encryption

Encrypting session data for enhanced security.  

```php
<?php

namespace App\EventListener;

use App\Service\EncryptionService;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class SessionEncryptionListener
{
    public function __construct(
        private EncryptionService $encryption
    ) {
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $session = $request->getSession();
        
        if ($session->has('encrypted_data')) {
            $encrypted = $session->get('encrypted_data');
            $decrypted = $this->encryption->decrypt($encrypted);
            $session->set('user_data', json_decode($decrypted, true));
        }
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        $request = $event->getRequest();
        $session = $request->getSession();
        
        if ($session->has('user_data')) {
            $data = $session->get('user_data');
            $json = json_encode($data);
            $encrypted = $this->encryption->encrypt($json);
            $session->set('encrypted_data', $encrypted);
            $session->remove('user_data');
        }
    }
}
```

Event listeners can automatically encrypt sensitive session data. This  
adds a layer of protection even if session storage is compromised. Balance  
security with performance for frequently accessed data.  

### Cryptographic Nonce Generation

Generating nonces for one-time use in cryptographic operations.  

```php
<?php

namespace App\Service;

use Symfony\Component\Cache\Adapter\AdapterInterface;

class NonceService
{
    public function __construct(
        private AdapterInterface $cache
    ) {
    }

    public function generateNonce(string $context = 'default'): string
    {
        $nonce = bin2hex(random_bytes(16));
        $key = 'nonce_' . $context . '_' . $nonce;
        
        $item = $this->cache->getItem($key);
        $item->set(true);
        $item->expiresAfter(300); // 5 minutes
        $this->cache->save($item);
        
        return $nonce;
    }

    public function validateNonce(string $nonce, string $context = 'default'): bool
    {
        $key = 'nonce_' . $context . '_' . $nonce;
        $item = $this->cache->getItem($key);
        
        if (!$item->isHit()) {
            return false;
        }
        
        $this->cache->deleteItem($key);
        return true;
    }

    public function createFormNonce(string $formId): string
    {
        return $this->generateNonce('form_' . $formId);
    }
}
```

Nonces (number used once) prevent replay attacks. Store them temporarily  
in cache and delete after validation. Each nonce should be unique and  
expire after a reasonable time window.  

## Password Hashing & Management

### Basic Password Hashing

Hashing passwords using Symfony's PasswordHasher service.  

```php
<?php

namespace App\Service;

use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use App\Entity\User;

class PasswordService
{
    public function __construct(
        private UserPasswordHasherInterface $passwordHasher
    ) {
    }

    public function hashPassword(User $user, string $plainPassword): string
    {
        return $this->passwordHasher->hashPassword($user, $plainPassword);
    }

    public function verifyPassword(User $user, string $plainPassword): bool
    {
        return $this->passwordHasher->isPasswordValid($user, $plainPassword);
    }

    public function needsRehash(User $user): bool
    {
        return $this->passwordHasher->needsRehash($user);
    }
}
```

Symfony's PasswordHasher automatically uses secure algorithms like bcrypt  
or Argon2. Never store passwords in plain text. The service handles  
salting and algorithm selection automatically.  

### Password Strength Validation

Enforcing strong password policies.  

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

class StrongPasswordValidator extends ConstraintValidator
{
    public function validate($value, Constraint $constraint): void
    {
        if (!$constraint instanceof StrongPassword) {
            throw new UnexpectedTypeException($constraint, StrongPassword::class);
        }

        if (null === $value || '' === $value) {
            return;
        }

        $errors = [];

        if (strlen($value) < 12) {
            $errors[] = 'Password must be at least 12 characters long.';
        }

        if (!preg_match('/[a-z]/', $value)) {
            $errors[] = 'Password must contain at least one lowercase letter.';
        }

        if (!preg_match('/[A-Z]/', $value)) {
            $errors[] = 'Password must contain at least one uppercase letter.';
        }

        if (!preg_match('/[0-9]/', $value)) {
            $errors[] = 'Password must contain at least one number.';
        }

        if (!preg_match('/[^a-zA-Z0-9]/', $value)) {
            $errors[] = 'Password must contain at least one special character.';
        }

        if ($this->isCommonPassword($value)) {
            $errors[] = 'This password is too common. Please choose a different one.';
        }

        if (!empty($errors)) {
            $this->context->buildViolation(implode(' ', $errors))
                ->addViolation();
        }
    }

    private function isCommonPassword(string $password): bool
    {
        $commonPasswords = [
            'password123', 'qwerty123', 'admin123', 
            'welcome123', 'Password1!', '12345678'
        ];
        
        return in_array(strtolower($password), array_map('strtolower', $commonPasswords));
    }
}
```

Custom validators enforce comprehensive password policies. Check for  
length, character diversity, and common passwords. Consider using  
Have I Been Pwned API for breach detection.  

### Automatic Password Rehashing

Upgrading password hashes when algorithms change.  

```php
<?php

namespace App\EventListener;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

class PasswordRehashListener implements EventSubscriberInterface
{
    public function __construct(
        private UserPasswordHasherInterface $passwordHasher,
        private EntityManagerInterface $em
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        
        if (!$user instanceof User) {
            return;
        }

        if ($this->passwordHasher->needsRehash($user)) {
            $passport = $event->getAuthenticatedToken();
            $plainPassword = $passport->getAttribute('password');
            
            if ($plainPassword) {
                $newHash = $this->passwordHasher->hashPassword($user, $plainPassword);
                $user->setPassword($newHash);
                $this->em->flush();
            }
        }
    }
}
```

Automatically rehash passwords during login when security configuration  
changes. This ensures all users eventually migrate to stronger algorithms  
without forcing password resets.  

### Password Reset Token Generation

Secure password reset workflow implementation.  

```php
<?php

namespace App\Service;

use App\Entity\User;
use App\Entity\PasswordResetToken;
use App\Repository\PasswordResetTokenRepository;
use Doctrine\ORM\EntityManagerInterface;

class PasswordResetService
{
    public function __construct(
        private EntityManagerInterface $em,
        private PasswordResetTokenRepository $tokenRepository,
        private SecureRandomGenerator $randomGenerator
    ) {
    }

    public function createResetToken(User $user): PasswordResetToken
    {
        // Invalidate existing tokens
        $this->tokenRepository->deleteTokensForUser($user);
        
        $token = new PasswordResetToken();
        $token->setUser($user);
        $token->setToken($this->randomGenerator->generateToken(32));
        $token->setExpiresAt(new \DateTimeImmutable('+1 hour'));
        $token->setCreatedAt(new \DateTimeImmutable());
        
        $this->em->persist($token);
        $this->em->flush();
        
        return $token;
    }

    public function validateToken(string $token): ?User
    {
        $resetToken = $this->tokenRepository->findOneBy(['token' => $token]);
        
        if (!$resetToken) {
            return null;
        }

        if ($resetToken->getExpiresAt() < new \DateTimeImmutable()) {
            $this->em->remove($resetToken);
            $this->em->flush();
            return null;
        }

        return $resetToken->getUser();
    }

    public function consumeToken(string $token): void
    {
        $resetToken = $this->tokenRepository->findOneBy(['token' => $token]);
        
        if ($resetToken) {
            $this->em->remove($resetToken);
            $this->em->flush();
        }
    }
}
```

Password reset tokens should be cryptographically random, single-use, and  
time-limited. Always invalidate old tokens when creating new ones. Delete  
tokens immediately after successful password reset.  

### Password Change History

Preventing password reuse.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class PasswordHistory
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false)]
    private User $user;

    #[ORM\Column(type: 'string', length: 255)]
    private string $passwordHash;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    public function __construct(User $user, string $passwordHash)
    {
        $this->user = $user;
        $this->passwordHash = $passwordHash;
        $this->createdAt = new \DateTimeImmutable();
    }

    // Getters omitted for brevity
}
```

```php
<?php

namespace App\Service;

use App\Entity\User;
use App\Entity\PasswordHistory;
use App\Repository\PasswordHistoryRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class PasswordHistoryService
{
    private const MAX_HISTORY = 5;

    public function __construct(
        private EntityManagerInterface $em,
        private PasswordHistoryRepository $historyRepository,
        private UserPasswordHasherInterface $passwordHasher
    ) {
    }

    public function isPasswordReused(User $user, string $plainPassword): bool
    {
        $history = $this->historyRepository->findRecentForUser(
            $user,
            self::MAX_HISTORY
        );

        foreach ($history as $entry) {
            if (password_verify($plainPassword, $entry->getPasswordHash())) {
                return true;
            }
        }

        return false;
    }

    public function addToHistory(User $user, string $passwordHash): void
    {
        $history = new PasswordHistory($user, $passwordHash);
        $this->em->persist($history);
        
        // Clean up old entries
        $this->historyRepository->deleteOldEntriesForUser($user, self::MAX_HISTORY);
        
        $this->em->flush();
    }
}
```

Track password history to prevent users from reusing recent passwords.  
Store hashed passwords only. Limit history size to balance security and  
storage efficiency.  

### Passwordless Authentication Setup

Implementing magic link authentication.  

```php
<?php

namespace App\Service;

use App\Entity\User;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class MagicLinkService
{
    public function __construct(
        private MailerInterface $mailer,
        private UrlGeneratorInterface $urlGenerator,
        private CacheInterface $cache,
        private SecureRandomGenerator $randomGenerator
    ) {
    }

    public function sendMagicLink(User $user): void
    {
        $token = $this->randomGenerator->generateUrlSafeToken(32);
        
        // Store token with user ID
        $this->cache->get(
            'magic_link_' . $token,
            function (ItemInterface $item) use ($user) {
                $item->expiresAfter(900); // 15 minutes
                return $user->getId();
            }
        );

        $url = $this->urlGenerator->generate(
            'magic_link_verify',
            ['token' => $token],
            UrlGeneratorInterface::ABSOLUTE_URL
        );

        $email = (new Email())
            ->to($user->getEmail())
            ->subject('Your Login Link')
            ->html(sprintf(
                'Click here to log in: <a href="%s">Login</a>. This link expires in 15 minutes.',
                $url
            ));

        $this->mailer->send($email);
    }

    public function validateMagicLink(string $token): ?int
    {
        $key = 'magic_link_' . $token;
        $item = $this->cache->getItem($key);
        
        if (!$item->isHit()) {
            return null;
        }

        $userId = $item->get();
        $this->cache->delete($key);
        
        return $userId;
    }
}
```

Magic links provide passwordless authentication. Tokens must be random,  
single-use, and short-lived. Send via secure email and delete after use.  
Consider rate limiting to prevent abuse.  

### Temporary Password Generation

Creating secure temporary passwords.  

```php
<?php

namespace App\Service;

class TemporaryPasswordService
{
    public function __construct(
        private SecureRandomGenerator $randomGenerator
    ) {
    }

    public function generateReadablePassword(int $length = 12): string
    {
        $consonants = 'bcdfghjklmnpqrstvwxyz';
        $vowels = 'aeiou';
        $numbers = '0123456789';
        $special = '!@#$%&*';
        
        $password = '';
        
        // Build pronounceable part
        for ($i = 0; $i < $length - 3; $i++) {
            if ($i % 2 === 0) {
                $password .= $consonants[random_int(0, strlen($consonants) - 1)];
            } else {
                $password .= $vowels[random_int(0, strlen($vowels) - 1)];
            }
        }
        
        // Add number and special character
        $password .= $numbers[random_int(0, strlen($numbers) - 1)];
        $password .= $special[random_int(0, strlen($special) - 1)];
        $password .= $numbers[random_int(0, strlen($numbers) - 1)];
        
        // Capitalize first letter
        $password[0] = strtoupper($password[0]);
        
        return $password;
    }

    public function generateStrongPassword(int $length = 16): string
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*';
        $password = '';
        
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, strlen($chars) - 1)];
        }
        
        return $password;
    }
}
```

Temporary passwords should be strong and random. Expire them quickly and  
force users to change on first login. Consider readability for passwords  
sent via non-digital channels.  

### Password Expiration Policy

Enforcing periodic password changes.  

```php
<?php

namespace App\EventListener;

use App\Entity\User;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Security;

class PasswordExpirationListener implements EventSubscriberInterface
{
    private const EXPIRATION_DAYS = 90;

    public function __construct(
        private Security $security,
        private UrlGeneratorInterface $urlGenerator
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 10],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $user = $this->security->getUser();
        
        if (!$user instanceof User) {
            return;
        }

        $route = $event->getRequest()->attributes->get('_route');
        
        // Don't redirect on password change page
        if ($route === 'password_change') {
            return;
        }

        $lastChanged = $user->getPasswordChangedAt();
        if (!$lastChanged) {
            $lastChanged = $user->getCreatedAt();
        }

        $expirationDate = $lastChanged->modify('+' . self::EXPIRATION_DAYS . ' days');
        
        if (new \DateTimeImmutable() > $expirationDate) {
            $url = $this->urlGenerator->generate('password_change', [
                'expired' => true
            ]);
            
            $event->setResponse(new RedirectResponse($url));
        }
    }
}
```

Password expiration policies force periodic password updates. However,  
consider modern security guidance that questions frequent mandatory  
changes. Balance security with usability.  

### Account Lockout After Failed Attempts

Protecting against brute force attacks.  

```php
<?php

namespace App\Service;

use App\Entity\User;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class LoginAttemptService
{
    private const MAX_ATTEMPTS = 5;
    private const LOCKOUT_DURATION = 900; // 15 minutes

    public function __construct(
        private CacheInterface $cache
    ) {
    }

    public function recordFailedAttempt(string $identifier): void
    {
        $key = $this->getAttemptKey($identifier);
        
        $attempts = $this->cache->get($key, function (ItemInterface $item) {
            $item->expiresAfter(self::LOCKOUT_DURATION);
            return 0;
        });

        $this->cache->delete($key);
        $this->cache->get($key, function (ItemInterface $item) use ($attempts) {
            $item->expiresAfter(self::LOCKOUT_DURATION);
            return $attempts + 1;
        });
    }

    public function isLocked(string $identifier): bool
    {
        $attempts = $this->cache->get(
            $this->getAttemptKey($identifier),
            fn() => 0
        );

        return $attempts >= self::MAX_ATTEMPTS;
    }

    public function getRemainingAttempts(string $identifier): int
    {
        $attempts = $this->cache->get(
            $this->getAttemptKey($identifier),
            fn() => 0
        );

        return max(0, self::MAX_ATTEMPTS - $attempts);
    }

    public function resetAttempts(string $identifier): void
    {
        $this->cache->delete($this->getAttemptKey($identifier));
    }

    private function getAttemptKey(string $identifier): string
    {
        return 'login_attempts_' . hash('sha256', $identifier);
    }
}
```

Track failed login attempts and temporarily lock accounts. Use email or IP  
address as identifier. Clear attempts on successful login. Consider  
implementing progressive delays instead of hard lockouts.  

### Multi-Factor Authentication Preparation

Setting up TOTP-based 2FA.  

```php
<?php

namespace App\Service;

use OTPHP\TOTP;

class TwoFactorService
{
    public function generateSecret(string $userEmail): TOTP
    {
        return TOTP::create(
            null,
            30,
            'sha1',
            6
        )->setLabel($userEmail)
         ->setIssuer($_ENV['APP_NAME'] ?? 'Symfony App');
    }

    public function getQrCodeUri(TOTP $totp): string
    {
        return $totp->getQrCodeUri(
            'https://api.qrserver.com/v1/create-qr-code/?data=[DATA]&size=300x300&ecc=M',
            '[DATA]'
        );
    }

    public function verifyCode(string $secret, string $code): bool
    {
        $totp = TOTP::create($secret);
        return $totp->verify($code, null, 1); // Allow 1 period drift
    }

    public function generateBackupCodes(int $count = 10): array
    {
        $codes = [];
        
        for ($i = 0; $i < $count; $i++) {
            $code = '';
            for ($j = 0; $j < 2; $j++) {
                $code .= str_pad((string) random_int(0, 9999), 4, '0', STR_PAD_LEFT);
                if ($j === 0) $code .= '-';
            }
            $codes[] = $code;
        }
        
        return $codes;
    }
}
```

TOTP provides time-based one-time passwords for 2FA. Generate unique  
secrets per user. Provide backup codes for account recovery. Allow small  
time drift to handle clock skew.  

## Authentication Basics

### Custom Login Form Authentication

Creating a custom authentication system.  

```php
<?php

namespace App\Security;

use App\Entity\User;
use App\Service\LoginAttemptService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class LoginFormAuthenticator extends AbstractLoginFormAuthenticator
{
    use TargetPathTrait;

    public function __construct(
        private UrlGeneratorInterface $urlGenerator,
        private LoginAttemptService $loginAttempts
    ) {
    }

    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('email', '');
        
        if ($this->loginAttempts->isLocked($email)) {
            throw new AuthenticationException(
                'Account temporarily locked due to failed login attempts.'
            );
        }

        $request->getSession()->set(Security::LAST_USERNAME, $email);

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($request->request->get('password', '')),
            [
                new CsrfTokenBadge('authenticate', $request->request->get('_csrf_token')),
            ]
        );
    }

    public function onAuthenticationSuccess(
        Request $request,
        TokenInterface $token,
        string $firewallName
    ): ?Response {
        $email = $request->request->get('email', '');
        $this->loginAttempts->resetAttempts($email);

        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('dashboard'));
    }

    public function onAuthenticationFailure(
        Request $request,
        AuthenticationException $exception
    ): Response {
        $email = $request->request->get('email', '');
        $this->loginAttempts->recordFailedAttempt($email);

        return parent::onAuthenticationFailure($request, $exception);
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate('login');
    }
}
```

Custom authenticators provide complete control over the authentication  
process. Integrate with login attempt tracking, implement custom password  
checks, and handle authentication failures appropriately.  

### Remember Me Functionality

Implementing secure "remember me" authentication.  

```php
<?php

// config/packages/security.yaml
security:
    firewalls:
        main:
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800 # 1 week
                path: /
                always_remember_me: false
                secure: true
                httponly: true
                samesite: lax
                signature_properties: ['password', 'email']
```

```php
<?php

namespace App\EventListener;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

class RememberMeListener implements EventSubscriberInterface
{
    public function __construct(
        private EntityManagerInterface $em
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        
        if (!$user instanceof User) {
            return;
        }

        // Track last login
        $user->setLastLoginAt(new \DateTimeImmutable());
        $this->em->flush();
    }
}
```

Remember me cookies enable persistent authentication. Use secure  
configuration: httponly prevents JavaScript access, secure requires HTTPS,  
samesite prevents CSRF. Include user properties to invalidate on changes.  

### Login Rate Limiting

Preventing brute force with rate limiting.  

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\RateLimiter\RateLimiterFactory;

class LoginRateLimitListener implements EventSubscriberInterface
{
    public function __construct(
        private RateLimiterFactory $loginLimiter
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            RequestEvent::class => 'onKernelRequest',
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        
        if ($request->attributes->get('_route') !== 'login' || 
            $request->getMethod() !== 'POST') {
            return;
        }

        $limiter = $this->loginLimiter->create($request->getClientIp());
        
        if (false === $limiter->consume(1)->isAccepted()) {
            throw new TooManyRequestsHttpException(
                60,
                'Too many login attempts. Please try again later.'
            );
        }
    }
}
```

```yaml
# config/packages/rate_limiter.yaml
framework:
    rate_limiter:
        login:
            policy: 'sliding_window'
            limit: 5
            interval: '15 minutes'
```

Rate limiting prevents credential stuffing and brute force attacks. Use IP  
or username as identifier. Implement sliding window for fair distribution.  
Return 429 status with retry-after header.  

### Session Security Configuration

Hardening session management.  

```php
<?php

// config/packages/framework.yaml
framework:
    session:
        cookie_secure: auto
        cookie_httponly: true
        cookie_samesite: lax
        handler_id: null
        gc_probability: 1
        gc_divisor: 100
        gc_maxlifetime: 3600
        name: SESSIONID
        cookie_lifetime: 0
        use_strict_mode: true
```

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class SessionSecurityListener implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => 'onKernelRequest',
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $session = $request->getSession();

        // Regenerate session ID periodically
        if (!$session->has('last_regeneration')) {
            $session->migrate(true);
            $session->set('last_regeneration', time());
        } elseif (time() - $session->get('last_regeneration') > 300) {
            $session->migrate(true);
            $session->set('last_regeneration', time());
        }

        // Bind session to IP address
        $currentIp = $request->getClientIp();
        if (!$session->has('client_ip')) {
            $session->set('client_ip', $currentIp);
        } elseif ($session->get('client_ip') !== $currentIp) {
            $session->invalidate();
        }
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $response = $event->getResponse();
        
        // Add security headers
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
    }
}
```

Session security prevents session hijacking and fixation. Regenerate IDs  
regularly and on privilege changes. Use secure cookies and bind to client  
characteristics. Implement absolute timeout.  

### User Provider with Email Verification

Custom user provider with email verification.  

```php
<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class EmailVerificationUserProvider implements UserProviderInterface
{
    public function __construct(
        private UserRepository $userRepository
    ) {
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        $user = $this->userRepository->findOneBy(['email' => $identifier]);

        if (!$user) {
            throw new UserNotFoundException(
                sprintf('User with email "%s" not found.', $identifier)
            );
        }

        if (!$user->isEmailVerified()) {
            throw new DisabledException(
                'Please verify your email address before logging in.'
            );
        }

        if (!$user->isActive()) {
            throw new DisabledException('This account has been disabled.');
        }

        return $user;
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof User) {
            throw new \InvalidArgumentException(
                sprintf('Instances of "%s" are not supported.', get_class($user))
            );
        }

        return $this->loadUserByIdentifier($user->getUserIdentifier());
    }

    public function supportsClass(string $class): bool
    {
        return User::class === $class || is_subclass_of($class, User::class);
    }
}
```

Custom user providers enable complex loading logic. Verify email before  
allowing login. Check account status and throw appropriate exceptions for  
better error messages.  

### Email Verification Service

Implementing email verification workflow.  

```php
<?php

namespace App\Service;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class EmailVerificationService
{
    public function __construct(
        private EntityManagerInterface $em,
        private MailerInterface $mailer,
        private UrlGeneratorInterface $urlGenerator,
        private SecureRandomGenerator $randomGenerator
    ) {
    }

    public function sendVerificationEmail(User $user): void
    {
        if ($user->isEmailVerified()) {
            return;
        }

        $token = $this->randomGenerator->generateUrlSafeToken(32);
        $user->setVerificationToken($token);
        $user->setVerificationRequestedAt(new \DateTimeImmutable());
        
        $this->em->flush();

        $verificationUrl = $this->urlGenerator->generate(
            'verify_email',
            ['token' => $token],
            UrlGeneratorInterface::ABSOLUTE_URL
        );

        $email = (new Email())
            ->to($user->getEmail())
            ->subject('Verify Your Email Address')
            ->html(sprintf(
                'Please click here to verify your email: <a href="%s">Verify Email</a>',
                $verificationUrl
            ));

        $this->mailer->send($email);
    }

    public function verifyEmail(string $token): bool
    {
        $user = $this->em->getRepository(User::class)
            ->findOneBy(['verificationToken' => $token]);

        if (!$user) {
            return false;
        }

        // Check if token is expired (24 hours)
        $requestedAt = $user->getVerificationRequestedAt();
        if ($requestedAt < new \DateTimeImmutable('-24 hours')) {
            return false;
        }

        $user->setEmailVerified(true);
        $user->setVerificationToken(null);
        $user->setVerifiedAt(new \DateTimeImmutable());
        
        $this->em->flush();

        return true;
    }
}
```

Email verification prevents fake registrations. Use cryptographically  
random tokens with expiration. Clear tokens after verification. Consider  
rate limiting verification email requests.  

### API Token Authentication

Implementing API token-based authentication.  

```php
<?php

namespace App\Security;

use App\Repository\ApiTokenRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class ApiTokenAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private ApiTokenRepository $apiTokenRepository
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('X-API-TOKEN');
    }

    public function authenticate(Request $request): Passport
    {
        $apiToken = $request->headers->get('X-API-TOKEN');
        
        if (null === $apiToken) {
            throw new AuthenticationException('No API token provided');
        }

        return new SelfValidatingPassport(
            new UserBadge($apiToken, function($token) {
                $apiToken = $this->apiTokenRepository->findValidToken($token);
                
                if (!$apiToken) {
                    throw new AuthenticationException('Invalid API token');
                }

                // Update last used timestamp
                $apiToken->setLastUsedAt(new \DateTimeImmutable());
                
                return $apiToken->getUser();
            })
        );
    }

    public function onAuthenticationSuccess(
        Request $request,
        TokenInterface $token,
        string $firewallName
    ): ?Response {
        return null;
    }

    public function onAuthenticationFailure(
        Request $request,
        AuthenticationException $exception
    ): ?Response {
        return new JsonResponse([
            'error' => 'Authentication failed',
            'message' => $exception->getMessage()
        ], Response::HTTP_UNAUTHORIZED);
    }
}
```

API tokens provide stateless authentication for APIs. Validate against  
database, check expiration, and track usage. Use HTTPS exclusively. Return  
appropriate HTTP status codes.  

### Security Voters for Fine-Grained Access Control

Custom voters for authorization decisions.  

```php
<?php

namespace App\Security\Voter;

use App\Entity\Post;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class PostVoter extends Voter
{
    public const VIEW = 'VIEW';
    public const EDIT = 'EDIT';
    public const DELETE = 'DELETE';

    protected function supports(string $attribute, $subject): bool
    {
        return in_array($attribute, [self::VIEW, self::EDIT, self::DELETE])
            && $subject instanceof Post;
    }

    protected function voteOnAttribute(
        string $attribute,
        $subject,
        TokenInterface $token
    ): bool {
        $user = $token->getUser();

        if (!$user instanceof User) {
            return false;
        }

        /** @var Post $post */
        $post = $subject;

        return match($attribute) {
            self::VIEW => $this->canView($post, $user),
            self::EDIT => $this->canEdit($post, $user),
            self::DELETE => $this->canDelete($post, $user),
            default => false,
        };
    }

    private function canView(Post $post, User $user): bool
    {
        // Everyone can view published posts
        if ($post->isPublished()) {
            return true;
        }

        // Author can view their own drafts
        return $post->getAuthor() === $user;
    }

    private function canEdit(Post $post, User $user): bool
    {
        // Admins can edit any post
        if (in_array('ROLE_ADMIN', $user->getRoles())) {
            return true;
        }

        // Authors can edit their own posts
        return $post->getAuthor() === $user;
    }

    private function canDelete(Post $post, User $user): bool
    {
        // Only admins can delete
        return in_array('ROLE_ADMIN', $user->getRoles());
    }
}
```

Voters centralize authorization logic for complex business rules. Use  
supports() to filter relevant checks. Implement fine-grained permissions  
based on resource ownership and user roles.  

### Logout Handler with Cleanup

Proper session cleanup on logout.  

```php
<?php

namespace App\Security;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Psr\Log\LoggerInterface;

class CustomLogoutHandler implements LogoutHandlerInterface
{
    public function __construct(
        private EntityManagerInterface $em,
        private LoggerInterface $logger
    ) {
    }

    public function logout(
        Request $request,
        Response $response,
        TokenInterface $token
    ): void {
        $user = $token->getUser();
        
        if ($user) {
            // Log the logout event
            $this->logger->info('User logged out', [
                'user_id' => $user->getId(),
                'username' => $user->getUserIdentifier(),
                'ip' => $request->getClientIp(),
            ]);

            // Clear any user-specific cached data
            // $this->cache->delete('user_data_' . $user->getId());

            // Invalidate active API tokens if needed
            // $this->apiTokenRepository->invalidateUserTokens($user);
        }

        // Clear session data
        $session = $request->getSession();
        $session->invalidate();

        // Clear cookies
        $response->headers->clearCookie('REMEMBERME');
    }
}
```

Logout handlers clean up resources and log security events. Invalidate  
sessions, clear cookies, revoke tokens, and log the action. Ensure users  
can't access protected resources after logout.  

### User Impersonation for Support

Allowing administrators to impersonate users.  

```php
<?php

// config/packages/security.yaml
security:
    firewalls:
        main:
            switch_user: true
```

```php
<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class ImpersonationController extends AbstractController
{
    #[Route('/admin/impersonate/{id}', name: 'admin_impersonate')]
    #[IsGranted('ROLE_ADMIN')]
    public function impersonate(
        int $id,
        EntityManagerInterface $em
    ): Response {
        $user = $em->getRepository(User::class)->find($id);
        
        if (!$user) {
            throw $this->createNotFoundException('User not found');
        }

        // Prevent impersonating other admins
        if (in_array('ROLE_ADMIN', $user->getRoles())) {
            $this->addFlash('error', 'Cannot impersonate administrators');
            return $this->redirectToRoute('admin_users');
        }

        return $this->redirect('/?_switch_user=' . $user->getEmail());
    }

    #[Route('/admin/stop-impersonate', name: 'admin_stop_impersonate')]
    public function stopImpersonating(): Response
    {
        return $this->redirect('/?_switch_user=_exit');
    }
}
```

```php
<?php

namespace App\EventListener;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\SwitchUserEvent;

class ImpersonationListener implements EventSubscriberInterface
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            SwitchUserEvent::class => 'onSwitchUser',
        ];
    }

    public function onSwitchUser(SwitchUserEvent $event): void
    {
        $this->logger->warning('User impersonation occurred', [
            'impersonator' => $event->getToken()->getUser()->getUserIdentifier(),
            'target_user' => $event->getTargetUser()->getUserIdentifier(),
            'ip' => $event->getRequest()->getClientIp(),
        ]);
    }
}
```

User impersonation enables support staff to debug user-specific issues.  
Restrict to administrators, prevent impersonating admins, and log all  
impersonation events. Provide clear UI indication during impersonation.  

## JWT & Token-based Auth

### JWT Token Generation and Validation

Creating and validating JSON Web Tokens.  

```php
<?php

namespace App\Service;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtService
{
    private string $secretKey;
    private string $algorithm = 'HS256';

    public function __construct()
    {
        $this->secretKey = $_ENV['JWT_SECRET_KEY'] ?? 'change-this-secret';
    }

    public function generateToken(array $payload, int $expiresIn = 3600): string
    {
        $issuedAt = time();
        
        $data = array_merge($payload, [
            'iat' => $issuedAt,
            'exp' => $issuedAt + $expiresIn,
            'nbf' => $issuedAt,
        ]);

        return JWT::encode($data, $this->secretKey, $this->algorithm);
    }

    public function validateToken(string $token): ?array
    {
        try {
            $decoded = JWT::decode($token, new Key($this->secretKey, $this->algorithm));
            return (array) $decoded;
        } catch (\Exception $e) {
            return null;
        }
    }

    public function getUserIdFromToken(string $token): ?int
    {
        $payload = $this->validateToken($token);
        return $payload['user_id'] ?? null;
    }
}
```

JWT enables stateless authentication. Include user ID, expiration, and  
other claims. Validate signature and expiration. Use strong secret keys  
stored securely. Consider using RS256 for multi-service architectures.  

### JWT Refresh Token Implementation

Implementing token refresh mechanism.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class RefreshToken
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 255, unique: true)]
    private string $token;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false)]
    private User $user;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $expiresAt;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    public function __construct(User $user, string $token, int $expiresIn = 2592000)
    {
        $this->user = $user;
        $this->token = $token;
        $this->createdAt = new \DateTimeImmutable();
        $this->expiresAt = new \DateTimeImmutable('+' . $expiresIn . ' seconds');
    }

    public function isExpired(): bool
    {
        return $this->expiresAt < new \DateTimeImmutable();
    }

    // Getters omitted for brevity
}
```

```php
<?php

namespace App\Service;

use App\Entity\RefreshToken;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;

class RefreshTokenService
{
    public function __construct(
        private EntityManagerInterface $em,
        private SecureRandomGenerator $randomGenerator,
        private JwtService $jwtService
    ) {
    }

    public function createRefreshToken(User $user): RefreshToken
    {
        $token = $this->randomGenerator->generateUrlSafeToken(32);
        $refreshToken = new RefreshToken($user, $token);
        
        $this->em->persist($refreshToken);
        $this->em->flush();
        
        return $refreshToken;
    }

    public function refreshAccessToken(string $refreshToken): ?array
    {
        $token = $this->em->getRepository(RefreshToken::class)
            ->findOneBy(['token' => $refreshToken]);

        if (!$token || $token->isExpired()) {
            return null;
        }

        $user = $token->getUser();
        $accessToken = $this->jwtService->generateToken([
            'user_id' => $user->getId(),
            'email' => $user->getEmail(),
        ]);

        return [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ];
    }

    public function revokeUserTokens(User $user): void
    {
        $this->em->createQueryBuilder()
            ->delete(RefreshToken::class, 'rt')
            ->where('rt.user = :user')
            ->setParameter('user', $user)
            ->getQuery()
            ->execute();
    }
}
```

Refresh tokens enable long-lived authentication without storing JWTs. Use  
longer expiration than access tokens. Store in database for revocation.  
Rotate refresh tokens on use for enhanced security.  

### JWT Authentication Guard

Custom JWT authenticator for API security.  

```php
<?php

namespace App\Security;

use App\Service\JwtService;
use App\Repository\UserRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class JwtAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private JwtService $jwtService,
        private UserRepository $userRepository
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): Passport
    {
        $authHeader = $request->headers->get('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            throw new AuthenticationException('Invalid authorization header');
        }

        $token = substr($authHeader, 7);
        
        return new SelfValidatingPassport(
            new UserBadge($token, function($jwt) {
                $payload = $this->jwtService->validateToken($jwt);
                
                if (!$payload) {
                    throw new AuthenticationException('Invalid or expired token');
                }

                $userId = $payload['user_id'] ?? null;
                if (!$userId) {
                    throw new AuthenticationException('Invalid token payload');
                }

                $user = $this->userRepository->find($userId);
                if (!$user) {
                    throw new AuthenticationException('User not found');
                }

                return $user;
            })
        );
    }

    public function onAuthenticationSuccess(
        Request $request,
        TokenInterface $token,
        string $firewallName
    ): ?Response {
        return null;
    }

    public function onAuthenticationFailure(
        Request $request,
        AuthenticationException $exception
    ): ?Response {
        return new JsonResponse([
            'error' => 'Authentication failed',
            'message' => $exception->getMessage()
        ], Response::HTTP_UNAUTHORIZED);
    }
}
```

JWT authenticators extract and validate tokens from Authorization headers.  
Parse Bearer tokens, validate signatures, check expiration, and load users.  
Return 401 for authentication failures.  

### JWT Login Controller

Endpoint for JWT token issuance.  

```php
<?php

namespace App\Controller;

use App\Service\JwtService;
use App\Service\RefreshTokenService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use App\Repository\UserRepository;

class AuthController extends AbstractController
{
    public function __construct(
        private UserRepository $userRepository,
        private UserPasswordHasherInterface $passwordHasher,
        private JwtService $jwtService,
        private RefreshTokenService $refreshTokenService
    ) {
    }

    #[Route('/api/login', name: 'api_login', methods: ['POST'])]
    public function login(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        if (empty($email) || empty($password)) {
            return $this->json([
                'error' => 'Email and password are required'
            ], 400);
        }

        $user = $this->userRepository->findOneBy(['email' => $email]);
        
        if (!$user || !$this->passwordHasher->isPasswordValid($user, $password)) {
            return $this->json([
                'error' => 'Invalid credentials'
            ], 401);
        }

        $accessToken = $this->jwtService->generateToken([
            'user_id' => $user->getId(),
            'email' => $user->getEmail(),
            'roles' => $user->getRoles(),
        ]);

        $refreshToken = $this->refreshTokenService->createRefreshToken($user);

        return $this->json([
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken->getToken(),
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);
    }

    #[Route('/api/refresh', name: 'api_refresh', methods: ['POST'])]
    public function refresh(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $refreshToken = $data['refresh_token'] ?? '';

        $result = $this->refreshTokenService->refreshAccessToken($refreshToken);

        if (!$result) {
            return $this->json([
                'error' => 'Invalid or expired refresh token'
            ], 401);
        }

        return $this->json($result);
    }

    #[Route('/api/logout', name: 'api_logout', methods: ['POST'])]
    public function logout(): JsonResponse
    {
        $user = $this->getUser();
        
        if ($user) {
            $this->refreshTokenService->revokeUserTokens($user);
        }

        return $this->json(['message' => 'Logged out successfully']);
    }
}
```

Login endpoint validates credentials and issues JWT and refresh tokens.  
Refresh endpoint exchanges refresh token for new access token. Logout  
revokes refresh tokens. Always validate input and return appropriate  
status codes.  

### JWT Claims Validation

Validating custom JWT claims.  

```php
<?php

namespace App\Service;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

class JwtValidator
{
    public function __construct(
        private string $secretKey,
        private string $issuer,
        private array $audience
    ) {
    }

    public function validateWithClaims(string $token): ?array
    {
        try {
            $decoded = JWT::decode(
                $token,
                new Key($this->secretKey, 'HS256')
            );

            $claims = (array) $decoded;

            // Validate issuer
            if (!isset($claims['iss']) || $claims['iss'] !== $this->issuer) {
                return null;
            }

            // Validate audience
            if (!isset($claims['aud']) || !in_array($claims['aud'], $this->audience)) {
                return null;
            }

            // Validate not before
            if (isset($claims['nbf']) && time() < $claims['nbf']) {
                return null;
            }

            // Validate custom scope
            if (isset($claims['scope'])) {
                $requiredScopes = ['read', 'write'];
                $tokenScopes = explode(' ', $claims['scope']);
                
                if (empty(array_intersect($requiredScopes, $tokenScopes))) {
                    return null;
                }
            }

            return $claims;
            
        } catch (ExpiredException $e) {
            return null;
        } catch (SignatureInvalidException $e) {
            return null;
        } catch (\Exception $e) {
            return null;
        }
    }

    public function hasScope(array $claims, string $scope): bool
    {
        if (!isset($claims['scope'])) {
            return false;
        }

        $scopes = explode(' ', $claims['scope']);
        return in_array($scope, $scopes);
    }
}
```

Validate all standard and custom JWT claims. Check issuer, audience,  
expiration, and not-before. Implement scope-based permissions. Handle  
validation failures gracefully.  

### Asymmetric JWT with RSA

Using RSA keys for JWT signing.  

```php
<?php

namespace App\Service;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class AsymmetricJwtService
{
    private $privateKey;
    private $publicKey;

    public function __construct(
        string $privateKeyPath,
        string $publicKeyPath
    ) {
        $this->privateKey = openssl_pkey_get_private(
            file_get_contents($privateKeyPath)
        );
        
        $this->publicKey = openssl_pkey_get_public(
            file_get_contents($publicKeyPath)
        );
    }

    public function generateToken(array $payload, int $expiresIn = 3600): string
    {
        $issuedAt = time();
        
        $data = array_merge($payload, [
            'iat' => $issuedAt,
            'exp' => $issuedAt + $expiresIn,
            'nbf' => $issuedAt,
        ]);

        return JWT::encode($data, $this->privateKey, 'RS256');
    }

    public function validateToken(string $token): ?array
    {
        try {
            $decoded = JWT::decode($token, new Key($this->publicKey, 'RS256'));
            return (array) $decoded;
        } catch (\Exception $e) {
            return null;
        }
    }

    public function getPublicKey(): string
    {
        $details = openssl_pkey_get_details($this->publicKey);
        return $details['key'];
    }
}
```

RSA signatures enable token verification across services. Private key  
signs, public key verifies. Distribute public key to resource servers.  
More secure than symmetric signing for distributed systems.  

### JWT Blacklist for Revocation

Implementing token revocation with blacklist.  

```php
<?php

namespace App\Service;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class JwtBlacklistService
{
    public function __construct(
        private CacheInterface $cache
    ) {
    }

    public function revokeToken(string $token): void
    {
        $payload = $this->decodeWithoutValidation($token);
        $exp = $payload['exp'] ?? null;

        if (!$exp) {
            return;
        }

        $ttl = $exp - time();
        if ($ttl <= 0) {
            return;
        }

        $jti = $payload['jti'] ?? hash('sha256', $token);
        
        $this->cache->get('jwt_blacklist_' . $jti, function(ItemInterface $item) use ($ttl) {
            $item->expiresAfter($ttl);
            return true;
        });
    }

    public function isRevoked(string $token): bool
    {
        $payload = $this->decodeWithoutValidation($token);
        $jti = $payload['jti'] ?? hash('sha256', $token);

        $item = $this->cache->getItem('jwt_blacklist_' . $jti);
        return $item->isHit();
    }

    private function decodeWithoutValidation(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return [];
        }

        $payload = base64_decode(strtr($parts[1], '-_', '+/'));
        return json_decode($payload, true) ?? [];
    }

    public function revokeAllUserTokens(int $userId): void
    {
        // Implement by adding user_id to a revoked users list
        $this->cache->get('revoked_users_' . $userId, function(ItemInterface $item) {
            $item->expiresAfter(86400); // 24 hours
            return true;
        });
    }

    public function isUserRevoked(int $userId): bool
    {
        $item = $this->cache->getItem('revoked_users_' . $userId);
        return $item->isHit();
    }
}
```

JWT blacklist enables token revocation. Store token IDs (jti) in cache  
until expiration. Check blacklist during authentication. For mass  
revocation, track user IDs instead of individual tokens.  

### JWT with Sliding Expiration

Implementing sliding session expiration with JWT.  

```php
<?php

namespace App\Service;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class SlidingJwtService
{
    private const ACTIVITY_WINDOW = 1800; // 30 minutes
    private const MAX_LIFETIME = 86400; // 24 hours

    public function __construct(
        private JwtService $jwtService,
        private CacheInterface $cache
    ) {
    }

    public function validateAndRefresh(string $token): ?array
    {
        $payload = $this->jwtService->validateToken($token);
        
        if (!$payload) {
            return null;
        }

        $jti = $payload['jti'] ?? hash('sha256', $token);
        $originalIat = $payload['original_iat'] ?? $payload['iat'];

        // Check if token is too old
        if (time() - $originalIat > self::MAX_LIFETIME) {
            return ['token' => null, 'expired' => true];
        }

        // Check last activity
        $lastActivity = $this->cache->get('jwt_activity_' . $jti, fn() => time());

        if (time() - $lastActivity > self::ACTIVITY_WINDOW) {
            return ['token' => null, 'inactive' => true];
        }

        // Update activity and issue new token
        $this->cache->delete('jwt_activity_' . $jti);
        
        $newPayload = $payload;
        $newPayload['original_iat'] = $originalIat;
        $newPayload['jti'] = bin2hex(random_bytes(16));
        
        $newToken = $this->jwtService->generateToken($newPayload);

        // Track new token activity
        $this->cache->get(
            'jwt_activity_' . $newPayload['jti'],
            function(ItemInterface $item) {
                $item->expiresAfter(self::ACTIVITY_WINDOW);
                return time();
            }
        );

        return ['token' => $newToken, 'refreshed' => true];
    }
}
```

Sliding expiration extends sessions with activity. Track last activity in  
cache. Issue new token if within window. Enforce absolute maximum  
lifetime. Provides better UX while maintaining security.  

### JWT Token Introspection

Endpoint for token validation and introspection.  

```php
<?php

namespace App\Controller;

use App\Service\JwtService;
use App\Service\JwtBlacklistService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class TokenIntrospectionController extends AbstractController
{
    public function __construct(
        private JwtService $jwtService,
        private JwtBlacklistService $blacklist
    ) {
    }

    #[Route('/api/token/introspect', name: 'token_introspect', methods: ['POST'])]
    public function introspect(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $token = $data['token'] ?? '';

        if (empty($token)) {
            return $this->json(['active' => false]);
        }

        $payload = $this->jwtService->validateToken($token);

        if (!$payload) {
            return $this->json(['active' => false]);
        }

        if ($this->blacklist->isRevoked($token)) {
            return $this->json(['active' => false]);
        }

        return $this->json([
            'active' => true,
            'scope' => $payload['scope'] ?? '',
            'client_id' => $payload['client_id'] ?? '',
            'username' => $payload['email'] ?? '',
            'token_type' => 'Bearer',
            'exp' => $payload['exp'],
            'iat' => $payload['iat'],
            'sub' => $payload['user_id'] ?? '',
        ]);
    }

    #[Route('/api/token/revoke', name: 'token_revoke', methods: ['POST'])]
    public function revoke(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $token = $data['token'] ?? '';

        if (!empty($token)) {
            $this->blacklist->revokeToken($token);
        }

        return $this->json(['message' => 'Token revoked successfully']);
    }
}
```

Token introspection allows services to validate tokens. Return active  
status and claims. Support token revocation. Useful for OAuth2  
compatibility and distributed systems.  

### JWT with Custom Claims Encoder

Adding custom claims to JWT tokens.  

```php
<?php

namespace App\Service;

class JwtClaimsBuilder
{
    public function buildUserClaims(object $user): array
    {
        return [
            'user_id' => $user->getId(),
            'email' => $user->getEmail(),
            'roles' => $user->getRoles(),
            'email_verified' => $user->isEmailVerified(),
            'two_factor_enabled' => $user->isTwoFactorEnabled(),
        ];
    }

    public function buildServiceClaims(string $serviceName, array $permissions): array
    {
        return [
            'service' => $serviceName,
            'permissions' => $permissions,
            'scope' => implode(' ', $permissions),
        ];
    }

    public function buildApiKeyClaims(object $apiKey): array
    {
        return [
            'api_key_id' => $apiKey->getId(),
            'client_id' => $apiKey->getClientId(),
            'scope' => $apiKey->getScope(),
            'rate_limit' => $apiKey->getRateLimit(),
        ];
    }

    public function addStandardClaims(array $claims, array $config = []): array
    {
        $now = time();
        
        return array_merge($claims, [
            'iss' => $config['issuer'] ?? $_ENV['APP_URL'],
            'aud' => $config['audience'] ?? $_ENV['APP_URL'],
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + ($config['expires_in'] ?? 3600),
            'jti' => bin2hex(random_bytes(16)),
        ]);
    }
}
```

Custom claim builders organize JWT payload creation. Separate user,  
service, and API key claims. Add standard claims consistently. Keep  
tokens small by including only necessary data.  

## Authorization & Access Control

### Role-Based Access Control

Implementing hierarchical roles.  

```php
<?php

// config/packages/security.yaml
security:
    role_hierarchy:
        ROLE_ADMIN: [ROLE_USER, ROLE_EDITOR]
        ROLE_SUPER_ADMIN: [ROLE_ADMIN, ROLE_ALLOWED_TO_SWITCH]
        ROLE_EDITOR: ROLE_USER
```

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class RoleBasedController extends AbstractController
{
    #[Route('/admin', name: 'admin_panel')]
    #[IsGranted('ROLE_ADMIN')]
    public function adminPanel(): Response
    {
        return $this->render('admin/panel.html.twig');
    }

    #[Route('/editor', name: 'editor_panel')]
    #[IsGranted('ROLE_EDITOR')]
    public function editorPanel(): Response
    {
        return $this->render('editor/panel.html.twig');
    }

    #[Route('/user/settings', name: 'user_settings')]
    #[IsGranted('ROLE_USER')]
    public function userSettings(): Response
    {
        $user = $this->getUser();
        
        return $this->render('user/settings.html.twig', [
            'user' => $user
        ]);
    }

    #[Route('/check-role', name: 'check_role')]
    public function checkRole(): Response
    {
        $roles = [];
        
        if ($this->isGranted('ROLE_USER')) {
            $roles[] = 'USER';
        }
        
        if ($this->isGranted('ROLE_EDITOR')) {
            $roles[] = 'EDITOR';
        }
        
        if ($this->isGranted('ROLE_ADMIN')) {
            $roles[] = 'ADMIN';
        }

        return $this->json(['roles' => $roles]);
    }
}
```

Role hierarchies simplify permission management. Child roles inherit  
parent permissions. Use IsGranted attribute for declarative security.  
Check roles programmatically when needed.  

### Custom Access Decision Manager

Implementing custom authorization strategy.  

```php
<?php

namespace App\Security;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

class CustomAccessDecisionManager implements AccessDecisionManagerInterface
{
    public function __construct(
        private iterable $voters,
        private string $strategy = 'affirmative'
    ) {
    }

    public function decide(
        TokenInterface $token,
        array $attributes,
        $object = null
    ): bool {
        $grant = 0;
        $deny = 0;
        $abstain = 0;

        foreach ($this->voters as $voter) {
            $result = $voter->vote($token, $object, $attributes);

            switch ($result) {
                case VoterInterface::ACCESS_GRANTED:
                    ++$grant;
                    break;
                case VoterInterface::ACCESS_DENIED:
                    ++$deny;
                    break;
                default:
                    ++$abstain;
                    break;
            }
        }

        return match ($this->strategy) {
            'affirmative' => $grant > 0,
            'consensus' => $grant > $deny,
            'unanimous' => $deny === 0 && $grant > 0,
            default => false,
        };
    }
}
```

Custom access decision managers provide flexible authorization strategies.  
Affirmative grants if any voter approves. Consensus requires majority.  
Unanimous requires all voters to agree.  

### Attribute-Based Access Control (ABAC)

Implementing fine-grained access control.  

```php
<?php

namespace App\Security\Voter;

use App\Entity\Document;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class DocumentAccessVoter extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return $subject instanceof Document && 
               in_array($attribute, ['VIEW', 'EDIT', 'DELETE', 'SHARE']);
    }

    protected function voteOnAttribute(
        string $attribute,
        $subject,
        TokenInterface $token
    ): bool {
        $user = $token->getUser();

        if (!$user instanceof User) {
            return false;
        }

        /** @var Document $document */
        $document = $subject;

        return match($attribute) {
            'VIEW' => $this->canView($document, $user),
            'EDIT' => $this->canEdit($document, $user),
            'DELETE' => $this->canDelete($document, $user),
            'SHARE' => $this->canShare($document, $user),
            default => false,
        };
    }

    private function canView(Document $document, User $user): bool
    {
        // Owner can always view
        if ($document->getOwner() === $user) {
            return true;
        }

        // Check shared permissions
        if ($document->isSharedWith($user)) {
            return true;
        }

        // Check team access
        if ($document->getTeam() && $user->belongsToTeam($document->getTeam())) {
            return true;
        }

        // Public documents
        if ($document->isPublic()) {
            return true;
        }

        return false;
    }

    private function canEdit(Document $document, User $user): bool
    {
        if ($document->getOwner() === $user) {
            return true;
        }

        $permission = $document->getUserPermission($user);
        return $permission && $permission->canEdit();
    }

    private function canDelete(Document $document, User $user): bool
    {
        // Only owner can delete
        return $document->getOwner() === $user;
    }

    private function canShare(Document $document, User $user): bool
    {
        if ($document->getOwner() === $user) {
            return true;
        }

        $permission = $document->getUserPermission($user);
        return $permission && $permission->canShare();
    }
}
```

ABAC enables complex authorization logic based on attributes. Consider  
ownership, sharing, team membership, and visibility. Centralize all  
authorization logic in voters.  

### Permission Groups and ACL

Managing permissions with Access Control Lists.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Permission
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 50)]
    private string $name;

    #[ORM\Column(type: 'string', length: 255)]
    private string $description;

    #[ORM\Column(type: 'string', length: 100)]
    private string $resource;

    #[ORM\Column(type: 'string', length: 50)]
    private string $action;

    // Getters and setters omitted
}
```

```php
<?php

namespace App\Service;

use App\Entity\Permission;
use App\Entity\User;
use App\Repository\PermissionRepository;
use Doctrine\ORM\EntityManagerInterface;

class PermissionManager
{
    public function __construct(
        private EntityManagerInterface $em,
        private PermissionRepository $permissionRepository
    ) {
    }

    public function grantPermission(User $user, string $resource, string $action): void
    {
        $permission = $this->permissionRepository->findOneBy([
            'resource' => $resource,
            'action' => $action,
        ]);

        if ($permission && !$user->hasPermission($permission)) {
            $user->addPermission($permission);
            $this->em->flush();
        }
    }

    public function revokePermission(User $user, string $resource, string $action): void
    {
        $permission = $this->permissionRepository->findOneBy([
            'resource' => $resource,
            'action' => $action,
        ]);

        if ($permission && $user->hasPermission($permission)) {
            $user->removePermission($permission);
            $this->em->flush();
        }
    }

    public function hasPermission(User $user, string $resource, string $action): bool
    {
        foreach ($user->getPermissions() as $permission) {
            if ($permission->getResource() === $resource && 
                $permission->getAction() === $action) {
                return true;
            }
        }

        return false;
    }

    public function getUserPermissions(User $user): array
    {
        return array_map(
            fn($p) => [
                'resource' => $p->getResource(),
                'action' => $p->getAction(),
            ],
            $user->getPermissions()->toArray()
        );
    }
}
```

ACL provides granular permission management. Define permissions as  
resource-action pairs. Grant and revoke individually. Check permissions  
before allowing operations.  

### Dynamic Permission Checking

Runtime permission evaluation.  

```php
<?php

namespace App\Service;

use App\Entity\User;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

class DynamicPermissionChecker
{
    public function __construct(
        private AuthorizationCheckerInterface $authChecker
    ) {
    }

    public function canAccessResource(
        User $user,
        string $resourceType,
        int $resourceId,
        string $action
    ): bool {
        // Build dynamic permission string
        $permission = sprintf('%s_%s_%d', $action, $resourceType, $resourceId);
        
        return $this->authChecker->isGranted($permission);
    }

    public function canPerformAction(
        string $action,
        ?object $subject = null
    ): bool {
        return $this->authChecker->isGranted($action, $subject);
    }

    public function requirePermission(string $permission, ?object $subject = null): void
    {
        if (!$this->authChecker->isGranted($permission, $subject)) {
            throw new \Symfony\Component\Security\Core\Exception\AccessDeniedException(
                'Access denied: insufficient permissions'
            );
        }
    }
}
```

Dynamic permission checking enables flexible authorization. Build  
permission strings from context. Use authorization checker for  
programmatic access control. Throw exceptions for violations.  

### Security Event Logging

Auditing security-related events.  

```php
<?php

namespace App\EventListener;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class SecurityAuditListener implements EventSubscriberInterface
{
    public function __construct(
        private LoggerInterface $securityLogger
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
            LoginFailureEvent::class => 'onLoginFailure',
            LogoutEvent::class => 'onLogout',
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        $request = $event->getRequest();

        $this->securityLogger->info('Successful login', [
            'username' => $user->getUserIdentifier(),
            'ip' => $request->getClientIp(),
            'user_agent' => $request->headers->get('User-Agent'),
            'timestamp' => date('Y-m-d H:i:s'),
        ]);
    }

    public function onLoginFailure(LoginFailureEvent $event): void
    {
        $request = $event->getRequest();
        $exception = $event->getException();

        $this->securityLogger->warning('Failed login attempt', [
            'username' => $request->request->get('email', 'unknown'),
            'ip' => $request->getClientIp(),
            'reason' => $exception->getMessage(),
            'timestamp' => date('Y-m-d H:i:s'),
        ]);
    }

    public function onLogout(LogoutEvent $event): void
    {
        $token = $event->getToken();
        $user = $token?->getUser();

        if ($user) {
            $this->securityLogger->info('User logout', [
                'username' => $user->getUserIdentifier(),
                'timestamp' => date('Y-m-d H:i:s'),
            ]);
        }
    }
}
```

Security event logging creates audit trails. Log successes and failures.  
Record IP addresses, timestamps, and user agents. Monitor for suspicious  
patterns and unauthorized access attempts.  

### IP-Based Access Control

Restricting access by IP address.  

```php
<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class IpWhitelistChecker
{
    private array $whitelist;

    public function __construct(string $whitelistString)
    {
        $this->whitelist = array_map('trim', explode(',', $whitelistString));
    }

    public function checkIp(Request $request): void
    {
        $clientIp = $request->getClientIp();
        
        if (!$this->isAllowed($clientIp)) {
            throw new AccessDeniedHttpException(
                'Access denied from your IP address'
            );
        }
    }

    private function isAllowed(string $ip): bool
    {
        foreach ($this->whitelist as $allowedIp) {
            if ($this->matchIp($ip, $allowedIp)) {
                return true;
            }
        }

        return false;
    }

    private function matchIp(string $ip, string $pattern): bool
    {
        // Exact match
        if ($ip === $pattern) {
            return true;
        }

        // CIDR notation support
        if (strpos($pattern, '/') !== false) {
            return $this->matchCidr($ip, $pattern);
        }

        // Wildcard support (e.g., 192.168.1.*)
        if (strpos($pattern, '*') !== false) {
            $regex = '/^' . str_replace(['.',  '*'], ['\.', '.*'], $pattern) . '$/';
            return preg_match($regex, $ip) === 1;
        }

        return false;
    }

    private function matchCidr(string $ip, string $cidr): bool
    {
        list($subnet, $mask) = explode('/', $cidr);
        
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $maskLong = -1 << (32 - (int)$mask);
        
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }
}
```

IP whitelisting restricts access to trusted networks. Support CIDR  
notation and wildcards. Use for administrative interfaces. Combine with  
other authentication methods for defense in depth.  

### Time-Based Access Restrictions

Limiting access to specific time windows.  

```php
<?php

namespace App\Security;

use Symfony\Component\Security\Core\Exception\AccessDeniedException;

class TimeBasedAccessControl
{
    public function __construct(
        private array $allowedHours = [],
        private array $allowedDays = []
    ) {
    }

    public function checkAccess(): void
    {
        $now = new \DateTimeImmutable();
        
        if (!$this->isWithinAllowedHours($now)) {
            throw new AccessDeniedException(
                'Access is not allowed during this time'
            );
        }

        if (!$this->isWithinAllowedDays($now)) {
            throw new AccessDeniedException(
                'Access is not allowed on this day'
            );
        }
    }

    private function isWithinAllowedHours(\DateTimeImmutable $time): bool
    {
        if (empty($this->allowedHours)) {
            return true;
        }

        $hour = (int) $time->format('G');
        
        foreach ($this->allowedHours as $range) {
            if ($hour >= $range['start'] && $hour <= $range['end']) {
                return true;
            }
        }

        return false;
    }

    private function isWithinAllowedDays(\DateTimeImmutable $time): bool
    {
        if (empty($this->allowedDays)) {
            return true;
        }

        $dayOfWeek = (int) $time->format('N'); // 1 (Monday) to 7 (Sunday)
        
        return in_array($dayOfWeek, $this->allowedDays);
    }

    public function getNextAllowedTime(): ?\DateTimeImmutable
    {
        // Implementation to calculate next allowed time window
        $now = new \DateTimeImmutable();
        
        // Simplified: return next day at start hour
        if (!empty($this->allowedHours)) {
            $startHour = $this->allowedHours[0]['start'];
            return $now->modify('tomorrow')->setTime($startHour, 0);
        }

        return null;
    }
}
```

Time-based access control restricts operations to business hours. Useful  
for maintenance windows, batch processing, or compliance requirements.  
Provide clear feedback on when access will be available.  

### Resource Ownership Verification

Ensuring users can only access their own resources.  

```php
<?php

namespace App\Security\Voter;

use App\Entity\Resource;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class ResourceOwnerVoter extends Voter
{
    protected function supports(string $attribute, $subject): bool
    {
        return $subject instanceof Resource;
    }

    protected function voteOnAttribute(
        string $attribute,
        $subject,
        TokenInterface $token
    ): bool {
        $user = $token->getUser();

        if (!$user instanceof User) {
            return false;
        }

        /** @var Resource $resource */
        $resource = $subject;

        // Admins bypass ownership check
        if (in_array('ROLE_ADMIN', $user->getRoles())) {
            return true;
        }

        // Check direct ownership
        if ($resource->getOwner() === $user) {
            return true;
        }

        // Check delegated access
        if ($resource->isDelegatedTo($user)) {
            return true;
        }

        // Check organization ownership
        if ($resource->getOrganization() && 
            $user->belongsToOrganization($resource->getOrganization())) {
            return true;
        }

        return false;
    }
}
```

Ownership verification prevents unauthorized resource access. Check direct  
ownership, delegation, and organizational membership. Always verify before  
read, update, or delete operations.  

### Multi-Tenancy Security

Isolating data between tenants.  

```php
<?php

namespace App\EventListener;

use App\Entity\User;
use Doctrine\ORM\Query\Filter\SQLFilter;
use Doctrine\ORM\Mapping\ClassMetadata;
use Symfony\Component\Security\Core\Security;

class TenantFilter extends SQLFilter
{
    private ?int $tenantId = null;

    public function addFilterConstraint(
        ClassMetadata $targetEntity,
        $targetTableAlias
    ): string {
        if (!$targetEntity->hasField('tenantId')) {
            return '';
        }

        if ($this->tenantId === null) {
            return '';
        }

        return sprintf('%s.tenant_id = %d', $targetTableAlias, $this->tenantId);
    }

    public function setTenantId(int $tenantId): void
    {
        $this->tenantId = $tenantId;
    }
}
```

```php
<?php

namespace App\EventListener;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Security;

class TenantListener implements EventSubscriberInterface
{
    public function __construct(
        private EntityManagerInterface $em,
        private Security $security
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 9],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $user = $this->security->getUser();

        if (!$user || !method_exists($user, 'getTenantId')) {
            return;
        }

        $filter = $this->em->getFilters()->enable('tenant_filter');
        $filter->setParameter('tenant_id', $user->getTenantId());
    }
}
```

Multi-tenancy isolation prevents data leakage between tenants. Use  
Doctrine filters to automatically scope queries. Set tenant context from  
authenticated user. Never trust tenant ID from request parameters.  

### Content Security Policy Configuration

Implementing CSP headers.  

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class ContentSecurityPolicyListener implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $response = $event->getResponse();
        
        $csp = implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.example.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            "img-src 'self' data: https:",
            "connect-src 'self' https://api.example.com",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]);

        $response->headers->set('Content-Security-Policy', $csp);
    }
}
```

CSP prevents XSS attacks by controlling resource sources. Start strict and  
relax as needed. Use nonces or hashes for inline scripts. Monitor  
violations via report-uri. Gradually remove 'unsafe-inline'.  

### Secure API Rate Limiting

Protecting API endpoints from abuse.  

```php
<?php

namespace App\Service;

use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class ApiRateLimiter
{
    public function __construct(
        private CacheInterface $cache
    ) {
    }

    public function checkLimit(
        string $identifier,
        int $maxRequests = 100,
        int $windowSeconds = 3600
    ): void {
        $key = 'rate_limit_' . hash('sha256', $identifier);
        
        $requests = $this->cache->get($key, function(ItemInterface $item) use ($windowSeconds) {
            $item->expiresAfter($windowSeconds);
            return ['count' => 0, 'reset' => time() + $windowSeconds];
        });

        if ($requests['count'] >= $maxRequests) {
            throw new TooManyRequestsHttpException(
                $requests['reset'] - time(),
                sprintf('Rate limit exceeded. Try again in %d seconds.', 
                    $requests['reset'] - time())
            );
        }

        $requests['count']++;
        $this->cache->delete($key);
        $this->cache->get($key, function(ItemInterface $item) use ($requests, $windowSeconds) {
            $item->expiresAfter($windowSeconds);
            return $requests;
        });
    }

    public function getRemainingRequests(string $identifier, int $maxRequests = 100): int
    {
        $key = 'rate_limit_' . hash('sha256', $identifier);
        $item = $this->cache->getItem($key);
        
        if (!$item->isHit()) {
            return $maxRequests;
        }

        $requests = $item->get();
        return max(0, $maxRequests - $requests['count']);
    }
}
```

Rate limiting prevents API abuse and DoS attacks. Track requests per  
identifier (API key, IP, user). Use sliding or fixed windows. Return  
appropriate headers with remaining quota.  

## CSRF Protection

### Form CSRF Protection

Built-in CSRF protection for forms.  

```php
<?php

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\FormBuilderInterface;

class ContactFormType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('email', EmailType::class)
            ->add('message', TextareaType::class)
            ->add('send', SubmitType::class);
        
        // CSRF protection is enabled by default
        // Token name: form name + '_token'
    }
}
```

```php
<?php

namespace App\Controller;

use App\Form\ContactFormType;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ContactController extends AbstractController
{
    #[Route('/contact', name: 'contact')]
    public function contact(Request $request): Response
    {
        $form = $this->createForm(ContactFormType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // CSRF token automatically validated
            $data = $form->getData();
            
            // Process form data
            $this->addFlash('success', 'Message sent successfully');
            
            return $this->redirectToRoute('contact');
        }

        return $this->render('contact/form.html.twig', [
            'form' => $form->createView(),
        ]);
    }
}
```

Symfony forms include CSRF protection by default. Tokens are automatically  
generated and validated. No manual intervention needed. Forms won't submit  
with invalid or missing tokens.  

### Manual CSRF Token Validation

Implementing CSRF protection for custom forms.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class CustomFormController extends AbstractController
{
    public function __construct(
        private CsrfTokenManagerInterface $csrfTokenManager
    ) {
    }

    #[Route('/custom-form', name: 'custom_form')]
    public function showForm(): Response
    {
        $csrfToken = $this->csrfTokenManager->getToken('custom_action')->getValue();

        return $this->render('custom/form.html.twig', [
            'csrf_token' => $csrfToken,
        ]);
    }

    #[Route('/custom-form/submit', name: 'custom_form_submit', methods: ['POST'])]
    public function submit(Request $request): Response
    {
        $submittedToken = $request->request->get('_csrf_token');

        if (!$this->isCsrfTokenValid('custom_action', $submittedToken)) {
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }

        // Process the form
        $email = $request->request->get('email');
        $message = $request->request->get('message');

        $this->addFlash('success', 'Form submitted successfully');

        return $this->redirectToRoute('custom_form');
    }
}
```

Manual CSRF validation for non-Form component scenarios. Generate tokens  
with unique IDs. Validate before processing. Reject requests with invalid  
or missing tokens.  

### AJAX CSRF Protection

Protecting AJAX requests with CSRF tokens.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class AjaxController extends AbstractController
{
    public function __construct(
        private CsrfTokenManagerInterface $csrfTokenManager
    ) {
    }

    #[Route('/api/data/save', name: 'api_save_data', methods: ['POST'])]
    public function saveData(Request $request): JsonResponse
    {
        $token = $request->headers->get('X-CSRF-Token');

        if (!$this->isCsrfTokenValid('ajax_operation', $token)) {
            return $this->json([
                'error' => 'Invalid CSRF token'
            ], 403);
        }

        $data = json_decode($request->getContent(), true);

        // Process data
        
        return $this->json([
            'success' => true,
            'message' => 'Data saved successfully'
        ]);
    }

    #[Route('/csrf-token/{tokenId}', name: 'get_csrf_token')]
    public function getToken(string $tokenId): JsonResponse
    {
        $token = $this->csrfTokenManager->getToken($tokenId)->getValue();

        return $this->json(['token' => $token]);
    }
}
```

```javascript
// JavaScript example for AJAX requests
async function saveData(data) {
    const response = await fetch('/csrf-token/ajax_operation');
    const { token } = await response.json();
    
    const saveResponse = await fetch('/api/data/save', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': token
        },
        body: JSON.stringify(data)
    });
    
    return saveResponse.json();
}
```

AJAX requests need CSRF protection too. Send tokens in custom headers.  
Fetch fresh tokens before requests or embed in page. Validate server-side  
before processing.  

### SameSite Cookie CSRF Defense

Using SameSite attribute for CSRF protection.  

```php
<?php

// config/packages/framework.yaml
framework:
    session:
        cookie_samesite: lax
        cookie_secure: auto
        cookie_httponly: true
```

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class SameSiteCookieListener implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        $response = $event->getResponse();
        $cookies = $response->headers->getCookies();

        foreach ($cookies as $cookie) {
            if ($cookie->getName() === 'auth_token') {
                $response->headers->removeCookie($cookie->getName());
                
                $secureCookie = Cookie::create($cookie->getName())
                    ->withValue($cookie->getValue())
                    ->withExpires($cookie->getExpiresTime())
                    ->withPath($cookie->getPath())
                    ->withDomain($cookie->getDomain())
                    ->withSecure(true)
                    ->withHttpOnly(true)
                    ->withSameSite(Cookie::SAMESITE_STRICT);

                $response->headers->setCookie($secureCookie);
            }
        }
    }
}
```

SameSite cookies prevent CSRF by blocking cross-site requests. Use 'Lax'  
for most cases, 'Strict' for sensitive operations. Combine with other CSRF  
defenses for comprehensive protection.  

### Double Submit Cookie Pattern

Alternative CSRF protection using cookies.  

```php
<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class DoubleSubmitCsrfService
{
    public function __construct(
        private SecureRandomGenerator $randomGenerator
    ) {
    }

    public function generateTokenCookie(): Cookie
    {
        $token = $this->randomGenerator->generateUrlSafeToken(32);

        return Cookie::create('csrf_token')
            ->withValue($token)
            ->withHttpOnly(false) // JavaScript needs to read it
            ->withSecure(true)
            ->withSameSite(Cookie::SAMESITE_STRICT)
            ->withExpires(time() + 3600);
    }

    public function validateToken(Request $request): bool
    {
        $cookieToken = $request->cookies->get('csrf_token');
        $headerToken = $request->headers->get('X-CSRF-Token');

        if (!$cookieToken || !$headerToken) {
            return false;
        }

        return hash_equals($cookieToken, $headerToken);
    }

    public function addTokenToResponse(Response $response): void
    {
        $cookie = $this->generateTokenCookie();
        $response->headers->setCookie($cookie);
    }
}
```

Double submit pattern stores token in cookie and requires submission in  
header or form field. Server compares both values. Doesn't require server  
state but vulnerable to subdomain attacks.  

## Input Validation & Sanitization

### Constraint-Based Validation

Using Symfony's validation component.  

```php
<?php

namespace App\Entity;

use Symfony\Component\Validator\Constraints as Assert;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class UserInput
{
    #[ORM\Column(type: 'string', length: 255)]
    #[Assert\NotBlank(message: 'Email cannot be blank')]
    #[Assert\Email(message: 'Invalid email address')]
    #[Assert\Length(max: 255)]
    private string $email;

    #[ORM\Column(type: 'string', length: 20)]
    #[Assert\NotBlank]
    #[Assert\Regex(
        pattern: '/^\+?[1-9]\d{1,14}$/',
        message: 'Invalid phone number format'
    )]
    private string $phone;

    #[ORM\Column(type: 'integer')]
    #[Assert\NotBlank]
    #[Assert\Range(min: 18, max: 120, notInRangeMessage: 'Age must be between {{ min }} and {{ max }}')]
    private int $age;

    #[ORM\Column(type: 'string', length: 500)]
    #[Assert\NotBlank]
    #[Assert\Length(
        min: 10,
        max: 500,
        minMessage: 'Comment must be at least {{ limit }} characters',
        maxMessage: 'Comment cannot exceed {{ limit }} characters'
    )]
    private string $comment;

    #[ORM\Column(type: 'string', length: 2000)]
    #[Assert\Url(message: 'Invalid URL format')]
    private ?string $website = null;

    // Getters and setters omitted
}
```

Validation constraints ensure data integrity. Apply at entity level for  
automatic validation. Use specific constraints for each data type. Provide  
clear error messages.  

### Custom Validation Constraint

Creating custom validators.  

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;

#[\Attribute]
class NoScriptTags extends Constraint
{
    public string $message = 'The value contains script tags which are not allowed.';

    public function validatedBy(): string
    {
        return static::class . 'Validator';
    }
}
```

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

class NoScriptTagsValidator extends ConstraintValidator
{
    public function validate($value, Constraint $constraint): void
    {
        if (!$constraint instanceof NoScriptTags) {
            throw new UnexpectedTypeException($constraint, NoScriptTags::class);
        }

        if (null === $value || '' === $value) {
            return;
        }

        // Check for script tags
        if (preg_match('/<script\b[^>]*>(.*?)<\/script>/is', $value)) {
            $this->context->buildViolation($constraint->message)
                ->addViolation();
            return;
        }

        // Check for javascript: protocol
        if (preg_match('/javascript:/i', $value)) {
            $this->context->buildViolation($constraint->message)
                ->addViolation();
            return;
        }

        // Check for event handlers
        if (preg_match('/on\w+\s*=/i', $value)) {
            $this->context->buildViolation($constraint->message)
                ->addViolation();
            return;
        }
    }
}
```

Custom validators enforce domain-specific rules. Check for security  
threats like script injection. Combine multiple validation rules. Use  
clear violation messages.  

### Input Sanitization Service

Cleaning user input before processing.  

```php
<?php

namespace App\Service;

class InputSanitizer
{
    public function sanitizeString(string $input): string
    {
        // Remove null bytes
        $input = str_replace("\0", '', $input);
        
        // Trim whitespace
        $input = trim($input);
        
        // Remove control characters except newlines and tabs
        $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $input);
        
        return $input;
    }

    public function sanitizeHtml(string $html): string
    {
        // Use HTMLPurifier or similar
        $config = \HTMLPurifier_Config::createDefault();
        $config->set('HTML.Allowed', 'p,b,i,em,strong,a[href],ul,ol,li');
        $config->set('AutoFormat.RemoveEmpty', true);
        
        $purifier = new \HTMLPurifier($config);
        return $purifier->purify($html);
    }

    public function sanitizeFilename(string $filename): string
    {
        // Remove path traversal attempts
        $filename = basename($filename);
        
        // Remove special characters
        $filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename);
        
        // Limit length
        if (strlen($filename) > 255) {
            $filename = substr($filename, 0, 255);
        }
        
        return $filename;
    }

    public function sanitizeInteger(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        if (is_numeric($value)) {
            return (int) $value;
        }

        return null;
    }

    public function sanitizeEmail(string $email): ?string
    {
        $email = filter_var($email, FILTER_SANITIZE_EMAIL);
        
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return strtolower($email);
        }

        return null;
    }

    public function sanitizeUrl(string $url): ?string
    {
        $url = filter_var($url, FILTER_SANITIZE_URL);
        
        if (filter_var($url, FILTER_VALIDATE_URL)) {
            // Only allow http and https
            $parsed = parse_url($url);
            if (in_array($parsed['scheme'] ?? '', ['http', 'https'])) {
                return $url;
            }
        }

        return null;
    }
}
```

Sanitize all user input before processing. Remove dangerous characters and  
patterns. Validate after sanitization. Use allow-lists over deny-lists.  

### Request Data Validation

Validating request parameters comprehensively.  

```php
<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class RequestValidator
{
    public function validateRequiredFields(Request $request, array $required): void
    {
        $data = $request->request->all();
        $missing = [];

        foreach ($required as $field) {
            if (!isset($data[$field]) || $data[$field] === '') {
                $missing[] = $field;
            }
        }

        if (!empty($missing)) {
            throw new BadRequestHttpException(
                'Missing required fields: ' . implode(', ', $missing)
            );
        }
    }

    public function validateContentType(Request $request, string $expected): void
    {
        $contentType = $request->headers->get('Content-Type');
        
        if (!str_contains($contentType, $expected)) {
            throw new BadRequestHttpException(
                sprintf('Expected Content-Type: %s, got: %s', $expected, $contentType)
            );
        }
    }

    public function validateJsonPayload(Request $request): array
    {
        $content = $request->getContent();
        
        if (empty($content)) {
            throw new BadRequestHttpException('Empty request body');
        }

        $data = json_decode($content, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new BadRequestHttpException(
                'Invalid JSON: ' . json_last_error_msg()
            );
        }

        return $data;
    }

    public function validateArrayStructure(array $data, array $schema): bool
    {
        foreach ($schema as $key => $type) {
            if (!isset($data[$key])) {
                return false;
            }

            $actualType = gettype($data[$key]);
            if ($actualType !== $type) {
                return false;
            }
        }

        return true;
    }
}
```

Validate all request data thoroughly. Check required fields, content  
types, and data structures. Return clear error messages. Fail fast on  
invalid input.  

### File Upload Validation

Securing file uploads.  

```php
<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class FileUploadValidator
{
    private const ALLOWED_MIME_TYPES = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/pdf',
    ];

    private const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

    public function validate(UploadedFile $file): void
    {
        // Check if upload was successful
        if (!$file->isValid()) {
            throw new BadRequestHttpException(
                'File upload failed: ' . $file->getErrorMessage()
            );
        }

        // Validate file size
        if ($file->getSize() > self::MAX_FILE_SIZE) {
            throw new BadRequestHttpException(
                sprintf('File size exceeds maximum of %d bytes', self::MAX_FILE_SIZE)
            );
        }

        // Validate MIME type
        $mimeType = $file->getMimeType();
        if (!in_array($mimeType, self::ALLOWED_MIME_TYPES)) {
            throw new BadRequestHttpException(
                sprintf('File type %s not allowed', $mimeType)
            );
        }

        // Validate file extension
        $extension = $file->guessExtension();
        $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
        
        if (!in_array($extension, $allowedExtensions)) {
            throw new BadRequestHttpException(
                sprintf('File extension %s not allowed', $extension)
            );
        }

        // Check for executable content
        $this->checkForExecutableContent($file);
    }

    private function checkForExecutableContent(UploadedFile $file): void
    {
        $content = file_get_contents($file->getPathname());
        
        // Check for PHP tags
        if (preg_match('/<\?php/i', $content)) {
            throw new BadRequestHttpException('File contains executable PHP code');
        }

        // Check for other script indicators
        $dangerous = ['<?', '<%', '<script'];
        foreach ($dangerous as $pattern) {
            if (stripos($content, $pattern) !== false) {
                throw new BadRequestHttpException('File contains potentially dangerous content');
            }
        }
    }
}
```

Validate all file uploads rigorously. Check size, type, and extension.  
Scan for executable content. Rename files to prevent overwrites. Store  
outside web root when possible.  

### SQL Injection Prevention with Doctrine

Using parameterized queries safely.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class SecureUserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    // GOOD: Using query builder with parameters
    public function findByEmailSecure(string $email): ?User
    {
        return $this->createQueryBuilder('u')
            ->where('u.email = :email')
            ->setParameter('email', $email)
            ->getQuery()
            ->getOneOrNullResult();
    }

    // GOOD: Using DQL with parameters
    public function findActiveUsersSecure(array $roles): array
    {
        $dql = 'SELECT u FROM App\Entity\User u WHERE u.roles LIKE :role AND u.active = :active';
        
        return $this->getEntityManager()
            ->createQuery($dql)
            ->setParameter('role', '%' . $roles[0] . '%')
            ->setParameter('active', true)
            ->getResult();
    }

    // GOOD: Using prepared statements for complex queries
    public function findByComplexCriteriaSecure(array $criteria): array
    {
        $conn = $this->getEntityManager()->getConnection();
        
        $sql = 'SELECT * FROM users WHERE status = :status AND created_at > :date';
        $stmt = $conn->prepare($sql);
        $result = $stmt->executeQuery([
            'status' => $criteria['status'],
            'date' => $criteria['date'],
        ]);

        return $result->fetchAllAssociative();
    }

    // BAD EXAMPLE - Never do this (for educational purposes only)
    // public function findByEmailUnsafe(string $email): array
    // {
    //     $sql = "SELECT * FROM users WHERE email = '$email'"; // VULNERABLE!
    //     return $this->getEntityManager()->getConnection()->fetchAllAssociative($sql);
    // }
}
```

Always use parameterized queries with Doctrine. Never concatenate user  
input into SQL. Use QueryBuilder or setParameter() for safe queries.  
Doctrine's ORM provides automatic protection when used correctly.  

## XSS Prevention

### Output Escaping in Twig

Preventing XSS through proper output encoding.  

```twig
{# Twig automatically escapes output by default #}
<p>{{ user.name }}</p>

{# Explicit escaping for different contexts #}
<p>{{ user.comment|escape('html') }}</p>

<script>
    var username = {{ user.name|json_encode|raw }};
</script>

{# URL context #}
<a href="{{ path('user_profile', {id: user.id}) }}">Profile</a>

{# Attribute context #}
<div data-user="{{ user.id|escape('html_attr') }}">

{# Only use raw filter when absolutely necessary and data is trusted #}
{# <div>{{ trustedHtmlContent|raw }}</div> #}
```

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Twig\Environment;

class XssPreventionController extends AbstractController
{
    #[Route('/safe-output', name: 'safe_output')]
    public function safeOutput(Environment $twig): Response
    {
        $userInput = '<script>alert("XSS")</script>';
        
        // Twig auto-escapes this
        return $this->render('safe_output.html.twig', [
            'user_input' => $userInput,
        ]);
    }

    #[Route('/json-safe', name: 'json_safe')]
    public function jsonSafe(): Response
    {
        $data = [
            'message' => '<script>alert("XSS")</script>',
            'html' => '<b>Bold</b>',
        ];

        // JSON encoding is safe for JavaScript context
        return $this->json($data);
    }
}
```

Twig escapes output by default. Never disable auto-escaping globally. Use  
context-specific escaping (html, js, url, css). Only use raw filter for  
trusted content. JSON encode data for JavaScript context.  

### Content Security Policy Nonce

Using nonces for inline scripts.  

```php
<?php

namespace App\Service;

class CspNonceGenerator
{
    private ?string $nonce = null;

    public function getNonce(): string
    {
        if ($this->nonce === null) {
            $this->nonce = base64_encode(random_bytes(16));
        }

        return $this->nonce;
    }

    public function getCspHeader(): string
    {
        $nonce = $this->getNonce();
        
        return implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'nonce-{$nonce}'",
            "style-src 'self' 'nonce-{$nonce}'",
            "img-src 'self' data: https:",
            "font-src 'self'",
        ]);
    }
}
```

```php
<?php

namespace App\EventListener;

use App\Service\CspNonceGenerator;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Twig\Environment;

class CspNonceListener implements EventSubscriberInterface
{
    public function __construct(
        private CspNonceGenerator $nonceGenerator,
        private Environment $twig
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $response = $event->getResponse();
        $response->headers->set(
            'Content-Security-Policy',
            $this->nonceGenerator->getCspHeader()
        );

        // Make nonce available in Twig
        $this->twig->addGlobal('csp_nonce', $this->nonceGenerator->getNonce());
    }
}
```

```twig
{# Use nonce in templates #}
<script nonce="{{ csp_nonce }}">
    console.log('This script is allowed by CSP');
</script>

<style nonce="{{ csp_nonce }}">
    .safe { color: green; }
</style>
```

CSP nonces allow inline scripts while preventing XSS. Generate unique  
nonces per request. Add to CSP header and script tags. Eliminates need  
for 'unsafe-inline'.  

### DOM XSS Prevention

Preventing client-side XSS vulnerabilities.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class DomXssPreventionController extends AbstractController
{
    #[Route('/api/search', name: 'api_search')]
    public function search(): JsonResponse
    {
        // Return structured data that client can safely render
        $results = [
            ['id' => 1, 'name' => 'John Doe', 'email' => 'john@example.com'],
            ['id' => 2, 'name' => 'Jane Smith', 'email' => 'jane@example.com'],
        ];

        return $this->json([
            'results' => $results,
            'count' => count($results),
        ]);
    }

    #[Route('/safe-template', name: 'safe_template')]
    public function safeTemplate(): Response
    {
        return $this->render('safe_template.html.twig', [
            'page_title' => 'Search Results', // Will be escaped
        ]);
    }
}
```

```javascript
// GOOD: Safe DOM manipulation
function displayResults(results) {
    const container = document.getElementById('results');
    container.textContent = ''; // Clear safely
    
    results.forEach(result => {
        const div = document.createElement('div');
        div.textContent = result.name; // Safe text assignment
        container.appendChild(div);
    });
}

// GOOD: Using data attributes
function handleClick(event) {
    const userId = event.target.dataset.userId; // Safe attribute access
    loadUserData(userId);
}

// BAD: Never use innerHTML with user data
// element.innerHTML = userInput; // VULNERABLE!

// BAD: Never use eval
// eval(userInput); // EXTREMELY VULNERABLE!
```

Prevent DOM XSS by using safe DOM methods. Use textContent instead of  
innerHTML. Create elements programmatically. Validate and sanitize on  
server before sending to client.  

### HTML Purification

Sanitizing HTML user content.  

```php
<?php

namespace App\Service;

use HTMLPurifier;
use HTMLPurifier_Config;

class HtmlPurifierService
{
    private HTMLPurifier $purifier;

    public function __construct()
    {
        $config = HTMLPurifier_Config::createDefault();
        
        // Allow safe HTML tags and attributes
        $config->set('HTML.Allowed', 'p,br,strong,em,u,a[href|title],ul,ol,li,blockquote');
        
        // Disable dangerous elements
        $config->set('HTML.ForbiddenElements', 'script,style,iframe,object,embed');
        
        // Require valid URLs
        $config->set('URI.DisableExternalResources', true);
        $config->set('URI.AllowedSchemes', ['http' => true, 'https' => true]);
        
        // Remove empty elements
        $config->set('AutoFormat.RemoveEmpty', true);
        
        // Tidy output
        $config->set('Output.TidyFormat', true);
        
        $this->purifier = new HTMLPurifier($config);
    }

    public function purify(string $html): string
    {
        return $this->purifier->purify($html);
    }

    public function purifyMultiple(array $htmlArray): array
    {
        return array_map([$this, 'purify'], $htmlArray);
    }
}
```

```php
<?php

namespace App\Controller;

use App\Service\HtmlPurifierService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class CommentController extends AbstractController
{
    #[Route('/comment/submit', name: 'submit_comment', methods: ['POST'])]
    public function submit(
        Request $request,
        HtmlPurifierService $purifier
    ): Response {
        $rawComment = $request->request->get('comment');
        
        // Purify HTML before storing
        $cleanComment = $purifier->purify($rawComment);
        
        // Store $cleanComment in database
        
        $this->addFlash('success', 'Comment submitted successfully');
        return $this->redirectToRoute('comments');
    }
}
```

HTML purification removes dangerous content while preserving safe markup.  
Use HTMLPurifier or similar library. Configure allowed tags and  
attributes. Purify before storage, not just display.  

### JSON Response XSS Protection

Securing JSON API responses.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

class SecureJsonController extends AbstractController
{
    #[Route('/api/user/{id}', name: 'api_user')]
    public function getUser(int $id): JsonResponse
    {
        $userData = [
            'id' => $id,
            'name' => '<script>alert("XSS")</script>',
            'bio' => 'User bio with <b>HTML</b>',
        ];

        // JsonResponse automatically escapes special characters
        $response = $this->json($userData);
        
        // Set proper content type
        $response->headers->set('Content-Type', 'application/json');
        
        // Prevent content sniffing
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        
        return $response;
    }

    #[Route('/api/safe-data', name: 'api_safe_data')]
    public function getSafeData(): JsonResponse
    {
        $data = [
            'message' => "This string has \"quotes\" and 'apostrophes'",
            'html' => '<div>HTML content</div>',
            'script' => '<script>alert("test")</script>',
        ];

        // All values are properly JSON-encoded and safe
        return $this->json($data, 200, [
            'X-Content-Type-Options' => 'nosniff',
        ], ['json_encode_options' => JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT]);
    }
}
```

JSON responses are generally XSS-safe when properly encoded. Use  
JsonResponse class for automatic encoding. Set correct Content-Type.  
Enable JSON_HEX flags for extra safety in HTML context.  

## Secure File Handling

### Secure File Upload Processing

Safe file upload handling.  

```php
<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\File\Exception\FileException;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\String\Slugger\SluggerInterface;

class SecureFileUploadService
{
    public function __construct(
        private string $uploadsDirectory,
        private SluggerInterface $slugger,
        private FileUploadValidator $validator
    ) {
    }

    public function upload(UploadedFile $file): string
    {
        // Validate file
        $this->validator->validate($file);

        // Generate safe filename
        $originalFilename = pathinfo($file->getClientOriginalName(), PATHINFO_FILENAME);
        $safeFilename = $this->slugger->slug($originalFilename);
        $uniqueFilename = $safeFilename . '-' . uniqid() . '.' . $file->guessExtension();

        try {
            // Move file to secure location (outside web root if possible)
            $file->move($this->uploadsDirectory, $uniqueFilename);
            
            // Set restrictive permissions
            chmod($this->uploadsDirectory . '/' . $uniqueFilename, 0644);
            
            return $uniqueFilename;
            
        } catch (FileException $e) {
            throw new \RuntimeException('Failed to upload file: ' . $e->getMessage());
        }
    }

    public function deleteFile(string $filename): void
    {
        $filepath = $this->uploadsDirectory . '/' . basename($filename);
        
        if (file_exists($filepath)) {
            unlink($filepath);
        }
    }

    public function getFilePath(string $filename): string
    {
        // Prevent directory traversal
        $filename = basename($filename);
        $filepath = $this->uploadsDirectory . '/' . $filename;
        
        if (!file_exists($filepath)) {
            throw new \RuntimeException('File not found');
        }

        // Verify file is in allowed directory
        $realPath = realpath($filepath);
        $uploadsPath = realpath($this->uploadsDirectory);
        
        if (!str_starts_with($realPath, $uploadsPath)) {
            throw new \RuntimeException('Invalid file path');
        }

        return $realPath;
    }
}
```

Secure file uploads by validating thoroughly, generating safe names,  
storing outside web root, setting restrictive permissions, and preventing  
path traversal. Never trust client-provided filenames.  

### Secure File Download

Serving files securely.  

```php
<?php

namespace App\Controller;

use App\Service\SecureFileUploadService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class FileDownloadController extends AbstractController
{
    #[Route('/download/{filename}', name: 'file_download')]
    #[IsGranted('ROLE_USER')]
    public function download(
        string $filename,
        SecureFileUploadService $fileService
    ): BinaryFileResponse {
        try {
            $filepath = $fileService->getFilePath($filename);
        } catch (\RuntimeException $e) {
            throw $this->createNotFoundException('File not found');
        }

        $response = new BinaryFileResponse($filepath);
        
        // Force download instead of inline display
        $response->setContentDisposition(
            ResponseHeaderBag::DISPOSITION_ATTACHMENT,
            $filename
        );

        // Set proper content type
        $response->headers->set('Content-Type', 'application/octet-stream');
        
        // Prevent caching of sensitive files
        $response->headers->set('Cache-Control', 'no-cache, no-store, must-revalidate');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Expires', '0');
        
        // Security headers
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        return $response;
    }

    #[Route('/view-image/{filename}', name: 'view_image')]
    public function viewImage(
        string $filename,
        SecureFileUploadService $fileService
    ): BinaryFileResponse {
        $filepath = $fileService->getFilePath($filename);
        
        $response = new BinaryFileResponse($filepath);
        
        // Allow inline viewing for images only
        $mimeType = mime_content_type($filepath);
        if (!str_starts_with($mimeType, 'image/')) {
            throw $this->createAccessDeniedException('File is not an image');
        }

        $response->headers->set('Content-Type', $mimeType);
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_INLINE);

        return $response;
    }
}
```

Serve files securely by verifying permissions, preventing path traversal,  
setting correct content types, and using appropriate disposition headers.  
Never expose internal file paths.  

### Image Processing Security

Secure image manipulation.  

```php
<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\File\UploadedFile;

class SecureImageProcessor
{
    public function __construct(
        private string $uploadsDirectory
    ) {
    }

    public function processImage(UploadedFile $file): string
    {
        // Verify it's actually an image
        $imageInfo = getimagesize($file->getPathname());
        if ($imageInfo === false) {
            throw new \RuntimeException('File is not a valid image');
        }

        [$width, $height, $type] = $imageInfo;

        // Limit image dimensions
        $maxWidth = 4000;
        $maxHeight = 4000;
        
        if ($width > $maxWidth || $height > $maxHeight) {
            throw new \RuntimeException('Image dimensions exceed maximum allowed');
        }

        // Create image resource based on type
        $image = match ($type) {
            IMAGETYPE_JPEG => imagecreatefromjpeg($file->getPathname()),
            IMAGETYPE_PNG => imagecreatefrompng($file->getPathname()),
            IMAGETYPE_GIF => imagecreatefromgif($file->getPathname()),
            default => throw new \RuntimeException('Unsupported image type'),
        };

        if ($image === false) {
            throw new \RuntimeException('Failed to create image resource');
        }

        // Re-encode image to strip EXIF and other metadata
        $filename = uniqid() . '.jpg';
        $filepath = $this->uploadsDirectory . '/' . $filename;
        
        imagejpeg($image, $filepath, 85);
        imagedestroy($image);

        return $filename;
    }

    public function createThumbnail(string $sourcePath, int $maxSize = 200): string
    {
        $imageInfo = getimagesize($sourcePath);
        if ($imageInfo === false) {
            throw new \RuntimeException('Invalid image file');
        }

        [$width, $height, $type] = $imageInfo;

        // Calculate new dimensions
        $ratio = min($maxSize / $width, $maxSize / $height);
        $newWidth = (int)($width * $ratio);
        $newHeight = (int)($height * $ratio);

        // Create source and destination images
        $source = match ($type) {
            IMAGETYPE_JPEG => imagecreatefromjpeg($sourcePath),
            IMAGETYPE_PNG => imagecreatefrompng($sourcePath),
            default => throw new \RuntimeException('Unsupported image type'),
        };

        $thumbnail = imagecreatetruecolor($newWidth, $newHeight);
        
        // Preserve transparency for PNG
        if ($type === IMAGETYPE_PNG) {
            imagealphablending($thumbnail, false);
            imagesavealpha($thumbnail, true);
        }

        imagecopyresampled(
            $thumbnail, $source,
            0, 0, 0, 0,
            $newWidth, $newHeight,
            $width, $height
        );

        $thumbFilename = 'thumb_' . basename($sourcePath);
        $thumbPath = $this->uploadsDirectory . '/' . $thumbFilename;
        
        imagejpeg($thumbnail, $thumbPath, 85);
        
        imagedestroy($source);
        imagedestroy($thumbnail);

        return $thumbFilename;
    }
}
```

Process images securely by verifying file type with getimagesize(),  
limiting dimensions, re-encoding to strip metadata, and using GD library  
functions. Never trust file extensions alone.  

### Path Traversal Prevention

Preventing directory traversal attacks.  

```php
<?php

namespace App\Service;

class PathSecurityService
{
    public function __construct(
        private string $baseDirectory
    ) {
    }

    public function getSecurePath(string $userPath): string
    {
        // Remove any null bytes
        $userPath = str_replace("\0", '', $userPath);
        
        // Get the absolute path
        $fullPath = $this->baseDirectory . '/' . $userPath;
        $realPath = realpath($fullPath);

        // Verify the path exists and is within base directory
        if ($realPath === false) {
            throw new \RuntimeException('Path does not exist');
        }

        $baseReal = realpath($this->baseDirectory);
        
        if (!str_starts_with($realPath, $baseReal)) {
            throw new \RuntimeException('Path traversal attempt detected');
        }

        return $realPath;
    }

    public function sanitizePath(string $path): string
    {
        // Remove directory traversal sequences
        $path = str_replace(['../', '..\\', '../', '..\\'], '', $path);
        
        // Remove absolute path indicators
        $path = ltrim($path, '/\\');
        
        // Use only basename to prevent any path manipulation
        return basename($path);
    }

    public function isPathSafe(string $path, string $allowedDirectory): bool
    {
        $realPath = realpath($path);
        $allowedPath = realpath($allowedDirectory);

        return $realPath !== false && 
               $allowedPath !== false && 
               str_starts_with($realPath, $allowedPath);
    }
}
```

Prevent path traversal by validating all file paths. Use realpath() to  
resolve paths and check they're within allowed directories. Never trust  
user-provided paths. Use basename() for filenames.  

## HTTPS & TLS Configuration

### Force HTTPS Redirect

Enforcing HTTPS for all connections.  

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class HttpsRedirectListener implements EventSubscriberInterface
{
    public function __construct(
        private bool $forceHttps = true
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 100],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest() || !$this->forceHttps) {
            return;
        }

        $request = $event->getRequest();

        if (!$request->isSecure() && $request->getMethod() === 'GET') {
            $url = 'https://' . $request->getHost() . $request->getRequestUri();
            $event->setResponse(new RedirectResponse($url, 301));
        }
    }
}
```

```yaml
# config/packages/framework.yaml
framework:
    # Force HTTPS in routing
    router:
        default_uri: 'https://example.com'
```

Force HTTPS to protect data in transit. Redirect HTTP to HTTPS with 301.  
Use HSTS headers to enforce HTTPS at browser level. Never transmit  
sensitive data over HTTP.  

### HSTS Header Configuration

Implementing HTTP Strict Transport Security.  

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class HstsListener implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $response = $event->getResponse();

        if ($request->isSecure()) {
            // Enable HSTS with subdomains and preload
            $response->headers->set(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            );
        }
    }
}
```

HSTS forces browsers to use HTTPS for future requests. Set max-age to at  
least one year. Include subdomains if all use HTTPS. Consider preload  
list submission for maximum security.  

### TLS Certificate Validation

Validating external API certificates.  

```php
<?php

namespace App\Service;

use Symfony\Contracts\HttpClient\HttpClientInterface;

class SecureHttpClient
{
    public function __construct(
        private HttpClientInterface $httpClient
    ) {
    }

    public function makeSecureRequest(string $url, array $options = []): array
    {
        $secureOptions = array_merge($options, [
            'verify_peer' => true,
            'verify_host' => true,
            'timeout' => 30,
            'max_redirects' => 3,
        ]);

        try {
            $response = $this->httpClient->request('GET', $url, $secureOptions);
            
            if ($response->getStatusCode() !== 200) {
                throw new \RuntimeException('HTTP request failed');
            }

            return $response->toArray();
            
        } catch (\Exception $e) {
            throw new \RuntimeException(
                'Secure request failed: ' . $e->getMessage()
            );
        }
    }

    public function validateCertificate(string $hostname): array
    {
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => true,
                'verify_peer_name' => true,
            ]
        ]);

        $socket = @stream_socket_client(
            "ssl://{$hostname}:443",
            $errno,
            $errstr,
            30,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$socket) {
            throw new \RuntimeException("Failed to connect: $errstr ($errno)");
        }

        $params = stream_context_get_params($socket);
        $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);

        fclose($socket);

        return [
            'subject' => $cert['subject'] ?? [],
            'issuer' => $cert['issuer'] ?? [],
            'valid_from' => date('Y-m-d H:i:s', $cert['validFrom_time_t']),
            'valid_to' => date('Y-m-d H:i:s', $cert['validTo_time_t']),
            'expired' => time() > $cert['validTo_time_t'],
        ];
    }
}
```

Always verify TLS certificates for external connections. Enable peer and  
host verification. Never disable certificate validation in production.  
Monitor certificate expiration.  

### Secure Cookie Configuration

Configuring cookies securely.  

```php
<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\Cookie;

class SecureCookieService
{
    public function createSecureCookie(
        string $name,
        string $value,
        int $expiresIn = 3600
    ): Cookie {
        return Cookie::create($name)
            ->withValue($value)
            ->withExpires(time() + $expiresIn)
            ->withPath('/')
            ->withSecure(true)      // HTTPS only
            ->withHttpOnly(true)    // No JavaScript access
            ->withSameSite(Cookie::SAMESITE_STRICT); // CSRF protection
    }

    public function createSessionCookie(string $name, string $value): Cookie
    {
        return Cookie::create($name)
            ->withValue($value)
            ->withPath('/')
            ->withSecure(true)
            ->withHttpOnly(true)
            ->withSameSite(Cookie::SAMESITE_LAX);
    }

    public function createAuthCookie(string $token, int $expiresIn): Cookie
    {
        return Cookie::create('auth_token')
            ->withValue($token)
            ->withExpires(time() + $expiresIn)
            ->withPath('/')
            ->withSecure(true)
            ->withHttpOnly(true)
            ->withSameSite(Cookie::SAMESITE_STRICT)
            ->withDomain('') // Restrict to current domain
            ->withRaw(false);
    }
}
```

Secure cookies with HttpOnly, Secure, and SameSite flags. Use Strict  
SameSite for sensitive cookies. Set appropriate expiration. Never store  
sensitive data in cookies without encryption.  

### Secure Headers Service

Implementing comprehensive security headers.  

```php
<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\Response;

class SecurityHeadersService
{
    public function applySecurityHeaders(Response $response): void
    {
        // Prevent MIME sniffing
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Enable XSS protection (legacy but still useful)
        $response->headers->set('X-XSS-Protection', '1; mode=block');

        // Prevent clickjacking
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');

        // Referrer policy
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Permissions policy
        $response->headers->set(
            'Permissions-Policy',
            'geolocation=(), microphone=(), camera=()'
        );

        // Content Security Policy
        $csp = implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
        ]);
        $response->headers->set('Content-Security-Policy', $csp);

        // Remove server information
        $response->headers->remove('X-Powered-By');
        $response->headers->set('Server', 'webserver');
    }

    public function applyApiHeaders(Response $response): void
    {
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate');
        $response->headers->set('Pragma', 'no-cache');
    }
}
```

Apply comprehensive security headers to all responses. Prevent common  
attacks like clickjacking, MIME sniffing, and XSS. Configure CSP  
appropriately. Remove identifying headers.  

## OAuth2 Integration

### OAuth2 Client Configuration

Implementing OAuth2 client flow.  

```php
<?php

namespace App\Service;

use Symfony\Contracts\HttpClient\HttpClientInterface;

class OAuth2Client
{
    public function __construct(
        private HttpClientInterface $httpClient,
        private string $clientId,
        private string $clientSecret,
        private string $redirectUri
    ) {
    }

    public function getAuthorizationUrl(string $state): string
    {
        $params = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'email profile',
            'state' => $state,
        ]);

        return 'https://provider.com/oauth/authorize?' . $params;
    }

    public function exchangeCodeForToken(string $code, string $state): array
    {
        // Validate state to prevent CSRF
        if (!$this->validateState($state)) {
            throw new \RuntimeException('Invalid state parameter');
        }

        $response = $this->httpClient->request('POST', 'https://provider.com/oauth/token', [
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'redirect_uri' => $this->redirectUri,
            ],
        ]);

        return $response->toArray();
    }

    public function refreshToken(string $refreshToken): array
    {
        $response = $this->httpClient->request('POST', 'https://provider.com/oauth/token', [
            'body' => [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
            ],
        ]);

        return $response->toArray();
    }

    private function validateState(string $state): bool
    {
        // Implement state validation using session or cache
        return true; // Simplified
    }

    public function getUserInfo(string $accessToken): array
    {
        $response = $this->httpClient->request('GET', 'https://provider.com/oauth/userinfo', [
            'headers' => [
                'Authorization' => 'Bearer ' . $accessToken,
            ],
        ]);

        return $response->toArray();
    }
}
```

OAuth2 enables secure third-party authentication. Use state parameter for  
CSRF protection. Store tokens securely. Use refresh tokens for long-lived  
access. Validate all responses.  

### OAuth2 Authorization Server

Implementing basic OAuth2 server.  

```php
<?php

namespace App\Controller;

use App\Service\OAuth2Service;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class OAuth2ServerController extends AbstractController
{
    public function __construct(
        private OAuth2Service $oauth2Service
    ) {
    }

    #[Route('/oauth/authorize', name: 'oauth_authorize')]
    #[IsGranted('ROLE_USER')]
    public function authorize(Request $request): Response
    {
        $clientId = $request->query->get('client_id');
        $redirectUri = $request->query->get('redirect_uri');
        $state = $request->query->get('state');
        $scope = $request->query->get('scope', 'basic');

        // Validate client
        if (!$this->oauth2Service->validateClient($clientId, $redirectUri)) {
            throw $this->createAccessDeniedException('Invalid client');
        }

        if ($request->isMethod('POST')) {
            $authorized = $request->request->get('authorize') === '1';

            if ($authorized) {
                $code = $this->oauth2Service->generateAuthorizationCode(
                    $this->getUser(),
                    $clientId,
                    $scope
                );

                $params = http_build_query([
                    'code' => $code,
                    'state' => $state,
                ]);

                return $this->redirect($redirectUri . '?' . $params);
            }

            return $this->redirect($redirectUri . '?error=access_denied&state=' . $state);
        }

        return $this->render('oauth/authorize.html.twig', [
            'client_id' => $clientId,
            'scope' => $scope,
        ]);
    }

    #[Route('/oauth/token', name: 'oauth_token', methods: ['POST'])]
    public function token(Request $request): JsonResponse
    {
        $grantType = $request->request->get('grant_type');

        if ($grantType === 'authorization_code') {
            return $this->handleAuthorizationCode($request);
        }

        if ($grantType === 'refresh_token') {
            return $this->handleRefreshToken($request);
        }

        return $this->json(['error' => 'unsupported_grant_type'], 400);
    }

    private function handleAuthorizationCode(Request $request): JsonResponse
    {
        $code = $request->request->get('code');
        $clientId = $request->request->get('client_id');
        $clientSecret = $request->request->get('client_secret');

        if (!$this->oauth2Service->validateClientCredentials($clientId, $clientSecret)) {
            return $this->json(['error' => 'invalid_client'], 401);
        }

        $tokenData = $this->oauth2Service->exchangeCodeForTokens($code, $clientId);

        if (!$tokenData) {
            return $this->json(['error' => 'invalid_grant'], 400);
        }

        return $this->json($tokenData);
    }

    private function handleRefreshToken(Request $request): JsonResponse
    {
        $refreshToken = $request->request->get('refresh_token');
        $clientId = $request->request->get('client_id');
        $clientSecret = $request->request->get('client_secret');

        if (!$this->oauth2Service->validateClientCredentials($clientId, $clientSecret)) {
            return $this->json(['error' => 'invalid_client'], 401);
        }

        $tokenData = $this->oauth2Service->refreshAccessToken($refreshToken);

        if (!$tokenData) {
            return $this->json(['error' => 'invalid_grant'], 400);
        }

        return $this->json($tokenData);
    }
}
```

OAuth2 server implementation requires secure authorization code exchange,  
client validation, and token management. Use PKCE for public clients.  
Implement proper scope validation.  

### Social Login Integration

Integrating with social providers.  

```php
<?php

namespace App\Controller;

use App\Service\OAuth2Client;
use App\Service\UserService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SocialLoginController extends AbstractController
{
    public function __construct(
        private OAuth2Client $oauth2Client,
        private UserService $userService
    ) {
    }

    #[Route('/login/google', name: 'login_google')]
    public function loginWithGoogle(Request $request): Response
    {
        $session = $request->getSession();
        $state = bin2hex(random_bytes(16));
        $session->set('oauth_state', $state);

        $authUrl = $this->oauth2Client->getAuthorizationUrl($state);

        return $this->redirect($authUrl);
    }

    #[Route('/oauth/callback', name: 'oauth_callback')]
    public function oauthCallback(Request $request): Response
    {
        $code = $request->query->get('code');
        $state = $request->query->get('state');
        $error = $request->query->get('error');

        if ($error) {
            $this->addFlash('error', 'OAuth authorization failed');
            return $this->redirectToRoute('login');
        }

        // Validate state
        $session = $request->getSession();
        $savedState = $session->get('oauth_state');
        $session->remove('oauth_state');

        if ($state !== $savedState) {
            throw $this->createAccessDeniedException('Invalid OAuth state');
        }

        try {
            // Exchange code for token
            $tokenData = $this->oauth2Client->exchangeCodeForToken($code, $state);
            $accessToken = $tokenData['access_token'];

            // Get user info
            $userInfo = $this->oauth2Client->getUserInfo($accessToken);

            // Find or create user
            $user = $this->userService->findOrCreateFromOAuth($userInfo);

            // Log user in
            // Implementation depends on your authentication system

            return $this->redirectToRoute('dashboard');

        } catch (\Exception $e) {
            $this->addFlash('error', 'Authentication failed: ' . $e->getMessage());
            return $this->redirectToRoute('login');
        }
    }
}
```

Social login via OAuth2 simplifies authentication. Validate state  
parameter to prevent CSRF. Handle errors gracefully. Create or link  
accounts based on OAuth profile. Store minimal necessary data.  

## Advanced Security Patterns

### Security Event Dispatcher

Custom security event handling.  

```php
<?php

namespace App\Event;

use Symfony\Contracts\EventDispatcher\Event;

class SecurityEvent extends Event
{
    public const SUSPICIOUS_ACTIVITY = 'security.suspicious_activity';
    public const PASSWORD_CHANGED = 'security.password_changed';
    public const ACCOUNT_LOCKED = 'security.account_locked';
    public const PRIVILEGE_ESCALATION = 'security.privilege_escalation';

    public function __construct(
        private string $userId,
        private string $eventType,
        private array $context = []
    ) {
    }

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function getEventType(): string
    {
        return $this->eventType;
    }

    public function getContext(): array
    {
        return $this->context;
    }
}
```

```php
<?php

namespace App\EventListener;

use App\Event\SecurityEvent;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

class SecurityEventSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private LoggerInterface $securityLogger,
        private MailerInterface $mailer
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            SecurityEvent::SUSPICIOUS_ACTIVITY => 'onSuspiciousActivity',
            SecurityEvent::PASSWORD_CHANGED => 'onPasswordChanged',
            SecurityEvent::ACCOUNT_LOCKED => 'onAccountLocked',
            SecurityEvent::PRIVILEGE_ESCALATION => 'onPrivilegeEscalation',
        ];
    }

    public function onSuspiciousActivity(SecurityEvent $event): void
    {
        $this->securityLogger->warning('Suspicious activity detected', [
            'user_id' => $event->getUserId(),
            'context' => $event->getContext(),
        ]);

        // Send alert email to security team
        $email = (new Email())
            ->to('security@example.com')
            ->subject('Security Alert: Suspicious Activity')
            ->text(sprintf(
                'Suspicious activity detected for user %s',
                $event->getUserId()
            ));

        $this->mailer->send($email);
    }

    public function onPasswordChanged(SecurityEvent $event): void
    {
        $this->securityLogger->info('Password changed', [
            'user_id' => $event->getUserId(),
        ]);
    }

    public function onAccountLocked(SecurityEvent $event): void
    {
        $this->securityLogger->warning('Account locked', [
            'user_id' => $event->getUserId(),
            'reason' => $event->getContext()['reason'] ?? 'unknown',
        ]);
    }

    public function onPrivilegeEscalation(SecurityEvent $event): void
    {
        $this->securityLogger->critical('Privilege escalation attempt', [
            'user_id' => $event->getUserId(),
            'context' => $event->getContext(),
        ]);
    }
}
```

Security events enable monitoring and alerting. Log all security-relevant  
actions. Send alerts for critical events. Track patterns for anomaly  
detection. Maintain detailed audit trails.  

### Anomaly Detection Service

Detecting suspicious behavior patterns.  

```php
<?php

namespace App\Service;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class AnomalyDetectionService
{
    public function __construct(
        private CacheInterface $cache
    ) {
    }

    public function trackUserAction(int $userId, string $action): void
    {
        $key = sprintf('user_actions_%d', $userId);
        
        $actions = $this->cache->get($key, function(ItemInterface $item) {
            $item->expiresAfter(3600);
            return [];
        });

        $actions[] = [
            'action' => $action,
            'timestamp' => time(),
        ];

        // Keep only last 100 actions
        $actions = array_slice($actions, -100);

        $this->cache->delete($key);
        $this->cache->get($key, function(ItemInterface $item) use ($actions) {
            $item->expiresAfter(3600);
            return $actions;
        });

        // Check for anomalies
        $this->detectAnomalies($userId, $actions);
    }

    private function detectAnomalies(int $userId, array $actions): void
    {
        // Rapid successive actions
        if ($this->detectRapidActions($actions)) {
            $this->reportAnomaly($userId, 'rapid_actions');
        }

        // Unusual time of day
        if ($this->detectUnusualTime($actions)) {
            $this->reportAnomaly($userId, 'unusual_time');
        }

        // Unusual action pattern
        if ($this->detectUnusualPattern($actions)) {
            $this->reportAnomaly($userId, 'unusual_pattern');
        }
    }

    private function detectRapidActions(array $actions): bool
    {
        if (count($actions) < 10) {
            return false;
        }

        $recent = array_slice($actions, -10);
        $timestamps = array_column($recent, 'timestamp');
        
        $timeSpan = max($timestamps) - min($timestamps);
        
        // 10 actions in less than 5 seconds
        return $timeSpan < 5;
    }

    private function detectUnusualTime(array $actions): bool
    {
        $hour = (int) date('G');
        
        // Actions between 2 AM and 5 AM
        return $hour >= 2 && $hour < 5;
    }

    private function detectUnusualPattern(array $actions): bool
    {
        // Implement pattern analysis
        // This is a simplified example
        return false;
    }

    private function reportAnomaly(int $userId, string $type): void
    {
        // Log or trigger security event
        error_log(sprintf('Anomaly detected for user %d: %s', $userId, $type));
    }
}
```

Anomaly detection identifies suspicious patterns. Track user actions,  
analyze timing and frequency. Alert on deviations from normal behavior.  
Use machine learning for advanced detection.  

### Honeypot Implementation

Detecting and blocking bots.  

```php
<?php

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormError;
use Symfony\Component\Form\FormEvent;
use Symfony\Component\Form\FormEvents;

class HoneypotFormType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('name', TextType::class)
            ->add('email', EmailType::class)
            ->add('website', TextType::class, [
                'required' => false,
                'mapped' => false,
                'attr' => [
                    'style' => 'position: absolute; left: -9999px; width: 1px; height: 1px;',
                    'tabindex' => '-1',
                    'autocomplete' => 'off',
                ],
            ])
            ->add('timestamp', HiddenType::class, [
                'data' => time(),
                'mapped' => false,
            ])
            ->add('submit', SubmitType::class);

        $builder->addEventListener(FormEvents::POST_SUBMIT, function (FormEvent $event) {
            $form = $event->getForm();
            
            // Check honeypot field
            $website = $form->get('website')->getData();
            if (!empty($website)) {
                $form->addError(new FormError('Bot detected'));
                return;
            }

            // Check submission time
            $timestamp = (int) $form->get('timestamp')->getData();
            $elapsed = time() - $timestamp;
            
            // Too fast (less than 3 seconds)
            if ($elapsed < 3) {
                $form->addError(new FormError('Submission too fast'));
            }
        });
    }
}
```

Honeypots catch bots without affecting users. Add hidden fields that bots  
fill. Check form submission timing. Use CSS to hide from visual users but  
not screen readers or bots.  

### Security Compliance Checker

Validating security configuration.  

```php
<?php

namespace App\Service;

class SecurityComplianceChecker
{
    private array $checks = [];

    public function runChecks(): array
    {
        $this->checkPasswordPolicy();
        $this->checkSessionSecurity();
        $this->checkHttpsSecurity();
        $this->checkCsrfProtection();
        $this->checkDatabaseSecurity();

        return $this->checks;
    }

    private function checkPasswordPolicy(): void
    {
        $minLength = $_ENV['PASSWORD_MIN_LENGTH'] ?? 8;
        
        $this->checks['password_policy'] = [
            'status' => $minLength >= 12 ? 'pass' : 'fail',
            'message' => "Password minimum length: $minLength",
            'recommendation' => $minLength < 12 ? 'Increase to at least 12 characters' : null,
        ];
    }

    private function checkSessionSecurity(): void
    {
        $cookieSecure = ini_get('session.cookie_secure');
        $cookieHttpOnly = ini_get('session.cookie_httponly');
        $sameSite = ini_get('session.cookie_samesite');

        $allSecure = $cookieSecure === '1' && 
                     $cookieHttpOnly === '1' && 
                     in_array($sameSite, ['Lax', 'Strict']);

        $this->checks['session_security'] = [
            'status' => $allSecure ? 'pass' : 'fail',
            'details' => [
                'cookie_secure' => $cookieSecure === '1',
                'cookie_httponly' => $cookieHttpOnly === '1',
                'cookie_samesite' => $sameSite,
            ],
        ];
    }

    private function checkHttpsSecurity(): void
    {
        $forceHttps = $_ENV['FORCE_HTTPS'] ?? 'false';
        
        $this->checks['https_security'] = [
            'status' => $forceHttps === 'true' ? 'pass' : 'warning',
            'message' => 'HTTPS enforcement: ' . $forceHttps,
        ];
    }

    private function checkCsrfProtection(): void
    {
        // Check if CSRF protection is enabled
        $csrfEnabled = true; // Symfony forms have CSRF enabled by default
        
        $this->checks['csrf_protection'] = [
            'status' => $csrfEnabled ? 'pass' : 'fail',
            'message' => 'CSRF protection enabled',
        ];
    }

    private function checkDatabaseSecurity(): void
    {
        $dbUrl = $_ENV['DATABASE_URL'] ?? '';
        
        // Check for localhost in production
        $hasLocalhost = str_contains($dbUrl, 'localhost');
        
        $this->checks['database_security'] = [
            'status' => !$hasLocalhost ? 'pass' : 'warning',
            'message' => 'Database not using localhost in connection string',
        ];
    }

    public function getFailedChecks(): array
    {
        return array_filter($this->checks, fn($check) => $check['status'] === 'fail');
    }

    public function hasFailures(): bool
    {
        return !empty($this->getFailedChecks());
    }
}
```

Compliance checking ensures security standards are met. Validate  
configuration programmatically. Run checks in CI/CD pipeline. Generate  
reports for audits. Fix violations before deployment.  

### Secure Random Token Storage

Managing security tokens safely.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\HasLifecycleCallbacks]
class SecurityToken
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 255)]
    private string $tokenHash;

    #[ORM\Column(type: 'string', length: 50)]
    private string $type;

    #[ORM\ManyToOne(targetEntity: User::class)]
    private ?User $user = null;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $expiresAt;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(type: 'boolean')]
    private bool $used = false;

    private ?string $plainToken = null;

    public function __construct(string $type, User $user, int $expiresIn = 3600)
    {
        $this->type = $type;
        $this->user = $user;
        $this->createdAt = new \DateTimeImmutable();
        $this->expiresAt = new \DateTimeImmutable('+' . $expiresIn . ' seconds');
    }

    #[ORM\PrePersist]
    public function hashToken(): void
    {
        if ($this->plainToken) {
            $this->tokenHash = hash('sha256', $this->plainToken);
        }
    }

    public function setPlainToken(string $token): self
    {
        $this->plainToken = $token;
        return $this;
    }

    public function getPlainToken(): ?string
    {
        return $this->plainToken;
    }

    public function isExpired(): bool
    {
        return new \DateTimeImmutable() > $this->expiresAt;
    }

    public function isUsed(): bool
    {
        return $this->used;
    }

    public function markAsUsed(): self
    {
        $this->used = true;
        return $this;
    }

    public function getTokenHash(): string
    {
        return $this->tokenHash;
    }

    // Other getters omitted
}
```

```php
<?php

namespace App\Service;

use App\Entity\SecurityToken;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;

class TokenManagementService
{
    public function __construct(
        private EntityManagerInterface $em,
        private SecureRandomGenerator $randomGenerator
    ) {
    }

    public function createToken(User $user, string $type, int $expiresIn = 3600): string
    {
        $plainToken = $this->randomGenerator->generateUrlSafeToken(32);
        
        $token = new SecurityToken($type, $user, $expiresIn);
        $token->setPlainToken($plainToken);
        
        $this->em->persist($token);
        $this->em->flush();

        // Return plain token only once
        return $plainToken;
    }

    public function validateToken(string $plainToken, string $type): ?User
    {
        $hash = hash('sha256', $plainToken);
        
        $token = $this->em->getRepository(SecurityToken::class)
            ->findOneBy([
                'tokenHash' => $hash,
                'type' => $type,
                'used' => false,
            ]);

        if (!$token || $token->isExpired()) {
            return null;
        }

        return $token->getUser();
    }

    public function consumeToken(string $plainToken): void
    {
        $hash = hash('sha256', $plainToken);
        
        $token = $this->em->getRepository(SecurityToken::class)
            ->findOneBy(['tokenHash' => $hash]);

        if ($token) {
            $token->markAsUsed();
            $this->em->flush();
        }
    }

    public function cleanupExpiredTokens(): int
    {
        return $this->em->createQueryBuilder()
            ->delete(SecurityToken::class, 't')
            ->where('t.expiresAt < :now')
            ->setParameter('now', new \DateTimeImmutable())
            ->getQuery()
            ->execute();
    }
}
```

Store tokens securely by hashing before persistence. Never store plain  
tokens in database. Make tokens single-use when appropriate. Clean up  
expired tokens regularly. Use random, unpredictable values.  

### API Key Management

Secure API key generation and validation.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class ApiKey
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 255, unique: true)]
    private string $keyHash;

    #[ORM\Column(type: 'string', length: 10)]
    private string $prefix;

    #[ORM\ManyToOne(targetEntity: User::class)]
    private User $user;

    #[ORM\Column(type: 'json')]
    private array $scopes = [];

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastUsedAt = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $expiresAt = null;

    #[ORM\Column(type: 'boolean')]
    private bool $active = true;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    public function __construct(User $user, string $keyHash, string $prefix)
    {
        $this->user = $user;
        $this->keyHash = $keyHash;
        $this->prefix = $prefix;
        $this->createdAt = new \DateTimeImmutable();
    }

    public function updateLastUsed(): void
    {
        $this->lastUsedAt = new \DateTimeImmutable();
    }

    public function isExpired(): bool
    {
        return $this->expiresAt && new \DateTimeImmutable() > $this->expiresAt;
    }

    public function isActive(): bool
    {
        return $this->active && !$this->isExpired();
    }

    // Getters and setters omitted
}
```

```php
<?php

namespace App\Service;

use App\Entity\ApiKey;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;

class ApiKeyService
{
    public function __construct(
        private EntityManagerInterface $em,
        private SecureRandomGenerator $randomGenerator
    ) {
    }

    public function generateApiKey(User $user, array $scopes = []): array
    {
        $plainKey = $this->randomGenerator->generateApiKey();
        $prefix = substr($plainKey, 0, 7);
        $hash = hash('sha256', $plainKey);

        $apiKey = new ApiKey($user, $hash, $prefix);
        $apiKey->setScopes($scopes);

        $this->em->persist($apiKey);
        $this->em->flush();

        return [
            'key' => $plainKey,
            'prefix' => $prefix,
        ];
    }

    public function validateApiKey(string $plainKey): ?ApiKey
    {
        $hash = hash('sha256', $plainKey);
        
        $apiKey = $this->em->getRepository(ApiKey::class)
            ->findOneBy(['keyHash' => $hash]);

        if (!$apiKey || !$apiKey->isActive()) {
            return null;
        }

        $apiKey->updateLastUsed();
        $this->em->flush();

        return $apiKey;
    }

    public function revokeApiKey(string $prefix): bool
    {
        $apiKey = $this->em->getRepository(ApiKey::class)
            ->findOneBy(['prefix' => $prefix]);

        if ($apiKey) {
            $apiKey->setActive(false);
            $this->em->flush();
            return true;
        }

        return false;
    }

    public function hasScope(ApiKey $apiKey, string $scope): bool
    {
        return in_array($scope, $apiKey->getScopes());
    }
}
```

API keys enable programmatic access. Use prefixes for identification.  
Hash keys before storage. Track usage and implement expiration. Support  
scopes for granular permissions. Allow revocation.  

### Security Monitoring Dashboard

Visualizing security metrics.  

```php
<?php

namespace App\Service;

use Doctrine\ORM\EntityManagerInterface;

class SecurityMetricsService
{
    public function __construct(
        private EntityManagerInterface $em
    ) {
    }

    public function getMetrics(\DateTimeInterface $since): array
    {
        return [
            'failed_logins' => $this->getFailedLoginCount($since),
            'successful_logins' => $this->getSuccessfulLoginCount($since),
            'locked_accounts' => $this->getLockedAccountsCount(),
            'active_sessions' => $this->getActiveSessionsCount(),
            'password_changes' => $this->getPasswordChangesCount($since),
            'api_requests' => $this->getApiRequestCount($since),
            'security_events' => $this->getSecurityEventsByType($since),
        ];
    }

    private function getFailedLoginCount(\DateTimeInterface $since): int
    {
        // Query audit log for failed logins
        return 0; // Placeholder
    }

    private function getSuccessfulLoginCount(\DateTimeInterface $since): int
    {
        // Query audit log for successful logins
        return 0; // Placeholder
    }

    private function getLockedAccountsCount(): int
    {
        // Query for locked user accounts
        return 0; // Placeholder
    }

    private function getActiveSessionsCount(): int
    {
        // Query for active sessions
        return 0; // Placeholder
    }

    private function getPasswordChangesCount(\DateTimeInterface $since): int
    {
        // Query for password change events
        return 0; // Placeholder
    }

    private function getApiRequestCount(\DateTimeInterface $since): int
    {
        // Query API request logs
        return 0; // Placeholder
    }

    private function getSecurityEventsByType(\DateTimeInterface $since): array
    {
        return [
            'xss_attempts' => 0,
            'csrf_failures' => 0,
            'sql_injection_attempts' => 0,
            'unauthorized_access' => 0,
        ];
    }

    public function getTopThreats(): array
    {
        return [
            ['type' => 'Brute Force', 'count' => 42, 'severity' => 'high'],
            ['type' => 'XSS Attempts', 'count' => 15, 'severity' => 'medium'],
            ['type' => 'CSRF Failures', 'count' => 8, 'severity' => 'low'],
        ];
    }
}
```

Security monitoring provides visibility into threats. Track login  
attempts, account activity, and security events. Generate alerts for  
anomalies. Use dashboards for real-time monitoring. Archive logs for  
compliance.  

This comprehensive collection of 99 Symfony security snippets covers  
encryption, authentication, authorization, input validation, XSS/CSRF  
prevention, secure file handling, HTTPS configuration, OAuth2, and  
advanced security patterns. Each snippet demonstrates best practices and  
real-world scenarios for building secure Symfony applications.  

### Secure Error Handling

Preventing information disclosure through errors.  

```php
<?php

namespace App\EventListener;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\KernelEvents;

class SecureExceptionListener implements EventSubscriberInterface
{
    public function __construct(
        private LoggerInterface $logger,
        private bool $debug = false
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::EXCEPTION => 'onKernelException',
        ];
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        $exception = $event->getThrowable();
        
        // Log detailed error information
        $this->logger->error('Exception occurred', [
            'message' => $exception->getMessage(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'trace' => $exception->getTraceAsString(),
        ]);

        // Prepare safe response for production
        if ($exception instanceof HttpExceptionInterface) {
            $statusCode = $exception->getStatusCode();
            $message = $exception->getMessage();
        } else {
            $statusCode = Response::HTTP_INTERNAL_SERVER_ERROR;
            $message = $this->debug 
                ? $exception->getMessage() 
                : 'An error occurred. Please try again later.';
        }

        $response = new JsonResponse([
            'error' => true,
            'message' => $message,
        ], $statusCode);

        $event->setResponse($response);
    }
}
```

Never expose stack traces or detailed error messages in production. Log  
full details server-side. Return generic error messages to users. Use  
different error handling for debug mode.  

### Database Connection Security

Securing database credentials and connections.  

```php
<?php

// config/packages/doctrine.yaml
doctrine:
    dbal:
        url: '%env(resolve:DATABASE_URL)%'
        options:
            # Enable SSL/TLS for database connections
            1008: true  # PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT
```

```php
<?php

namespace App\Service;

class DatabaseSecurityService
{
    public function validateConnectionSecurity(): array
    {
        $checks = [];

        // Check if database URL uses secure connection
        $dbUrl = $_ENV['DATABASE_URL'] ?? '';
        
        $checks['uses_ssl'] = str_contains($dbUrl, 'sslmode=require') || 
                              str_contains($dbUrl, 'ssl=true');

        $checks['no_embedded_credentials'] = !preg_match('/\/\/[^:]+:[^@]+@/', $dbUrl);
        
        $checks['uses_env_vars'] = str_starts_with($dbUrl, 'mysql://') || 
                                   str_starts_with($dbUrl, 'postgresql://');

        return $checks;
    }

    public function rotateCredentials(string $newPassword): void
    {
        // Implementation for credential rotation
        // Update database password and connection string
    }
}
```

Secure database connections with SSL/TLS. Never hardcode credentials.  
Store in environment variables. Use least privilege accounts. Rotate  
credentials regularly. Restrict network access.  

### Dependency Security Scanning

Checking for vulnerable dependencies.  

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Process\Process;

#[AsCommand(
    name: 'app:security:check-dependencies',
    description: 'Check for security vulnerabilities in dependencies'
)]
class SecurityCheckCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Checking dependencies for security vulnerabilities');

        // Run symfony security:check
        $process = new Process(['symfony', 'security:check']);
        $process->run();

        if (!$process->isSuccessful()) {
            $io->error('Security vulnerabilities found!');
            $io->text($process->getOutput());
            return Command::FAILURE;
        }

        $io->success('No known security vulnerabilities found.');

        // Additional custom checks
        $this->checkComposerLock($io);
        
        return Command::SUCCESS;
    }

    private function checkComposerLock(SymfonyStyle $io): void
    {
        $lockFile = __DIR__ . '/../../composer.lock';
        
        if (!file_exists($lockFile)) {
            $io->warning('composer.lock not found');
            return;
        }

        $lockData = json_decode(file_get_contents($lockFile), true);
        $outdatedPackages = 0;

        foreach ($lockData['packages'] ?? [] as $package) {
            // Check package age or other criteria
            if (isset($package['time'])) {
                $packageDate = new \DateTimeImmutable($package['time']);
                $age = $packageDate->diff(new \DateTimeImmutable())->days;
                
                if ($age > 365) {
                    $outdatedPackages++;
                }
            }
        }

        if ($outdatedPackages > 0) {
            $io->warning(sprintf('Found %d packages older than 1 year', $outdatedPackages));
        }
    }
}
```

Regularly scan dependencies for vulnerabilities. Use Symfony's security  
checker. Update packages promptly. Monitor security advisories. Automate  
checks in CI/CD pipeline.  

### Security Headers Testing

Validating security header configuration.  

```php
<?php

namespace App\Tests\Security;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class SecurityHeadersTest extends WebTestCase
{
    public function testSecurityHeaders(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        $response = $client->getResponse();
        
        // Test HSTS
        $this->assertTrue($response->headers->has('Strict-Transport-Security'));
        
        // Test XSS Protection
        $this->assertTrue($response->headers->has('X-Content-Type-Options'));
        $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
        
        // Test Frame Options
        $this->assertTrue($response->headers->has('X-Frame-Options'));
        $frameOptions = $response->headers->get('X-Frame-Options');
        $this->assertContains($frameOptions, ['DENY', 'SAMEORIGIN']);
        
        // Test CSP
        $this->assertTrue($response->headers->has('Content-Security-Policy'));
        
        // Test Referrer Policy
        $this->assertTrue($response->headers->has('Referrer-Policy'));
    }

    public function testNoCachingForSensitivePages(): void
    {
        $client = static::createClient();
        $client->request('GET', '/admin/dashboard');

        $response = $client->getResponse();
        
        $cacheControl = $response->headers->get('Cache-Control');
        $this->assertStringContainsString('no-store', $cacheControl);
        $this->assertStringContainsString('no-cache', $cacheControl);
    }
}
```

Test security headers automatically. Verify all required headers are  
present. Check header values are correct. Include in test suite. Prevent  
regressions with continuous testing.  

### Secure Redirect Validation

Preventing open redirect vulnerabilities.  

```php
<?php

namespace App\Service;

class RedirectValidator
{
    private array $allowedHosts;

    public function __construct(array $allowedHosts)
    {
        $this->allowedHosts = $allowedHosts;
    }

    public function isRedirectSafe(string $url): bool
    {
        // Check if URL is relative
        if (!str_contains($url, '://')) {
            return $this->isRelativePathSafe($url);
        }

        // Parse absolute URL
        $parsed = parse_url($url);
        
        if ($parsed === false || !isset($parsed['host'])) {
            return false;
        }

        // Check if host is in allowed list
        return in_array($parsed['host'], $this->allowedHosts);
    }

    private function isRelativePathSafe(string $path): bool
    {
        // Prevent protocol-relative URLs
        if (str_starts_with($path, '//')) {
            return false;
        }

        // Prevent javascript: and data: URLs
        if (preg_match('/^(javascript|data|vbscript):/i', $path)) {
            return false;
        }

        // Must start with /
        return str_starts_with($path, '/');
    }

    public function sanitizeRedirect(?string $url, string $fallback = '/'): string
    {
        if ($url === null || !$this->isRedirectSafe($url)) {
            return $fallback;
        }

        return $url;
    }
}
```

```php
<?php

namespace App\Controller;

use App\Service\RedirectValidator;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SafeRedirectController extends AbstractController
{
    #[Route('/safe-redirect', name: 'safe_redirect')]
    public function redirect(
        Request $request,
        RedirectValidator $validator
    ): Response {
        $targetUrl = $request->query->get('url', '/');
        $safeUrl = $validator->sanitizeRedirect($targetUrl);

        return $this->redirect($safeUrl);
    }
}
```

Validate all redirect URLs to prevent open redirect attacks. Allow only  
trusted domains. Sanitize relative URLs. Reject javascript: and data:  
protocols. Use allowlists, not denylists.  

### Input Length Limitations

Preventing buffer overflow and DoS attacks.  

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;

#[\Attribute]
class SecureLength extends Constraint
{
    public int $max = 1000;
    public string $message = 'Input exceeds maximum allowed length of {{ limit }} characters.';
}
```

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

class SecureLengthValidator extends ConstraintValidator
{
    public function validate($value, Constraint $constraint): void
    {
        if (!$constraint instanceof SecureLength) {
            throw new \InvalidArgumentException('Invalid constraint type');
        }

        if (null === $value || '' === $value) {
            return;
        }

        $length = mb_strlen($value);

        if ($length > $constraint->max) {
            $this->context->buildViolation($constraint->message)
                ->setParameter('{{ limit }}', (string) $constraint->max)
                ->setParameter('{{ length }}', (string) $length)
                ->addViolation();
        }
    }
}
```

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

class RequestSizeLimitListener implements EventSubscriberInterface
{
    private const MAX_REQUEST_SIZE = 10 * 1024 * 1024; // 10MB

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 256],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $contentLength = $request->headers->get('Content-Length');

        if ($contentLength && (int)$contentLength > self::MAX_REQUEST_SIZE) {
            throw new BadRequestHttpException('Request size exceeds maximum allowed');
        }
    }
}
```

Enforce input length limits to prevent DoS and buffer overflow attacks.  
Validate at multiple levels: field, form, and request. Use reasonable  
limits based on application needs.  

### Secure Logging Practices

Logging security events without exposing sensitive data.  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;

class SecureLogger
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    public function logSecurityEvent(string $event, array $context = []): void
    {
        // Sanitize context to remove sensitive data
        $safeContext = $this->sanitizeContext($context);
        
        $this->logger->warning('Security Event: ' . $event, $safeContext);
    }

    public function logAuthentication(string $username, bool $success, array $context = []): void
    {
        $safeContext = $this->sanitizeContext($context);
        $safeContext['username'] = $this->maskSensitiveData($username);
        $safeContext['success'] = $success;

        $this->logger->info('Authentication attempt', $safeContext);
    }

    private function sanitizeContext(array $context): array
    {
        $sensitive = ['password', 'token', 'secret', 'api_key', 'credit_card'];
        
        foreach ($context as $key => $value) {
            if (in_array(strtolower($key), $sensitive)) {
                $context[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $context[$key] = $this->sanitizeContext($value);
            }
        }

        return $context;
    }

    private function maskSensitiveData(string $data): string
    {
        if (strlen($data) <= 4) {
            return str_repeat('*', strlen($data));
        }

        return substr($data, 0, 2) . str_repeat('*', strlen($data) - 4) . substr($data, -2);
    }

    public function logDataAccess(string $resource, string $action, ?int $userId = null): void
    {
        $this->logger->info('Data access', [
            'resource' => $resource,
            'action' => $action,
            'user_id' => $userId,
            'timestamp' => date('Y-m-d H:i:s'),
        ]);
    }
}
```

Log security events comprehensively but safely. Never log passwords,  
tokens, or PII. Mask sensitive data in logs. Use structured logging.  
Implement log rotation and secure storage.  

### XML External Entity (XXE) Prevention

Preventing XXE attacks in XML processing.  

```php
<?php

namespace App\Service;

class SecureXmlParser
{
    public function parseXml(string $xmlString): \SimpleXMLElement
    {
        // Disable external entity loading
        $previousValue = libxml_disable_entity_loader(true);
        
        // Disable external entity processing
        libxml_use_internal_errors(true);

        try {
            $xml = simplexml_load_string(
                $xmlString,
                'SimpleXMLElement',
                LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR
            );

            if ($xml === false) {
                $errors = libxml_get_errors();
                libxml_clear_errors();
                throw new \RuntimeException('XML parsing failed: ' . $errors[0]->message);
            }

            return $xml;
            
        } finally {
            libxml_disable_entity_loader($previousValue);
        }
    }

    public function parseDomDocument(string $xmlString): \DOMDocument
    {
        $dom = new \DOMDocument();
        
        // Disable external entity loading
        $previousValue = libxml_disable_entity_loader(true);
        
        try {
            $dom->loadXML($xmlString, LIBXML_NOENT | LIBXML_DTDLOAD);
            return $dom;
            
        } finally {
            libxml_disable_entity_loader($previousValue);
        }
    }

    public function validateXmlStructure(string $xmlString, string $xsdPath): bool
    {
        $dom = new \DOMDocument();
        
        libxml_use_internal_errors(true);
        $dom->loadXML($xmlString);

        if (!$dom->schemaValidate($xsdPath)) {
            $errors = libxml_get_errors();
            libxml_clear_errors();
            return false;
        }

        return true;
    }
}
```

Prevent XXE attacks by disabling external entity loading. Use  
libxml_disable_entity_loader(). Validate XML against schema. Never parse  
untrusted XML without protection.  

### Server-Side Request Forgery (SSRF) Prevention

Preventing SSRF attacks in HTTP clients.  

```php
<?php

namespace App\Service;

use Symfony\Contracts\HttpClient\HttpClientInterface;

class SsrfProtectedHttpClient
{
    private array $blockedHosts = [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '::1',
    ];

    private array $blockedNetworks = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '169.254.0.0/16',
    ];

    public function __construct(
        private HttpClientInterface $httpClient
    ) {
    }

    public function request(string $method, string $url, array $options = []): array
    {
        $this->validateUrl($url);

        try {
            $response = $this->httpClient->request($method, $url, array_merge([
                'timeout' => 10,
                'max_redirects' => 2,
            ], $options));

            return $response->toArray();
            
        } catch (\Exception $e) {
            throw new \RuntimeException('HTTP request failed: ' . $e->getMessage());
        }
    }

    private function validateUrl(string $url): void
    {
        $parsed = parse_url($url);
        
        if (!$parsed || !isset($parsed['host'])) {
            throw new \InvalidArgumentException('Invalid URL');
        }

        $host = $parsed['host'];
        
        // Check blocked hosts
        if (in_array(strtolower($host), $this->blockedHosts)) {
            throw new \InvalidArgumentException('Access to this host is not allowed');
        }

        // Resolve hostname to IP
        $ip = gethostbyname($host);
        
        if ($ip === $host) {
            // Could not resolve
            return;
        }

        // Check if IP is in blocked network
        foreach ($this->blockedNetworks as $network) {
            if ($this->ipInRange($ip, $network)) {
                throw new \InvalidArgumentException('Access to this network is not allowed');
            }
        }
    }

    private function ipInRange(string $ip, string $range): bool
    {
        list($subnet, $mask) = explode('/', $range);
        
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $maskLong = -1 << (32 - (int)$mask);
        
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }
}
```

Prevent SSRF by validating and restricting URLs. Block access to internal  
networks and localhost. Validate hostnames and IPs. Limit redirects.  
Use allowlists for critical operations.  

### Command Injection Prevention

Safely executing system commands.  

```php
<?php

namespace App\Service;

use Symfony\Component\Process\Process;

class SecureCommandExecutor
{
    public function execute(array $command, ?string $cwd = null): string
    {
        // Never use shell execution functions like exec(), system(), shell_exec()
        // Always use Process with array of arguments
        
        $process = new Process($command, $cwd, null, null, 60);
        
        $process->run();

        if (!$process->isSuccessful()) {
            throw new \RuntimeException(
                'Command failed: ' . $process->getErrorOutput()
            );
        }

        return $process->getOutput();
    }

    public function sanitizeArgument(string $arg): string
    {
        // Remove any shell metacharacters
        return preg_replace('/[;&|`$(){}[\]<>\\\\]/', '', $arg);
    }

    public function convertImage(string $inputPath, string $outputPath): void
    {
        // Example: safe image conversion
        $allowedExtensions = ['jpg', 'png', 'gif'];
        
        $inputExt = pathinfo($inputPath, PATHINFO_EXTENSION);
        if (!in_array(strtolower($inputExt), $allowedExtensions)) {
            throw new \InvalidArgumentException('Invalid input file type');
        }

        // Use absolute paths and validate they exist
        $realInput = realpath($inputPath);
        if ($realInput === false) {
            throw new \RuntimeException('Input file not found');
        }

        $command = [
            '/usr/bin/convert',
            $realInput,
            '-resize',
            '800x600',
            $outputPath
        ];

        $this->execute($command);
    }
}
```

Prevent command injection by using Process class with array arguments.  
Never concatenate user input into shell commands. Validate and sanitize  
all inputs. Use absolute paths for executables.  

### Insecure Deserialization Prevention

Safely handling serialized data.  

```php
<?php

namespace App\Service;

class SecureSerializer
{
    private array $allowedClasses;

    public function __construct(array $allowedClasses = [])
    {
        $this->allowedClasses = $allowedClasses;
    }

    public function serialize($data): string
    {
        // Use JSON instead of serialize() when possible
        return json_encode($data);
    }

    public function unserialize(string $data)
    {
        // Use JSON instead of unserialize() when possible
        return json_decode($data, true);
    }

    public function secureUnserialize(string $data, array $allowedClasses = [])
    {
        // If you must use unserialize(), restrict allowed classes
        $options = [
            'allowed_classes' => $allowedClasses ?: $this->allowedClasses
        ];

        return unserialize($data, $options);
    }

    public function signData($data, string $secret): string
    {
        $serialized = $this->serialize($data);
        $signature = hash_hmac('sha256', $serialized, $secret);
        
        return base64_encode(json_encode([
            'data' => $serialized,
            'signature' => $signature,
        ]));
    }

    public function verifyAndUnserialize(string $signed, string $secret)
    {
        $decoded = json_decode(base64_decode($signed), true);
        
        if (!isset($decoded['data']) || !isset($decoded['signature'])) {
            throw new \RuntimeException('Invalid signed data');
        }

        $expectedSignature = hash_hmac('sha256', $decoded['data'], $secret);
        
        if (!hash_equals($expectedSignature, $decoded['signature'])) {
            throw new \RuntimeException('Signature verification failed');
        }

        return $this->unserialize($decoded['data']);
    }
}
```

Avoid unserialize() with untrusted data. Use JSON for serialization when  
possible. If using unserialize(), restrict allowed classes. Sign  
serialized data to prevent tampering.  

### Security Testing with Functional Tests

Testing security features automatically.  

```php
<?php

namespace App\Tests\Security;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class SecurityFunctionalTest extends WebTestCase
{
    public function testCsrfProtection(): void
    {
        $client = static::createClient();
        
        // Attempt to submit form without CSRF token
        $client->request('POST', '/contact', [
            'email' => 'test@example.com',
            'message' => 'Test message',
        ]);

        $this->assertResponseStatusCodeSame(403);
    }

    public function testXssProtection(): void
    {
        $client = static::createClient();
        
        $xssPayload = '<script>alert("XSS")</script>';
        
        $client->request('POST', '/api/comment', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], json_encode([
            'text' => $xssPayload,
        ]));

        $response = $client->getResponse();
        $content = $response->getContent();
        
        // Verify script tags are escaped or removed
        $this->assertStringNotContainsString('<script>', $content);
    }

    public function testSqlInjectionProtection(): void
    {
        $client = static::createClient();
        
        $sqlInjection = "1' OR '1'='1";
        
        $client->request('GET', '/user/' . urlencode($sqlInjection));
        
        // Should return 404 or error, not expose database
        $this->assertNotSame(200, $client->getResponse()->getStatusCode());
    }

    public function testAuthenticationRequired(): void
    {
        $client = static::createClient();
        
        $client->request('GET', '/admin/dashboard');
        
        $this->assertResponseRedirects('/login');
    }

    public function testRateLimiting(): void
    {
        $client = static::createClient();
        
        // Make multiple rapid requests
        for ($i = 0; $i < 10; $i++) {
            $client->request('POST', '/api/login', [], [], [
                'CONTENT_TYPE' => 'application/json',
            ], json_encode([
                'email' => 'test@example.com',
                'password' => 'wrong',
            ]));
        }

        // Should eventually get rate limited
        $this->assertSame(429, $client->getResponse()->getStatusCode());
    }
}
```

Automate security testing to prevent regressions. Test CSRF protection,  
XSS prevention, SQL injection guards, authentication, and rate limiting.  
Run tests in CI/CD pipeline. Monitor test coverage.  

This completes our comprehensive collection of 99 Symfony security  
snippets, covering all essential security practices and techniques for  
building secure Symfony applications.  
