# Symfony Security

This comprehensive guide covers security fundamentals in Symfony,  
focusing on authentication and authorization. It provides 60 practical  
examples demonstrating how to secure Symfony applications, from basic  
setup to advanced security patterns.  

## Introduction

### Understanding Symfony Security Component

The Symfony Security component provides a complete security system for  
web applications.  

The Security component handles authentication (verifying user identity) and  
authorization (checking permissions). It includes firewalls for protecting  
application areas, user providers for loading users, and access control  
for managing permissions. The component integrates seamlessly with Doctrine,  
forms, and other Symfony features.  

### Security Configuration Overview

Basic security.yaml configuration structure.  

```yaml
# config/packages/security.yaml
security:
    # Password hashing configuration
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'
    
    # User providers define how to load users
    providers:
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email
    
    # Firewalls protect different parts of your application
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            lazy: true
            provider: app_user_provider
    
    # Access control rules
    access_control:
        # - { path: ^/admin, roles: ROLE_ADMIN }
```

The security.yaml file is the central configuration for security. Password  
hashers configure how passwords are encrypted. Providers define where users  
come from. Firewalls protect URL patterns. Access control rules define  
who can access which URLs.  

### Security Component Architecture

Understanding the security workflow in Symfony.  

The security process begins when a request enters a firewall. The  
authenticator attempts to extract credentials from the request. The user  
provider loads the user from storage. The password hasher verifies  
credentials. Upon success, a security token is created and stored in the  
session. Access control rules then check if the authenticated user has  
permission to access the requested resource.  

## Authentication Setup

### User Entity Implementation

Creating a secure User entity.  

```php
<?php

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: '`user`')]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 180, unique: true)]
    private ?string $email = null;

    #[ORM\Column]
    private array $roles = [];

    #[ORM\Column]
    private ?string $password = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): self
    {
        $this->email = $email;
        return $this;
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    public function getRoles(): array
    {
        $roles = $this->roles;
        $roles[] = 'ROLE_USER';
        
        return array_unique($roles);
    }

    public function setRoles(array $roles): self
    {
        $this->roles = $roles;
        return $this;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): self
    {
        $this->password = $password;
        return $this;
    }

    public function eraseCredentials(): void
    {
        // Clear temporary sensitive data
    }
}
```

The User entity must implement UserInterface for authentication.  
PasswordAuthenticatedUserInterface is required for password-based  
authentication. getUserIdentifier() returns the unique user identifier.  
getRoles() always includes ROLE_USER by default. eraseCredentials()  
removes sensitive temporary data after authentication.  

### Firewall Configuration

Configuring firewalls to protect application areas.  

```yaml
# config/packages/security.yaml
security:
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        
        api:
            pattern: ^/api
            stateless: true
            provider: app_user_provider
        
        main:
            pattern: ^/
            lazy: true
            provider: app_user_provider
            
            form_login:
                login_path: app_login
                check_path: app_login
                default_target_path: app_dashboard
                enable_csrf: true
            
            logout:
                path: app_logout
                target: app_home
            
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800
                path: /
                always_remember_me: false
```

Firewalls are evaluated in order from top to bottom. The dev firewall  
disables security for development tools. API firewall uses stateless  
authentication without sessions. Main firewall handles form-based login  
with CSRF protection. Remember me provides persistent authentication.  
Lazy loading delays authentication until needed.  

### User Provider Configuration

Configuring how users are loaded from storage.  

```yaml
# config/packages/security.yaml
security:
    providers:
        # Entity provider loads users from database
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email
        
        # Memory provider for testing
        in_memory:
            memory:
                users:
                    admin:
                        password: '$2y$13$hashed_password'
                        roles: ['ROLE_ADMIN']
        
        # Chain provider tries multiple providers
        chain_provider:
            chain:
                providers: ['app_user_provider', 'in_memory']
```

User providers define how to load user objects. Entity providers load  
from database using Doctrine. Memory providers store users in configuration  
(useful for testing). Chain providers try multiple providers in sequence.  
The property defines which field to use for lookup (usually email or  
username).  

### Custom User Provider

Creating a custom user provider for advanced scenarios.  

```php
<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class CustomUserProvider implements UserProviderInterface, PasswordUpgraderInterface
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
                sprintf('User "%s" not found.', $identifier)
            );
        }
        
        if (!$user->isActive()) {
            throw new UserNotFoundException('User account is disabled.');
        }
        
        return $user;
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(
                sprintf('Invalid user class "%s".', get_class($user))
            );
        }
        
        return $this->loadUserByIdentifier($user->getUserIdentifier());
    }

    public function supportsClass(string $class): bool
    {
        return User::class === $class || is_subclass_of($class, User::class);
    }

    public function upgradePassword(
        PasswordAuthenticatedUserInterface $user,
        string $newHashedPassword
    ): void {
        if (!$user instanceof User) {
            return;
        }
        
        $user->setPassword($newHashedPassword);
        $this->userRepository->save($user, true);
    }
}
```

Custom user providers allow loading users with custom logic. Implement  
loadUserByIdentifier() to load users by their identifier. refreshUser()  
reloads user data from storage. upgradePassword() rehashes passwords when  
the hashing algorithm changes. Add custom validation like checking if  
the account is active.  

## Form Login Authentication

### Login Controller

Implementing form-based login.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    #[Route('/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_dashboard');
        }
        
        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException(
            'This should never be reached. Logout is handled by the security system.'
        );
    }
}
```

The login action displays the login form. AuthenticationUtils provides  
error messages and the last attempted username. Redirect already  
authenticated users to prevent accessing the login page. The logout  
action is intercepted by Symfony's security system and never executed.  

### Login Form Template

Creating a secure login form with CSRF protection.  

```twig
{# templates/security/login.html.twig #}
{% extends 'base.html.twig' %}

{% block title %}Log in{% endblock %}

{% block body %}
<div class="login-form">
    <h1>Please sign in</h1>

    {% if error %}
        <div class="alert alert-danger">
            {{ error.messageKey|trans(error.messageData, 'security') }}
        </div>
    {% endif %}

    <form method="post">
        <div class="form-group">
            <label for="username">Email</label>
            <input type="email" 
                   id="username" 
                   name="_username" 
                   value="{{ last_username }}" 
                   required 
                   autofocus>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" 
                   id="password" 
                   name="_password" 
                   required>
        </div>

        <input type="hidden" 
               name="_csrf_token" 
               value="{{ csrf_token('authenticate') }}">

        <div class="form-check">
            <input type="checkbox" 
                   id="remember_me" 
                   name="_remember_me">
            <label for="remember_me">Remember me</label>
        </div>

        <button type="submit">Sign in</button>
    </form>

    <p>
        Don't have an account? <a href="{{ path('app_register') }}">Register here</a>
    </p>
</div>
{% endblock %}
```

The form uses standard field names (_username, _password, _csrf_token).  
CSRF tokens protect against cross-site request forgery. The remember_me  
checkbox enables persistent authentication. Error messages are translated  
for internationalization. Preserve the last username for better user  
experience.  

### Registration Controller

Implementing user registration with password hashing.  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\RegistrationFormType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

class RegistrationController extends AbstractController
{
    #[Route('/register', name: 'app_register')]
    public function register(
        Request $request,
        UserPasswordHasherInterface $passwordHasher,
        EntityManagerInterface $entityManager
    ): Response {
        $user = new User();
        $form = $this->createForm(RegistrationFormType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $hashedPassword = $passwordHasher->hashPassword(
                $user,
                $form->get('plainPassword')->getData()
            );
            $user->setPassword($hashedPassword);
            $user->setRoles(['ROLE_USER']);

            $entityManager->persist($user);
            $entityManager->flush();

            return $this->redirectToRoute('app_login');
        }

        return $this->render('registration/register.html.twig', [
            'registrationForm' => $form,
        ]);
    }
}
```

Never store plain-text passwords. Use UserPasswordHasherInterface to  
hash passwords securely. The hasher automatically uses the configured  
algorithm (bcrypt by default). Extract the plain password from the form  
before hashing. Set default roles for new users. Always persist new  
entities before flushing.  

### Registration Form Type

Creating a registration form with password validation.  

```php
<?php

namespace App\Form;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\IsTrue;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class RegistrationFormType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('email', EmailType::class, [
                'constraints' => [
                    new NotBlank([
                        'message' => 'Please enter an email address',
                    ]),
                ],
            ])
            ->add('plainPassword', RepeatedType::class, [
                'type' => PasswordType::class,
                'mapped' => false,
                'first_options' => [
                    'label' => 'Password',
                    'attr' => ['autocomplete' => 'new-password'],
                ],
                'second_options' => [
                    'label' => 'Confirm Password',
                    'attr' => ['autocomplete' => 'new-password'],
                ],
                'constraints' => [
                    new NotBlank([
                        'message' => 'Please enter a password',
                    ]),
                    new Length([
                        'min' => 8,
                        'minMessage' => 'Your password must be at least {{ limit }} characters',
                        'max' => 4096,
                    ]),
                ],
            ])
            ->add('agreeTerms', CheckboxType::class, [
                'mapped' => false,
                'constraints' => [
                    new IsTrue([
                        'message' => 'You must agree to the terms and conditions.',
                    ]),
                ],
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => User::class,
        ]);
    }
}
```

Use RepeatedType for password confirmation. Set mapped to false for  
fields not directly stored in the entity. Add autocomplete attributes  
for better browser integration. Enforce minimum password length and  
other constraints. Use checkboxes for terms acceptance. Provide  
clear validation messages.  

### Custom Form Login Authenticator

Creating a custom authenticator for form login.  

```php
<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class LoginFormAuthenticator extends AbstractLoginFormAuthenticator
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'app_login';

    public function __construct(
        private UrlGeneratorInterface $urlGenerator
    ) {
    }

    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('_username', '');
        
        $request->getSession()->set(SecurityRequestAttributes::LAST_USERNAME, $email);

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($request->request->get('_password', '')),
            [
                new CsrfTokenBadge('authenticate', $request->request->get('_csrf_token')),
                new RememberMeBadge(),
            ]
        );
    }

    public function onAuthenticationSuccess(
        Request $request,
        TokenInterface $token,
        string $firewallName
    ): ?Response {
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('app_dashboard'));
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}
```

Custom authenticators provide full control over the authentication  
process. Passport contains user badge, credentials, and security badges.  
CsrfTokenBadge validates CSRF tokens. RememberMeBadge enables remember  
me functionality. Store last username in session for display on errors.  
Redirect to target path or default dashboard on success.  

## HTTP Basic Authentication

### HTTP Basic Auth Configuration

Configuring HTTP Basic authentication for APIs.  

```yaml
# config/packages/security.yaml
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            http_basic:
                realm: 'Secured API'
```

HTTP Basic sends credentials with each request using Authorization  
header. It's simple but requires HTTPS in production. Stateless means  
no session is created. The realm identifies the protected area. Browsers  
show a login dialog automatically.  

### HTTP Basic Custom Authenticator

Implementing custom HTTP Basic authentication.  

```php
<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

class HttpBasicAuthenticator extends AbstractAuthenticator
{
    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization') &&
               str_starts_with($request->headers->get('Authorization'), 'Basic ');
    }

    public function authenticate(Request $request): Passport
    {
        $authHeader = $request->headers->get('Authorization');
        $credentials = base64_decode(substr($authHeader, 6));
        [$identifier, $password] = explode(':', $credentials, 2);

        return new Passport(
            new UserBadge($identifier),
            new PasswordCredentials($password)
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
        return new Response(
            'Authentication required',
            Response::HTTP_UNAUTHORIZED,
            ['WWW-Authenticate' => 'Basic realm="Secured API"']
        );
    }
}
```

Check for Basic Authorization header in supports(). Decode base64  
credentials and split by colon. Return WWW-Authenticate header on  
failure to trigger browser dialog. Return null on success to continue  
the request. Use HTTPS to protect credentials in transit.  

## JWT Authentication

### JWT Service Implementation

Creating a service for JWT token generation and validation.  

```php
<?php

namespace App\Service;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtService
{
    private string $secretKey;
    private string $algorithm = 'HS256';
    private int $expirationTime = 3600;

    public function __construct(string $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    public function generateToken(int $userId, string $email, array $roles = []): string
    {
        $issuedAt = time();
        $expirationTime = $issuedAt + $this->expirationTime;

        $payload = [
            'iat' => $issuedAt,
            'exp' => $expirationTime,
            'user_id' => $userId,
            'email' => $email,
            'roles' => $roles,
        ];

        return JWT::encode($payload, $this->secretKey, $this->algorithm);
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

    public function refreshToken(string $token): ?string
    {
        $payload = $this->validateToken($token);
        
        if (!$payload) {
            return null;
        }

        return $this->generateToken(
            $payload['user_id'],
            $payload['email'],
            $payload['roles']
        );
    }
}
```

JWT provides stateless authentication without sessions. Include user ID,  
email, roles, and expiration in the payload. Use a strong secret key  
stored in environment variables. Validate tokens by checking signature  
and expiration. Provide refresh functionality for extending sessions.  

### JWT Authenticator

Implementing JWT authentication for APIs.  

```php
<?php

namespace App\Security;

use App\Repository\UserRepository;
use App\Service\JwtService;
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
        return $request->headers->has('Authorization') &&
               str_starts_with($request->headers->get('Authorization'), 'Bearer ');
    }

    public function authenticate(Request $request): Passport
    {
        $authHeader = $request->headers->get('Authorization');
        $token = substr($authHeader, 7);

        if (!$token) {
            throw new AuthenticationException('No token provided');
        }

        return new SelfValidatingPassport(
            new UserBadge($token, function($token) {
                $payload = $this->jwtService->validateToken($token);
                
                if (!$payload) {
                    throw new AuthenticationException('Invalid token');
                }

                $user = $this->userRepository->find($payload['user_id']);
                
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

Check for Bearer token in Authorization header. Extract token and  
validate using JwtService. Use SelfValidatingPassport since JWT  
validation proves identity. Load user from database using user ID  
from token. Return JSON error responses for API consistency.  

### JWT Login Endpoint

Creating an endpoint to issue JWT tokens.  

```php
<?php

namespace App\Controller;

use App\Repository\UserRepository;
use App\Service\JwtService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

class AuthApiController extends AbstractController
{
    #[Route('/api/login', name: 'api_login', methods: ['POST'])]
    public function login(
        Request $request,
        UserRepository $userRepository,
        UserPasswordHasherInterface $passwordHasher,
        JwtService $jwtService
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        
        if (!isset($data['email']) || !isset($data['password'])) {
            return $this->json([
                'error' => 'Email and password required'
            ], Response::HTTP_BAD_REQUEST);
        }

        $user = $userRepository->findOneBy(['email' => $data['email']]);

        if (!$user || !$passwordHasher->isPasswordValid($user, $data['password'])) {
            return $this->json([
                'error' => 'Invalid credentials'
            ], Response::HTTP_UNAUTHORIZED);
        }

        $token = $jwtService->generateToken(
            $user->getId(),
            $user->getEmail(),
            $user->getRoles()
        );

        return $this->json([
            'token' => $token,
            'user' => [
                'id' => $user->getId(),
                'email' => $user->getEmail(),
                'roles' => $user->getRoles(),
            ]
        ]);
    }

    #[Route('/api/refresh', name: 'api_refresh', methods: ['POST'])]
    public function refresh(Request $request, JwtService $jwtService): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $oldToken = $data['token'] ?? '';

        $newToken = $jwtService->refreshToken($oldToken);

        if (!$newToken) {
            return $this->json([
                'error' => 'Invalid or expired token'
            ], Response::HTTP_UNAUTHORIZED);
        }

        return $this->json(['token' => $newToken]);
    }
}
```

Accept email and password as JSON. Validate credentials using the  
password hasher. Generate JWT with user information on successful  
authentication. Return both token and user data. Provide refresh  
endpoint for token renewal. Use appropriate HTTP status codes.  

## Authorization and Access Control

### Role-Based Access Control

Implementing hierarchical role-based authorization.  

```yaml
# config/packages/security.yaml
security:
    role_hierarchy:
        ROLE_ADMIN: [ROLE_USER, ROLE_EDITOR]
        ROLE_SUPER_ADMIN: [ROLE_ADMIN, ROLE_ALLOWED_TO_SWITCH]
        ROLE_EDITOR: ROLE_USER
    
    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN }
        - { path: ^/api, roles: ROLE_USER }
        - { path: ^/editor, roles: ROLE_EDITOR }
```

Role hierarchy automatically grants child roles to parent roles. Users  
with ROLE_ADMIN automatically have ROLE_USER and ROLE_EDITOR. Access  
control rules are evaluated in order. First matching rule applies.  
Use regular expressions for complex path patterns.  

### Controller Security with Attributes

Securing controller actions using attributes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class AdminController extends AbstractController
{
    #[Route('/admin', name: 'admin_dashboard')]
    #[IsGranted('ROLE_ADMIN')]
    public function dashboard(): Response
    {
        return $this->render('admin/dashboard.html.twig');
    }

    #[Route('/admin/users', name: 'admin_users')]
    #[IsGranted('ROLE_ADMIN')]
    public function users(): Response
    {
        return $this->render('admin/users.html.twig');
    }

    #[Route('/admin/settings', name: 'admin_settings')]
    #[IsGranted('ROLE_SUPER_ADMIN')]
    public function settings(): Response
    {
        return $this->render('admin/settings.html.twig');
    }
}
```

IsGranted attribute checks permissions before executing the action.  
Throws AccessDeniedException if user lacks required role. More  
convenient than manual checks. Can be applied to entire classes or  
individual methods. Supports role hierarchy automatically.  

### Manual Security Checks

Performing security checks programmatically in controllers.  

```php
<?php

namespace App\Controller;

use App\Entity\Post;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

class PostController extends AbstractController
{
    #[Route('/post/{id}/edit', name: 'post_edit')]
    public function edit(Post $post): Response
    {
        // Check if user is logged in
        if (!$this->getUser()) {
            throw $this->createAccessDeniedException('You must be logged in.');
        }

        // Check for specific role
        $this->denyAccessUnlessGranted('ROLE_EDITOR');

        // Check using custom permission
        if (!$this->isGranted('EDIT', $post)) {
            throw new AccessDeniedException('You cannot edit this post.');
        }

        // Check ownership
        if ($post->getAuthor() !== $this->getUser()) {
            $this->denyAccessUnlessGranted('ROLE_ADMIN');
        }

        return $this->render('post/edit.html.twig', ['post' => $post]);
    }

    #[Route('/post/{id}/delete', name: 'post_delete')]
    public function delete(Post $post): Response
    {
        // Multiple conditions
        if (!$this->isGranted('DELETE', $post) && 
            !$this->isGranted('ROLE_ADMIN')) {
            throw $this->createAccessDeniedException();
        }

        // Delete logic here

        return $this->redirectToRoute('post_list');
    }
}
```

Use getUser() to check authentication. denyAccessUnlessGranted() throws  
exception if permission is denied. isGranted() returns boolean for  
conditional logic. createAccessDeniedException() creates proper exception.  
Combine role checks with custom permissions using voters.  

### Security Voters

Implementing custom authorization logic with voters.  

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

    protected function supports(string $attribute, mixed $subject): bool
    {
        if (!in_array($attribute, [self::VIEW, self::EDIT, self::DELETE])) {
            return false;
        }

        if (!$subject instanceof Post) {
            return false;
        }

        return true;
    }

    protected function voteOnAttribute(
        string $attribute,
        mixed $subject,
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
        if ($post->isPublished()) {
            return true;
        }

        return $this->canEdit($post, $user);
    }

    private function canEdit(Post $post, User $user): bool
    {
        return $user === $post->getAuthor();
    }

    private function canDelete(Post $post, User $user): bool
    {
        if (in_array('ROLE_ADMIN', $user->getRoles())) {
            return true;
        }

        return $user === $post->getAuthor();
    }
}
```

Voters implement fine-grained access control based on object state.  
supports() determines if voter handles the permission check.  
voteOnAttribute() contains the authorization logic. Separate methods  
for each permission improve readability. Check object state and user  
properties to make decisions.  

### Advanced Voter with Multiple Conditions

Complex voter with business logic.  

```php
<?php

namespace App\Security\Voter;

use App\Entity\Document;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\Security;

class DocumentVoter extends Voter
{
    public const VIEW = 'VIEW';
    public const EDIT = 'EDIT';
    public const SHARE = 'SHARE';
    public const DELETE = 'DELETE';

    public function __construct(
        private Security $security
    ) {
    }

    protected function supports(string $attribute, mixed $subject): bool
    {
        return $subject instanceof Document && 
               in_array($attribute, [self::VIEW, self::EDIT, self::SHARE, self::DELETE]);
    }

    protected function voteOnAttribute(
        string $attribute,
        mixed $subject,
        TokenInterface $token
    ): bool {
        $user = $token->getUser();

        if (!$user instanceof User) {
            return false;
        }

        /** @var Document $document */
        $document = $subject;

        // Admins can do anything
        if ($this->security->isGranted('ROLE_ADMIN')) {
            return true;
        }

        return match($attribute) {
            self::VIEW => $this->canView($document, $user),
            self::EDIT => $this->canEdit($document, $user),
            self::SHARE => $this->canShare($document, $user),
            self::DELETE => $this->canDelete($document, $user),
            default => false,
        };
    }

    private function canView(Document $document, User $user): bool
    {
        // Owner can view
        if ($document->getOwner() === $user) {
            return true;
        }

        // Shared users can view
        if ($document->getSharedWith()->contains($user)) {
            return true;
        }

        // Department members can view department documents
        if ($document->getDepartment() === $user->getDepartment() && 
            $document->isVisibleToDepartment()) {
            return true;
        }

        return false;
    }

    private function canEdit(Document $document, User $user): bool
    {
        // Only owner can edit
        if ($document->getOwner() === $user) {
            return true;
        }

        // Editors can edit if shared with edit permission
        return $document->hasEditAccess($user);
    }

    private function canShare(Document $document, User $user): bool
    {
        // Only owner can share
        return $document->getOwner() === $user;
    }

    private function canDelete(Document $document, User $user): bool
    {
        // Only owner can delete
        if ($document->getOwner() !== $user) {
            return false;
        }

        // Cannot delete if document is locked
        if ($document->isLocked()) {
            return false;
        }

        return true;
    }
}
```

Inject Security service to check roles within voter. Admins bypass  
all checks for convenience. View permission checks ownership, sharing,  
and department visibility. Edit requires ownership or explicit permission.  
Share and delete restricted to owners. Check document state like locks.  

### Template Security Checks

Checking permissions in Twig templates.  

```twig
{# templates/post/show.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
<article>
    <h1>{{ post.title }}</h1>
    <p>{{ post.content }}</p>

    <div class="post-actions">
        {% if is_granted('ROLE_USER') %}
            <a href="{{ path('post_comment', {id: post.id}) }}">
                Add Comment
            </a>
        {% endif %}

        {% if is_granted('EDIT', post) %}
            <a href="{{ path('post_edit', {id: post.id}) }}">
                Edit Post
            </a>
        {% endif %}

        {% if is_granted('DELETE', post) %}
            <a href="{{ path('post_delete', {id: post.id}) }}" 
               onclick="return confirm('Are you sure?')">
                Delete Post
            </a>
        {% endif %}

        {% if is_granted('ROLE_ADMIN') %}
            <a href="{{ path('post_moderate', {id: post.id}) }}">
                Moderate
            </a>
        {% endif %}
    </div>

    {% if app.user %}
        <p>Logged in as: {{ app.user.userIdentifier }}</p>
        
        {% if app.user.id == post.author.id %}
            <div class="author-notice">
                You are the author of this post
            </div>
        {% endif %}
    {% else %}
        <p>Please <a href="{{ path('app_login') }}">log in</a> to interact</p>
    {% endif %}
</article>
{% endblock %}
```

Use is_granted() to check permissions in templates. Pass object as  
second parameter for voter checks. Access current user via app.user.  
Show or hide UI elements based on permissions. Check authentication  
with app.user. Display conditional content for authors or admins.  


## Password Management

### Secure Password Hashing

Using Symfony's password hasher for secure storage.  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

class PasswordController extends AbstractController
{
    #[Route('/change-password', name: 'change_password')]
    public function changePassword(
        Request $request,
        UserPasswordHasherInterface $passwordHasher,
        EntityManagerInterface $em
    ): Response {
        /** @var User $user */
        $user = $this->getUser();
        
        $currentPassword = $request->request->get('current_password');
        $newPassword = $request->request->get('new_password');

        // Verify current password
        if (!$passwordHasher->isPasswordValid($user, $currentPassword)) {
            $this->addFlash('error', 'Current password is incorrect');
            return $this->redirectToRoute('user_profile');
        }

        // Hash and set new password
        $hashedPassword = $passwordHasher->hashPassword($user, $newPassword);
        $user->setPassword($hashedPassword);

        $em->flush();

        $this->addFlash('success', 'Password changed successfully');
        return $this->redirectToRoute('user_profile');
    }
}
```

Always verify the current password before allowing changes. Use  
isPasswordValid() to check existing passwords. Never compare password  
hashes directly. The hasher uses timing-safe comparisons to prevent  
timing attacks. Flash messages provide user feedback.  

### Password Reset Workflow

Implementing secure password reset functionality.  

```php
<?php

namespace App\Service;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class PasswordResetService
{
    public function __construct(
        private EntityManagerInterface $em,
        private MailerInterface $mailer,
        private UrlGeneratorInterface $urlGenerator
    ) {
    }

    public function sendResetEmail(User $user): void
    {
        $token = bin2hex(random_bytes(32));
        $expiresAt = new \DateTimeImmutable('+1 hour');

        $user->setResetToken($token);
        $user->setResetTokenExpiresAt($expiresAt);
        $this->em->flush();

        $resetUrl = $this->urlGenerator->generate(
            'password_reset_confirm',
            ['token' => $token],
            UrlGeneratorInterface::ABSOLUTE_URL
        );

        $email = (new Email())
            ->to($user->getEmail())
            ->subject('Password Reset Request')
            ->html(sprintf(
                'Click here to reset your password: <a href="%s">Reset Password</a>. This link expires in 1 hour.',
                $resetUrl
            ));

        $this->mailer->send($email);
    }

    public function validateResetToken(string $token): ?User
    {
        $user = $this->em->getRepository(User::class)
            ->findOneBy(['resetToken' => $token]);

        if (!$user || 
            !$user->getResetTokenExpiresAt() ||
            $user->getResetTokenExpiresAt() < new \DateTimeImmutable()) {
            return null;
        }

        return $user;
    }

    public function resetPassword(User $user, string $hashedPassword): void
    {
        $user->setPassword($hashedPassword);
        $user->setResetToken(null);
        $user->setResetTokenExpiresAt(null);
        $this->em->flush();
    }
}
```

Generate cryptographically secure random tokens. Set expiration time  
for security. Clear token after successful reset. Validate both token  
existence and expiration. Send reset link via email only. Never expose  
user information in error messages.  

### Password Strength Validation

Enforcing strong password requirements.  

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

class StrongPasswordValidator extends ConstraintValidator
{
    public function validate(mixed $value, Constraint $constraint): void
    {
        if (!$constraint instanceof StrongPassword) {
            throw new UnexpectedTypeException($constraint, StrongPassword::class);
        }

        if (null === $value || '' === $value) {
            return;
        }

        $password = (string) $value;

        // Check minimum length
        if (strlen($password) < 8) {
            $this->context->buildViolation($constraint->messageTooShort)
                ->addViolation();
            return;
        }

        // Check for uppercase letter
        if (!preg_match('/[A-Z]/', $password)) {
            $this->context->buildViolation($constraint->messageNoUppercase)
                ->addViolation();
        }

        // Check for lowercase letter
        if (!preg_match('/[a-z]/', $password)) {
            $this->context->buildViolation($constraint->messageNoLowercase)
                ->addViolation();
        }

        // Check for number
        if (!preg_match('/\d/', $password)) {
            $this->context->buildViolation($constraint->messageNoNumber)
                ->addViolation();
        }

        // Check for special character
        if (!preg_match('/[^a-zA-Z\d]/', $password)) {
            $this->context->buildViolation($constraint->messageNoSpecial)
                ->addViolation();
        }

        // Check for common passwords
        $commonPasswords = ['password', '12345678', 'qwerty', 'admin'];
        if (in_array(strtolower($password), $commonPasswords)) {
            $this->context->buildViolation($constraint->messageCommon)
                ->addViolation();
        }
    }
}
```

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;

#[\Attribute]
class StrongPassword extends Constraint
{
    public string $messageTooShort = 'Password must be at least 8 characters long.';
    public string $messageNoUppercase = 'Password must contain at least one uppercase letter.';
    public string $messageNoLowercase = 'Password must contain at least one lowercase letter.';
    public string $messageNoNumber = 'Password must contain at least one number.';
    public string $messageNoSpecial = 'Password must contain at least one special character.';
    public string $messageCommon = 'This password is too common. Please choose a stronger password.';
}
```

Custom validators enforce password complexity rules. Check for multiple  
character types (uppercase, lowercase, numbers, special chars). Reject  
common weak passwords. Provide specific error messages for each  
requirement. Use as a constraint on form fields or entity properties.  

### Password History Prevention

Preventing password reuse with history tracking.  

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

    #[ORM\Column(length: 255)]
    private string $passwordHash;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    public function __construct(User $user, string $passwordHash)
    {
        $this->user = $user;
        $this->passwordHash = $passwordHash;
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getPasswordHash(): string
    {
        return $this->passwordHash;
    }

    public function getUser(): User
    {
        return $this->user;
    }
}
```

```php
<?php

namespace App\Service;

use App\Entity\PasswordHistory;
use App\Entity\User;
use App\Repository\PasswordHistoryRepository;
use Doctrine\ORM\EntityManagerInterface;

class PasswordHistoryService
{
    private const MAX_HISTORY = 5;

    public function __construct(
        private EntityManagerInterface $em,
        private PasswordHistoryRepository $historyRepository
    ) {
    }

    public function isPasswordReused(User $user, string $plainPassword): bool
    {
        $history = $this->historyRepository->findRecentForUser($user, self::MAX_HISTORY);

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
        
        $this->historyRepository->deleteOldEntriesForUser($user, self::MAX_HISTORY);
        
        $this->em->flush();
    }
}
```

Track password history to prevent reuse. Store only hashed passwords,  
never plain text. Limit history size to balance security and storage.  
Use password_verify() to check against historical hashes. Clean up  
old entries automatically when adding new ones.  

## Securing Routes and Resources

### Access Control in security.yaml

Defining URL-based access control rules.  

```yaml
# config/packages/security.yaml
security:
    access_control:
        # Public routes (order matters - first match wins)
        - { path: ^/login, roles: PUBLIC_ACCESS }
        - { path: ^/register, roles: PUBLIC_ACCESS }
        - { path: ^/password-reset, roles: PUBLIC_ACCESS }
        
        # API routes require authentication
        - { path: ^/api/public, roles: PUBLIC_ACCESS }
        - { path: ^/api, roles: ROLE_USER }
        
        # Admin routes
        - { path: ^/admin, roles: ROLE_ADMIN }
        
        # Editor routes
        - { path: ^/content/edit, roles: ROLE_EDITOR }
        
        # Require authentication for everything else under /app
        - { path: ^/app, roles: ROLE_USER }
        
        # IP restriction for sensitive routes
        - { path: ^/admin/security, roles: ROLE_SUPER_ADMIN, ips: [127.0.0.1, ::1] }
        
        # Channel security (require HTTPS)
        - { path: ^/checkout, roles: ROLE_USER, requires_channel: https }
```

Access control rules are evaluated top to bottom. First matching rule  
applies. PUBLIC_ACCESS allows anonymous access. Use regular expressions  
for complex patterns. Restrict by IP for sensitive areas. Require HTTPS  
for payment and sensitive data routes.  

### Route-Specific Security

Securing individual routes with requirements.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/dashboard')]
#[IsGranted('ROLE_USER')]
class DashboardController extends AbstractController
{
    #[Route('', name: 'dashboard_home')]
    public function index(): Response
    {
        return $this->render('dashboard/index.html.twig');
    }

    #[Route('/profile', name: 'dashboard_profile')]
    public function profile(): Response
    {
        return $this->render('dashboard/profile.html.twig', [
            'user' => $this->getUser()
        ]);
    }

    #[Route('/settings', name: 'dashboard_settings')]
    #[IsGranted('ROLE_USER')]
    public function settings(): Response
    {
        return $this->render('dashboard/settings.html.twig');
    }

    #[Route('/admin', name: 'dashboard_admin')]
    #[IsGranted('ROLE_ADMIN')]
    public function admin(): Response
    {
        return $this->render('dashboard/admin.html.twig');
    }
}
```

Apply IsGranted to entire controller classes for consistent protection.  
Override with method-level attributes when needed. Combine route prefixes  
with security attributes for organized code. All routes in class inherit  
class-level security unless overridden.  

### Resource-Based Authorization

Securing resources based on ownership and permissions.  

```php
<?php

namespace App\Controller;

use App\Entity\Article;
use App\Repository\ArticleRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/article')]
class ArticleController extends AbstractController
{
    #[Route('/{id}', name: 'article_show')]
    public function show(Article $article): Response
    {
        $this->denyAccessUnlessGranted('VIEW', $article);
        
        return $this->render('article/show.html.twig', [
            'article' => $article
        ]);
    }

    #[Route('/{id}/edit', name: 'article_edit')]
    public function edit(Article $article, Request $request, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('EDIT', $article);
        
        if ($request->isMethod('POST')) {
            $article->setTitle($request->request->get('title'));
            $article->setContent($request->request->get('content'));
            $em->flush();
            
            return $this->redirectToRoute('article_show', ['id' => $article->getId()]);
        }
        
        return $this->render('article/edit.html.twig', [
            'article' => $article
        ]);
    }

    #[Route('/{id}/delete', name: 'article_delete', methods: ['POST'])]
    public function delete(Article $article, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('DELETE', $article);
        
        $em->remove($article);
        $em->flush();
        
        return $this->redirectToRoute('article_list');
    }

    #[Route('/{id}/publish', name: 'article_publish', methods: ['POST'])]
    public function publish(Article $article, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('PUBLISH', $article);
        
        $article->setPublishedAt(new \DateTimeImmutable());
        $article->setStatus('published');
        $em->flush();
        
        return $this->redirectToRoute('article_show', ['id' => $article->getId()]);
    }
}
```

Check permissions on specific resource instances. Voters evaluate  
object state and user permissions. Different actions require different  
permissions (VIEW, EDIT, DELETE, PUBLISH). Throw AccessDeniedException  
if user lacks permission. This enables fine-grained control.  

### API Resource Protection

Securing API endpoints and resources.  

```php
<?php

namespace App\Controller\Api;

use App\Entity\Product;
use App\Repository\ProductRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/api/products')]
#[IsGranted('ROLE_USER')]
class ProductApiController extends AbstractController
{
    #[Route('', name: 'api_products_list', methods: ['GET'])]
    public function list(ProductRepository $productRepository): JsonResponse
    {
        $products = $productRepository->findAll();
        
        return $this->json($products, Response::HTTP_OK, [], [
            'groups' => ['product:read']
        ]);
    }

    #[Route('/{id}', name: 'api_products_show', methods: ['GET'])]
    public function show(Product $product): JsonResponse
    {
        $this->denyAccessUnlessGranted('VIEW', $product);
        
        return $this->json($product, Response::HTTP_OK, [], [
            'groups' => ['product:read', 'product:detail']
        ]);
    }

    #[Route('', name: 'api_products_create', methods: ['POST'])]
    #[IsGranted('ROLE_EDITOR')]
    public function create(Request $request, EntityManagerInterface $em): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        
        $product = new Product();
        $product->setName($data['name']);
        $product->setPrice($data['price']);
        $product->setOwner($this->getUser());
        
        $em->persist($product);
        $em->flush();
        
        return $this->json($product, Response::HTTP_CREATED, [], [
            'groups' => ['product:read']
        ]);
    }

    #[Route('/{id}', name: 'api_products_update', methods: ['PUT'])]
    public function update(
        Product $product,
        Request $request,
        EntityManagerInterface $em
    ): JsonResponse {
        $this->denyAccessUnlessGranted('EDIT', $product);
        
        $data = json_decode($request->getContent(), true);
        
        $product->setName($data['name'] ?? $product->getName());
        $product->setPrice($data['price'] ?? $product->getPrice());
        
        $em->flush();
        
        return $this->json($product, Response::HTTP_OK, [], [
            'groups' => ['product:read']
        ]);
    }

    #[Route('/{id}', name: 'api_products_delete', methods: ['DELETE'])]
    public function delete(Product $product, EntityManagerInterface $em): JsonResponse
    {
        $this->denyAccessUnlessGranted('DELETE', $product);
        
        $em->remove($product);
        $em->flush();
        
        return $this->json(null, Response::HTTP_NO_CONTENT);
    }
}
```

Protect API endpoints with role-based and resource-based checks.  
Return appropriate HTTP status codes. Use serialization groups to  
control exposed data. Validate permissions before modifications.  
Create requires role, update/delete require resource permission.  

## CSRF Protection

### CSRF Tokens in Forms

Implementing CSRF protection in forms.  

```php
<?php

namespace App\Form;

use App\Entity\Comment;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class CommentType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('content', TextareaType::class, [
                'label' => 'Your Comment',
                'attr' => ['rows' => 5]
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Comment::class,
            'csrf_protection' => true,
            'csrf_field_name' => '_token',
            'csrf_token_id' => 'comment_item',
        ]);
    }
}
```

```twig
{# templates/comment/form.html.twig #}
{{ form_start(form) }}
    {{ form_row(form.content) }}
    
    {# CSRF token is automatically included #}
    
    <button type="submit">Post Comment</button>
{{ form_end(form) }}
```

CSRF protection is enabled by default in Symfony forms. The token is  
automatically generated and validated. Customize token ID for different  
form types. The token prevents malicious sites from submitting forms  
on behalf of users. Never disable CSRF protection in production.  

### Manual CSRF Token Management

Using CSRF tokens outside of forms.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class ActionController extends AbstractController
{
    #[Route('/article/{id}/like', name: 'article_like', methods: ['POST'])]
    public function like(
        int $id,
        Request $request,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response {
        $token = new CsrfToken('article_like', $request->request->get('_token'));
        
        if (!$csrfTokenManager->isTokenValid($token)) {
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }
        
        // Process like action
        
        return $this->json(['success' => true]);
    }

    #[Route('/article/{id}/delete', name: 'article_delete', methods: ['POST'])]
    public function delete(
        int $id,
        Request $request,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response {
        $submittedToken = $request->request->get('_token');
        
        if (!$this->isCsrfTokenValid('delete_article', $submittedToken)) {
            $this->addFlash('error', 'Invalid security token');
            return $this->redirectToRoute('article_list');
        }
        
        // Process deletion
        
        return $this->redirectToRoute('article_list');
    }
}
```

```twig
{# templates/article/actions.html.twig #}
<form method="post" action="{{ path('article_like', {id: article.id}) }}">
    <input type="hidden" name="_token" value="{{ csrf_token('article_like') }}">
    <button type="submit">Like</button>
</form>

<form method="post" action="{{ path('article_delete', {id: article.id}) }}" 
      onsubmit="return confirm('Are you sure?')">
    <input type="hidden" name="_token" value="{{ csrf_token('delete_article') }}">
    <button type="submit">Delete</button>
</form>
```

Generate CSRF tokens manually for non-form actions. Use unique token  
IDs for different operations. Validate tokens before processing state-  
changing operations. isCsrfTokenValid() is a shortcut method. Always  
use POST for state-changing operations with CSRF protection.  

### CSRF Protection for AJAX Requests

Securing AJAX calls with CSRF tokens.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class AjaxController extends AbstractController
{
    #[Route('/api/update-status', name: 'api_update_status', methods: ['POST'])]
    public function updateStatus(Request $request): JsonResponse
    {
        $token = $request->headers->get('X-CSRF-TOKEN');
        
        if (!$this->isCsrfTokenValid('ajax_operation', $token)) {
            return $this->json([
                'error' => 'Invalid CSRF token'
            ], 403);
        }
        
        $data = json_decode($request->getContent(), true);
        
        // Process the request
        
        return $this->json(['success' => true]);
    }
}
```

```twig
{# templates/base.html.twig #}
<script>
    // Store CSRF token globally
    window.csrfToken = '{{ csrf_token('ajax_operation') }}';
    
    // Example AJAX request
    fetch('/api/update-status', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': window.csrfToken
        },
        body: JSON.stringify({
            status: 'active'
        })
    })
    .then(response => response.json())
    .then(data => console.log(data));
</script>
```

Include CSRF token in AJAX request headers. Store token in JavaScript  
variable accessible to all scripts. Validate token on server side before  
processing. Use consistent token ID for all AJAX operations or different  
IDs for different operation types.  

## Input Validation and Sanitization

### Entity Validation Constraints

Validating user input with constraints.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;

#[ORM\Entity]
#[UniqueEntity(fields: ['email'], message: 'This email is already registered')]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 180)]
    #[Assert\NotBlank(message: 'Email is required')]
    #[Assert\Email(message: 'Please enter a valid email address')]
    #[Assert\Length(max: 180)]
    private ?string $email = null;

    #[ORM\Column(length: 100)]
    #[Assert\NotBlank]
    #[Assert\Length(
        min: 2,
        max: 100,
        minMessage: 'Name must be at least {{ limit }} characters',
        maxMessage: 'Name cannot exceed {{ limit }} characters'
    )]
    #[Assert\Regex(
        pattern: '/^[a-zA-Z\s]+$/',
        message: 'Name can only contain letters and spaces'
    )]
    private ?string $name = null;

    #[ORM\Column(type: 'integer')]
    #[Assert\NotNull]
    #[Assert\Range(
        min: 18,
        max: 120,
        notInRangeMessage: 'Age must be between {{ min }} and {{ max }}'
    )]
    private ?int $age = null;

    #[ORM\Column(type: 'text', nullable: true)]
    #[Assert\Length(max: 1000)]
    private ?string $bio = null;

    // Getters and setters...
}
```

Use validation constraints to ensure data integrity. NotBlank prevents  
empty values. Email validates format. Length restricts string size.  
Regex enforces patterns. Range validates numeric values. UniqueEntity  
prevents duplicates. Constraints run automatically when validating  
entities.  

### Form Input Sanitization

Sanitizing user input before processing.  

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
        
        // Remove invisible characters
        $input = preg_replace('/[\x00-\x1F\x7F]/u', '', $input);
        
        return $input;
    }

    public function sanitizeHtml(string $input): string
    {
        // Strip all HTML tags except allowed ones
        $allowedTags = '<p><br><strong><em><ul><ol><li><a>';
        $input = strip_tags($input, $allowedTags);
        
        // Remove dangerous attributes
        $input = preg_replace('/<a[^>]*href=["\']javascript:[^"\']*["\'][^>]*>/i', '', $input);
        $input = preg_replace('/on\w+\s*=\s*["\'][^"\']*["\']/i', '', $input);
        
        return $input;
    }

    public function sanitizeEmail(string $email): string
    {
        return filter_var($email, FILTER_SANITIZE_EMAIL);
    }

    public function sanitizeUrl(string $url): string
    {
        return filter_var($url, FILTER_SANITIZE_URL);
    }

    public function sanitizeFilename(string $filename): string
    {
        // Remove path traversal attempts
        $filename = basename($filename);
        
        // Allow only alphanumeric, dash, underscore, and dot
        $filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename);
        
        // Prevent double extensions
        $filename = preg_replace('/\.+/', '.', $filename);
        
        return $filename;
    }
}
```

```php
<?php

namespace App\Controller;

use App\Service\InputSanitizer;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserInputController extends AbstractController
{
    #[Route('/comment', name: 'submit_comment', methods: ['POST'])]
    public function submitComment(Request $request, InputSanitizer $sanitizer): Response
    {
        $rawComment = $request->request->get('comment');
        
        // Sanitize input
        $comment = $sanitizer->sanitizeHtml($rawComment);
        
        // Further processing...
        
        return $this->redirectToRoute('comment_success');
    }
}
```

Always sanitize user input before processing or storage. Remove null  
bytes and control characters. Strip dangerous HTML tags and attributes.  
Use filter_var() for emails and URLs. Sanitize filenames to prevent  
directory traversal. Combine sanitization with validation for defense  
in depth.  

## Session Security

### Secure Session Configuration

Configuring sessions securely.  

```yaml
# config/packages/framework.yaml
framework:
    session:
        # Use strict session cookie settings
        cookie_secure: 'auto'  # true in production with HTTPS
        cookie_httponly: true
        cookie_samesite: 'lax'
        
        # Session handler
        handler_id: null
        
        # Session metadata
        metadata_update_threshold: 0
        
        # Cookie lifetime (in seconds)
        cookie_lifetime: 3600
        
        # Garbage collection
        gc_probability: 1
        gc_divisor: 100
        gc_maxlifetime: 3600
```

Set cookie_secure to true in production to require HTTPS. cookie_httponly  
prevents JavaScript access to cookies. cookie_samesite prevents CSRF  
attacks. Configure appropriate lifetime based on security requirements.  
Enable garbage collection to remove old sessions.  

### Session Fixation Prevention

Regenerating session IDs on authentication.  

```php
<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class LoginSuccessHandler implements AuthenticationSuccessHandlerInterface
{
    public function __construct(
        private UrlGeneratorInterface $urlGenerator
    ) {
    }

    public function onAuthenticationSuccess(
        Request $request,
        TokenInterface $token
    ): Response {
        // Regenerate session to prevent fixation attacks
        $request->getSession()->migrate(true);
        
        // Clear any sensitive data from session
        $request->getSession()->remove('temp_data');
        
        // Log successful login
        // ... logging logic ...
        
        // Redirect to dashboard
        return new RedirectResponse(
            $this->urlGenerator->generate('app_dashboard')
        );
    }
}
```

Session fixation allows attackers to hijack user sessions. Regenerate  
session ID after successful login using migrate(). The true parameter  
deletes the old session. Clear temporary data that shouldn't persist.  
Symfony's security component handles this automatically for form login.  

### Session Data Management

Securely storing and accessing session data.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Annotation\Route;

class SessionController extends AbstractController
{
    #[Route('/cart/add/{productId}', name: 'cart_add')]
    public function addToCart(int $productId, Request $request): Response
    {
        $session = $request->getSession();
        
        // Get current cart
        $cart = $session->get('cart', []);
        
        // Add product
        if (isset($cart[$productId])) {
            $cart[$productId]++;
        } else {
            $cart[$productId] = 1;
        }
        
        // Store back in session
        $session->set('cart', $cart);
        
        // Use flash messages for one-time messages
        $this->addFlash('success', 'Product added to cart');
        
        return $this->redirectToRoute('product_list');
    }

    #[Route('/preferences/save', name: 'preferences_save')]
    public function savePreferences(Request $request): Response
    {
        $session = $request->getSession();
        
        // Store user preferences
        $session->set('theme', $request->request->get('theme'));
        $session->set('language', $request->request->get('language'));
        
        // Never store sensitive data in sessions
        // Use database for passwords, payment info, etc.
        
        return $this->redirectToRoute('user_profile');
    }

    #[Route('/cart/clear', name: 'cart_clear')]
    public function clearCart(Request $request): Response
    {
        $session = $request->getSession();
        
        // Remove specific item
        $session->remove('cart');
        
        return $this->redirectToRoute('cart_view');
    }
}
```

Store only necessary data in sessions. Never store passwords or payment  
information. Use get() with default value for safety. Flash messages  
are perfect for one-time notifications. Clear session data when no  
longer needed. Validate session data before using it.  

## Security Best Practices

### Remember Me Security

Implementing secure remember me functionality.  

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800  # 1 week
                path: /
                always_remember_me: false
                signature_properties: ['password']
                token_provider:
                    doctrine: true
```

Remember me uses cookies for persistent authentication. Use strong  
random secret. Set appropriate lifetime (1 week is reasonable).  
signature_properties invalidates tokens when password changes. Doctrine  
token provider stores tokens in database for better security. Users  
should opt-in, not always remember.  

### User Impersonation

Allowing admins to impersonate users safely.  

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            switch_user: true
```

```php
<?php

namespace App\Controller\Admin;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_ALLOWED_TO_SWITCH')]
class ImpersonationController extends AbstractController
{
    #[Route('/admin/impersonate/{id}', name: 'admin_impersonate')]
    public function impersonate(User $user): Response
    {
        // Redirect with switch user parameter
        return $this->redirectToRoute('app_dashboard', [
            '_switch_user' => $user->getEmail()
        ]);
    }
}
```

```twig
{# templates/admin/user_list.html.twig #}
{% for user in users %}
    <tr>
        <td>{{ user.email }}</td>
        <td>
            {% if is_granted('ROLE_ALLOWED_TO_SWITCH') %}
                <a href="{{ path('admin_impersonate', {id: user.id}) }}">
                    Impersonate
                </a>
            {% endif %}
        </td>
    </tr>
{% endfor %}

{# Show exit impersonation if currently impersonating #}
{% if is_granted('ROLE_PREVIOUS_ADMIN') %}
    <div class="impersonation-notice">
        You are impersonating {{ app.user.userIdentifier }}
        <a href="{{ path('app_dashboard', {'_switch_user': '_exit'}) }}">
            Exit Impersonation
        </a>
    </div>
{% endif %}
```

User impersonation helps admins debug user issues. Require  
ROLE_ALLOWED_TO_SWITCH permission. Add _switch_user parameter with  
user identifier. Use _exit to stop impersonating. Show clear indicator  
when impersonating. Log impersonation events for audit trail.  

### Rate Limiting for Security

Protecting against brute force attacks.  

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\RateLimiter\RateLimiterFactory;

#[AsEventListener(event: 'kernel.request', priority: 10)]
class LoginRateLimiter
{
    public function __construct(
        private RateLimiterFactory $loginLimiter
    ) {
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        
        // Only limit login attempts
        if ($request->getPathInfo() !== '/login' || !$request->isMethod('POST')) {
            return;
        }
        
        // Create limiter based on IP and username
        $username = $request->request->get('_username', 'anonymous');
        $identifier = $request->getClientIp() . '_' . $username;
        
        $limiter = $this->loginLimiter->create($identifier);
        $limit = $limiter->consume();
        
        if (!$limit->isAccepted()) {
            $event->setResponse(new Response(
                'Too many login attempts. Please try again later.',
                Response::HTTP_TOO_MANY_REQUESTS
            ));
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

Rate limiting prevents brute force attacks. Limit login attempts per  
IP and username combination. Use sliding window policy for fairness.  
Return 429 status code when limit exceeded. Configure appropriate  
limits and intervals. Consider legitimate users who forget passwords.  

### Security Event Logging

Logging security-related events for monitoring.  

```php
<?php

namespace App\EventListener;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class SecurityEventLogger
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    #[AsEventListener(event: LoginSuccessEvent::class)]
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        $request = $event->getRequest();
        
        $this->logger->info('User login successful', [
            'user' => $user->getUserIdentifier(),
            'ip' => $request->getClientIp(),
            'user_agent' => $request->headers->get('User-Agent'),
            'firewall' => $event->getFirewallName(),
        ]);
    }

    #[AsEventListener(event: LoginFailureEvent::class)]
    public function onLoginFailure(LoginFailureEvent $event): void
    {
        $request = $event->getRequest();
        $exception = $event->getException();
        
        $this->logger->warning('User login failed', [
            'username' => $request->request->get('_username'),
            'ip' => $request->getClientIp(),
            'reason' => $exception->getMessage(),
            'firewall' => $event->getFirewallName(),
        ]);
    }

    #[AsEventListener(event: LogoutEvent::class)]
    public function onLogout(LogoutEvent $event): void
    {
        $token = $event->getToken();
        
        if ($token && $token->getUser()) {
            $this->logger->info('User logout', [
                'user' => $token->getUser()->getUserIdentifier(),
            ]);
        }
    }
}
```

Log all security events for monitoring and forensics. Track successful  
logins, failures, and logouts. Include IP address, user agent, and  
timestamp. Store username for failed attempts to detect attacks. Use  
appropriate log levels (info for success, warning for failures). Comply  
with privacy regulations when logging.  

### Secure File Upload Handling

Validating and securing file uploads.  

```php
<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\File\Exception\FileException;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\String\Slugger\SluggerInterface;

class FileUploadService
{
    private const ALLOWED_MIME_TYPES = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/pdf',
    ];
    
    private const MAX_FILE_SIZE = 5242880; // 5MB

    public function __construct(
        private string $uploadDirectory,
        private SluggerInterface $slugger
    ) {
    }

    public function upload(UploadedFile $file): string
    {
        // Validate file size
        if ($file->getSize() > self::MAX_FILE_SIZE) {
            throw new FileException('File size exceeds maximum allowed size');
        }

        // Validate MIME type
        $mimeType = $file->getMimeType();
        if (!in_array($mimeType, self::ALLOWED_MIME_TYPES)) {
            throw new FileException('Invalid file type');
        }

        // Validate file extension matches MIME type
        $extension = $file->guessExtension();
        if (!$extension) {
            throw new FileException('Invalid file extension');
        }

        // Generate safe filename
        $originalFilename = pathinfo($file->getClientOriginalName(), PATHINFO_FILENAME);
        $safeFilename = $this->slugger->slug($originalFilename);
        $newFilename = $safeFilename . '-' . uniqid() . '.' . $extension;

        try {
            $file->move($this->uploadDirectory, $newFilename);
        } catch (FileException $e) {
            throw new FileException('Failed to upload file');
        }

        return $newFilename;
    }

    public function delete(string $filename): void
    {
        $filepath = $this->uploadDirectory . '/' . $filename;
        
        // Prevent directory traversal
        $realpath = realpath($filepath);
        if (!$realpath || !str_starts_with($realpath, $this->uploadDirectory)) {
            throw new FileException('Invalid file path');
        }

        if (file_exists($filepath)) {
            unlink($filepath);
        }
    }
}
```

Validate file size to prevent DoS attacks. Check MIME type against  
whitelist. Verify extension matches MIME type. Generate unique safe  
filenames to prevent overwrites. Prevent directory traversal when  
deleting. Store uploads outside web root if possible. Scan for malware  
in production environments.  

### Environment-Specific Security

Managing security settings per environment.  

```yaml
# config/packages/security.yaml
security:
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface:
            algorithm: auto
            cost: 12
```

```yaml
# config/packages/dev/security.yaml
security:
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface:
            algorithm: auto
            cost: 4  # Lower cost for faster tests in dev
```

```yaml
# config/packages/prod/security.yaml
security:
    firewalls:
        main:
            remember_me:
                secure: true  # Force HTTPS in production
```

Use different security settings per environment. Lower hash cost in  
development for speed. Force HTTPS in production. Enable strict  
session settings in production. Use in-memory providers for testing.  
Never expose debug information in production.  

This comprehensive guide covered 60 practical examples of Symfony  
security fundamentals. From basic authentication setup to advanced  
security patterns, these examples provide a solid foundation for  
building secure Symfony applications. Always follow security best  
practices, keep dependencies updated, and conduct regular security  
audits of your application.  

## Advanced Security Patterns

### Two-Factor Authentication

Implementing two-factor authentication for enhanced security.  

```php
<?php

namespace App\Service;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpAuthenticatorInterface;

class TwoFactorService
{
    public function __construct(
        private EntityManagerInterface $em,
        private TotpAuthenticatorInterface $totpAuthenticator
    ) {
    }

    public function enableTwoFactor(User $user): string
    {
        if (!$user->isTotpAuthenticationEnabled()) {
            $secret = $this->totpAuthenticator->generateSecret();
            $user->setTotpSecret($secret);
            $this->em->flush();
        }
        
        return $this->totpAuthenticator->getQRContent($user);
    }

    public function verifyCode(User $user, string $code): bool
    {
        return $this->totpAuthenticator->checkCode($user, $code);
    }

    public function disableTwoFactor(User $user): void
    {
        $user->setTotpSecret(null);
        $this->em->flush();
    }
}
```

```php
<?php

namespace App\Controller;

use App\Service\TwoFactorService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class TwoFactorController extends AbstractController
{
    #[Route('/2fa/setup', name: 'two_factor_setup')]
    public function setup(TwoFactorService $twoFactorService): Response
    {
        $user = $this->getUser();
        $qrCodeContent = $twoFactorService->enableTwoFactor($user);
        
        return $this->render('security/2fa_setup.html.twig', [
            'qrCodeContent' => $qrCodeContent,
        ]);
    }

    #[Route('/2fa/verify', name: 'two_factor_verify', methods: ['POST'])]
    public function verify(
        Request $request,
        TwoFactorService $twoFactorService
    ): Response {
        $user = $this->getUser();
        $code = $request->request->get('code');
        
        if ($twoFactorService->verifyCode($user, $code)) {
            $this->addFlash('success', '2FA enabled successfully');
            return $this->redirectToRoute('user_profile');
        }
        
        $this->addFlash('error', 'Invalid verification code');
        return $this->redirectToRoute('two_factor_setup');
    }
}
```

Two-factor authentication adds an extra security layer. Use TOTP  
(Time-based One-Time Password) for compatibility with apps like  
Google Authenticator. Generate QR codes for easy setup. Verify  
codes before enabling. Store backup codes for account recovery.  

### Security Headers Configuration

Setting security headers to protect against common attacks.  

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

#[AsEventListener(event: 'kernel.response')]
class SecurityHeadersListener
{
    public function onKernelResponse(ResponseEvent $event): void
    {
        $response = $event->getResponse();
        
        // Content Security Policy
        $response->headers->set(
            'Content-Security-Policy',
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;"
        );
        
        // Prevent clickjacking
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');
        
        // Prevent MIME sniffing
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        
        // Enable XSS protection
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        
        // HSTS for HTTPS enforcement
        $response->headers->set(
            'Strict-Transport-Security',
            'max-age=31536000; includeSubDomains'
        );
        
        // Referrer policy
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        
        // Permissions policy
        $response->headers->set(
            'Permissions-Policy',
            'geolocation=(), microphone=(), camera=()'
        );
    }
}
```

Security headers protect against various attacks. Content-Security-Policy  
prevents XSS by controlling resource loading. X-Frame-Options prevents  
clickjacking. X-Content-Type-Options prevents MIME sniffing. HSTS forces  
HTTPS connections. Configure CSP carefully to avoid breaking functionality.  

### API Key Authentication

Implementing API key-based authentication.  

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

    #[ORM\Column(length: 64, unique: true)]
    private string $apiKey;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false)]
    private User $user;

    #[ORM\Column(length: 100)]
    private string $name;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $expiresAt = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastUsedAt = null;

    #[ORM\Column]
    private bool $isActive = true;

    public function __construct()
    {
        $this->apiKey = bin2hex(random_bytes(32));
    }

    // Getters and setters...
}
```

```php
<?php

namespace App\Security;

use App\Repository\ApiKeyRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class ApiKeyAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private ApiKeyRepository $apiKeyRepository
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('X-API-KEY');
    }

    public function authenticate(Request $request): Passport
    {
        $apiKeyValue = $request->headers->get('X-API-KEY');
        
        if (!$apiKeyValue) {
            throw new AuthenticationException('No API key provided');
        }

        return new SelfValidatingPassport(
            new UserBadge($apiKeyValue, function($apiKeyValue) {
                $apiKey = $this->apiKeyRepository->findOneBy([
                    'apiKey' => $apiKeyValue,
                    'isActive' => true
                ]);
                
                if (!$apiKey) {
                    throw new AuthenticationException('Invalid API key');
                }
                
                if ($apiKey->getExpiresAt() && 
                    $apiKey->getExpiresAt() < new \DateTimeImmutable()) {
                    throw new AuthenticationException('API key expired');
                }
                
                $apiKey->setLastUsedAt(new \DateTimeImmutable());
                
                return $apiKey->getUser();
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
            'error' => $exception->getMessage()
        ], Response::HTTP_UNAUTHORIZED);
    }
}
```

API keys provide simple authentication for APIs. Generate cryptographically  
secure random keys. Track last usage timestamp. Support expiration dates.  
Allow users to manage multiple keys. Provide ability to revoke keys.  
Use HTTPS to protect keys in transit.  

### OAuth2 Client Integration

Integrating OAuth2 for third-party authentication.  

```yaml
# config/packages/knpu_oauth2_client.yaml
knpu_oauth2_client:
    clients:
        google:
            type: google
            client_id: '%env(GOOGLE_CLIENT_ID)%'
            client_secret: '%env(GOOGLE_CLIENT_SECRET)%'
            redirect_route: oauth_check_google
            redirect_params: {}
        
        github:
            type: github
            client_id: '%env(GITHUB_CLIENT_ID)%'
            client_secret: '%env(GITHUB_CLIENT_SECRET)%'
            redirect_route: oauth_check_github
```

```php
<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class OAuthController extends AbstractController
{
    #[Route('/oauth/connect/google', name: 'oauth_connect_google')]
    public function connectGoogle(ClientRegistry $clientRegistry): RedirectResponse
    {
        return $clientRegistry
            ->getClient('google')
            ->redirect(['profile', 'email']);
    }

    #[Route('/oauth/check/google', name: 'oauth_check_google')]
    public function checkGoogle(Request $request, ClientRegistry $clientRegistry)
    {
        // This route is intercepted by the OAuth2 authenticator
    }

    #[Route('/oauth/connect/github', name: 'oauth_connect_github')]
    public function connectGithub(ClientRegistry $clientRegistry): RedirectResponse
    {
        return $clientRegistry
            ->getClient('github')
            ->redirect(['user:email']);
    }

    #[Route('/oauth/check/github', name: 'oauth_check_github')]
    public function checkGithub()
    {
        // This route is intercepted by the OAuth2 authenticator
    }
}
```

OAuth2 allows users to login with existing accounts (Google, GitHub,  
etc.). Store client credentials securely in environment variables.  
Configure redirect routes for callback handling. Request only necessary  
scopes. Link OAuth accounts to local user accounts. Handle cases where  
email is not provided.  

### Account Lockout After Failed Attempts

Implementing account lockout for security.  

```php
<?php

namespace App\EventListener;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

class LoginAttemptListener
{
    private const MAX_ATTEMPTS = 5;
    private const LOCKOUT_DURATION = 1800; // 30 minutes

    public function __construct(
        private EntityManagerInterface $em
    ) {
    }

    #[AsEventListener(event: LoginFailureEvent::class)]
    public function onLoginFailure(LoginFailureEvent $event): void
    {
        $request = $event->getRequest();
        $username = $request->request->get('_username');
        
        if (!$username) {
            return;
        }
        
        $user = $this->em->getRepository(User::class)
            ->findOneBy(['email' => $username]);
        
        if (!$user) {
            return;
        }
        
        $user->incrementLoginAttempts();
        
        if ($user->getLoginAttempts() >= self::MAX_ATTEMPTS) {
            $user->setLockedUntil(
                new \DateTimeImmutable('+' . self::LOCKOUT_DURATION . ' seconds')
            );
        }
        
        $this->em->flush();
    }

    #[AsEventListener(event: LoginSuccessEvent::class)]
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        
        if ($user instanceof User) {
            $user->resetLoginAttempts();
            $user->setLockedUntil(null);
            $user->setLastLoginAt(new \DateTimeImmutable());
            $this->em->flush();
        }
    }
}
```

Account lockout prevents brute force attacks. Track failed login  
attempts per user. Lock account temporarily after threshold. Reset  
counter on successful login. Notify users of lockout via email.  
Provide account recovery mechanism. Consider permanent lockout for  
repeated violations.  

### Database Encryption for Sensitive Data

Encrypting sensitive database fields.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\HasLifecycleCallbacks]
class Payment
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(type: 'text')]
    private string $encryptedCardNumber;

    private ?string $cardNumber = null;

    #[ORM\Column(length: 4)]
    private string $lastFourDigits;

    public function getCardNumber(): ?string
    {
        return $this->cardNumber;
    }

    public function setCardNumber(?string $cardNumber): self
    {
        $this->cardNumber = $cardNumber;
        
        if ($cardNumber) {
            $this->lastFourDigits = substr($cardNumber, -4);
        }
        
        return $this;
    }

    public function getLastFourDigits(): string
    {
        return $this->lastFourDigits;
    }

    public function getEncryptedCardNumber(): string
    {
        return $this->encryptedCardNumber;
    }

    public function setEncryptedCardNumber(string $encryptedCardNumber): self
    {
        $this->encryptedCardNumber = $encryptedCardNumber;
        return $this;
    }
}
```

```php
<?php

namespace App\EventListener;

use App\Entity\Payment;
use App\Service\EncryptionService;
use Doctrine\Bundle\DoctrineBundle\Attribute\AsEntityListener;
use Doctrine\ORM\Events;

#[AsEntityListener(event: Events::prePersist, entity: Payment::class)]
#[AsEntityListener(event: Events::preUpdate, entity: Payment::class)]
#[AsEntityListener(event: Events::postLoad, entity: Payment::class)]
class PaymentEncryptionListener
{
    public function __construct(
        private EncryptionService $encryptionService
    ) {
    }

    public function prePersist(Payment $payment): void
    {
        $this->encryptData($payment);
    }

    public function preUpdate(Payment $payment): void
    {
        $this->encryptData($payment);
    }

    public function postLoad(Payment $payment): void
    {
        $encrypted = $payment->getEncryptedCardNumber();
        if ($encrypted) {
            $decrypted = $this->encryptionService->decrypt($encrypted);
            $payment->setCardNumber($decrypted);
        }
    }

    private function encryptData(Payment $payment): void
    {
        $cardNumber = $payment->getCardNumber();
        if ($cardNumber) {
            $encrypted = $this->encryptionService->encrypt($cardNumber);
            $payment->setEncryptedCardNumber($encrypted);
        }
    }
}
```

Encrypt sensitive data like credit cards before storing. Use lifecycle  
callbacks for automatic encryption/decryption. Store last four digits  
unencrypted for display. Never log or expose full card numbers. Use  
strong encryption algorithms. Rotate encryption keys regularly. Consider  
using payment processors to avoid storing card data.  

### Content Security Policy Management

Managing Content Security Policy dynamically.  

```php
<?php

namespace App\Service;

class CspBuilder
{
    private array $directives = [];

    public function __construct()
    {
        $this->directives = [
            'default-src' => ["'self'"],
            'script-src' => ["'self'"],
            'style-src' => ["'self'"],
            'img-src' => ["'self'", 'data:', 'https:'],
            'font-src' => ["'self'"],
            'connect-src' => ["'self'"],
            'frame-ancestors' => ["'none'"],
            'base-uri' => ["'self'"],
            'form-action' => ["'self'"],
        ];
    }

    public function addScriptSrc(string $source): self
    {
        $this->directives['script-src'][] = $source;
        return $this;
    }

    public function addStyleSrc(string $source): self
    {
        $this->directives['style-src'][] = $source;
        return $this;
    }

    public function addNonce(string $directive, string $nonce): self
    {
        $this->directives[$directive][] = "'nonce-{$nonce}'";
        return $this;
    }

    public function build(): string
    {
        $parts = [];
        foreach ($this->directives as $directive => $sources) {
            $parts[] = $directive . ' ' . implode(' ', $sources);
        }
        
        return implode('; ', $parts);
    }
}
```

```php
<?php

namespace App\Controller;

use App\Service\CspBuilder;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SecurePageController extends AbstractController
{
    #[Route('/secure-page', name: 'secure_page')]
    public function index(CspBuilder $cspBuilder): Response
    {
        $nonce = base64_encode(random_bytes(16));
        
        $csp = $cspBuilder
            ->addScriptSrc('https://cdn.example.com')
            ->addNonce('script-src', $nonce)
            ->build();
        
        $response = $this->render('secure/page.html.twig', [
            'nonce' => $nonce,
        ]);
        
        $response->headers->set('Content-Security-Policy', $csp);
        
        return $response;
    }
}
```

CSP prevents XSS attacks by controlling resource loading. Build policies  
dynamically based on page needs. Use nonces for inline scripts and styles.  
Start with restrictive policy and relax as needed. Monitor CSP violations  
using report-uri directive. Test thoroughly as CSP can break functionality.  

### Audit Trail for Security Events

Implementing comprehensive security auditing.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'security_audit_log')]
#[ORM\Index(columns: ['user_id', 'created_at'])]
#[ORM\Index(columns: ['event_type', 'created_at'])]
class SecurityAuditLog
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(targetEntity: User::class)]
    private ?User $user = null;

    #[ORM\Column(length: 50)]
    private string $eventType;

    #[ORM\Column(length: 45)]
    private string $ipAddress;

    #[ORM\Column(type: 'text', nullable: true)]
    private ?string $userAgent = null;

    #[ORM\Column(type: 'json')]
    private array $metadata = [];

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    public function __construct(
        string $eventType,
        string $ipAddress,
        ?User $user = null
    ) {
        $this->eventType = $eventType;
        $this->ipAddress = $ipAddress;
        $this->user = $user;
        $this->createdAt = new \DateTimeImmutable();
    }

    // Getters and setters...
}
```

```php
<?php

namespace App\Service;

use App\Entity\SecurityAuditLog;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

class AuditLogger
{
    public function __construct(
        private EntityManagerInterface $em,
        private RequestStack $requestStack
    ) {
    }

    public function log(string $eventType, ?User $user = null, array $metadata = []): void
    {
        $request = $this->requestStack->getCurrentRequest();
        
        $log = new SecurityAuditLog(
            $eventType,
            $request?->getClientIp() ?? 'unknown'
        );
        
        $log->setUser($user);
        $log->setUserAgent($request?->headers->get('User-Agent'));
        $log->setMetadata($metadata);
        
        $this->em->persist($log);
        $this->em->flush();
    }

    public function logLogin(User $user, bool $success): void
    {
        $this->log(
            $success ? 'login_success' : 'login_failure',
            $user,
            ['success' => $success]
        );
    }

    public function logPermissionDenied(User $user, string $resource): void
    {
        $this->log('permission_denied', $user, [
            'resource' => $resource
        ]);
    }

    public function logDataAccess(User $user, string $entityType, int $entityId): void
    {
        $this->log('data_access', $user, [
            'entity_type' => $entityType,
            'entity_id' => $entityId
        ]);
    }
}
```

Maintain comprehensive audit logs for security events. Track user,  
timestamp, IP address, and user agent. Store event metadata as JSON.  
Index frequently queried columns. Log authentication events, permission  
denials, and sensitive data access. Retain logs according to compliance  
requirements. Review logs regularly for suspicious activity.  

### Secure Password Recovery

Implementing secure password recovery flow.  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\PasswordResetRequestType;
use App\Form\PasswordResetType;
use App\Service\PasswordResetService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

class PasswordRecoveryController extends AbstractController
{
    #[Route('/password-reset/request', name: 'password_reset_request')]
    public function request(
        Request $request,
        PasswordResetService $resetService,
        EntityManagerInterface $em
    ): Response {
        $form = $this->createForm(PasswordResetRequestType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $email = $form->get('email')->getData();
            $user = $em->getRepository(User::class)->findOneBy(['email' => $email]);
            
            if ($user) {
                $resetService->sendResetEmail($user);
            }
            
            // Always show success message to prevent email enumeration
            $this->addFlash('success', 
                'If the email exists, you will receive password reset instructions.'
            );
            
            return $this->redirectToRoute('app_login');
        }

        return $this->render('security/password_reset_request.html.twig', [
            'form' => $form,
        ]);
    }

    #[Route('/password-reset/confirm/{token}', name: 'password_reset_confirm')]
    public function confirm(
        string $token,
        Request $request,
        PasswordResetService $resetService,
        UserPasswordHasherInterface $passwordHasher,
        EntityManagerInterface $em
    ): Response {
        $user = $resetService->validateResetToken($token);
        
        if (!$user) {
            $this->addFlash('error', 'Invalid or expired reset token');
            return $this->redirectToRoute('password_reset_request');
        }

        $form = $this->createForm(PasswordResetType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $newPassword = $form->get('plainPassword')->getData();
            $hashedPassword = $passwordHasher->hashPassword($user, $newPassword);
            
            $resetService->resetPassword($user, $hashedPassword);
            
            $this->addFlash('success', 'Password reset successfully');
            return $this->redirectToRoute('app_login');
        }

        return $this->render('security/password_reset_confirm.html.twig', [
            'form' => $form,
        ]);
    }
}
```

Never reveal whether email exists to prevent enumeration. Use  
cryptographically random tokens with expiration. Send reset link via  
email only. Invalidate token after use. Rate limit reset requests.  
Log all reset attempts. Consider requiring current password for  
authenticated password changes.  

### Role-Based Access in Queries

Filtering database queries based on user roles.  

```php
<?php

namespace App\Repository;

use App\Entity\Document;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class DocumentRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Document::class);
    }

    public function findAccessibleByUser(User $user): array
    {
        $qb = $this->createQueryBuilder('d');
        
        // Admins see everything
        if (in_array('ROLE_ADMIN', $user->getRoles())) {
            return $qb->getQuery()->getResult();
        }
        
        // Regular users see only their documents and shared ones
        return $qb
            ->where('d.owner = :user')
            ->orWhere(':user MEMBER OF d.sharedWith')
            ->andWhere('d.isPublished = true OR d.owner = :user')
            ->setParameter('user', $user)
            ->getQuery()
            ->getResult();
    }

    public function findEditableByUser(User $user): array
    {
        $qb = $this->createQueryBuilder('d');
        
        if (in_array('ROLE_ADMIN', $user->getRoles())) {
            return $qb->getQuery()->getResult();
        }
        
        return $qb
            ->where('d.owner = :user')
            ->setParameter('user', $user)
            ->getQuery()
            ->getResult();
    }

    public function findByDepartmentIfAuthorized(User $user, string $department): array
    {
        if ($user->getDepartment() !== $department && 
            !in_array('ROLE_ADMIN', $user->getRoles())) {
            return [];
        }
        
        return $this->createQueryBuilder('d')
            ->where('d.department = :department')
            ->andWhere('d.isVisibleToDepartment = true')
            ->setParameter('department', $department)
            ->getQuery()
            ->getResult();
    }
}
```

Filter database queries based on user permissions. Prevent unauthorized  
data access at query level. Different methods for different access  
levels. Admins bypass filters. Combine ownership and sharing checks.  
Never rely solely on client-side filtering. This provides defense  
in depth.  

### Secure API Response Filtering

Filtering API responses based on permissions.  

```php
<?php

namespace App\Serializer;

use App\Entity\User;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Serializer\Normalizer\ContextAwareNormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

class UserNormalizer implements ContextAwareNormalizerInterface
{
    public function __construct(
        private NormalizerInterface $normalizer,
        private AuthorizationCheckerInterface $authChecker
    ) {
    }

    public function normalize($object, ?string $format = null, array $context = []): array
    {
        $data = $this->normalizer->normalize($object, $format, $context);
        
        // Remove sensitive fields for non-admins
        if (!$this->authChecker->isGranted('ROLE_ADMIN')) {
            unset($data['email']);
            unset($data['phone']);
            unset($data['address']);
        }
        
        // Remove roles from response for security
        if (isset($data['roles']) && !$this->authChecker->isGranted('ROLE_SUPER_ADMIN')) {
            unset($data['roles']);
        }
        
        return $data;
    }

    public function supportsNormalization($data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof User;
    }
}
```

```php
<?php

namespace App\Controller\Api;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

class UserApiController extends AbstractController
{
    #[Route('/api/users/{id}', name: 'api_user_show', methods: ['GET'])]
    public function show(User $user): JsonResponse
    {
        // Serializer automatically filters based on permissions
        return $this->json($user, 200, [], [
            'groups' => $this->determineSerializationGroups()
        ]);
    }

    private function determineSerializationGroups(): array
    {
        $groups = ['user:read'];
        
        if ($this->isGranted('ROLE_ADMIN')) {
            $groups[] = 'user:admin';
        }
        
        if ($this->isGranted('ROLE_SUPER_ADMIN')) {
            $groups[] = 'user:super_admin';
        }
        
        return $groups;
    }
}
```

Filter API responses based on user permissions. Remove sensitive fields  
for unauthorized users. Use custom normalizers for complex filtering.  
Combine with serialization groups. Never expose more data than necessary.  
Different groups for different permission levels.  

### IP Whitelist for Admin Access

Restricting admin access by IP address.  

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Security;

#[AsEventListener(event: 'kernel.request', priority: 9)]
class AdminIpWhitelistListener
{
    private array $allowedIps = [
        '127.0.0.1',
        '::1',
        // Add your office IPs here
    ];

    public function __construct(
        private Security $security
    ) {
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        
        // Only check admin routes
        if (!str_starts_with($request->getPathInfo(), '/admin')) {
            return;
        }
        
        // Allow if user is not admin (will be blocked by role check)
        if (!$this->security->isGranted('ROLE_ADMIN')) {
            return;
        }
        
        $clientIp = $request->getClientIp();
        
        if (!in_array($clientIp, $this->allowedIps)) {
            throw new AccessDeniedHttpException(
                'Admin access is restricted to specific IP addresses'
            );
        }
    }
}
```

Restrict sensitive areas by IP address. Combine with role-based checks.  
Use environment variables for IP configuration. Consider VPN requirements  
for remote access. Log blocked access attempts. Update whitelist as  
needed. Provide clear error messages.  

### Email Verification for Registration

Requiring email verification before account activation.  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\EmailVerificationService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class EmailVerificationController extends AbstractController
{
    #[Route('/verify-email/{token}', name: 'verify_email')]
    public function verify(
        string $token,
        EmailVerificationService $verificationService,
        EntityManagerInterface $em
    ): Response {
        $user = $em->getRepository(User::class)
            ->findOneBy(['verificationToken' => $token]);
        
        if (!$user) {
            $this->addFlash('error', 'Invalid verification token');
            return $this->redirectToRoute('app_login');
        }
        
        if ($user->getVerificationTokenExpiresAt() < new \DateTimeImmutable()) {
            $this->addFlash('error', 'Verification token has expired');
            return $this->redirectToRoute('app_login');
        }
        
        $user->setIsVerified(true);
        $user->setVerificationToken(null);
        $user->setVerificationTokenExpiresAt(null);
        $em->flush();
        
        $this->addFlash('success', 'Email verified successfully! You can now log in.');
        return $this->redirectToRoute('app_login');
    }

    #[Route('/resend-verification', name: 'resend_verification')]
    public function resend(
        Request $request,
        EmailVerificationService $verificationService,
        EntityManagerInterface $em
    ): Response {
        $email = $request->request->get('email');
        $user = $em->getRepository(User::class)->findOneBy(['email' => $email]);
        
        if ($user && !$user->isVerified()) {
            $verificationService->sendVerificationEmail($user);
        }
        
        // Always show success to prevent email enumeration
        $this->addFlash('success', 
            'If the email exists and is not verified, a new verification email has been sent.'
        );
        
        return $this->redirectToRoute('app_login');
    }
}
```

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
        private MailerInterface $mailer,
        private UrlGeneratorInterface $urlGenerator,
        private EntityManagerInterface $em
    ) {
    }

    public function sendVerificationEmail(User $user): void
    {
        $token = bin2hex(random_bytes(32));
        $expiresAt = new \DateTimeImmutable('+24 hours');
        
        $user->setVerificationToken($token);
        $user->setVerificationTokenExpiresAt($expiresAt);
        $this->em->flush();
        
        $verifyUrl = $this->urlGenerator->generate(
            'verify_email',
            ['token' => $token],
            UrlGeneratorInterface::ABSOLUTE_URL
        );
        
        $email = (new Email())
            ->to($user->getEmail())
            ->subject('Verify your email address')
            ->html(sprintf(
                'Please click this link to verify your email: <a href="%s">Verify Email</a><br>This link expires in 24 hours.',
                $verifyUrl
            ));
        
        $this->mailer->send($email);
    }
}
```

Require email verification to prevent fake accounts. Generate secure  
random tokens with expiration. Send verification link immediately after  
registration. Prevent login for unverified users. Allow resending  
verification emails. Clear tokens after successful verification.  
Set reasonable expiration (24 hours).  

### Security Testing

Writing security tests for authentication and authorization.  

```php
<?php

namespace App\Tests\Security;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class SecurityTest extends WebTestCase
{
    public function testLoginWithValidCredentials(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/login');
        
        $form = $crawler->selectButton('Sign in')->form([
            '_username' => 'user@example.com',
            '_password' => 'password123',
        ]);
        
        $client->submit($form);
        
        $this->assertResponseRedirects('/dashboard');
    }

    public function testLoginWithInvalidCredentials(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/login');
        
        $form = $crawler->selectButton('Sign in')->form([
            '_username' => 'user@example.com',
            '_password' => 'wrongpassword',
        ]);
        
        $client->submit($form);
        
        $this->assertResponseRedirects('/login');
        $client->followRedirect();
        $this->assertSelectorTextContains('.alert-danger', 'Invalid credentials');
    }

    public function testAdminAreaRequiresAuthentication(): void
    {
        $client = static::createClient();
        $client->request('GET', '/admin');
        
        $this->assertResponseRedirects('/login');
    }

    public function testAdminAreaRequiresAdminRole(): void
    {
        $client = static::createClient();
        
        $user = new User();
        $user->setEmail('user@example.com');
        $user->setRoles(['ROLE_USER']);
        
        $client->loginUser($user);
        $client->request('GET', '/admin');
        
        $this->assertResponseStatusCodeSame(403);
    }

    public function testAdminCanAccessAdminArea(): void
    {
        $client = static::createClient();
        
        $admin = new User();
        $admin->setEmail('admin@example.com');
        $admin->setRoles(['ROLE_ADMIN']);
        
        $client->loginUser($admin);
        $client->request('GET', '/admin');
        
        $this->assertResponseIsSuccessful();
    }

    public function testCsrfProtectionOnForms(): void
    {
        $client = static::createClient();
        
        $client->request('POST', '/comment', [
            'comment' => ['content' => 'Test comment'],
            // Missing CSRF token
        ]);
        
        $this->assertResponseStatusCodeSame(400);
    }

    public function testUserCanOnlyEditOwnPosts(): void
    {
        $client = static::createClient();
        
        $user = new User();
        $user->setEmail('user@example.com');
        $user->setRoles(['ROLE_USER']);
        
        $client->loginUser($user);
        $client->request('GET', '/post/999/edit'); // Post owned by another user
        
        $this->assertResponseStatusCodeSame(403);
    }
}
```

Write comprehensive security tests. Test authentication flows. Verify  
authorization rules. Test CSRF protection. Check role-based access.  
Test resource ownership validation. Use loginUser() helper for  
authenticated tests. Test both success and failure scenarios.  

This comprehensive security guide provides 60 practical examples covering  
all aspects of Symfony security, from basic authentication to advanced  
security patterns. Use these examples as a foundation for building  
secure, production-ready Symfony applications.  

### Security Configuration Validation

Validating security configuration in development.  

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Yaml\Yaml;

#[AsCommand(
    name: 'app:security:validate',
    description: 'Validate security configuration'
)]
class SecurityValidationCommand extends Command
{
    public function __construct(
        private string $projectDir,
        private AuthorizationCheckerInterface $authChecker
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $configFile = $this->projectDir . '/config/packages/security.yaml';
        
        if (!file_exists($configFile)) {
            $io->error('Security configuration file not found');
            return Command::FAILURE;
        }
        
        $config = Yaml::parseFile($configFile);
        $security = $config['security'] ?? [];
        
        $issues = [];
        
        // Check password hasher configuration
        if (!isset($security['password_hashers'])) {
            $issues[] = 'Password hashers not configured';
        }
        
        // Check for CSRF protection in firewalls
        foreach ($security['firewalls'] ?? [] as $name => $firewall) {
            if ($name === 'dev') {
                continue;
            }
            
            if (isset($firewall['form_login']) && 
                (!isset($firewall['form_login']['enable_csrf']) || 
                 $firewall['form_login']['enable_csrf'] !== true)) {
                $issues[] = "CSRF protection not enabled for firewall: {$name}";
            }
            
            if (isset($firewall['remember_me']) && 
                !isset($firewall['remember_me']['secret'])) {
                $issues[] = "Remember me secret not configured for firewall: {$name}";
            }
        }
        
        // Check access control rules
        if (empty($security['access_control'])) {
            $io->warning('No access control rules defined');
        }
        
        // Check role hierarchy
        if (!isset($security['role_hierarchy'])) {
            $io->warning('Role hierarchy not configured');
        }
        
        if (empty($issues)) {
            $io->success('Security configuration validated successfully');
            return Command::SUCCESS;
        }
        
        $io->error('Security configuration issues found:');
        foreach ($issues as $issue) {
            $io->writeln('  - ' . $issue);
        }
        
        return Command::FAILURE;
    }
}
```

```bash
# Run validation command
php bin/console app:security:validate
```

Validate security configuration automatically. Check for common  
misconfigurations. Verify CSRF protection is enabled. Ensure password  
hashers are configured. Check remember me secrets. Validate access  
control rules. Run as part of CI/CD pipeline. Fail builds on security  
issues. This catches configuration problems early in development.  
