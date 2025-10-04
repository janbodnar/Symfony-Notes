# Symfony Framework - 100 Frequently Asked Questions

Symfony is a comprehensive PHP web application framework and a set of  
reusable PHP components designed to build robust, scalable, and  
maintainable web applications and APIs. Created by Fabien Potencier in  
2005, Symfony has evolved into one of the most influential frameworks in  
the PHP ecosystem, powering thousands of applications and serving as the  
foundation for other popular frameworks like Laravel and Drupal.  

## Introduction to Symfony

### Purpose

Symfony provides a structured approach to web development with  
pre-built components for common tasks like routing, security, forms,  
and database abstraction. It promotes best practices, enables code  
reusability, and reduces development time while maintaining high code  
quality and testability.  

### Architecture

Symfony follows a Model-View-Controller (MVC) architectural pattern  
built on several core principles:  

**Component-Based Architecture**: Symfony is composed of independent,  
reusable components that can be used separately or together. Components  
like HttpFoundation, Console, and EventDispatcher are used by many  
other PHP projects.  

**Service Container**: A powerful dependency injection container manages  
object creation and configuration, promoting loose coupling and  
testability.  

**HTTP-Centric Design**: Built around the HTTP specification with  
Request and Response objects at its core, following the HTTP  
request-response cycle.  

**Event-Driven System**: The EventDispatcher component allows different  
parts of the application to communicate through events without tight  
coupling.  

### Core Components

**HttpFoundation**: Object-oriented layer for HTTP specification,  
providing Request, Response, Session, and Cookie objects.  

**Routing**: Maps URLs to controller actions with support for  
parameters, requirements, and HTTP method constraints.  

**Controller**: Handles requests and returns responses, with built-in  
helpers for common tasks like rendering templates and redirects.  

**Templating (Twig)**: Secure, fast, and flexible template engine for  
generating HTML and other text formats.  

**Doctrine ORM**: Database abstraction layer for working with databases  
using objects instead of SQL queries.  

**Security**: Comprehensive authentication and authorization system with  
support for various authentication methods and access control.  

**Form**: Framework for creating, processing, and validating HTML forms  
with automatic CSRF protection.  

**Validation**: Constraint-based validation system for validating data  
against business rules.  

**Console**: Framework for building command-line tools with arguments,  
options, and interactive prompts.  

---

## Installation & Setup

### 1. How do I install Symfony?

Use Composer to create a new Symfony project:  

```bash
# Install Symfony CLI (recommended)
curl -sS https://get.symfony.com/cli/installer | bash

# Create a new web application
symfony new my_project --webapp

# Or create a minimal application
symfony new my_project

# Using Composer directly
composer create-project symfony/skeleton my_project
composer create-project symfony/website-skeleton my_project
```

The `--webapp` flag installs common packages for web applications  
including Twig, Doctrine ORM, security, and forms. The skeleton version  
creates a minimal installation where you add packages as needed.  

### 2. What are the system requirements for Symfony?

Symfony 7.x requires:  

- PHP 8.2 or higher  
- Composer 2.0 or higher  
- PHP extensions: ctype, iconv, PCRE, Session, SimpleXML, Tokenizer  

Optional but recommended:  

- PDO (for database access)  
- Intl extension (for internationalization)  
- APCu extension (for performance)  
- OpenSSL extension (for security features)  

Check requirements with:  

```bash
symfony check:requirements
```

### 3. How do I start the development server?

```bash
# Using Symfony CLI (recommended)
symfony serve

# Or with specific port
symfony serve -d --port=8080

# Using PHP built-in server
php -S localhost:8000 -t public/
```

The Symfony CLI provides additional features like automatic HTTPS,  
environment variable management, and local domain names.  

### 4. What is the directory structure of a Symfony project?

```
my_project/
├── bin/                    # Executable files (console)
├── config/                 # Configuration files
│   ├── packages/          # Bundle configuration
│   ├── routes/            # Routing configuration
│   └── services.yaml      # Service container configuration
├── migrations/            # Database migrations
├── public/                # Web root directory
│   └── index.php         # Front controller
├── src/                   # Application source code
│   ├── Controller/       # Controllers
│   ├── Entity/           # Doctrine entities
│   ├── Form/             # Form types
│   ├── Repository/       # Doctrine repositories
│   └── Kernel.php        # Application kernel
├── templates/             # Twig templates
├── tests/                 # Automated tests
├── translations/          # Translation files
├── var/                   # Cache and logs
│   ├── cache/            # Application cache
│   └── log/              # Application logs
└── vendor/                # Composer dependencies
```

The `src/` directory contains your application code, `config/` holds  
configuration, `templates/` stores Twig templates, and `public/` is the  
web-accessible directory.  

### 5. How do I install additional bundles or packages?

```bash
# Install using Composer
composer require symfony/mailer

# Install development dependencies
composer require --dev symfony/maker-bundle

# Install multiple packages
composer require symfony/orm-pack symfony/validator

# Search for packages
symfony search security

# Remove a package
composer remove symfony/mailer
```

Symfony Flex automatically configures most packages after installation.  

### 6. What is Symfony Flex?

Symfony Flex is a Composer plugin that automates package installation  
and configuration. It:  

- Adds recipes that auto-configure bundles  
- Updates configuration files automatically  
- Manages environment variables  
- Provides package aliases (e.g., `composer require orm` instead of  
  `symfony/orm-pack`)  

When you install a package, Flex executes its recipe to add necessary  
configuration to `config/packages/`, routing to `config/routes/`, and  
environment variables to `.env`.  

### 7. How do I manage environment variables?

Environment variables are stored in `.env` files:  

```bash
# .env - Default values for all environments
APP_ENV=dev
APP_SECRET=changeme
DATABASE_URL="mysql://user:pass@localhost:3306/dbname"

# .env.local - Local overrides (not committed)
DATABASE_URL="mysql://root:root@localhost:3306/myapp"

# .env.prod - Production-specific values
APP_ENV=prod
APP_DEBUG=0
```

Access in code:  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class ConfigController extends AbstractController
{
    public function show(ParameterBagInterface $params): Response
    {
        $env = $params->get('kernel.environment');
        $secret = $_ENV['APP_SECRET'];
        
        return $this->render('config/show.html.twig', [
            'environment' => $env,
        ]);
    }
}
```

Never commit `.env.local` or files containing secrets.  

### 8. How do I configure different environments (dev, test, prod)?

Symfony supports multiple environments through the `APP_ENV` variable:  

```yaml
# config/packages/framework.yaml
framework:
    secret: '%env(APP_SECRET)%'

# config/packages/dev/framework.yaml - Development only
framework:
    profiler: { only_exceptions: false }

# config/packages/prod/framework.yaml - Production only
framework:
    cache:
        app: cache.adapter.apcu
```

Switch environments:  

```bash
# Development
APP_ENV=dev symfony console cache:clear

# Production
APP_ENV=prod symfony console cache:clear
```

Each environment can have its own configuration in  
`config/packages/{env}/`.  

### 9. How do I clear the cache?

```bash
# Clear cache for current environment
php bin/console cache:clear

# Clear cache for specific environment
php bin/console cache:clear --env=prod

# Warm up cache after clearing
php bin/console cache:warmup --env=prod

# Clear only specific cache pool
php bin/console cache:pool:clear cache.app
```

In development, cache is automatically refreshed. In production, clear  
cache after deployment.  

### 10. What is the difference between dev and prod environments?

**Development (dev)**:  

- Debug toolbar and profiler enabled  
- Detailed error messages  
- Cache automatically refreshed  
- Asset compilation on-the-fly  
- Slower performance  

**Production (prod)**:  

- Debug mode disabled  
- Generic error pages  
- Aggressive caching  
- Optimized autoloader  
- Maximum performance  

```yaml
# config/packages/dev/web_profiler.yaml
web_profiler:
    toolbar: true
    intercept_redirects: false

# config/packages/prod/routing.yaml
framework:
    router:
        strict_requirements: null
```

### 11. How do I update Symfony to the latest version?

```bash
# Update all packages
composer update

# Update Symfony packages only
composer update "symfony/*"

# Update to specific version
composer require symfony/framework-bundle:^7.0

# Check for outdated packages
composer outdated "symfony/*"

# Use Symfony's update tool
composer recipes:update
```

Test thoroughly after updates, especially for major version changes.  

### 12. How do I check which version of Symfony I'm using?

```bash
# Using Symfony console
php bin/console about

# Check specific component version
composer show symfony/framework-bundle

# List all Symfony packages
composer show symfony/*
```

The `about` command shows Symfony version, PHP version, environment,  
and debug mode.  


---

## Configuration

### 13. How do I configure services in Symfony?

Services are configured in `config/services.yaml`:  

```yaml
services:
    _defaults:
        autowire: true
        autoconfigure: true

    App\:
        resource: '../src/'
        exclude:
            - '../src/DependencyInjection/'
            - '../src/Entity/'
            - '../src/Kernel.php'

    # Explicit service configuration
    App\Service\MailerService:
        arguments:
            $from: '%env(MAILER_FROM)%'

    # Service with specific configuration
    app.custom_service:
        class: App\Service\CustomService
        arguments:
            $apiKey: '%env(API_KEY)%'
        calls:
            - setLogger: ['@logger']
```

Autowiring automatically resolves dependencies by type-hinting.  

### 14. What is autowiring and autoconfigure?

**Autowiring** automatically injects dependencies based on type-hints:  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;
use Doctrine\ORM\EntityManagerInterface;

class UserService
{
    // Dependencies automatically injected
    public function __construct(
        private LoggerInterface $logger,
        private EntityManagerInterface $em
    ) {
    }
}
```

**Autoconfigure** automatically applies tags based on implemented  
interfaces:  

```yaml
services:
    _defaults:
        autowire: true
        autoconfigure: true  # Automatically tags services
```

For example, EventSubscribers are automatically tagged as event  
subscribers.  

### 15. How do I define parameters?

Parameters store configuration values:  

```yaml
# config/services.yaml
parameters:
    app.admin_email: 'admin@example.com'
    app.items_per_page: 20
    app.upload_dir: '%kernel.project_dir%/public/uploads'

services:
    App\Service\NotificationService:
        arguments:
            $adminEmail: '%app.admin_email%'
```

Access in controllers:  

```php
<?php

$email = $this->getParameter('app.admin_email');
```

Use environment variables for sensitive data.  

### 16. How do I access configuration values in my code?

```php
<?php

namespace App\Service;

use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class ConfigService
{
    public function __construct(
        private ParameterBagInterface $params
    ) {
    }

    public function getUploadDir(): string
    {
        return $this->params->get('app.upload_dir');
    }

    public function isDebug(): bool
    {
        return $this->params->get('kernel.debug');
    }
}
```

Or bind parameters directly:  

```yaml
services:
    _defaults:
        bind:
            $projectDir: '%kernel.project_dir%'
            $uploadDir: '%app.upload_dir%'
```

### 17. How do I configure bundle settings?

Each bundle has its own configuration file in `config/packages/`:  

```yaml
# config/packages/doctrine.yaml
doctrine:
    dbal:
        url: '%env(resolve:DATABASE_URL)%'
    orm:
        auto_generate_proxy_classes: true
        naming_strategy: doctrine.orm.naming_strategy.underscore_number_aware
        auto_mapping: true
        mappings:
            App:
                is_bundle: false
                dir: '%kernel.project_dir%/src/Entity'
                prefix: 'App\Entity'
                alias: App

# config/packages/framework.yaml
framework:
    secret: '%env(APP_SECRET)%'
    csrf_protection: true
    http_method_override: false
    session:
        handler_id: null
        cookie_secure: auto
        cookie_samesite: lax
```

Environment-specific overrides go in  
`config/packages/{env}/bundle_name.yaml`.  

### 18. What is the difference between parameters and environment variables?

**Environment Variables**:  

- Stored in `.env` files  
- Can vary between deployments  
- Used for secrets and deployment-specific values  
- Accessed via `$_ENV` or `%env(VAR_NAME)%`  

**Parameters**:  

- Stored in `config/services.yaml`  
- Part of application configuration  
- Compiled into container  
- Accessed via `$this->getParameter()`  

```yaml
parameters:
    app.items_per_page: 20  # Application constant

services:
    App\Service\ApiClient:
        arguments:
            $apiKey: '%env(API_KEY)%'  # Environment-specific
            $itemsPerPage: '%app.items_per_page%'  # Application constant
```

### 19. How do I create environment-specific configuration?

Create configuration files in environment subdirectories:  

```yaml
# config/packages/monolog.yaml - All environments
monolog:
    channels:
        - deprecation

# config/packages/dev/monolog.yaml - Development only
monolog:
    handlers:
        main:
            type: stream
            path: "%kernel.logs_dir%/%kernel.environment%.log"
            level: debug

# config/packages/prod/monolog.yaml - Production only
monolog:
    handlers:
        main:
            type: fingers_crossed
            action_level: error
            handler: nested
        nested:
            type: stream
            path: php://stderr
            level: debug
```

Files in environment subdirectories override or extend the base  
configuration.  

### 20. How do I use the service container?

Access services in controllers:  

```php
<?php

namespace App\Controller;

use App\Service\MailerService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class EmailController extends AbstractController
{
    // Method 1: Constructor injection (recommended)
    public function __construct(
        private MailerService $mailer
    ) {
    }

    public function send(): Response
    {
        $this->mailer->send('test@example.com', 'Hello there!');
        return new Response('Email sent!');
    }

    // Method 2: Method injection
    #[Route('/send-alternative')]
    public function sendAlternative(MailerService $mailer): Response
    {
        $mailer->send('test@example.com', 'Hello there!');
        return new Response('Email sent!');
    }
}
```

In other services, use constructor injection exclusively.  

### 21. How do I make a service public?

By default, services are private. Make them public if needed:  

```yaml
services:
    App\Service\LegacyService:
        public: true
```

Access public services:  

```php
<?php

$service = $container->get(App\Service\LegacyService::class);
```

Use dependency injection instead of public services when possible.  

### 22. How do I debug service configuration?

```bash
# List all services
php bin/console debug:container

# Search for specific service
php bin/console debug:container mailer

# Show service details
php bin/console debug:container App\Service\MailerService

# Show all parameters
php bin/console debug:container --parameters

# Show environment variables
php bin/console debug:container --env-vars
```

Use `debug:autowiring` to see available autowiring type-hints:  

```bash
php bin/console debug:autowiring
php bin/console debug:autowiring logger
```


---

## Routing

### 23. How do I define routes?

Routes can be defined using attributes (recommended) or YAML:  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProductController extends AbstractController
{
    #[Route('/products', name: 'product_list')]
    public function list(): Response
    {
        return $this->render('product/list.html.twig');
    }

    #[Route('/product/{id}', name: 'product_show', requirements: ['id' => '\d+'])]
    public function show(int $id): Response
    {
        return $this->render('product/show.html.twig', ['id' => $id]);
    }
}
```

YAML alternative:  

```yaml
# config/routes.yaml
product_list:
    path: /products
    controller: App\Controller\ProductController::list

product_show:
    path: /product/{id}
    controller: App\Controller\ProductController::show
    requirements:
        id: '\d+'
```

### 24. How do I generate URLs from routes?

In controllers:  

```php
<?php

// Generate path
$path = $this->generateUrl('product_show', ['id' => 42]);
// Result: /product/42

// Generate absolute URL
$url = $this->generateUrl('product_show', ['id' => 42], UrlGeneratorInterface::ABSOLUTE_URL);
// Result: https://example.com/product/42
```

In Twig templates:  

```twig
{# Generate path #}
<a href="{{ path('product_show', {'id': 42}) }}">View Product</a>

{# Generate absolute URL #}
<a href="{{ url('product_show', {'id': 42}) }}">View Product</a>
```

In services:  

```php
<?php

use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class NotificationService
{
    public function __construct(
        private UrlGeneratorInterface $router
    ) {
    }

    public function getProductUrl(int $id): string
    {
        return $this->router->generate('product_show', ['id' => $id]);
    }
}
```

### 25. How do I use route parameters?

```php
<?php

#[Route('/blog/{slug}', name: 'blog_post')]
public function show(string $slug): Response
{
    // $slug is automatically extracted from URL
}

#[Route('/archive/{year}/{month}', name: 'archive')]
public function archive(int $year, int $month): Response
{
    // Multiple parameters
}

#[Route('/user/{id}', name: 'user_profile', requirements: ['id' => '\d+'])]
public function profile(int $id): Response
{
    // Parameter with regex requirement
}

#[Route('/category/{name}', name: 'category', defaults: ['name' => 'general'])]
public function category(string $name): Response
{
    // Optional parameter with default value
}
```

Parameters are automatically type-converted based on method signature.  

### 26. How do I add route requirements?

Requirements use regex patterns to validate parameters:  

```php
<?php

// Digits only
#[Route('/page/{page}', requirements: ['page' => '\d+'])]
public function paginated(int $page): Response { }

// Alphanumeric with hyphens
#[Route('/post/{slug}', requirements: ['slug' => '[a-z0-9-]+'])]
public function post(string $slug): Response { }

// Date format
#[Route('/archive/{date}', requirements: ['date' => '\d{4}-\d{2}-\d{2}'])]
public function archive(string $date): Response { }

// Multiple requirements
#[Route(
    '/article/{year}/{month}/{slug}',
    requirements: [
        'year' => '\d{4}',
        'month' => '\d{2}',
        'slug' => '[a-z0-9-]+'
    ]
)]
public function article(int $year, int $month, string $slug): Response { }
```

If URL doesn't match requirements, route is not matched.  

### 27. How do I restrict routes to specific HTTP methods?

```php
<?php

// Single method
#[Route('/api/users', name: 'api_users_create', methods: ['POST'])]
public function create(): Response { }

// Multiple methods
#[Route('/api/users/{id}', name: 'api_users_update', methods: ['PUT', 'PATCH'])]
public function update(int $id): Response { }

// Different methods, same path
#[Route('/api/resource', name: 'api_resource_list', methods: ['GET'])]
public function list(): Response { }

#[Route('/api/resource', name: 'api_resource_create', methods: ['POST'])]
public function create(): Response { }
```

Requesting with wrong method returns 405 Method Not Allowed.  

### 28. How do I use route prefixes?

Apply a prefix to all routes in a controller:  

```php
<?php

#[Route('/admin')]
class AdminController extends AbstractController
{
    #[Route('/dashboard', name: 'admin_dashboard')]
    public function dashboard(): Response
    {
        // URL: /admin/dashboard
    }

    #[Route('/users', name: 'admin_users')]
    public function users(): Response
    {
        // URL: /admin/users
    }
}
```

Or in YAML:  

```yaml
# config/routes/admin.yaml
admin:
    resource: '../src/Controller/Admin/'
    type: attribute
    prefix: /admin
```

### 29. How do I debug routes?

```bash
# List all routes
php bin/console debug:router

# Search for specific route
php bin/console debug:router product

# Show route details
php bin/console debug:router product_show

# Match URL to route
php bin/console router:match /product/123

# Show routes for specific controller
php bin/console debug:router --show-controllers
```

### 30. How do I redirect to another route?

```php
<?php

// Redirect to route
return $this->redirectToRoute('product_list');

// Redirect with parameters
return $this->redirectToRoute('product_show', ['id' => 42]);

// Redirect with status code
return $this->redirectToRoute('product_show', ['id' => 42], 301);

// Redirect to URL
return $this->redirect('https://example.com');

// Permanent redirect
return $this->redirectToRoute('new_route', [], 301);
```

### 31. How do I create multi-language routes?

```php
<?php

#[Route(
    path: [
        'en' => '/about',
        'fr' => '/a-propos',
        'de' => '/uber-uns'
    ],
    name: 'about'
)]
public function about(): Response
{
    return $this->render('about.html.twig');
}
```

Or use route prefixes:  

```yaml
# config/routes.yaml
app_en:
    resource: '../src/Controller/'
    type: attribute
    prefix: /{_locale}
    requirements:
        _locale: en|fr|de
    defaults:
        _locale: en
```

### 32. How do I handle trailing slashes in URLs?

Configure trailing slash behavior:  

```yaml
# config/packages/routing.yaml
framework:
    router:
        strict_requirements: ~
        utf8: true
```

Or use route configuration:  

```php
<?php

// Redirect /blog/ to /blog
#[Route('/blog', name: 'blog')]
public function blog(): Response { }

// Allow both with and without trailing slash
#[Route('/blog/{page}', name: 'blog_page', requirements: ['page' => '\d+'])]
#[Route('/blog/{page}/', name: 'blog_page_slash', requirements: ['page' => '\d+'])]
public function page(int $page): Response { }
```


---

## Controllers

### 33. How do I create a controller?

```bash
# Using Maker Bundle
php bin/console make:controller ProductController
```

Manual creation:  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProductController extends AbstractController
{
    #[Route('/products', name: 'product_list')]
    public function list(): Response
    {
        return $this->render('product/list.html.twig', [
            'products' => [],
        ]);
    }
}
```

Controllers extending `AbstractController` gain access to helper  
methods like `render()`, `redirectToRoute()`, and `json()`.  

### 34. How do I return JSON responses?

```php
<?php

#[Route('/api/products', name: 'api_products')]
public function apiList(): JsonResponse
{
    $products = [
        ['id' => 1, 'name' => 'Product 1', 'price' => 29.99],
        ['id' => 2, 'name' => 'Product 2', 'price' => 39.99],
    ];

    return $this->json($products);
}

// With status code and headers
#[Route('/api/product/{id}', name: 'api_product')]
public function apiShow(int $id): JsonResponse
{
    $product = ['id' => $id, 'name' => 'Product ' . $id];

    return $this->json($product, 200, [
        'Content-Type' => 'application/json',
        'X-Custom-Header' => 'value'
    ]);
}

// With serialization groups
#[Route('/api/users', name: 'api_users')]
public function users(): JsonResponse
{
    $users = $this->userRepository->findAll();

    return $this->json($users, 200, [], [
        'groups' => ['user:read']
    ]);
}
```

### 35. How do I access request data?

```php
<?php

use Symfony\Component\HttpFoundation\Request;

#[Route('/form', name: 'form_submit', methods: ['POST'])]
public function submit(Request $request): Response
{
    // Query parameters ($_GET)
    $page = $request->query->get('page', 1);

    // POST data
    $email = $request->request->get('email');

    // All POST data
    $formData = $request->request->all();

    // Headers
    $contentType = $request->headers->get('Content-Type');

    // Cookies
    $sessionId = $request->cookies->get('PHPSESSID');

    // Files
    $uploadedFile = $request->files->get('document');

    // JSON content
    $data = $request->toArray(); // PHP 8.1+

    // Raw content
    $content = $request->getContent();

    // Server variables
    $userAgent = $request->server->get('HTTP_USER_AGENT');

    return $this->json(['status' => 'received']);
}
```

### 36. How do I use dependency injection in controllers?

```php
<?php

namespace App\Controller;

use App\Service\ProductService;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;

class ProductController extends AbstractController
{
    // Constructor injection (recommended for multiple dependencies)
    public function __construct(
        private ProductService $productService,
        private EntityManagerInterface $em,
        private LoggerInterface $logger
    ) {
    }

    #[Route('/products', name: 'product_list')]
    public function list(): Response
    {
        $products = $this->productService->getAll();
        $this->logger->info('Listed products', ['count' => count($products)]);

        return $this->render('product/list.html.twig', [
            'products' => $products,
        ]);
    }

    // Method injection (for single action)
    #[Route('/product/{id}', name: 'product_show')]
    public function show(int $id, ProductService $service): Response
    {
        $product = $service->find($id);

        return $this->render('product/show.html.twig', [
            'product' => $product,
        ]);
    }
}
```

### 37. How do I render templates?

```php
<?php

// Basic template rendering
#[Route('/home', name: 'home')]
public function home(): Response
{
    return $this->render('home.html.twig');
}

// With variables
#[Route('/profile/{username}', name: 'profile')]
public function profile(string $username): Response
{
    return $this->render('profile.html.twig', [
        'username' => $username,
        'joinedDate' => new \DateTime('2023-01-15'),
    ]);
}

// Render string
#[Route('/email-preview', name: 'email_preview')]
public function emailPreview(): Response
{
    $html = $this->renderView('email/welcome.html.twig', [
        'name' => 'John',
    ]);

    return new Response($html);
}
```

### 38. How do I handle forms in controllers?

```php
<?php

use App\Entity\Product;
use App\Form\ProductType;
use Symfony\Component\HttpFoundation\Request;

#[Route('/product/new', name: 'product_new')]
public function new(Request $request, EntityManagerInterface $em): Response
{
    $product = new Product();
    $form = $this->createForm(ProductType::class, $product);

    $form->handleRequest($request);

    if ($form->isSubmitted() && $form->isValid()) {
        $em->persist($product);
        $em->flush();

        $this->addFlash('success', 'Product created!');

        return $this->redirectToRoute('product_show', [
            'id' => $product->getId()
        ]);
    }

    return $this->render('product/new.html.twig', [
        'form' => $form,
    ]);
}
```

### 39. How do I use flash messages?

```php
<?php

// Add flash message
$this->addFlash('success', 'Operation completed successfully!');
$this->addFlash('error', 'An error occurred.');
$this->addFlash('warning', 'Please review your input.');
$this->addFlash('info', 'Information message.');

// Add multiple messages of same type
$this->addFlash('success', 'First success message');
$this->addFlash('success', 'Second success message');

// In controller action
#[Route('/user/delete/{id}', name: 'user_delete')]
public function delete(int $id): Response
{
    // Delete user logic...

    $this->addFlash('success', 'User deleted successfully!');

    return $this->redirectToRoute('user_list');
}
```

Display in Twig:  

```twig
{% for message in app.flashes('success') %}
    <div class="alert alert-success">{{ message }}</div>
{% endfor %}

{% for label, messages in app.flashes %}
    {% for message in messages %}
        <div class="alert alert-{{ label }}">{{ message }}</div>
    {% endfor %}
{% endfor %}
```

### 40. How do I use ParamConverter?

ParamConverter automatically converts route parameters to objects:  

```php
<?php

use App\Entity\Product;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\ParamConverter;

// Automatic conversion (by ID)
#[Route('/product/{id}', name: 'product_show')]
public function show(Product $product): Response
{
    // $product automatically loaded by ID
    return $this->render('product/show.html.twig', [
        'product' => $product,
    ]);
}

// By custom property
#[Route('/product/slug/{slug}', name: 'product_by_slug')]
public function showBySlug(Product $product): Response
{
    // Automatically finds product by slug
    return $this->render('product/show.html.twig', [
        'product' => $product,
    ]);
}

// Multiple conversions
#[Route('/category/{categoryId}/product/{productId}')]
public function categoryProduct(
    #[MapEntity(id: 'categoryId')] Category $category,
    #[MapEntity(id: 'productId')] Product $product
): Response
{
    return $this->render('product/category_product.html.twig', [
        'category' => $category,
        'product' => $product,
    ]);
}
```

Returns 404 if entity not found.  

### 41. How do I handle file uploads?

```php
<?php

use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;

#[Route('/upload', name: 'file_upload', methods: ['POST'])]
public function upload(Request $request, string $uploadDir): Response
{
    /** @var UploadedFile $file */
    $file = $request->files->get('document');

    if ($file) {
        $originalFilename = pathinfo(
            $file->getClientOriginalName(),
            PATHINFO_FILENAME
        );

        $safeFilename = transliterator_transliterate(
            'Any-Latin; Latin-ASCII; [^A-Za-z0-9_] remove; Lower()',
            $originalFilename
        );

        $newFilename = $safeFilename . '-' . uniqid() . '.' . $file->guessExtension();

        try {
            $file->move($uploadDir, $newFilename);
        } catch (FileException $e) {
            $this->addFlash('error', 'Upload failed');
        }

        $this->addFlash('success', 'File uploaded successfully!');
    }

    return $this->redirectToRoute('file_list');
}
```

### 42. How do I create error pages?

Override default error templates:  

```twig
{# templates/bundles/TwigBundle/Exception/error404.html.twig #}
{% extends 'base.html.twig' %}

{% block title %}Page Not Found{% endblock %}

{% block body %}
    <h1>Page Not Found</h1>
    <p>The page you requested could not be found.</p>
    <a href="{{ path('home') }}">Return Home</a>
{% endblock %}

{# templates/bundles/TwigBundle/Exception/error.html.twig #}
{# Generic error page for all status codes #}
{% extends 'base.html.twig' %}

{% block title %}Error {{ status_code }}{% endblock %}

{% block body %}
    <h1>An Error Occurred</h1>
    <p>{{ status_text }}</p>
{% endblock %}
```

In controllers:  

```php
<?php

// Throw 404
throw $this->createNotFoundException('Product not found');

// Custom status code
throw new HttpException(403, 'Access denied');
```


---

## Doctrine & Database

### 43. How do I configure database connection?

Configure database in `.env`:  

```bash
# MySQL
DATABASE_URL="mysql://user:password@localhost:3306/database_name?serverVersion=8.0"

# PostgreSQL
DATABASE_URL="postgresql://user:password@localhost:5432/database_name?serverVersion=15&charset=utf8"

# SQLite
DATABASE_URL="sqlite:///%kernel.project_dir%/var/data.db"
```

Doctrine configuration in `config/packages/doctrine.yaml`:  

```yaml
doctrine:
    dbal:
        url: '%env(resolve:DATABASE_URL)%'
        profiling_collect_backtrace: '%kernel.debug%'
    orm:
        auto_generate_proxy_classes: true
        enable_lazy_ghost_objects: true
        naming_strategy: doctrine.orm.naming_strategy.underscore_number_aware
        auto_mapping: true
        mappings:
            App:
                is_bundle: false
                dir: '%kernel.project_dir%/src/Entity'
                prefix: 'App\Entity'
                alias: App
```

### 44. How do I create an entity?

```bash
# Using Maker Bundle
php bin/console make:entity Product
```

Manual creation:  

```php
<?php

namespace App\Entity;

use App\Repository\ProductRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: ProductRepository::class)]
#[ORM\Table(name: 'products')]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $name = null;

    #[ORM\Column(type: 'text', nullable: true)]
    private ?string $description = null;

    #[ORM\Column(type: 'decimal', precision: 10, scale: 2)]
    private ?string $price = null;

    #[ORM\Column(type: 'datetime_immutable')]
    private ?\DateTimeImmutable $createdAt = null;

    public function __construct()
    {
        $this->createdAt = new \DateTimeImmutable();
    }

    // Getters and setters...
    public function getId(): ?int
    {
        return $this->id;
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): self
    {
        $this->name = $name;
        return $this;
    }
}
```

### 45. How do I create and run migrations?

```bash
# Create migration from entity changes
php bin/console make:migration

# Review the generated migration file in migrations/
# Then execute the migration
php bin/console doctrine:migrations:migrate

# Check migration status
php bin/console doctrine:migrations:status

# Rollback last migration
php bin/console doctrine:migrations:migrate prev

# Execute specific migration
php bin/console doctrine:migrations:execute 'DoctrineMigrations\Version20231201120000' --up
```

Migration example:  

```php
<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20231201120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Create products table';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('CREATE TABLE products (
            id INT AUTO_INCREMENT NOT NULL,
            name VARCHAR(255) NOT NULL,
            price NUMERIC(10, 2) NOT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY(id)
        ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE products');
    }
}
```

### 46. How do I persist and retrieve data?

```php
<?php

use App\Entity\Product;
use Doctrine\ORM\EntityManagerInterface;

class ProductController extends AbstractController
{
    #[Route('/product/new', name: 'product_new')]
    public function new(EntityManagerInterface $em): Response
    {
        $product = new Product();
        $product->setName('Laptop');
        $product->setPrice('999.99');

        // Persist (mark for insertion)
        $em->persist($product);

        // Execute the query
        $em->flush();

        return $this->redirectToRoute('product_show', [
            'id' => $product->getId()
        ]);
    }

    #[Route('/product/{id}', name: 'product_show')]
    public function show(int $id, EntityManagerInterface $em): Response
    {
        $product = $em->getRepository(Product::class)->find($id);

        if (!$product) {
            throw $this->createNotFoundException('Product not found');
        }

        return $this->render('product/show.html.twig', [
            'product' => $product,
        ]);
    }

    #[Route('/product/{id}/edit', name: 'product_edit')]
    public function edit(int $id, EntityManagerInterface $em): Response
    {
        $product = $em->getRepository(Product::class)->find($id);
        $product->setPrice('1099.99');

        // No need to persist, entity already managed
        $em->flush();

        return $this->redirectToRoute('product_show', ['id' => $id]);
    }

    #[Route('/product/{id}/delete', name: 'product_delete')]
    public function delete(int $id, EntityManagerInterface $em): Response
    {
        $product = $em->getRepository(Product::class)->find($id);

        $em->remove($product);
        $em->flush();

        return $this->redirectToRoute('product_list');
    }
}
```

### 47. How do I create custom repository methods?

```php
<?php

namespace App\Repository;

use App\Entity\Product;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class ProductRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Product::class);
    }

    public function findByPriceRange(float $min, float $max): array
    {
        return $this->createQueryBuilder('p')
            ->where('p.price >= :min')
            ->andWhere('p.price <= :max')
            ->setParameter('min', $min)
            ->setParameter('max', $max)
            ->orderBy('p.price', 'ASC')
            ->getQuery()
            ->getResult();
    }

    public function findActiveProducts(): array
    {
        return $this->createQueryBuilder('p')
            ->where('p.active = :active')
            ->setParameter('active', true)
            ->orderBy('p.createdAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    public function findOneBySlug(string $slug): ?Product
    {
        return $this->createQueryBuilder('p')
            ->where('p.slug = :slug')
            ->setParameter('slug', $slug)
            ->getQuery()
            ->getOneOrNullResult();
    }

    public function countByCategory(string $category): int
    {
        return $this->createQueryBuilder('p')
            ->select('COUNT(p.id)')
            ->where('p.category = :category')
            ->setParameter('category', $category)
            ->getQuery()
            ->getSingleScalarResult();
    }
}
```

Use in controllers:  

```php
<?php

#[Route('/products/expensive', name: 'expensive_products')]
public function expensive(ProductRepository $repository): Response
{
    $products = $repository->findByPriceRange(1000, 5000);

    return $this->render('product/list.html.twig', [
        'products' => $products,
    ]);
}
```

### 48. How do I define entity relationships?

**One-to-Many**:  

```php
<?php

// Category.php
#[ORM\Entity]
class Category
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $name = null;

    #[ORM\OneToMany(targetEntity: Product::class, mappedBy: 'category')]
    private Collection $products;

    public function __construct()
    {
        $this->products = new ArrayCollection();
    }

    public function getProducts(): Collection
    {
        return $this->products;
    }
}

// Product.php
#[ORM\Entity]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(targetEntity: Category::class, inversedBy: 'products')]
    #[ORM\JoinColumn(nullable: false)]
    private ?Category $category = null;

    public function getCategory(): ?Category
    {
        return $this->category;
    }

    public function setCategory(?Category $category): self
    {
        $this->category = $category;
        return $this;
    }
}
```

**Many-to-Many**:  

```php
<?php

// Product.php
#[ORM\Entity]
class Product
{
    #[ORM\ManyToMany(targetEntity: Tag::class, inversedBy: 'products')]
    #[ORM\JoinTable(name: 'product_tags')]
    private Collection $tags;

    public function __construct()
    {
        $this->tags = new ArrayCollection();
    }

    public function addTag(Tag $tag): self
    {
        if (!$this->tags->contains($tag)) {
            $this->tags->add($tag);
        }
        return $this;
    }

    public function removeTag(Tag $tag): self
    {
        $this->tags->removeElement($tag);
        return $this;
    }
}

// Tag.php
#[ORM\Entity]
class Tag
{
    #[ORM\ManyToMany(targetEntity: Product::class, mappedBy: 'tags')]
    private Collection $products;
}
```

### 49. How do I use DQL (Doctrine Query Language)?

```php
<?php

use Doctrine\ORM\EntityManagerInterface;

class ProductService
{
    public function __construct(
        private EntityManagerInterface $em
    ) {
    }

    public function findExpensiveProducts(): array
    {
        $dql = 'SELECT p FROM App\Entity\Product p WHERE p.price > :price ORDER BY p.price DESC';

        $query = $this->em->createQuery($dql);
        $query->setParameter('price', 1000);

        return $query->getResult();
    }

    public function findProductsWithCategory(): array
    {
        $dql = 'SELECT p, c FROM App\Entity\Product p JOIN p.category c WHERE c.active = :active';

        $query = $this->em->createQuery($dql);
        $query->setParameter('active', true);

        return $query->getResult();
    }

    public function findProductCount(): int
    {
        $dql = 'SELECT COUNT(p.id) FROM App\Entity\Product p WHERE p.active = :active';

        $query = $this->em->createQuery($dql);
        $query->setParameter('active', true);

        return $query->getSingleScalarResult();
    }

    public function updatePrices(float $multiplier): void
    {
        $dql = 'UPDATE App\Entity\Product p SET p.price = p.price * :multiplier';

        $query = $this->em->createQuery($dql);
        $query->setParameter('multiplier', $multiplier);
        $query->execute();
    }
}
```

### 50. How do I implement pagination?

Using QueryBuilder:  

```php
<?php

use Doctrine\ORM\Tools\Pagination\Paginator;

public function findPaginated(int $page = 1, int $limit = 10): Paginator
{
    $query = $this->createQueryBuilder('p')
        ->orderBy('p.createdAt', 'DESC')
        ->setFirstResult(($page - 1) * $limit)
        ->setMaxResults($limit)
        ->getQuery();

    return new Paginator($query);
}
```

In controller:  

```php
<?php

#[Route('/products/page/{page}', name: 'product_list', requirements: ['page' => '\d+'])]
public function list(int $page = 1, ProductRepository $repository): Response
{
    $paginator = $repository->findPaginated($page, 20);

    $totalItems = count($paginator);
    $totalPages = ceil($totalItems / 20);

    return $this->render('product/list.html.twig', [
        'products' => $paginator,
        'currentPage' => $page,
        'totalPages' => $totalPages,
    ]);
}
```

### 51. How do I use database fixtures?

Install DoctrineFixturesBundle:  

```bash
composer require --dev orm-fixtures
```

Create fixtures:  

```php
<?php

namespace App\DataFixtures;

use App\Entity\Product;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;

class ProductFixtures extends Fixture
{
    public function load(ObjectManager $manager): void
    {
        for ($i = 1; $i <= 10; $i++) {
            $product = new Product();
            $product->setName('Product ' . $i);
            $product->setPrice(rand(10, 1000) . '.99');

            $manager->persist($product);
        }

        $manager->flush();
    }
}
```

Load fixtures:  

```bash
# Load fixtures (clears database first)
php bin/console doctrine:fixtures:load

# Append without clearing
php bin/console doctrine:fixtures:load --append
```

### 52. How do I optimize Doctrine performance?

```php
<?php

// 1. Use eager loading to avoid N+1 queries
$products = $repository->createQueryBuilder('p')
    ->leftJoin('p.category', 'c')
    ->addSelect('c')
    ->getQuery()
    ->getResult();

// 2. Use partial objects for read-only data
$products = $repository->createQueryBuilder('p')
    ->select('partial p.{id, name, price}')
    ->getQuery()
    ->getResult();

// 3. Use query result cache
$query = $repository->createQueryBuilder('p')
    ->where('p.active = :active')
    ->setParameter('active', true)
    ->getQuery();

$query->enableResultCache(3600, 'active_products');
$products = $query->getResult();

// 4. Batch processing for large datasets
$batchSize = 20;
for ($i = 1; $i <= 1000; $i++) {
    $product = new Product();
    $product->setName('Product ' . $i);

    $em->persist($product);

    if (($i % $batchSize) === 0) {
        $em->flush();
        $em->clear();
    }
}
$em->flush();
$em->clear();

// 5. Use indexes
#[ORM\Entity]
#[ORM\Index(columns: ['created_at'])]
#[ORM\Index(columns: ['category_id', 'active'])]
class Product
{
    // ...
}
```

### 53. How do I handle transactions?

```php
<?php

use Doctrine\ORM\EntityManagerInterface;

public function transferFunds(
    int $fromAccountId,
    int $toAccountId,
    float $amount,
    EntityManagerInterface $em
): void
{
    $em->beginTransaction();

    try {
        $fromAccount = $em->find(Account::class, $fromAccountId);
        $toAccount = $em->find(Account::class, $toAccountId);

        $fromAccount->withdraw($amount);
        $toAccount->deposit($amount);

        $em->flush();
        $em->commit();
    } catch (\Exception $e) {
        $em->rollback();
        throw $e;
    }
}

// Alternative: using transactional
public function transferFundsTransactional(
    int $fromAccountId,
    int $toAccountId,
    float $amount,
    EntityManagerInterface $em
): void
{
    $em->transactional(function($em) use ($fromAccountId, $toAccountId, $amount) {
        $fromAccount = $em->find(Account::class, $fromAccountId);
        $toAccount = $em->find(Account::class, $toAccountId);

        $fromAccount->withdraw($amount);
        $toAccount->deposit($amount);
    });
}
```

### 54. How do I work with raw SQL queries?

```php
<?php

use Doctrine\DBAL\Connection;

class ReportService
{
    public function __construct(
        private Connection $connection
    ) {
    }

    public function getMonthlyRevenue(int $year, int $month): array
    {
        $sql = 'SELECT DATE(created_at) as date, SUM(amount) as revenue
                FROM orders
                WHERE YEAR(created_at) = :year AND MONTH(created_at) = :month
                GROUP BY DATE(created_at)
                ORDER BY date';

        $stmt = $this->connection->prepare($sql);
        $result = $stmt->executeQuery([
            'year' => $year,
            'month' => $month,
        ]);

        return $result->fetchAllAssociative();
    }

    public function updateProductPrices(float $multiplier): int
    {
        $sql = 'UPDATE products SET price = price * :multiplier WHERE active = 1';

        $stmt = $this->connection->prepare($sql);

        return $stmt->executeStatement(['multiplier' => $multiplier]);
    }
}
```


---

## Security

### 55. How do I create a User entity for authentication?

```bash
php bin/console make:user
```

This creates:  

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

### 56. How do I implement login functionality?

```bash
# Create login form
php bin/console make:security:form-login
```

Configure security:  

```yaml
# config/packages/security.yaml
security:
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'

    providers:
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        main:
            lazy: true
            provider: app_user_provider
            form_login:
                login_path: app_login
                check_path: app_login
                enable_csrf: true
            logout:
                path: app_logout
                target: app_home

    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN }
        - { path: ^/profile, roles: ROLE_USER }
```

Login controller:  

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
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}
```

### 57. How do I hash passwords?

```php
<?php

use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class RegistrationController extends AbstractController
{
    #[Route('/register', name: 'app_register')]
    public function register(
        Request $request,
        UserPasswordHasherInterface $passwordHasher,
        EntityManagerInterface $em
    ): Response
    {
        $user = new User();
        $form = $this->createForm(RegistrationFormType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $hashedPassword = $passwordHasher->hashPassword(
                $user,
                $form->get('plainPassword')->getData()
            );

            $user->setPassword($hashedPassword);

            $em->persist($user);
            $em->flush();

            return $this->redirectToRoute('app_login');
        }

        return $this->render('registration/register.html.twig', [
            'registrationForm' => $form,
        ]);
    }
}
```

Hash password from command line:  

```bash
php bin/console security:hash-password
```

### 58. How do I restrict access to controllers?

Using attributes:  

```php
<?php

use Symfony\Component\Security\Http\Attribute\IsGranted;

// Entire controller
#[IsGranted('ROLE_ADMIN')]
class AdminController extends AbstractController
{
    #[Route('/admin/dashboard', name: 'admin_dashboard')]
    public function dashboard(): Response
    {
        return $this->render('admin/dashboard.html.twig');
    }
}

// Individual action
class UserController extends AbstractController
{
    #[Route('/user/delete/{id}', name: 'user_delete')]
    #[IsGranted('ROLE_ADMIN')]
    public function delete(int $id): Response
    {
        // Only admins can access
    }

    // Check specific object permissions
    #[Route('/post/{id}/edit', name: 'post_edit')]
    #[IsGranted('EDIT', 'post')]
    public function edit(Post $post): Response
    {
        // User must have EDIT permission on this specific post
    }
}
```

In controller methods:  

```php
<?php

public function show(): Response
{
    // Deny access if user doesn't have ROLE_ADMIN
    $this->denyAccessUnlessGranted('ROLE_ADMIN');

    // Deny access with custom message
    $this->denyAccessUnlessGranted('ROLE_ADMIN', null, 'Access Denied');

    // Check permission and handle manually
    if (!$this->isGranted('ROLE_ADMIN')) {
        throw $this->createAccessDeniedException();
    }
}
```

### 59. How do I check user permissions?

In controllers:  

```php
<?php

// Check single role
if ($this->isGranted('ROLE_ADMIN')) {
    // User is admin
}

// Check multiple roles
if ($this->isGranted('ROLE_ADMIN') || $this->isGranted('ROLE_EDITOR')) {
    // User is admin or editor
}

// Check object-level permission
$post = $repository->find($id);
if ($this->isGranted('EDIT', $post)) {
    // User can edit this post
}
```

In Twig templates:  

```twig
{% if is_granted('ROLE_ADMIN') %}
    <a href="{{ path('admin_dashboard') }}">Admin Panel</a>
{% endif %}

{% if is_granted('EDIT', post) %}
    <a href="{{ path('post_edit', {id: post.id}) }}">Edit</a>
{% endif %}

{# Check if user is authenticated #}
{% if is_granted('IS_AUTHENTICATED_FULLY') %}
    <p>Welcome, {{ app.user.email }}</p>
{% endif %}
```

In services:  

```php
<?php

use Symfony\Bundle\SecurityBundle\Security;

class PostService
{
    public function __construct(
        private Security $security
    ) {
    }

    public function canEdit(Post $post): bool
    {
        return $this->security->isGranted('EDIT', $post);
    }

    public function getCurrentUser(): ?User
    {
        return $this->security->getUser();
    }
}
```

### 60. How do I implement custom voters?

Create a voter for custom authorization logic:  

```php
<?php

namespace App\Security\Voter;

use App\Entity\Post;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class PostVoter extends Voter
{
    const VIEW = 'VIEW';
    const EDIT = 'EDIT';
    const DELETE = 'DELETE';

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
    ): bool
    {
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
            default => throw new \LogicException('This code should not be reached!')
        };
    }

    private function canView(Post $post, User $user): bool
    {
        // Anyone can view published posts
        if ($post->isPublished()) {
            return true;
        }

        // Only author can view unpublished posts
        return $post->getAuthor() === $user;
    }

    private function canEdit(Post $post, User $user): bool
    {
        // Author can edit
        return $post->getAuthor() === $user;
    }

    private function canDelete(Post $post, User $user): bool
    {
        // Only author or admin can delete
        return $post->getAuthor() === $user || 
               in_array('ROLE_ADMIN', $user->getRoles());
    }
}
```

Use the voter:  

```php
<?php

$this->denyAccessUnlessGranted('EDIT', $post);
```

### 61. How do I get the current user?

In controllers:  

```php
<?php

public function profile(): Response
{
    // Method 1: Using getUser()
    $user = $this->getUser();

    if (!$user) {
        throw $this->createAccessDeniedException();
    }

    return $this->render('user/profile.html.twig', [
        'user' => $user,
    ]);
}

// Method 2: Type-hint in method
public function dashboard(#[CurrentUser] ?User $user): Response
{
    if (!$user) {
        throw $this->createAccessDeniedException();
    }

    return $this->render('user/dashboard.html.twig', [
        'user' => $user,
    ]);
}
```

In services:  

```php
<?php

use Symfony\Bundle\SecurityBundle\Security;

class UserService
{
    public function __construct(
        private Security $security
    ) {
    }

    public function getCurrentUserEmail(): ?string
    {
        $user = $this->security->getUser();

        if (!$user instanceof User) {
            return null;
        }

        return $user->getEmail();
    }
}
```

In Twig:  

```twig
{% if app.user %}
    <p>Hello, {{ app.user.email }}</p>
{% endif %}
```

### 62. How do I implement Remember Me functionality?

Configure in `security.yaml`:  

```yaml
security:
    firewalls:
        main:
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800 # 1 week in seconds
                path: /
                always_remember_me: false
```

In login form:  

```twig
<form method="post">
    <input type="email" name="_username" required>
    <input type="password" name="_password" required>

    <label>
        <input type="checkbox" name="_remember_me"> Remember me
    </label>

    <button type="submit">Login</button>
</form>
```

### 63. How do I implement CSRF protection?

CSRF protection is enabled by default for forms:  

```yaml
# config/packages/framework.yaml
framework:
    csrf_protection: true
```

Forms automatically include CSRF tokens:  

```twig
{{ form_start(form) }}
    {# CSRF token automatically included #}
    {{ form_widget(form) }}
    <button type="submit">Submit</button>
{{ form_end(form) }}
```

For custom forms:  

```twig
<form method="post">
    <input type="text" name="username">

    <input type="hidden" name="_csrf_token"
           value="{{ csrf_token('authenticate') }}">

    <button type="submit">Submit</button>
</form>
```

Validate in controller:  

```php
<?php

use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;

public function submit(
    Request $request,
    CsrfTokenManagerInterface $csrfTokenManager
): Response
{
    $token = new CsrfToken('authenticate', $request->request->get('_csrf_token'));

    if (!$csrfTokenManager->isTokenValid($token)) {
        throw new \Exception('Invalid CSRF token');
    }

    // Process form
}
```

### 64. How do I implement API authentication with tokens?

Using API tokens:  

```yaml
# config/packages/security.yaml
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            custom_authenticators:
                - App\Security\ApiTokenAuthenticator
```

Create authenticator:  

```php
<?php

namespace App\Security;

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
            new UserBadge($apiToken, function($apiToken) {
                // Load user by API token
                return $this->userRepository->findOneBy(['apiToken' => $apiToken]);
            })
        );
    }

    public function onAuthenticationSuccess(
        Request $request,
        TokenInterface $token,
        string $firewallName
    ): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(
        Request $request,
        AuthenticationException $exception
    ): ?Response
    {
        return new JsonResponse([
            'message' => 'Authentication failed'
        ], Response::HTTP_UNAUTHORIZED);
    }
}
```


---

## Forms

### 65. How do I create a form?

```bash
php bin/console make:form ProductType
```

Creates a form class:  

```php
<?php

namespace App\Form;

use App\Entity\Product;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\MoneyType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class ProductType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('name', TextType::class, [
                'label' => 'Product Name',
                'required' => true,
            ])
            ->add('description', TextareaType::class, [
                'label' => 'Description',
                'required' => false,
            ])
            ->add('price', MoneyType::class, [
                'currency' => 'USD',
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Product::class,
        ]);
    }
}
```

Use in controller:  

```php
<?php

#[Route('/product/new', name: 'product_new')]
public function new(Request $request, EntityManagerInterface $em): Response
{
    $product = new Product();
    $form = $this->createForm(ProductType::class, $product);

    $form->handleRequest($request);

    if ($form->isSubmitted() && $form->isValid()) {
        $em->persist($product);
        $em->flush();

        return $this->redirectToRoute('product_list');
    }

    return $this->render('product/new.html.twig', [
        'form' => $form,
    ]);
}
```

### 66. How do I render forms in Twig?

```twig
{# Quick rendering #}
{{ form(form) }}

{# Custom rendering #}
{{ form_start(form) }}
    {{ form_errors(form) }}

    <div class="form-group">
        {{ form_label(form.name) }}
        {{ form_widget(form.name, {'attr': {'class': 'form-control'}}) }}
        {{ form_errors(form.name) }}
        {{ form_help(form.name) }}
    </div>

    <div class="form-group">
        {{ form_label(form.description) }}
        {{ form_widget(form.description) }}
        {{ form_errors(form.description) }}
    </div>

    {{ form_rest(form) }}

    <button type="submit" class="btn btn-primary">Submit</button>
{{ form_end(form) }}

{# Row rendering #}
{{ form_start(form) }}
    {{ form_row(form.name) }}
    {{ form_row(form.description) }}
    {{ form_row(form.price) }}

    <button type="submit">Submit</button>
{{ form_end(form) }}
```

### 67. How do I add validation to forms?

Add constraints to entity:  

```php
<?php

namespace App\Entity;

use Symfony\Component\Validator\Constraints as Assert;

class Product
{
    #[ORM\Column(length: 255)]
    #[Assert\NotBlank(message: 'Product name is required')]
    #[Assert\Length(
        min: 3,
        max: 255,
        minMessage: 'Product name must be at least {{ limit }} characters',
        maxMessage: 'Product name cannot be longer than {{ limit }} characters'
    )]
    private ?string $name = null;

    #[ORM\Column(type: 'decimal', precision: 10, scale: 2)]
    #[Assert\NotBlank]
    #[Assert\Positive]
    #[Assert\Range(
        min: 0.01,
        max: 999999.99,
        notInRangeMessage: 'Price must be between {{ min }} and {{ max }}'
    )]
    private ?string $price = null;

    #[ORM\Column(length: 180, unique: true)]
    #[Assert\NotBlank]
    #[Assert\Email(message: 'Please enter a valid email')]
    private ?string $email = null;

    #[Assert\Url(message: 'Please enter a valid URL')]
    private ?string $website = null;
}
```

Common constraints:  

```php
<?php

#[Assert\NotBlank]
#[Assert\NotNull]
#[Assert\Email]
#[Assert\Length(min: 10, max: 100)]
#[Assert\Range(min: 1, max: 100)]
#[Assert\Choice(['option1', 'option2', 'option3'])]
#[Assert\Regex(pattern: '/^[a-z0-9-]+$/')]
#[Assert\Url]
#[Assert\Ip]
#[Assert\Positive]
#[Assert\PositiveOrZero]
#[Assert\Negative]
#[Assert\Date]
#[Assert\DateTime]
#[Assert\Time]
#[Assert\File(maxSize: '1024k', mimeTypes: ['application/pdf'])]
#[Assert\Image(maxWidth: 1000, maxHeight: 1000)]
```

### 68. How do I handle file uploads in forms?

Add file field to form:  

```php
<?php

use Symfony\Component\Form\Extension\Core\Type\FileType;
use Symfony\Component\Validator\Constraints\File;

public function buildForm(FormBuilderInterface $builder, array $options): void
{
    $builder
        ->add('image', FileType::class, [
            'label' => 'Product Image',
            'mapped' => false,
            'required' => false,
            'constraints' => [
                new File([
                    'maxSize' => '1024k',
                    'mimeTypes' => [
                        'image/jpeg',
                        'image/png',
                        'image/gif',
                    ],
                    'mimeTypesMessage' => 'Please upload a valid image',
                ])
            ],
        ]);
}
```

Handle in controller:  

```php
<?php

#[Route('/product/new', name: 'product_new')]
public function new(
    Request $request,
    EntityManagerInterface $em,
    string $uploadDir
): Response
{
    $product = new Product();
    $form = $this->createForm(ProductType::class, $product);
    $form->handleRequest($request);

    if ($form->isSubmitted() && $form->isValid()) {
        $imageFile = $form->get('image')->getData();

        if ($imageFile) {
            $originalFilename = pathinfo(
                $imageFile->getClientOriginalName(),
                PATHINFO_FILENAME
            );

            $safeFilename = transliterator_transliterate(
                'Any-Latin; Latin-ASCII; [^A-Za-z0-9_] remove; Lower()',
                $originalFilename
            );

            $newFilename = $safeFilename . '-' . uniqid() . '.' . 
                          $imageFile->guessExtension();

            $imageFile->move($uploadDir, $newFilename);

            $product->setImageFilename($newFilename);
        }

        $em->persist($product);
        $em->flush();

        return $this->redirectToRoute('product_list');
    }

    return $this->render('product/new.html.twig', [
        'form' => $form,
    ]);
}
```

### 69. How do I create form collections?

For one-to-many relationships:  

```php
<?php

use Symfony\Component\Form\Extension\Core\Type\CollectionType;

class OrderType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('customerName')
            ->add('items', CollectionType::class, [
                'entry_type' => OrderItemType::class,
                'entry_options' => ['label' => false],
                'allow_add' => true,
                'allow_delete' => true,
                'by_reference' => false,
            ]);
    }
}

class OrderItemType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('product')
            ->add('quantity')
            ->add('price');
    }
}
```

Render in Twig with JavaScript for add/remove:  

```twig
{{ form_start(form) }}
    {{ form_row(form.customerName) }}

    <ul class="items" data-prototype="{{ form_widget(form.items.vars.prototype)|e('html_attr') }}">
        {% for item in form.items %}
            <li>
                {{ form_row(item.product) }}
                {{ form_row(item.quantity) }}
                {{ form_row(item.price) }}
                <button type="button" class="remove-item">Remove</button>
            </li>
        {% endfor %}
    </ul>

    <button type="button" class="add-item">Add Item</button>
    <button type="submit">Save</button>
{{ form_end(form) }}
```

### 70. How do I customize form rendering?

Create form theme:  

```twig
{# templates/form/custom_theme.html.twig #}
{% block form_row %}
    <div class="custom-row">
        {{ form_label(form) }}
        {{ form_widget(form) }}
        {{ form_errors(form) }}
    </div>
{% endblock %}

{% block text_widget %}
    <input type="text" {{ block('widget_attributes') }} class="custom-input" />
{% endblock %}
```

Apply theme:  

```yaml
# config/packages/twig.yaml
twig:
    form_themes:
        - 'form/custom_theme.html.twig'
```

Or per-form:  

```twig
{% form_theme form 'form/custom_theme.html.twig' %}
{{ form(form) }}
```

### 71. How do I create choice fields?

```php
<?php

use Symfony\Component\Form\Extension\Core\Type\ChoiceType;

$builder
    // Simple choices
    ->add('category', ChoiceType::class, [
        'choices' => [
            'Electronics' => 'electronics',
            'Books' => 'books',
            'Clothing' => 'clothing',
        ],
    ])

    // Multiple selection
    ->add('tags', ChoiceType::class, [
        'choices' => [
            'New' => 'new',
            'Popular' => 'popular',
            'Sale' => 'sale',
        ],
        'multiple' => true,
        'expanded' => false, // false = select, true = checkboxes
    ])

    // Radio buttons
    ->add('status', ChoiceType::class, [
        'choices' => [
            'Active' => 'active',
            'Inactive' => 'inactive',
        ],
        'expanded' => true, // true = radio buttons
        'multiple' => false,
    ])

    // Entity choices
    ->add('category', EntityType::class, [
        'class' => Category::class,
        'choice_label' => 'name',
        'placeholder' => 'Choose a category',
    ]);
```

### 72. How do I use form events?

```php
<?php

use Symfony\Component\Form\FormEvent;
use Symfony\Component\Form\FormEvents;

class ProductType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('name')
            ->add('price');

        // PRE_SET_DATA: Modify form based on data
        $builder->addEventListener(
            FormEvents::PRE_SET_DATA,
            function (FormEvent $event) {
                $product = $event->getData();
                $form = $event->getForm();

                // Add different fields based on product status
                if ($product && $product->isPublished()) {
                    $form->add('publishedAt', DateTimeType::class);
                }
            }
        );

        // PRE_SUBMIT: Modify data before validation
        $builder->addEventListener(
            FormEvents::PRE_SUBMIT,
            function (FormEvent $event) {
                $data = $event->getData();

                // Normalize data
                if (isset($data['name'])) {
                    $data['name'] = trim($data['name']);
                    $event->setData($data);
                }
            }
        );

        // SUBMIT: Access both original and submitted data
        $builder->addEventListener(
            FormEvents::SUBMIT,
            function (FormEvent $event) {
                $product = $event->getData();

                // Auto-generate slug from name
                if ($product && !$product->getSlug()) {
                    $slug = strtolower(str_replace(' ', '-', $product->getName()));
                    $product->setSlug($slug);
                }
            }
        );
    }
}
```


---

## Testing

### 73. How do I write unit tests?

```bash
# Install PHPUnit
composer require --dev symfony/test-pack
```

Create unit test:  

```php
<?php

namespace App\Tests\Service;

use App\Service\Calculator;
use PHPUnit\Framework\TestCase;

class CalculatorTest extends TestCase
{
    private Calculator $calculator;

    protected function setUp(): void
    {
        $this->calculator = new Calculator();
    }

    public function testAdd(): void
    {
        $result = $this->calculator->add(2, 3);
        $this->assertEquals(5, $result);
    }

    public function testAddNegativeNumbers(): void
    {
        $result = $this->calculator->add(-5, 3);
        $this->assertEquals(-2, $result);
    }

    /**
     * @dataProvider additionProvider
     */
    public function testAddWithDataProvider(int $a, int $b, int $expected): void
    {
        $result = $this->calculator->add($a, $b);
        $this->assertEquals($expected, $result);
    }

    public function additionProvider(): array
    {
        return [
            [1, 2, 3],
            [0, 0, 0],
            [-1, 1, 0],
            [10, 5, 15],
        ];
    }
}
```

Run tests:  

```bash
php bin/phpunit
php bin/phpunit tests/Service/CalculatorTest.php
php bin/phpunit --filter testAdd
```

### 74. How do I write functional tests?

Test controllers and routes:  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ProductControllerTest extends WebTestCase
{
    public function testProductList(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/products');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorTextContains('h1', 'Products');
    }

    public function testProductShow(): void
    {
        $client = static::createClient();
        $client->request('GET', '/product/1');

        $this->assertResponseIsSuccessful();
        $this->assertResponseHeaderSame('Content-Type', 'text/html; charset=UTF-8');
    }

    public function testProductNotFound(): void
    {
        $client = static::createClient();
        $client->request('GET', '/product/999999');

        $this->assertResponseStatusCodeSame(404);
    }

    public function testCreateProduct(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/product/new');

        $form = $crawler->selectButton('Save')->form([
            'product[name]' => 'Test Product',
            'product[price]' => '29.99',
        ]);

        $client->submit($form);

        $this->assertResponseRedirects();
        $client->followRedirect();

        $this->assertSelectorTextContains('.alert-success', 'Product created');
    }
}
```

### 75. How do I test with database?

```php
<?php

namespace App\Tests\Repository;

use App\Entity\Product;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class ProductRepositoryTest extends KernelTestCase
{
    private $entityManager;

    protected function setUp(): void
    {
        $kernel = self::bootKernel();

        $this->entityManager = $kernel->getContainer()
            ->get('doctrine')
            ->getManager();
    }

    public function testFindByPriceRange(): void
    {
        $product = new Product();
        $product->setName('Test Product');
        $product->setPrice('99.99');

        $this->entityManager->persist($product);
        $this->entityManager->flush();

        $products = $this->entityManager
            ->getRepository(Product::class)
            ->findByPriceRange(50, 150);

        $this->assertCount(1, $products);
        $this->assertEquals('Test Product', $products[0]->getName());
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        $this->entityManager->close();
        $this->entityManager = null;
    }
}
```

Configure test database:  

```yaml
# config/packages/test/doctrine.yaml
doctrine:
    dbal:
        dbname_suffix: '_test'
```

### 76. How do I test authenticated routes?

```php
<?php

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class AdminControllerTest extends WebTestCase
{
    public function testAdminDashboardRequiresLogin(): void
    {
        $client = static::createClient();
        $client->request('GET', '/admin/dashboard');

        $this->assertResponseRedirects('/login');
    }

    public function testAdminDashboardWithAuth(): void
    {
        $client = static::createClient();

        // Create user
        $userRepository = static::getContainer()->get('doctrine')->getRepository(User::class);
        $testUser = $userRepository->findOneByEmail('admin@test.com');

        // Simulate authentication
        $client->loginUser($testUser);

        $client->request('GET', '/admin/dashboard');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorTextContains('h1', 'Admin Dashboard');
    }
}
```

### 77. How do I mock services in tests?

```php
<?php

use App\Service\EmailService;
use App\Service\UserService;
use PHPUnit\Framework\TestCase;

class UserServiceTest extends TestCase
{
    public function testRegisterSendsEmail(): void
    {
        // Create mock
        $emailService = $this->createMock(EmailService::class);

        // Set expectation
        $emailService
            ->expects($this->once())
            ->method('sendWelcomeEmail')
            ->with($this->equalTo('test@example.com'));

        $userService = new UserService($emailService);
        $userService->register('test@example.com', 'password');
    }

    public function testGetUserStats(): void
    {
        $emailService = $this->createMock(EmailService::class);

        // Stub method to return specific value
        $emailService
            ->method('isEmailValid')
            ->willReturn(true);

        $userService = new UserService($emailService);
        $result = $userService->validateEmail('test@example.com');

        $this->assertTrue($result);
    }
}
```

### 78. How do I use fixtures in tests?

```php
<?php

namespace App\Tests;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Liip\TestFixturesBundle\Services\DatabaseToolCollection;

class ProductControllerTest extends WebTestCase
{
    private $databaseTool;

    protected function setUp(): void
    {
        parent::setUp();
        $this->databaseTool = static::getContainer()->get(DatabaseToolCollection::class)->get();
    }

    public function testProductList(): void
    {
        // Load fixtures
        $this->databaseTool->loadFixtures([
            'App\DataFixtures\ProductFixtures',
        ]);

        $client = static::createClient();
        $client->request('GET', '/products');

        $this->assertResponseIsSuccessful();
    }
}
```

---

## Performance

### 79. How do I cache data in Symfony?

```php
<?php

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class ProductService
{
    public function __construct(
        private CacheInterface $cache,
        private ProductRepository $repository
    ) {
    }

    public function getProducts(): array
    {
        return $this->cache->get('product_list', function (ItemInterface $item) {
            $item->expiresAfter(3600); // 1 hour

            return $this->repository->findAll();
        });
    }

    public function getProduct(int $id): ?Product
    {
        return $this->cache->get("product_{$id}", function (ItemInterface $item) use ($id) {
            $item->expiresAfter(1800); // 30 minutes
            $item->tag(['products']);

            return $this->repository->find($id);
        });
    }

    public function clearProductCache(): void
    {
        $this->cache->delete('product_list');
        $this->cache->invalidateTags(['products']);
    }
}
```

Configure cache:  

```yaml
# config/packages/cache.yaml
framework:
    cache:
        app: cache.adapter.filesystem
        # app: cache.adapter.redis
        # default_redis_provider: redis://localhost
```

### 80. How do I optimize Doctrine queries?

```php
<?php

// 1. Eager loading to prevent N+1 queries
$products = $repository->createQueryBuilder('p')
    ->leftJoin('p.category', 'c')
    ->addSelect('c')
    ->leftJoin('p.tags', 't')
    ->addSelect('t')
    ->getQuery()
    ->getResult();

// 2. Use indexes
#[ORM\Entity]
#[ORM\Index(columns: ['created_at'])]
#[ORM\Index(columns: ['category_id', 'active'])]
class Product { }

// 3. Use query result cache
$query = $repository->createQueryBuilder('p')
    ->where('p.active = :active')
    ->setParameter('active', true)
    ->getQuery();

$query->enableResultCache(3600, 'active_products');
$products = $query->getResult();

// 4. Use partial objects for specific fields
$products = $repository->createQueryBuilder('p')
    ->select('partial p.{id, name, price}')
    ->getQuery()
    ->getResult();

// 5. Batch processing for large datasets
$batchSize = 20;
for ($i = 1; $i <= 1000; $i++) {
    $product = new Product();
    $product->setName('Product ' . $i);

    $em->persist($product);

    if (($i % $batchSize) === 0) {
        $em->flush();
        $em->clear();
    }
}
$em->flush();
$em->clear();
```

### 81. How do I enable HTTP caching?

```php
<?php

use Symfony\Component\HttpFoundation\Response;

#[Route('/product/{id}', name: 'product_show')]
public function show(Product $product): Response
{
    $response = $this->render('product/show.html.twig', [
        'product' => $product,
    ]);

    // Public cache for 1 hour
    $response->setPublic();
    $response->setMaxAge(3600);

    // Validation based on modification time
    $response->setLastModified($product->getUpdatedAt());

    // ETag for validation
    $response->setETag(md5($product->getId() . $product->getUpdatedAt()->getTimestamp()));

    return $response;
}

// Respond with 304 Not Modified if not changed
#[Route('/api/product/{id}')]
public function apiShow(Request $request, Product $product): Response
{
    $response = new Response();
    $response->setLastModified($product->getUpdatedAt());
    $response->setPublic();

    if ($response->isNotModified($request)) {
        return $response;
    }

    $response->setContent(json_encode([
        'id' => $product->getId(),
        'name' => $product->getName(),
    ]));

    return $response;
}
```

### 82. How do I use profiler to debug performance?

```bash
# Enable profiler in dev environment (enabled by default)
# Visit any page and click the toolbar at bottom

# View profiler for last request
http://localhost:8000/_profiler/

# Analyze specific aspects:
# - Timeline: See event execution order
# - Database: View queries and execution time
# - Cache: See cache hits/misses
# - HTTP: Request/response details
```

Programmatic profiling:  

```php
<?php

use Symfony\Component\Stopwatch\Stopwatch;

class ProductService
{
    public function __construct(
        private Stopwatch $stopwatch
    ) {
    }

    public function processProducts(): void
    {
        $this->stopwatch->start('product_processing');

        // Do work
        foreach ($this->products as $product) {
            $this->stopwatch->start('product_item');
            $this->process($product);
            $this->stopwatch->stop('product_item');
        }

        $event = $this->stopwatch->stop('product_processing');

        // Get duration in milliseconds
        $duration = $event->getDuration();
        $memory = $event->getMemory();
    }
}
```

### 83. How do I optimize assets?

```bash
# Install Asset Mapper
composer require symfony/asset-mapper symfony/asset symfony/twig-pack

# Compile assets for production
php bin/console asset-map:compile
```

Configure:  

```yaml
# config/packages/asset_mapper.yaml
framework:
    asset_mapper:
        paths:
            - assets/
        excluded_patterns:
            - */tests/*
            - */*.test.js
```

Link assets:  

```twig
<link rel="stylesheet" href="{{ asset('styles/app.css') }}">
<script src="{{ asset('app.js') }}"></script>
```

### 84. How do I use APCu for caching?

```yaml
# config/packages/cache.yaml
framework:
    cache:
        app: cache.adapter.apcu
        default_redis_provider: 'redis://localhost'

        pools:
            cache.app:
                adapter: cache.adapter.apcu
            cache.system:
                adapter: cache.adapter.system
```

Ensure APCu is installed:  

```bash
# Install APCu extension
pecl install apcu

# Enable in php.ini
extension=apcu.so
apc.enabled=1
apc.shm_size=32M
```

---

## Deployment

### 85. How do I prepare for production deployment?

```bash
# 1. Set environment to production
APP_ENV=prod

# 2. Install production dependencies
composer install --no-dev --optimize-autoloader

# 3. Clear and warm cache
php bin/console cache:clear --env=prod
php bin/console cache:warmup --env=prod

# 4. Run migrations
php bin/console doctrine:migrations:migrate --no-interaction

# 5. Compile assets
php bin/console asset-map:compile

# 6. Set proper permissions
chmod -R 755 var/cache var/log
```

Production `.env`:  

```bash
APP_ENV=prod
APP_DEBUG=0
APP_SECRET=your-secure-secret-here
DATABASE_URL="mysql://user:password@localhost:3306/database"
```

### 86. How do I configure web server for Symfony?

**Apache** (`.htaccess` in `public/`):  

```apache
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^(.*)$ index.php [QSA,L]
</IfModule>
```

**Nginx**:  

```nginx
server {
    listen 80;
    server_name example.com;
    root /var/www/project/public;

    location / {
        try_files $uri /index.php$is_args$args;
    }

    location ~ ^/index\.php(/|$) {
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
        fastcgi_split_path_info ^(.+\.php)(/.*)$;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        fastcgi_param DOCUMENT_ROOT $realpath_root;
        internal;
    }

    location ~ \.php$ {
        return 404;
    }

    error_log /var/log/nginx/project_error.log;
    access_log /var/log/nginx/project_access.log;
}
```

### 87. How do I handle environment-specific configuration?

```yaml
# config/packages/prod/doctrine.yaml - Production only
doctrine:
    orm:
        metadata_cache_driver:
            type: pool
            pool: doctrine.system_cache_pool
        query_cache_driver:
            type: pool
            pool: doctrine.query_cache_pool
        result_cache_driver:
            type: pool
            pool: doctrine.result_cache_pool

# config/packages/prod/monolog.yaml
monolog:
    handlers:
        main:
            type: fingers_crossed
            action_level: error
            handler: nested
        nested:
            type: stream
            path: php://stderr
            level: debug
        console:
            type: console
            process_psr_3_messages: false
```

### 88. How do I deploy with Docker?

Create `Dockerfile`:  

```dockerfile
FROM php:8.2-fpm

RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libpq-dev \
    libzip-dev

RUN docker-php-ext-install pdo pdo_mysql zip opcache

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

COPY . .

RUN composer install --no-dev --optimize-autoloader

RUN php bin/console cache:clear --env=prod
RUN php bin/console cache:warmup --env=prod

CMD ["php-fpm"]
```

Create `docker-compose.yml`:  

```yaml
version: '3.8'

services:
  app:
    build: .
    volumes:
      - .:/var/www/html
    environment:
      DATABASE_URL: mysql://user:password@db:3306/symfony
      APP_ENV: prod
    depends_on:
      - db

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./public:/var/www/html/public
      - ./docker/nginx.conf:/etc/nginx/conf.d/default.conf
    depends_on:
      - app

  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: symfony
    volumes:
      - db_data:/var/lib/mysql

volumes:
  db_data:
```

### 89. How do I optimize for production?

```yaml
# config/packages/prod/framework.yaml
framework:
    router:
        strict_requirements: null
    cache:
        app: cache.adapter.apcu
    php_errors:
        log: true

# Enable OPcache
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=20000
opcache.validate_timestamps=0

# Realpath cache
realpath_cache_size=4096K
realpath_cache_ttl=600
```

### 90. How do I monitor a production application?

Use Monolog for logging:  

```yaml
# config/packages/prod/monolog.yaml
monolog:
    handlers:
        main:
            type: stream
            path: "%kernel.logs_dir%/%kernel.environment%.log"
            level: error
        
        sentry:
            type: sentry
            dsn: '%env(SENTRY_DSN)%'
            level: error
```

Track errors in controllers:  

```php
<?php

use Psr\Log\LoggerInterface;

class ProductController extends AbstractController
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    #[Route('/product/{id}')]
    public function show(int $id): Response
    {
        try {
            $product = $this->repository->find($id);

            if (!$product) {
                $this->logger->warning('Product not found', ['id' => $id]);
                throw $this->createNotFoundException();
            }

            return $this->render('product/show.html.twig', [
                'product' => $product,
            ]);
        } catch (\Exception $e) {
            $this->logger->error('Error showing product', [
                'id' => $id,
                'exception' => $e->getMessage(),
            ]);

            throw $e;
        }
    }
}
```


---

## Services & Dependency Injection

### 91. How do I create a custom service?

Create service class:  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;

class EmailNotificationService
{
    public function __construct(
        private LoggerInterface $logger,
        private string $fromEmail
    ) {
    }

    public function sendNotification(string $to, string $message): void
    {
        $this->logger->info('Sending notification', [
            'to' => $to,
            'from' => $this->fromEmail,
        ]);

        // Send email logic
    }
}
```

Configure service:  

```yaml
# config/services.yaml
services:
    App\Service\EmailNotificationService:
        arguments:
            $fromEmail: '%env(MAILER_FROM)%'
```

Use in controller:  

```php
<?php

#[Route('/notify')]
public function notify(EmailNotificationService $notifier): Response
{
    $notifier->sendNotification('user@example.com', 'Hello there!');
    return new Response('Notification sent!');
}
```

### 92. How do I inject parameters into services?

```yaml
# config/services.yaml
parameters:
    app.upload_dir: '%kernel.project_dir%/public/uploads'
    app.max_file_size: 1048576

services:
    _defaults:
        bind:
            $uploadDir: '%app.upload_dir%'
            $maxFileSize: '%app.max_file_size%'

    App\Service\FileUploader:
        arguments:
            $uploadDirectory: '%app.upload_dir%'
```

In service:  

```php
<?php

namespace App\Service;

class FileUploader
{
    public function __construct(
        private string $uploadDirectory,
        private int $maxFileSize
    ) {
    }

    public function upload(UploadedFile $file): string
    {
        if ($file->getSize() > $this->maxFileSize) {
            throw new \Exception('File too large');
        }

        $filename = uniqid() . '.' . $file->guessExtension();
        $file->move($this->uploadDirectory, $filename);

        return $filename;
    }
}
```

### 93. How do I use service tags?

Tags group services for specific purposes:  

```php
<?php

namespace App\Handler;

use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('app.notification_handler')]
interface NotificationHandlerInterface
{
    public function handle(Notification $notification): void;
    public function supports(Notification $notification): bool;
}

class EmailHandler implements NotificationHandlerInterface
{
    public function handle(Notification $notification): void
    {
        // Send email
    }

    public function supports(Notification $notification): bool
    {
        return $notification->getType() === 'email';
    }
}

class SmsHandler implements NotificationHandlerInterface
{
    public function handle(Notification $notification): void
    {
        // Send SMS
    }

    public function supports(Notification $notification): bool
    {
        return $notification->getType() === 'sms';
    }
}
```

Consume tagged services:  

```php
<?php

namespace App\Service;

class NotificationDispatcher
{
    private iterable $handlers;

    public function __construct(
        #[TaggedIterator('app.notification_handler')] iterable $handlers
    ) {
        $this->handlers = $handlers;
    }

    public function dispatch(Notification $notification): void
    {
        foreach ($this->handlers as $handler) {
            if ($handler->supports($notification)) {
                $handler->handle($notification);
                return;
            }
        }

        throw new \Exception('No handler found');
    }
}
```

### 94. How do I use service decoration?

Decorate existing service to add functionality:  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;

class LoggingMailer implements MailerInterface
{
    public function __construct(
        private MailerInterface $decorated,
        private LoggerInterface $logger
    ) {
    }

    public function send(Email $email): void
    {
        $this->logger->info('Sending email', [
            'to' => $email->getTo(),
            'subject' => $email->getSubject(),
        ]);

        $this->decorated->send($email);

        $this->logger->info('Email sent successfully');
    }
}
```

Configure decoration:  

```yaml
# config/services.yaml
services:
    App\Service\LoggingMailer:
        decorates: App\Service\MailerService
        arguments:
            $decorated: '@.inner'
```

### 95. How do I create service aliases?

```yaml
# config/services.yaml
services:
    # Main service
    App\Service\PaymentGateway:
        class: App\Service\StripePaymentGateway

    # Alias
    App\Service\PaymentGatewayInterface: '@App\Service\PaymentGateway'

    # Named alias
    payment_gateway: '@App\Service\PaymentGateway'
```

Use alias:  

```php
<?php

public function __construct(
    PaymentGatewayInterface $paymentGateway
) {
    // Receives StripePaymentGateway
}
```

---

## Templating

### 96. How do I pass data to templates?

```php
<?php

#[Route('/products')]
public function list(ProductRepository $repository): Response
{
    $products = $repository->findAll();

    return $this->render('product/list.html.twig', [
        'products' => $products,
        'title' => 'Product List',
        'currentDate' => new \DateTime(),
    ]);
}
```

Access in Twig:  

```twig
<h1>{{ title }}</h1>
<p>Date: {{ currentDate|date('Y-m-d') }}</p>

{% for product in products %}
    <div>{{ product.name }} - ${{ product.price }}</div>
{% endfor %}
```

### 97. How do I create custom Twig filters and functions?

Create Twig extension:  

```php
<?php

namespace App\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFilter;
use Twig\TwigFunction;

class AppExtension extends AbstractExtension
{
    public function getFilters(): array
    {
        return [
            new TwigFilter('price', [$this, 'formatPrice']),
            new TwigFilter('excerpt', [$this, 'getExcerpt']),
        ];
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('area', [$this, 'calculateArea']),
            new TwigFunction('random_color', [$this, 'getRandomColor']),
        ];
    }

    public function formatPrice(float $price): string
    {
        return '$' . number_format($price, 2);
    }

    public function getExcerpt(string $text, int $length = 100): string
    {
        if (strlen($text) <= $length) {
            return $text;
        }

        return substr($text, 0, $length) . '...';
    }

    public function calculateArea(float $width, float $height): float
    {
        return $width * $height;
    }

    public function getRandomColor(): string
    {
        return sprintf('#%06X', mt_rand(0, 0xFFFFFF));
    }
}
```

Use in templates:  

```twig
<p>Price: {{ product.price|price }}</p>
<p>{{ description|excerpt(50) }}</p>
<p>Area: {{ area(10, 20) }} sq ft</p>
<div style="background-color: {{ random_color() }}">Content</div>
```

### 98. How do I use template inheritance?

Base template:  

```twig
{# templates/base.html.twig #}
<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}My App{% endblock %}</title>
    {% block stylesheets %}
        <link rel="stylesheet" href="{{ asset('css/app.css') }}">
    {% endblock %}
</head>
<body>
    <header>
        {% block header %}
            <nav>Navigation</nav>
        {% endblock %}
    </header>

    <main>
        {% block body %}{% endblock %}
    </main>

    <footer>
        {% block footer %}
            <p>&copy; {{ 'now'|date('Y') }} My Company</p>
        {% endblock %}
    </footer>

    {% block javascripts %}
        <script src="{{ asset('js/app.js') }}"></script>
    {% endblock %}
</body>
</html>
```

Child template:  

```twig
{# templates/product/list.html.twig #}
{% extends 'base.html.twig' %}

{% block title %}Products - {{ parent() }}{% endblock %}

{% block body %}
    <h1>Products</h1>

    {% for product in products %}
        <div class="product">
            <h2>{{ product.name }}</h2>
            <p>{{ product.price|price }}</p>
        </div>
    {% endfor %}
{% endblock %}
```

---

## Console Commands

### 99. How do I create custom console commands?

```bash
php bin/console make:command app:process-orders
```

Creates:  

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:process-orders',
    description: 'Process pending orders',
)]
class ProcessOrdersCommand extends Command
{
    public function __construct(
        private OrderService $orderService
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('limit', InputArgument::OPTIONAL, 'Number of orders to process', 10)
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Force processing')
            ->addOption('status', 's', InputOption::VALUE_REQUIRED, 'Filter by status');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $limit = $input->getArgument('limit');
        $force = $input->getOption('force');
        $status = $input->getOption('status');

        $io->title('Processing Orders');

        if ($force) {
            $io->warning('Force mode enabled');
        }

        $io->section('Loading orders');

        $orders = $this->orderService->getPendingOrders($limit, $status);

        if (empty($orders)) {
            $io->success('No orders to process');
            return Command::SUCCESS;
        }

        $io->progressStart(count($orders));

        foreach ($orders as $order) {
            $this->orderService->process($order);
            $io->progressAdvance();
        }

        $io->progressFinish();

        $io->success(sprintf('Processed %d orders', count($orders)));

        return Command::SUCCESS;
    }
}
```

Run command:  

```bash
php bin/console app:process-orders
php bin/console app:process-orders 50 --force --status=pending
```

### 100. How do I create interactive console commands?

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:user:create')]
class CreateUserCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $helper = $this->getHelper('question');

        // Text question
        $emailQuestion = new Question('Please enter email: ');
        $email = $helper->ask($input, $output, $emailQuestion);

        // Hidden question for password
        $passwordQuestion = new Question('Please enter password: ');
        $passwordQuestion->setHidden(true);
        $passwordQuestion->setHiddenFallback(false);
        $password = $helper->ask($input, $output, $passwordQuestion);

        // Choice question
        $roleQuestion = new ChoiceQuestion(
            'Please select role',
            ['ROLE_USER', 'ROLE_ADMIN', 'ROLE_EDITOR'],
            0
        );
        $role = $helper->ask($input, $output, $roleQuestion);

        // Confirmation question
        $confirmQuestion = new ConfirmationQuestion(
            'Do you want to create this user? (yes/no) ',
            false
        );

        if (!$helper->ask($input, $output, $confirmQuestion)) {
            $io->warning('User creation cancelled');
            return Command::SUCCESS;
        }

        // Create user
        $io->success(sprintf(
            'User created: %s with role %s',
            $email,
            $role
        ));

        return Command::SUCCESS;
    }
}
```

Run interactively:  

```bash
php bin/console app:user:create
```

---

## Conclusion

This FAQ covers 100 of the most frequently asked questions about the  
Symfony framework, organized into practical categories. Each question  
includes clear explanations and working code examples that demonstrate  
best practices and real-world usage patterns.  

Key areas covered include:  

**Getting Started**: Installation, project structure, environment setup,  
and basic configuration to help new developers start building Symfony  
applications quickly.  

**Core Concepts**: Configuration management, routing, controllers, and  
dependency injection that form the foundation of any Symfony application.  

**Database & ORM**: Doctrine integration, entity management, query  
building, migrations, and performance optimization for data persistence.  

**Security**: Authentication, authorization, user management, CSRF  
protection, and API security for building secure applications.  

**Forms & Validation**: Form creation, rendering, validation constraints,  
file uploads, and custom form types for handling user input.  

**Testing**: Unit tests, functional tests, database testing, and mocking  
to ensure application quality and reliability.  

**Performance**: Caching strategies, query optimization, HTTP caching,  
and profiling tools for building fast, scalable applications.  

**Deployment**: Production configuration, web server setup, Docker  
deployment, and monitoring for running Symfony in production.  

**Advanced Topics**: Custom services, Twig templating, console commands,  
and API development for extending Symfony's capabilities.  

For more detailed information, consult the official Symfony documentation  
at https://symfony.com/doc/current/index.html, which provides  
comprehensive guides, reference materials, and best practices for all  
aspects of the framework.  

