# Symfony Project Structure

A Symfony application follows a well-organized directory structure that  
separates concerns and promotes maintainability. Understanding this structure  
is essential for working effectively with the framework.  

This guide provides a comprehensive overview of a typical Symfony project  
structure, explaining the purpose of each directory and file, how they  
interact, and best practices for organizing your code.  

## Standard Directory Layout

A modern Symfony application (version 4+) has the following structure:  

```
my-symfony-project/
├── bin/
│   └── console
├── config/
│   ├── packages/
│   ├── routes/
│   ├── bundles.php
│   ├── routes.yaml
│   └── services.yaml
├── migrations/
├── public/
│   └── index.php
├── src/
│   ├── Controller/
│   ├── Entity/
│   ├── Repository/
│   ├── Service/
│   └── Kernel.php
├── templates/
├── tests/
├── translations/
├── var/
│   ├── cache/
│   └── log/
├── vendor/
├── .env
├── .env.local
├── .gitignore
├── composer.json
└── symfony.lock
```

This structure is the result of years of refinement and represents best  
practices for organizing a PHP application. Each directory has a specific  
purpose and follows the principle of separation of concerns.  

## Core Directories

### src/ - Application Source Code

The `src/` directory contains all your application's PHP code. This is  
where you write your business logic, controllers, entities, and services.  

**Structure**:  

```php
<?php

src/
├── Controller/          # HTTP request handlers
├── Entity/             # Doctrine entities (database models)
├── Repository/         # Database query methods
├── Service/            # Business logic services
├── Form/               # Form types
├── EventListener/      # Event subscribers and listeners
├── Security/           # Authentication and authorization
├── Command/            # Console commands
└── Kernel.php          # Application kernel
```

**Example Controller**:  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class HomeController extends AbstractController
{
    #[Route('/', name: 'app_home')]
    public function index(): Response
    {
        return $this->render('home/index.html.twig', [
            'title' => 'Welcome to Symfony',
        ]);
    }
}
```

The controller handles HTTP requests and returns responses. It uses the  
`#[Route]` attribute to map URLs to controller actions. The `render()`  
method loads a Twig template and passes data to it.  

**Example Entity**:  

```php
<?php

namespace App\Entity;

use App\Repository\ProductRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: ProductRepository::class)]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private string $name;

    #[ORM\Column]
    private float $price;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): self
    {
        $this->name = $name;
        return $this;
    }

    public function getPrice(): float
    {
        return $this->price;
    }

    public function setPrice(float $price): self
    {
        $this->price = $price;
        return $this;
    }
}
```

Entities represent database tables and use Doctrine ORM attributes to  
define mappings. Each property corresponds to a database column. The  
entity class is a plain PHP object with getters and setters.  

**Example Service**:  

```php
<?php

namespace App\Service;

use App\Entity\Product;
use App\Repository\ProductRepository;
use Doctrine\ORM\EntityManagerInterface;

class ProductManager
{
    public function __construct(
        private ProductRepository $productRepository,
        private EntityManagerInterface $entityManager
    ) {
    }

    public function createProduct(string $name, float $price): Product
    {
        $product = new Product();
        $product->setName($name);
        $product->setPrice($price);

        $this->entityManager->persist($product);
        $this->entityManager->flush();

        return $product;
    }

    public function findExpensiveProducts(float $minPrice): array
    {
        return $this->productRepository->findByMinPrice($minPrice);
    }
}
```

Services encapsulate business logic and are automatically registered in  
the dependency injection container. Dependencies are injected through  
the constructor using autowiring.  

**Best Practices for src/**:  

- Organize code by feature or domain when applications grow large  
- Keep controllers thin by moving logic to services  
- Use proper namespacing following PSR-4 autoloading standard  
- One class per file with the filename matching the class name  
- Place interfaces in the same namespace as implementations  

### config/ - Configuration Files

The `config/` directory contains all configuration for your application.  
Symfony uses YAML as the default format, but also supports PHP, XML, and  
annotations.  

**Structure**:  

```
config/
├── packages/           # Bundle configuration
│   ├── dev/           # Development environment
│   ├── prod/          # Production environment
│   ├── test/          # Test environment
│   ├── cache.yaml
│   ├── doctrine.yaml
│   ├── framework.yaml
│   ├── routing.yaml
│   └── security.yaml
├── routes/            # Route definitions
│   └── annotations.yaml
├── bundles.php        # Registered bundles
├── routes.yaml        # Main routing file
└── services.yaml      # Service container configuration
```

**Example services.yaml**:  

```yaml
# config/services.yaml
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

    App\Service\EmailService:
        arguments:
            $fromAddress: '%env(MAIL_FROM_ADDRESS)%'
```

This configuration enables autowiring and autoconfiguring for all services  
in the `src/` directory. The `_defaults` section applies settings to all  
services defined below it. Specific services can override defaults with  
custom arguments.  

**Example framework.yaml**:  

```yaml
# config/packages/framework.yaml
framework:
    secret: '%env(APP_SECRET)%'
    csrf_protection: true
    http_method_override: false
    
    session:
        handler_id: null
        cookie_secure: auto
        cookie_samesite: lax
        
    php_errors:
        log: true
```

Framework configuration controls core Symfony features like sessions,  
CSRF protection, and error handling. Environment variables are referenced  
using the `%env()%` syntax.  

**Environment-Specific Configuration**:  

```yaml
# config/packages/dev/monolog.yaml
monolog:
    handlers:
        main:
            type: stream
            path: "%kernel.logs_dir%/%kernel.environment%.log"
            level: debug
```

```yaml
# config/packages/prod/monolog.yaml
monolog:
    handlers:
        main:
            type: fingers_crossed
            action_level: error
            handler: nested
        nested:
            type: stream
            path: "%kernel.logs_dir%/%kernel.environment%.log"
            level: error
```

Files in environment-specific directories override base configuration.  
Development uses verbose logging while production logs only errors to  
minimize performance impact.  

**Best Practices for config/**:  

- Use environment variables for sensitive data and environment-specific values  
- Keep development, test, and production configurations separate  
- Document custom configuration parameters  
- Use semantic configuration when creating bundles  
- Organize routes by feature or module in the routes/ directory  

### public/ - Web Root Directory

The `public/` directory is the web server's document root. Only files in  
this directory are accessible directly via HTTP.  

**Structure**:  

```
public/
├── index.php          # Front controller
├── .htaccess          # Apache configuration
├── robots.txt         # Search engine directives
├── favicon.ico        # Site favicon
├── css/              # Public stylesheets
├── js/               # Public JavaScript files
└── images/           # Public images
```

**Front Controller (index.php)**:  

```php
<?php

use App\Kernel;

require_once dirname(__DIR__).'/vendor/autoload_runtime.php';

return function (array $context) {
    return new Kernel($context['APP_ENV'], (bool) $context['APP_DEBUG']);
};
```

The front controller is the entry point for all HTTP requests. It  
bootstraps the application kernel and handles the request/response cycle.  
All requests are routed through this single file, enabling URL rewriting  
and centralized request handling.  

**Best Practices for public/**:  

- Never store sensitive files in public/ as they're web-accessible  
- Use AssetMapper or Webpack Encore for managing CSS/JS assets  
- Configure web server to prevent directory listing  
- Serve assets with proper cache headers for performance  
- Use a CDN for static assets in production  

### var/ - Variable Data

The `var/` directory contains files that are generated during application  
runtime. These files should not be committed to version control.  

**Structure**:  

```
var/
├── cache/            # Compiled container and cached data
│   ├── dev/         # Development cache
│   └── prod/        # Production cache
└── log/             # Application logs
    ├── dev.log
    ├── prod.log
    └── test.log
```

**Cache Directory**:  

The cache directory stores the compiled dependency injection container,  
routing configuration, and template cache. Symfony automatically rebuilds  
cache when configuration changes in development mode.  

```bash
# Clear cache for current environment
php bin/console cache:clear

# Clear cache for production
php bin/console cache:clear --env=prod

# Warm up cache without clearing
php bin/console cache:warmup
```

**Log Directory**:  

Application logs are written here based on Monolog configuration. Different  
log levels and handlers can be configured per environment.  

```php
<?php

namespace App\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class LoggingController extends AbstractController
{
    #[Route('/process', name: 'app_process')]
    public function process(LoggerInterface $logger): Response
    {
        $logger->info('Processing started');
        
        // Business logic here
        
        $logger->info('Processing completed');
        
        return new Response('Done');
    }
}
```

The logger is automatically injected and writes to configured log files.  
Different log channels can be used for different parts of the application.  

**Best Practices for var/**:  

- Add var/ to .gitignore (except var/.gitkeep)  
- Ensure var/ directory is writable by the web server  
- Regularly rotate log files to prevent disk space issues  
- Monitor log files for errors in production  
- Clear cache after deploying configuration changes  

### vendor/ - Third-Party Dependencies

The `vendor/` directory contains all third-party packages installed via  
Composer, including Symfony components and bundles.  

**Structure**:  

```
vendor/
├── symfony/          # Symfony components
├── doctrine/         # Doctrine packages
├── twig/            # Twig templating engine
├── autoload.php     # Composer autoloader
└── ...              # Other dependencies
```

This directory is managed entirely by Composer and should never be  
modified manually. All dependencies are defined in composer.json.  

**Example composer.json**:  

```json
{
    "name": "acme/my-project",
    "type": "project",
    "require": {
        "php": ">=8.2",
        "symfony/console": "7.0.*",
        "symfony/framework-bundle": "7.0.*",
        "symfony/yaml": "7.0.*",
        "doctrine/doctrine-bundle": "^2.11",
        "doctrine/orm": "^3.0"
    },
    "require-dev": {
        "symfony/maker-bundle": "^1.52",
        "phpunit/phpunit": "^10.5"
    },
    "autoload": {
        "psr-4": {
            "App\\": "src/"
        }
    }
}
```

The `require` section lists production dependencies while `require-dev`  
contains development-only tools like testing frameworks and code generators.  

**Best Practices for vendor/**:  

- Add vendor/ to .gitignore  
- Use Composer lock file (composer.lock) for consistent deployments  
- Run `composer install --no-dev --optimize-autoloader` in production  
- Regularly update dependencies for security patches  
- Use semantic versioning constraints in composer.json  

### bin/ - Executable Scripts

The `bin/` directory contains executable scripts, primarily the Symfony  
console application.  

**Structure**:  

```
bin/
└── console          # Symfony console application
```

**Console Application**:  

```bash
# List all available commands
php bin/console list

# Clear cache
php bin/console cache:clear

# Create a new controller
php bin/console make:controller ProductController

# Run database migrations
php bin/console doctrine:migrations:migrate

# Create a new entity
php bin/console make:entity Product
```

The console provides access to hundreds of commands for managing your  
application, including code generation, cache management, database  
operations, and custom commands.  

**Custom Console Command**:  

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(
    name: 'app:process-orders',
    description: 'Process pending orders'
)]
class ProcessOrdersCommand extends Command
{
    protected function execute(
        InputInterface $input, 
        OutputInterface $output
    ): int {
        $output->writeln('Processing orders...');
        
        // Business logic here
        
        $output->writeln('Done!');
        
        return Command::SUCCESS;
    }
}
```

Custom commands are automatically registered when placed in the  
`src/Command/` directory. They extend the Command class and implement  
the execute() method.  

**Best Practices for bin/**:  

- Make console file executable: `chmod +x bin/console`  
- Create custom commands for repetitive tasks  
- Use command arguments and options for flexibility  
- Document custom commands with descriptions  
- Return appropriate exit codes from commands  

### tests/ - Automated Tests

The `tests/` directory contains all automated tests for your application,  
organized to mirror the `src/` directory structure.  

**Structure**:  

```
tests/
├── Controller/      # Controller/integration tests
├── Service/        # Service unit tests
├── Entity/         # Entity tests
├── Repository/     # Repository tests
└── bootstrap.php   # Test bootstrap
```

**Controller Test Example**:  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class HomeControllerTest extends WebTestCase
{
    public function testHomePageIsSuccessful(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorTextContains('h1', 'Welcome');
    }
}
```

Web tests use the WebTestCase base class which provides a test client for  
making HTTP requests and asserting responses. The test client simulates  
a browser without requiring a running server.  

**Service Test Example**:  

```php
<?php

namespace App\Tests\Service;

use App\Service\ProductManager;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class ProductManagerTest extends KernelTestCase
{
    public function testCreateProduct(): void
    {
        self::bootKernel();
        
        $productManager = self::getContainer()
            ->get(ProductManager::class);
        
        $product = $productManager->createProduct('Test Product', 19.99);
        
        $this->assertSame('Test Product', $product->getName());
        $this->assertSame(19.99, $product->getPrice());
    }
}
```

Unit tests for services use KernelTestCase when they need access to the  
service container. This allows testing services with their real dependencies  
or mocked dependencies.  

**Running Tests**:  

```bash
# Run all tests
php bin/phpunit

# Run specific test file
php bin/phpunit tests/Controller/HomeControllerTest.php

# Run tests with coverage
php bin/phpunit --coverage-html var/coverage
```

**Best Practices for tests/**:  

- Maintain test coverage for critical business logic  
- Use data providers for testing multiple scenarios  
- Mock external dependencies to isolate unit tests  
- Write integration tests for critical user workflows  
- Use fixtures for consistent test data  

### templates/ - Twig Templates

The `templates/` directory contains Twig template files for rendering HTML  
responses.  

**Structure**:  

```
templates/
├── base.html.twig           # Base layout template
├── home/
│   └── index.html.twig      # Home page template
└── product/
    ├── list.html.twig       # Product list
    └── show.html.twig       # Product detail
```

**Base Template**:  

```twig
{# templates/base.html.twig #}
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>{% block title %}Welcome{% endblock %}</title>
        {% block stylesheets %}
            <link rel="stylesheet" href="{{ asset('css/app.css') }}">
        {% endblock %}
    </head>
    <body>
        <header>
            <nav>
                <a href="{{ path('app_home') }}">Home</a>
                <a href="{{ path('product_list') }}">Products</a>
            </nav>
        </header>
        
        <main>
            {% block body %}{% endblock %}
        </main>
        
        <footer>
            <p>&copy; {{ 'now'|date('Y') }} My Company</p>
        </footer>
        
        {% block javascripts %}
            <script src="{{ asset('js/app.js') }}"></script>
        {% endblock %}
    </body>
</html>
```

The base template defines the overall page structure with blocks that  
child templates can override. The `path()` function generates URLs from  
route names.  

**Child Template**:  

```twig
{# templates/product/list.html.twig #}
{% extends 'base.html.twig' %}

{% block title %}Product List{% endblock %}

{% block body %}
    <h1>Our Products</h1>
    
    <div class="product-grid">
        {% for product in products %}
            <div class="product-card">
                <h2>{{ product.name }}</h2>
                <p class="price">${{ product.price|number_format(2) }}</p>
                <a href="{{ path('product_show', {id: product.id}) }}">
                    View Details
                </a>
            </div>
        {% else %}
            <p>No products available.</p>
        {% endfor %}
    </div>
{% endblock %}
```

Child templates extend the base template and override specific blocks.  
Twig provides filters like `number_format` for formatting output and  
control structures like `for` loops.  

**Best Practices for templates/**:  

- Organize templates by controller or feature  
- Use template inheritance to avoid duplication  
- Create reusable template fragments with include  
- Escape output by default (Twig does this automatically)  
- Keep business logic out of templates  

### migrations/ - Database Migrations

The `migrations/` directory contains Doctrine migration files that  
track database schema changes over time.  

**Structure**:  

```
migrations/
├── Version20240101120000.php
├── Version20240115093000.php
└── Version20240201150000.php
```

**Example Migration**:  

```php
<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20240101120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Create product table';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('CREATE TABLE product (
            id INT AUTO_INCREMENT NOT NULL, 
            name VARCHAR(255) NOT NULL, 
            price DOUBLE PRECISION NOT NULL, 
            PRIMARY KEY(id)
        ) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE product');
    }
}
```

Migrations are versioned changes to your database schema. The `up()`  
method applies changes while `down()` reverts them. Migrations are  
executed in chronological order.  

**Working with Migrations**:  

```bash
# Generate migration from entity changes
php bin/console make:migration

# Execute pending migrations
php bin/console doctrine:migrations:migrate

# Rollback last migration
php bin/console doctrine:migrations:migrate prev

# Check migration status
php bin/console doctrine:migrations:status
```

**Best Practices for migrations/**:  

- Generate migrations instead of writing them manually  
- Review generated migrations before executing  
- Test migrations in development before production  
- Never modify executed migrations  
- Keep migrations in version control  

### translations/ - Translation Files

The `translations/` directory contains translation files for  
internationalization (i18n) support.  

**Structure**:  

```
translations/
├── messages.en.yaml      # English translations
├── messages.fr.yaml      # French translations
├── validators.en.yaml    # English validation messages
└── validators.fr.yaml    # French validation messages
```

**Example Translation File**:  

```yaml
# translations/messages.en.yaml
welcome:
    title: 'Welcome to our application'
    message: 'Hello there!'

product:
    add: 'Add Product'
    edit: 'Edit Product'
    delete: 'Delete Product'
    not_found: 'Product not found'

navigation:
    home: 'Home'
    products: 'Products'
    about: 'About Us'
```

**Using Translations in Controllers**:  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Contracts\Translation\TranslatorInterface;

class ProductController extends AbstractController
{
    #[Route('/product/add', name: 'product_add')]
    public function add(TranslatorInterface $translator): Response
    {
        $message = $translator->trans('product.add');
        
        $this->addFlash('success', $message);
        
        return $this->redirectToRoute('product_list');
    }
}
```

**Using Translations in Templates**:  

```twig
{# templates/product/list.html.twig #}
<h1>{{ 'welcome.title'|trans }}</h1>

<nav>
    <a href="{{ path('app_home') }}">
        {{ 'navigation.home'|trans }}
    </a>
    <a href="{{ path('product_list') }}">
        {{ 'navigation.products'|trans }}
    </a>
</nav>
```

**Best Practices for translations/**:  

- Use translation keys instead of hardcoded text  
- Organize translations by domain (messages, validators, etc.)  
- Support multiple locales from the start if needed  
- Use ICU message format for complex translations  
- Extract translatable strings automatically  

## Configuration Files

### .env - Environment Variables

Environment variables define configuration that changes between  
environments. Symfony uses dotenv to load these variables.  

```bash
# .env
APP_ENV=dev
APP_SECRET=your-secret-key
DATABASE_URL="mysql://user:pass@localhost:3306/myapp"
MAILER_DSN=smtp://localhost:1025
```

```bash
# .env.local (not committed to git)
APP_ENV=dev
APP_DEBUG=1
DATABASE_URL="mysql://root:root@127.0.0.1:3306/myapp_dev"
```

The `.env` file contains default values and is committed to version  
control. The `.env.local` file overrides values for local development  
and should not be committed.  

**Environment Priority**:  

1. Real environment variables (set by hosting platform)  
2. `.env.local.php` (cached environment variables)  
3. `.env.local` (local overrides, not committed)  
4. `.env` (default values, committed)  

**Best Practices**:  

- Never commit `.env.local` or production secrets  
- Use strong random values for APP_SECRET  
- Document required variables in `.env`  
- Use different database names for dev/test/prod  
- Reference environment variables in config with `%env(VAR_NAME)%`  

### composer.json - Dependency Management

The composer.json file defines project metadata, dependencies, and  
autoloading configuration.  

```json
{
    "name": "acme/my-app",
    "type": "project",
    "license": "MIT",
    "minimum-stability": "stable",
    "prefer-stable": true,
    "require": {
        "php": ">=8.2",
        "ext-ctype": "*",
        "ext-iconv": "*",
        "symfony/console": "7.0.*",
        "symfony/dotenv": "7.0.*",
        "symfony/flex": "^2",
        "symfony/framework-bundle": "7.0.*",
        "symfony/runtime": "7.0.*",
        "symfony/yaml": "7.0.*"
    },
    "require-dev": {
        "symfony/maker-bundle": "^1.52"
    },
    "config": {
        "allow-plugins": {
            "symfony/flex": true,
            "symfony/runtime": true
        },
        "sort-packages": true
    },
    "autoload": {
        "psr-4": {
            "App\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "App\\Tests\\": "tests/"
        }
    },
    "scripts": {
        "auto-scripts": {
            "cache:clear": "symfony-cmd",
            "assets:install %PUBLIC_DIR%": "symfony-cmd"
        },
        "post-install-cmd": [
            "@auto-scripts"
        ],
        "post-update-cmd": [
            "@auto-scripts"
        ]
    }
}
```

**Best Practices**:  

- Use semantic versioning constraints  
- Separate production and development dependencies  
- Lock versions with composer.lock  
- Define autoloading for better performance  
- Use scripts for automated tasks  

### symfony.lock - Symfony Flex Lock File

The symfony.lock file is managed by Symfony Flex and tracks installed  
recipes. It ensures consistent package configuration across environments.  

```json
{
    "symfony/console": {
        "version": "7.0",
        "recipe": {
            "repo": "github.com/symfony/recipes",
            "branch": "main",
            "version": "5.3",
            "ref": "1781ff40d490"
        }
    }
}
```

This file should be committed to version control to ensure all developers  
and deployment environments use the same package configurations.  

## How Components Interact

### Request/Response Flow

Understanding how Symfony processes HTTP requests helps you work  
effectively with the framework:  

1. **Request arrives**: Web server routes all requests to `public/index.php`  
2. **Kernel boots**: The Kernel initializes the service container  
3. **Routing**: Router matches URL to a controller action  
4. **Controller execution**: Controller method is called with dependencies  
5. **Business logic**: Services process data, interact with database  
6. **Response creation**: Controller returns a Response object  
7. **Response sent**: Kernel sends response to the browser  

**Example Flow**:  

```php
<?php

// 1. Router matches /product/123 to ProductController::show
namespace App\Controller;

use App\Repository\ProductRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProductController extends AbstractController
{
    #[Route('/product/{id}', name: 'product_show')]
    public function show(
        int $id,
        ProductRepository $repository  // 2. Dependency injected
    ): Response {
        // 3. Repository queries database
        $product = $repository->find($id);
        
        if (!$product) {
            throw $this->createNotFoundException('Product not found');
        }
        
        // 4. Template rendered with data
        return $this->render('product/show.html.twig', [
            'product' => $product,
        ]);
    }
}
```

### Service Container Integration

The service container manages object creation and dependency injection:  

```php
<?php

// Service definition (automatically registered)
namespace App\Service;

use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;

class OrderProcessor
{
    public function __construct(
        private EntityManagerInterface $entityManager,
        private LoggerInterface $logger,
        private string $adminEmail
    ) {
    }

    public function processOrder(Order $order): void
    {
        $this->logger->info('Processing order', ['id' => $order->getId()]);
        
        // Process order logic
        
        $this->entityManager->flush();
    }
}
```

```yaml
# config/services.yaml - Configuration
services:
    App\Service\OrderProcessor:
        arguments:
            $adminEmail: '%env(ADMIN_EMAIL)%'
```

```php
<?php

// Usage in controller
namespace App\Controller;

use App\Service\OrderProcessor;

class OrderController extends AbstractController
{
    #[Route('/order/{id}/process', name: 'order_process')]
    public function process(
        Order $order,
        OrderProcessor $processor  // Automatically injected
    ): Response {
        $processor->processOrder($order);
        
        return $this->redirectToRoute('order_list');
    }
}
```

### Database Integration

Doctrine ORM integrates seamlessly with Symfony:  

```php
<?php

// Entity defines database structure
namespace App\Entity;

use App\Repository\OrderRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: OrderRepository::class)]
class Order
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(targetEntity: User::class)]
    private User $user;

    #[ORM\OneToMany(targetEntity: OrderItem::class, mappedBy: 'order')]
    private Collection $items;

    public function __construct()
    {
        $this->items = new ArrayCollection();
    }

    // Getters and setters...
}
```

```php
<?php

// Repository provides query methods
namespace App\Repository;

use App\Entity\Order;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class OrderRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Order::class);
    }

    public function findRecentOrders(int $limit = 10): array
    {
        return $this->createQueryBuilder('o')
            ->orderBy('o.createdAt', 'DESC')
            ->setMaxResults($limit)
            ->getQuery()
            ->getResult();
    }
}
```

## Best Practices

### Organizing Large Applications

As applications grow, consider organizing code by feature or domain:  

```
src/
├── Product/
│   ├── Controller/
│   │   └── ProductController.php
│   ├── Entity/
│   │   └── Product.php
│   ├── Repository/
│   │   └── ProductRepository.php
│   └── Service/
│       └── ProductManager.php
├── Order/
│   ├── Controller/
│   ├── Entity/
│   ├── Repository/
│   └── Service/
└── User/
    ├── Controller/
    ├── Entity/
    ├── Repository/
    └── Security/
```

This domain-driven structure groups related code together, making it  
easier to understand and maintain as the application scales.  

### Security Considerations

**File Permissions**:  

```bash
# Set proper permissions
chmod -R 755 bin/console
chmod -R 775 var/
chown -R www-data:www-data var/
```

**Environment Variables**:  

- Never commit `.env.local` or production secrets  
- Use secret management tools for production (Vault, AWS Secrets Manager)  
- Rotate secrets regularly  
- Use strong random values for APP_SECRET  

**Code Organization**:  

- Keep sensitive logic out of templates  
- Validate and sanitize all user input  
- Use Symfony's built-in CSRF protection  
- Configure security headers properly  

### Performance Optimization

**Cache Configuration**:  

```yaml
# config/packages/prod/cache.yaml
framework:
    cache:
        app: cache.adapter.redis
        default_redis_provider: redis://localhost
        
        pools:
            cache.app:
                adapter: cache.adapter.redis
                default_lifetime: 3600
```

**Asset Optimization**:  

- Use AssetMapper or Webpack Encore for asset management  
- Enable HTTP/2 for better performance  
- Implement proper cache headers  
- Minify CSS and JavaScript in production  

**Database Optimization**:  

- Use Doctrine's second-level cache for frequently accessed data  
- Implement pagination for large datasets  
- Optimize queries with proper indexes  
- Use partial objects when full entities aren't needed  

### Development Workflow

**Local Development Setup**:  

```bash
# Clone repository
git clone https://github.com/acme/my-app.git
cd my-app

# Install dependencies
composer install

# Configure environment
cp .env .env.local
# Edit .env.local with local database credentials

# Create database
php bin/console doctrine:database:create

# Run migrations
php bin/console doctrine:migrations:migrate

# Start development server
symfony serve
```

**Common Commands**:  

```bash
# Generate code
php bin/console make:controller
php bin/console make:entity
php bin/console make:form

# Database operations
php bin/console doctrine:migrations:migrate
php bin/console doctrine:schema:validate

# Cache operations
php bin/console cache:clear
php bin/console cache:warmup

# Run tests
php bin/phpunit
```

## Conclusion

Understanding Symfony's project structure is fundamental to working  
effectively with the framework. Each directory serves a specific purpose:  

- **src/** contains your application code  
- **config/** manages configuration  
- **public/** is the web-accessible directory  
- **var/** stores generated files  
- **vendor/** contains third-party dependencies  
- **bin/** provides executable scripts  
- **tests/** ensures code quality  
- **templates/** renders views  

The structure promotes separation of concerns, makes code organization  
intuitive, and follows industry best practices. As you work with Symfony,  
this organization will become second nature, allowing you to focus on  
building features rather than deciding where code should live.  

The framework's conventions, combined with powerful tools like Symfony Flex  
and MakerBundle, create a productive development environment that scales  
from small applications to large enterprise systems.  
