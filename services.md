# Symfony Services and Dependency Injection

This comprehensive guide explores Symfony's service container and dependency  
injection system, from foundational concepts to advanced patterns. Learn how  
to leverage services to build maintainable, testable applications with  
loosely coupled components.  

## What are Services?

Services are PHP objects that perform specific tasks within an application.  
They encapsulate business logic, data access, external API communication,  
email sending, file processing, and any other discrete functionality. In  
Symfony, almost everything is a service - from core framework components  
to custom application code.  

A service represents a single responsibility in the application. Rather than  
creating objects with `new` throughout the codebase, services are registered  
in a central container and injected where needed. This approach promotes  
code reuse, testability, and maintainability.  

### Core Characteristics

**Single Responsibility**: Each service focuses on one specific task or  
domain. An email service handles email operations, a payment service manages  
payment processing, and a user service handles user-related business logic.  
This separation creates clear boundaries and makes code easier to understand.  

**Stateless**: Services typically don't maintain state between method calls.  
They accept inputs, perform operations, and return results without relying  
on instance variables that persist across requests. This makes services  
thread-safe and predictable.  

**Reusable**: Services are designed to be used in multiple contexts. The  
same email service can be used in controllers, console commands, event  
listeners, and other services. This eliminates code duplication and ensures  
consistent behavior.  

**Testable**: Services accept dependencies through constructors, making them  
easy to test with mocked dependencies. This enables unit testing in isolation  
without requiring database connections or external services.  

**Configurable**: Services can be configured with parameters like API keys,  
environment-specific URLs, or feature flags. Configuration happens in one  
place rather than being scattered throughout the code.  

### Role in Symfony Architecture

Services form the foundation of Symfony's architecture. The framework itself  
is built from services - the router, request handler, security system,  
template engine, and database abstraction are all services managed by the  
container.  

**Framework Integration**: Symfony components are exposed as services,  
allowing applications to interact with framework features through dependency  
injection. This creates a consistent programming model where everything is  
accessed the same way.  

**Application Structure**: Business logic lives in custom services rather  
than controllers. Controllers become thin coordination layers that delegate  
work to services. This separation improves testability and keeps controllers  
focused on HTTP concerns.  

**Extensibility**: Third-party bundles register services that integrate  
seamlessly with applications. Installing a bundle makes its services  
immediately available through autowiring and type-hinting.  

**Configuration Management**: The service container compiles configuration  
from multiple sources into optimized service definitions. This happens once  
during cache warming, making runtime service access extremely fast.  

## The Service Container

The service container, also called the dependency injection container, is  
the central registry of all services in a Symfony application. It knows how  
to instantiate, configure, and wire together every service, managing their  
entire lifecycle.  

### Container Responsibilities

**Service Registration**: The container maintains a registry of service  
definitions including class names, constructor arguments, method calls, and  
configuration. Services can be registered manually or discovered  
automatically through directory scanning.  

**Dependency Resolution**: When a service is requested, the container  
analyzes its constructor parameters and automatically provides required  
dependencies. This recursive process continues until all dependencies are  
resolved and the complete object graph is constructed.  

**Lifecycle Management**: The container controls service instantiation and  
scope. Most services are lazy-loaded - created only when first requested.  
Once created, services are cached and reused throughout the request,  
ensuring efficient memory usage.  

**Configuration Application**: The container applies configuration to  
services, injecting parameters, calling setter methods, and setting up  
service relationships according to configuration files.  

### Container Compilation

During development, the container is rebuilt on each request to reflect code  
and configuration changes. In production, the container is compiled into  
optimized PHP code during cache warming, eliminating runtime overhead.  

The compilation process resolves all service definitions, performs validation,  
and generates specialized code for service instantiation. This pre-computation  
means production applications pay almost no penalty for using dependency  
injection.  

**Development Mode**: Container compilation happens automatically when  
configuration or service definitions change. This provides immediate feedback  
but adds slight overhead to each request.  

**Production Mode**: The container is compiled once during deployment via  
`cache:clear` or `cache:warmup`. The compiled container is pure PHP code  
with minimal overhead, making service access nearly as fast as manual object  
creation.  

### Service IDs and Types

Services are identified by their fully qualified class name (FQCN) or a  
custom string identifier. Modern Symfony applications primarily use class  
names as service IDs, enabling type-safe autowiring.  

```php
<?php

// Service ID is the class name
App\Service\EmailService::class

// Legacy string-based service ID
'app.mailer.service'
```

Services registered by class name can be autowired by type-hinting the class  
in constructors. This eliminates manual service lookup and creates  
self-documenting code.  

## Dependency Injection Fundamentals

Dependency injection is a design pattern where objects receive their  
dependencies from external sources rather than creating them internally.  
Instead of using `new` to instantiate dependencies, objects declare what  
they need, and the container provides those dependencies.  

### Why Dependency Injection?

**Loose Coupling**: Classes depend on interfaces rather than concrete  
implementations. This allows swapping implementations without changing  
dependent code. A class using `LoggerInterface` doesn't care if logs go to  
files, databases, or external services.  

**Testability**: Dependencies can be replaced with test doubles (mocks,  
stubs, fakes) during testing. This enables fast, isolated unit tests that  
don't require database connections, file systems, or network access.  

**Flexibility**: Configuration determines which implementations are injected.  
Different implementations can be used in different environments without code  
changes. Development might use a fake email service while production uses  
the real one.  

**Maintainability**: Dependencies are explicit and visible in constructors.  
Reading a constructor signature immediately reveals what a class needs to  
function. This clarity improves code understanding and maintenance.  

**Reusability**: Services can be used in multiple contexts because their  
dependencies are provided externally. The same service works in controllers,  
commands, event listeners, and other services.  

### Types of Dependency Injection

**Constructor Injection**: Dependencies are passed through the constructor  
and stored as instance properties. This is the preferred method in Symfony  
because it makes dependencies explicit and ensures objects are fully  
initialized before use.  

**Setter Injection**: Dependencies are provided through setter methods after  
object creation. This is useful for optional dependencies or when circular  
dependencies prevent constructor injection.  

**Method Injection**: Dependencies are passed to individual methods. Symfony  
uses this for controller actions, allowing services to be injected per-action  
rather than in the constructor.  

Symfony primarily uses constructor injection for services and method  
injection for controllers, creating a consistent and predictable pattern.  

### Autowiring

Autowiring is Symfony's automatic dependency injection mechanism. It analyzes  
constructor type-hints and automatically provides matching services from the  
container. This eliminates manual service wiring and reduces configuration.  

When a service constructor type-hints `LoggerInterface`, autowiring finds a  
service implementing that interface and injects it automatically. No  
configuration is needed beyond enabling autowiring in service defaults.  

Autowiring works by matching type-hints to service definitions. For classes  
and interfaces, the container looks for services with matching types. This  
makes adding dependencies as simple as adding constructor parameters.  

## Creating Custom Services

Custom services encapsulate application-specific business logic. They are  
plain PHP classes placed in the `src/` directory, typically under  
`src/Service/`, though organization is flexible.  

### Basic Service

Creating a simple service with dependencies.  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;

class NotificationService
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    public function send(string $recipient, string $message): bool
    {
        $this->logger->info('Sending notification', [
            'recipient' => $recipient,
            'message' => $message
        ]);

        // Notification sending logic here
        $success = true;

        if ($success) {
            $this->logger->info('Notification sent', ['recipient' => $recipient]);
        } else {
            $this->logger->error('Failed to send notification', [
                'recipient' => $recipient
            ]);
        }

        return $success;
    }
}
```

This service is automatically registered and autowired. The logger dependency  
is injected automatically because autowiring is enabled by default. The  
service can now be used anywhere in the application by type-hinting  
`NotificationService` in constructors.  

### Service with Configuration

Services often need configuration like API keys, URLs, or environment-specific  
settings. These are injected through constructor parameters.  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;

class EmailService
{
    public function __construct(
        private LoggerInterface $logger,
        private string $fromAddress,
        private string $smtpHost,
        private int $smtpPort = 587
    ) {
    }

    public function send(string $to, string $subject, string $body): bool
    {
        $this->logger->info('Sending email', [
            'from' => $this->fromAddress,
            'to' => $to,
            'subject' => $subject,
            'smtp_host' => $this->smtpHost
        ]);

        // Email sending implementation
        // Configure SMTP connection using $this->smtpHost and $this->smtpPort
        $sent = true;

        return $sent;
    }

    public function sendBatch(array $recipients, string $subject, string $body): int
    {
        $sent = 0;

        foreach ($recipients as $recipient) {
            if ($this->send($recipient, $subject, $body)) {
                $sent++;
            }
        }

        $this->logger->info('Batch email completed', [
            'total' => count($recipients),
            'sent' => $sent
        ]);

        return $sent;
    }
}
```

Configuration is provided in `config/services.yaml`:  

```yaml
# config/services.yaml
services:
    App\Service\EmailService:
        arguments:
            $fromAddress: '%env(MAIL_FROM_ADDRESS)%'
            $smtpHost: '%env(SMTP_HOST)%'
            $smtpPort: 587
```

Named arguments bind specific values to constructor parameters. Environment  
variables are referenced with `%env(VAR_NAME)%` syntax. Scalar values can be  
provided directly. This separation keeps configuration out of code and  
enables environment-specific settings.  

### Service with Multiple Dependencies

Real-world services often combine multiple dependencies to accomplish  
complex tasks.  

```php
<?php

namespace App\Service;

use App\Repository\ProductRepository;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;

class ProductService
{
    public function __construct(
        private ProductRepository $productRepository,
        private EntityManagerInterface $entityManager,
        private LoggerInterface $logger,
        private float $taxRate
    ) {
    }

    public function findProductWithTax(int $id): ?array
    {
        $product = $this->productRepository->find($id);

        if (!$product) {
            $this->logger->warning('Product not found', ['id' => $id]);
            return null;
        }

        $price = $product->getPrice();
        $priceWithTax = $price * (1 + $this->taxRate);

        return [
            'product' => $product,
            'price' => $price,
            'tax' => $price * $this->taxRate,
            'total' => $priceWithTax
        ];
    }

    public function updateStock(int $productId, int $quantity): bool
    {
        $product = $this->productRepository->find($productId);

        if (!$product) {
            return false;
        }

        $product->setStock($product->getStock() + $quantity);
        $this->entityManager->flush();

        $this->logger->info('Stock updated', [
            'product_id' => $productId,
            'new_stock' => $product->getStock()
        ]);

        return true;
    }

    public function getLowStockProducts(int $threshold = 10): array
    {
        return $this->productRepository->createQueryBuilder('p')
            ->where('p.stock < :threshold')
            ->setParameter('threshold', $threshold)
            ->getQuery()
            ->getResult();
    }
}
```

```yaml
# config/services.yaml
services:
    App\Service\ProductService:
        arguments:
            $taxRate: 0.21
```

The repository, entity manager, and logger are autowired automatically. Only  
the tax rate parameter requires manual configuration. This service  
demonstrates combining framework services (EntityManager, Logger) with  
custom repositories and scalar configuration.  

## Service Registration

Symfony provides multiple ways to register services, from automatic  
registration through directory scanning to explicit manual configuration.  

### Autoconfiguration

The default `config/services.yaml` automatically registers all classes in  
`src/` as services with autowiring enabled.  

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
```

**autowire: true**: Enables automatic dependency injection based on  
type-hints. The container automatically resolves and injects constructor  
dependencies.  

**autoconfigure: true**: Automatically applies tags based on implemented  
interfaces. Classes implementing `EventSubscriberInterface` are tagged as  
event subscribers, `CommandInterface` implementations are registered as  
commands.  

**resource**: Specifies which files to scan for services. The wildcard  
pattern registers everything under `src/`.  

**exclude**: Lists directories to skip during service registration. Entities,  
value objects, and infrastructure code are typically excluded.  

This configuration means any class created under `src/` is automatically  
available as a service with zero additional configuration.  

### Manual Service Registration

For fine-grained control, services can be registered explicitly with custom  
configuration.  

```yaml
# config/services.yaml
services:
    # Explicit service with full configuration
    app.payment.processor:
        class: App\Service\PaymentProcessor
        arguments:
            $apiKey: '%env(PAYMENT_API_KEY)%'
            $apiSecret: '%env(PAYMENT_API_SECRET)%'
            $environment: '%kernel.environment%'
        calls:
            - setLogger: ['@logger']
        tags:
            - { name: 'app.payment_handler' }

    # Service with factory
    app.pdf.generator:
        class: App\Service\PdfGenerator
        factory: ['App\Factory\PdfGeneratorFactory', 'create']
        arguments:
            $orientation: 'portrait'
            $pageSize: 'A4'

    # Service alias
    App\Service\PaymentInterface:
        alias: app.payment.processor
```

**class**: Specifies the service class. When using FQCN as service ID, this  
is optional.  

**arguments**: Provides constructor parameters. Named parameters start with  
`$`, services are referenced with `@serviceName`.  

**calls**: Defines setter injection methods called after construction.  

**tags**: Applies tags for service collection and processing.  

**factory**: Uses a factory method to create the service instead of direct  
instantiation.  

**alias**: Creates an alternative name for accessing the service.  

Manual registration is useful when autoconfiguration is insufficient, when  
working with third-party code, or when complex initialization is required.  

### Service Parameters

Parameters are static configuration values referenced throughout service  
definitions. They enable reusing values and organizing configuration.  

```yaml
# config/services.yaml
parameters:
    app.supported_locales: ['en', 'fr', 'de', 'es']
    app.upload.max_size: 5242880
    app.upload.allowed_extensions: ['jpg', 'png', 'pdf', 'doc']
    app.api.timeout: 30
    app.api.retry_attempts: 3

services:
    App\Service\FileUploadService:
        arguments:
            $maxSize: '%app.upload.max_size%'
            $allowedExtensions: '%app.upload.allowed_extensions%'
            $uploadDir: '%kernel.project_dir%/public/uploads'

    App\Service\ApiClient:
        arguments:
            $timeout: '%app.api.timeout%'
            $retryAttempts: '%app.api.retry_attempts%'
            $baseUrl: '%env(API_BASE_URL)%'
```

Parameters are referenced with `%parameter.name%` syntax. Environment  
variables use `%env(VAR_NAME)%`. Kernel parameters like `kernel.project_dir`  
provide framework information.  

## Using Services in Controllers

Controllers access services through dependency injection, making business  
logic easily accessible and testable. Symfony supports both constructor and  
method injection in controllers.  

### Constructor Injection

Injecting services through controller constructor for use across multiple  
actions.  

```php
<?php

namespace App\Controller;

use App\Service\ProductService;
use App\Service\EmailService;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ProductController extends AbstractController
{
    public function __construct(
        private ProductService $productService,
        private EmailService $emailService,
        private LoggerInterface $logger
    ) {
    }

    #[Route('/products', name: 'product_list')]
    public function list(): Response
    {
        $products = $this->productService->findAll();

        $this->logger->info('Product list viewed', [
            'count' => count($products)
        ]);

        return $this->render('product/list.html.twig', [
            'products' => $products
        ]);
    }

    #[Route('/products/{id}', name: 'product_show')]
    public function show(int $id): Response
    {
        $productData = $this->productService->findProductWithTax($id);

        if (!$productData) {
            throw $this->createNotFoundException('Product not found');
        }

        return $this->render('product/show.html.twig', $productData);
    }

    #[Route('/products/{id}/purchase', name: 'product_purchase')]
    public function purchase(int $id): Response
    {
        $productData = $this->productService->findProductWithTax($id);

        if (!$productData) {
            throw $this->createNotFoundException('Product not found');
        }

        $this->emailService->send(
            'customer@example.com',
            'Purchase Confirmation',
            'Thank you for your purchase!'
        );

        $this->addFlash('success', 'Purchase completed successfully');

        return $this->redirectToRoute('product_show', ['id' => $id]);
    }
}
```

Constructor injection is ideal when multiple controller actions use the same  
services. Services are stored as private properties and available throughout  
the controller. This reduces repetition and centralizes dependency  
declarations.  

### Method Injection

Injecting services directly into action methods for single-use scenarios.  

```php
<?php

namespace App\Controller;

use App\Service\NotificationService;
use App\Service\ProductService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class OrderController extends AbstractController
{
    #[Route('/order/create', name: 'order_create', methods: ['POST'])]
    public function create(
        Request $request,
        ProductService $productService,
        NotificationService $notificationService
    ): Response {
        $productId = (int) $request->request->get('product_id');
        $quantity = (int) $request->request->get('quantity');

        $product = $productService->findProductWithTax($productId);

        if (!$product) {
            throw $this->createNotFoundException('Product not found');
        }

        $total = $product['total'] * $quantity;

        $notificationService->send(
            'admin@example.com',
            sprintf('New order: %d x %s', $quantity, $product['product']->getName())
        );

        $this->addFlash('success', sprintf('Order placed. Total: $%.2f', $total));

        return $this->redirectToRoute('order_confirmation');
    }

    #[Route('/order/cancel/{id}', name: 'order_cancel')]
    public function cancel(int $id, NotificationService $notificationService): Response
    {
        $notificationService->send(
            'customer@example.com',
            sprintf('Order #%d cancelled', $id)
        );

        $this->addFlash('info', 'Order cancelled');

        return $this->redirectToRoute('home');
    }
}
```

Method injection provides services only to actions that need them. This keeps  
controllers lightweight and makes dependencies explicit at the action level.  
It's particularly useful for services used in only one or two actions.  

### Combining Both Approaches

Using constructor injection for commonly used services and method injection  
for occasional dependencies.  

```php
<?php

namespace App\Controller;

use App\Service\EmailService;
use App\Service\ProductService;
use App\Service\PaymentService;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class CheckoutController extends AbstractController
{
    public function __construct(
        private ProductService $productService,
        private EmailService $emailService,
        private LoggerInterface $logger
    ) {
    }

    #[Route('/checkout', name: 'checkout')]
    public function index(): Response
    {
        $products = $this->productService->findAll();

        return $this->render('checkout/index.html.twig', [
            'products' => $products
        ]);
    }

    #[Route('/checkout/process', name: 'checkout_process', methods: ['POST'])]
    public function process(
        Request $request,
        PaymentService $paymentService,
        EntityManagerInterface $entityManager
    ): Response {
        $productId = (int) $request->request->get('product_id');
        $amount = (float) $request->request->get('amount');

        $product = $this->productService->findProductWithTax($productId);

        if (!$product) {
            throw $this->createNotFoundException('Product not found');
        }

        $paymentResult = $paymentService->charge($amount, 'USD');

        if ($paymentResult['success']) {
            $this->productService->updateStock($productId, -1);

            $this->emailService->send(
                'customer@example.com',
                'Payment Confirmation',
                'Your payment was processed successfully'
            );

            $this->logger->info('Payment processed', [
                'product_id' => $productId,
                'amount' => $amount
            ]);

            $this->addFlash('success', 'Payment completed');
        } else {
            $this->logger->error('Payment failed', [
                'product_id' => $productId,
                'amount' => $amount
            ]);

            $this->addFlash('error', 'Payment failed');
        }

        return $this->redirectToRoute('checkout_confirmation');
    }
}
```

This hybrid approach balances convenience and explicitness. Frequently used  
services in the constructor reduce parameter lists, while occasional  
dependencies are injected per-action.  

## Using Services in Other Services

Services commonly depend on other services to accomplish their tasks. This  
composition creates flexible, maintainable service graphs.  

### Service Composition

Building complex services by combining simpler ones.  

```php
<?php

namespace App\Service;

use App\Repository\UserRepository;
use Psr\Log\LoggerInterface;

class UserNotificationService
{
    public function __construct(
        private UserRepository $userRepository,
        private EmailService $emailService,
        private NotificationService $notificationService,
        private LoggerInterface $logger
    ) {
    }

    public function notifyUser(int $userId, string $message): bool
    {
        $user = $this->userRepository->find($userId);

        if (!$user) {
            $this->logger->error('User not found for notification', [
                'user_id' => $userId
            ]);
            return false;
        }

        $emailSent = $this->emailService->send(
            $user->getEmail(),
            'Notification',
            $message
        );

        $notificationSent = $this->notificationService->send(
            $user->getEmail(),
            $message
        );

        $this->logger->info('User notified', [
            'user_id' => $userId,
            'email_sent' => $emailSent,
            'notification_sent' => $notificationSent
        ]);

        return $emailSent || $notificationSent;
    }

    public function notifyAllUsers(string $message): int
    {
        $users = $this->userRepository->findAll();
        $notified = 0;

        foreach ($users as $user) {
            if ($this->notifyUser($user->getId(), $message)) {
                $notified++;
            }
        }

        $this->logger->info('Mass notification completed', [
            'total_users' => count($users),
            'notified' => $notified
        ]);

        return $notified;
    }

    public function notifyAdmins(string $message): int
    {
        $admins = $this->userRepository->findByRole('ROLE_ADMIN');
        $notified = 0;

        $emails = array_map(fn($admin) => $admin->getEmail(), $admins);

        $this->emailService->sendBatch($emails, 'Admin Notification', $message);

        foreach ($admins as $admin) {
            if ($this->notificationService->send($admin->getEmail(), $message)) {
                $notified++;
            }
        }

        return $notified;
    }
}
```

Service composition promotes code reuse and single responsibility. Each  
service focuses on one task, and complex functionality emerges from  
combining services. This makes testing easier since each service can be  
tested independently with mocked dependencies.  

### Injecting Interfaces

Depending on interfaces rather than concrete implementations enables  
flexibility and testability.  

```php
<?php

namespace App\Service;

interface StorageInterface
{
    public function store(string $filename, string $content): bool;
    public function retrieve(string $filename): ?string;
    public function delete(string $filename): bool;
}

class LocalStorageService implements StorageInterface
{
    public function __construct(
        private string $storageDir
    ) {
    }

    public function store(string $filename, string $content): bool
    {
        $path = $this->storageDir . '/' . $filename;
        return file_put_contents($path, $content) !== false;
    }

    public function retrieve(string $filename): ?string
    {
        $path = $this->storageDir . '/' . $filename;
        
        if (!file_exists($path)) {
            return null;
        }

        return file_get_contents($path);
    }

    public function delete(string $filename): bool
    {
        $path = $this->storageDir . '/' . $filename;
        
        if (!file_exists($path)) {
            return false;
        }

        return unlink($path);
    }
}

class S3StorageService implements StorageInterface
{
    public function __construct(
        private string $bucket,
        private string $region
    ) {
    }

    public function store(string $filename, string $content): bool
    {
        // AWS S3 upload implementation
        return true;
    }

    public function retrieve(string $filename): ?string
    {
        // AWS S3 download implementation
        return 'content';
    }

    public function delete(string $filename): bool
    {
        // AWS S3 delete implementation
        return true;
    }
}
```

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;

class FileService
{
    public function __construct(
        private StorageInterface $storage,
        private LoggerInterface $logger
    ) {
    }

    public function saveFile(string $filename, string $content): bool
    {
        $this->logger->info('Saving file', ['filename' => $filename]);

        $result = $this->storage->store($filename, $content);

        if ($result) {
            $this->logger->info('File saved successfully', [
                'filename' => $filename
            ]);
        } else {
            $this->logger->error('Failed to save file', [
                'filename' => $filename
            ]);
        }

        return $result;
    }

    public function getFile(string $filename): ?string
    {
        return $this->storage->retrieve($filename);
    }
}
```

```yaml
# config/services.yaml
services:
    # Bind interface to implementation
    App\Service\StorageInterface:
        alias: App\Service\LocalStorageService

    App\Service\LocalStorageService:
        arguments:
            $storageDir: '%kernel.project_dir%/var/storage'

    App\Service\S3StorageService:
        arguments:
            $bucket: '%env(AWS_S3_BUCKET)%'
            $region: '%env(AWS_REGION)%'
```

The FileService depends on StorageInterface, not a concrete implementation.  
Configuration determines which storage service is used. This allows swapping  
local storage for S3 storage without changing FileService code.  

## Built-in Symfony Services

Symfony provides numerous built-in services for common tasks. These services  
are immediately available through autowiring by type-hinting their interfaces  
or classes.  

### Logger Service

Logging application events, errors, and debugging information.  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;

class DataImportService
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    public function import(string $filename): int
    {
        $this->logger->info('Starting data import', ['file' => $filename]);

        try {
            $imported = 0;

            // Import logic here
            $imported = 100;

            $this->logger->info('Import completed', [
                'file' => $filename,
                'records' => $imported
            ]);

            return $imported;
        } catch (\Exception $e) {
            $this->logger->error('Import failed', [
                'file' => $filename,
                'error' => $e->getMessage()
            ]);

            throw $e;
        }
    }

    public function validateData(array $data): array
    {
        $errors = [];

        foreach ($data as $index => $row) {
            if (empty($row['email'])) {
                $errors[] = "Row $index: Email required";
                $this->logger->warning('Validation failed', [
                    'row' => $index,
                    'error' => 'Missing email'
                ]);
            }
        }

        if (empty($errors)) {
            $this->logger->debug('Validation passed', ['rows' => count($data)]);
        }

        return $errors;
    }
}
```

The logger service accepts messages at different severity levels: debug,  
info, notice, warning, error, critical, alert, and emergency. Context arrays  
provide additional information for each log entry.  

### Entity Manager

Accessing Doctrine's entity manager for database operations.  

```php
<?php

namespace App\Service;

use App\Entity\Order;
use App\Entity\OrderItem;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;

class OrderService
{
    public function __construct(
        private EntityManagerInterface $entityManager,
        private LoggerInterface $logger
    ) {
    }

    public function createOrder(int $userId, array $items): Order
    {
        $order = new Order();
        $order->setUserId($userId);
        $order->setCreatedAt(new \DateTime());
        $order->setStatus('pending');

        $total = 0;

        foreach ($items as $itemData) {
            $item = new OrderItem();
            $item->setProductId($itemData['product_id']);
            $item->setQuantity($itemData['quantity']);
            $item->setPrice($itemData['price']);
            
            $order->addItem($item);
            $total += $itemData['price'] * $itemData['quantity'];
        }

        $order->setTotal($total);

        $this->entityManager->persist($order);
        $this->entityManager->flush();

        $this->logger->info('Order created', [
            'order_id' => $order->getId(),
            'user_id' => $userId,
            'total' => $total
        ]);

        return $order;
    }

    public function updateOrderStatus(int $orderId, string $status): bool
    {
        $order = $this->entityManager->getRepository(Order::class)->find($orderId);

        if (!$order) {
            return false;
        }

        $oldStatus = $order->getStatus();
        $order->setStatus($status);
        $order->setUpdatedAt(new \DateTime());

        $this->entityManager->flush();

        $this->logger->info('Order status updated', [
            'order_id' => $orderId,
            'old_status' => $oldStatus,
            'new_status' => $status
        ]);

        return true;
    }

    public function cancelOrder(int $orderId): bool
    {
        $order = $this->entityManager->getRepository(Order::class)->find($orderId);

        if (!$order || $order->getStatus() === 'cancelled') {
            return false;
        }

        $order->setStatus('cancelled');
        $order->setUpdatedAt(new \DateTime());

        $this->entityManager->flush();

        return true;
    }
}
```

The entity manager provides methods to persist, remove, flush, and query  
entities. It's the central access point for all Doctrine database operations.  

### Request Stack

Accessing the current request and request history.  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

class AnalyticsService
{
    public function __construct(
        private RequestStack $requestStack,
        private LoggerInterface $logger
    ) {
    }

    public function trackPageView(): void
    {
        $request = $this->requestStack->getCurrentRequest();

        if (!$request) {
            return;
        }

        $data = [
            'url' => $request->getPathInfo(),
            'method' => $request->getMethod(),
            'ip' => $request->getClientIp(),
            'user_agent' => $request->headers->get('User-Agent'),
            'referer' => $request->headers->get('Referer'),
            'timestamp' => new \DateTime()
        ];

        $this->logger->info('Page view tracked', $data);

        // Store analytics data
    }

    public function getClientInfo(): array
    {
        $request = $this->requestStack->getCurrentRequest();

        if (!$request) {
            return [];
        }

        return [
            'ip' => $request->getClientIp(),
            'locale' => $request->getLocale(),
            'preferred_language' => $request->getPreferredLanguage(),
            'is_secure' => $request->isSecure(),
            'is_ajax' => $request->isXmlHttpRequest()
        ];
    }
}
```

RequestStack provides access to the current request from anywhere in the  
application. This is useful for services that need request information but  
aren't directly invoked from controllers.  

### Router Service

Generating URLs and working with routes programmatically.  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class NotificationUrlService
{
    public function __construct(
        private UrlGeneratorInterface $router,
        private EmailService $emailService,
        private LoggerInterface $logger
    ) {
    }

    public function sendOrderConfirmation(int $orderId, string $email): void
    {
        $orderUrl = $this->router->generate(
            'order_show',
            ['id' => $orderId],
            UrlGeneratorInterface::ABSOLUTE_URL
        );

        $message = sprintf(
            'Your order has been confirmed. View details: %s',
            $orderUrl
        );

        $this->emailService->send($email, 'Order Confirmation', $message);

        $this->logger->info('Order confirmation sent', [
            'order_id' => $orderId,
            'email' => $email
        ]);
    }

    public function generatePasswordResetUrl(string $token): string
    {
        return $this->router->generate(
            'password_reset',
            ['token' => $token],
            UrlGeneratorInterface::ABSOLUTE_URL
        );
    }

    public function buildNavigationMenu(): array
    {
        return [
            'Home' => $this->router->generate('home'),
            'Products' => $this->router->generate('product_list'),
            'About' => $this->router->generate('about'),
            'Contact' => $this->router->generate('contact')
        ];
    }
}
```

The router service generates URLs from route names and parameters. It ensures  
URLs are consistent and automatically handles URL format changes.  

### Parameter Bag

Accessing application parameters and configuration.  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class ConfigurationService
{
    public function __construct(
        private ParameterBagInterface $params,
        private LoggerInterface $logger
    ) {
    }

    public function getUploadConfig(): array
    {
        return [
            'max_size' => $this->params->get('app.upload.max_size'),
            'allowed_extensions' => $this->params->get('app.upload.allowed_extensions'),
            'upload_dir' => $this->params->get('kernel.project_dir') . '/public/uploads'
        ];
    }

    public function getSupportedLocales(): array
    {
        return $this->params->get('app.supported_locales');
    }

    public function isProduction(): bool
    {
        return $this->params->get('kernel.environment') === 'prod';
    }

    public function logConfiguration(): void
    {
        $this->logger->info('Application configuration', [
            'environment' => $this->params->get('kernel.environment'),
            'debug' => $this->params->get('kernel.debug'),
            'project_dir' => $this->params->get('kernel.project_dir')
        ]);
    }
}
```

ParameterBagInterface provides access to all container parameters. This is  
useful for services that need to read configuration or make decisions based  
on environment settings.  

### Event Dispatcher

Dispatching and listening to application events.  

```php
<?php

namespace App\Service;

use App\Event\OrderPlacedEvent;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

class OrderEventService
{
    public function __construct(
        private EventDispatcherInterface $dispatcher,
        private LoggerInterface $logger
    ) {
    }

    public function dispatchOrderPlaced(int $orderId, int $userId, float $total): void
    {
        $event = new OrderPlacedEvent($orderId, $userId, $total);

        $this->dispatcher->dispatch($event, OrderPlacedEvent::NAME);

        $this->logger->info('Order placed event dispatched', [
            'order_id' => $orderId,
            'user_id' => $userId,
            'total' => $total
        ]);
    }
}
```

```php
<?php

namespace App\Event;

use Symfony\Contracts\EventDispatcher\Event;

class OrderPlacedEvent extends Event
{
    public const NAME = 'order.placed';

    public function __construct(
        private int $orderId,
        private int $userId,
        private float $total
    ) {
    }

    public function getOrderId(): int
    {
        return $this->orderId;
    }

    public function getUserId(): int
    {
        return $this->userId;
    }

    public function getTotal(): float
    {
        return $this->total;
    }
}
```

```php
<?php

namespace App\EventListener;

use App\Event\OrderPlacedEvent;
use App\Service\EmailService;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener(event: OrderPlacedEvent::NAME)]
class OrderPlacedListener
{
    public function __construct(
        private EmailService $emailService
    ) {
    }

    public function __invoke(OrderPlacedEvent $event): void
    {
        $this->emailService->send(
            'admin@example.com',
            'New Order',
            sprintf('Order #%d placed by user %d', 
                $event->getOrderId(),
                $event->getUserId()
            )
        );
    }
}
```

Event dispatcher enables decoupled communication between components. Events  
represent things that happened, and listeners respond without tight coupling.  

## Service Debugging and Inspection

Symfony provides console commands to inspect services, debug autowiring, and  
understand the service container.  

### Listing Services

```bash
# List all services
php bin/console debug:container

# Search for specific services
php bin/console debug:container email

# Show service details
php bin/console debug:container App\Service\EmailService

# List services with specific tag
php bin/console debug:container --tag=kernel.event_listener

# Show only public services
php bin/console debug:container --show-public

# List all parameters
php bin/console debug:container --parameters
```

The debug:container command shows all registered services, their IDs, and  
their classes. Service details include constructor arguments, method calls,  
and tags.  

### Debugging Autowiring

```bash
# List all autowirable types
php bin/console debug:autowiring

# Search for specific type
php bin/console debug:autowiring logger

# Show interface autowiring candidates
php bin/console debug:autowiring LoggerInterface
```

The debug:autowiring command shows which classes and interfaces can be  
type-hinted for automatic injection. This helps understand what services  
are available through autowiring.  

### Configuration Inspection

```bash
# Show service configuration
php bin/console config:dump-reference framework

# Show current configuration
php bin/console debug:config framework

# Show specific configuration path
php bin/console debug:config framework session
```

These commands help verify service configuration and understand available  
options for framework bundles.  

## Conclusion

Services and dependency injection form the foundation of Symfony applications.  
They enable loose coupling, testability, and maintainability by organizing  
code into reusable, focused components.  

The service container manages object creation and wiring, eliminating manual  
instantiation and configuration. Autowiring makes dependency injection nearly  
automatic, requiring minimal configuration while providing maximum flexibility.  

Understanding services is essential for effective Symfony development.  
Creating well-designed services, leveraging built-in framework services, and  
using dependency injection properly leads to clean, maintainable applications  
that scale from simple websites to complex enterprise systems.  

Whether building custom business logic, integrating third-party APIs, or  
extending framework functionality, services provide the structure and  
flexibility needed for modern PHP applications. Master services and  
dependency injection to unlock Symfony's full potential.  
