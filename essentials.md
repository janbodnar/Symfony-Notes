# Symfony Essentials

100 essential Symfony code snippets showcasing the most important aspects  
of the framework. This guide follows a progressive learning path, starting  
with foundational concepts and advancing to complex integrations.  

## Routing

### Basic Route Definition

Defining a simple route using PHP attributes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class WelcomeController extends AbstractController
{
    #[Route('/', name: 'app_welcome')]
    public function index(): Response
    {
        return new Response('Hello there!');
    }
}
```

This is the simplest form of a Symfony controller. The Route attribute maps  
the root URL to the index method. Controllers extending AbstractController  
gain access to helpful methods for rendering templates, redirecting, and  
working with flash messages.  

### Route Parameters

Capturing dynamic values from URLs.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProductController extends AbstractController
{
    #[Route('/product/{id}', name: 'product_show')]
    public function show(int $id): Response
    {
        return new Response(sprintf('Product ID: %d', $id));
    }

    #[Route('/product/{slug}/details', name: 'product_details')]
    public function details(string $slug): Response
    {
        return new Response(sprintf('Product: %s', $slug));
    }
}
```

Route parameters are automatically extracted and type-converted. The  
parameter name in curly braces must match the method parameter name.  
Symfony automatically converts string values to the specified type (int,  
string, etc.).  

### Route Requirements

Adding constraints to route parameters.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class BlogController extends AbstractController
{
    #[Route('/blog/{page}', name: 'blog_list', requirements: ['page' => '\d+'])]
    public function list(int $page = 1): Response
    {
        return new Response(sprintf('Blog page: %d', $page));
    }

    #[Route('/post/{slug}', name: 'post_show', requirements: ['slug' => '[a-z0-9-]+'])]
    public function show(string $slug): Response
    {
        return new Response(sprintf('Post: %s', $slug));
    }
}
```

Requirements use regular expressions to validate route parameters. If a  
parameter doesn't match the requirement, the route won't match and Symfony  
will try the next route. Default values can be provided for optional  
parameters.  

### HTTP Method Constraints

Restricting routes to specific HTTP methods.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ApiProductController extends AbstractController
{
    #[Route('/api/products', name: 'api_products_list', methods: ['GET'])]
    public function list(): Response
    {
        return $this->json(['products' => []]);
    }

    #[Route('/api/products', name: 'api_products_create', methods: ['POST'])]
    public function create(Request $request): Response
    {
        return $this->json(['created' => true], 201);
    }

    #[Route('/api/products/{id}', name: 'api_products_update', methods: ['PUT', 'PATCH'])]
    public function update(int $id, Request $request): Response
    {
        return $this->json(['updated' => $id]);
    }

    #[Route('/api/products/{id}', name: 'api_products_delete', methods: ['DELETE'])]
    public function delete(int $id): Response
    {
        return $this->json(['deleted' => $id]);
    }
}
```

The methods parameter restricts which HTTP methods can access the route.  
This is essential for RESTful APIs where the same URL has different  
behaviors based on the HTTP method. Multiple methods can be specified as  
an array.  

### Route Prefixes

Grouping routes with common prefixes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/admin')]
class AdminController extends AbstractController
{
    #[Route('/', name: 'admin_dashboard')]
    public function dashboard(): Response
    {
        return new Response('Admin Dashboard');
    }

    #[Route('/users', name: 'admin_users')]
    public function users(): Response
    {
        return new Response('User Management');
    }

    #[Route('/settings', name: 'admin_settings')]
    public function settings(): Response
    {
        return new Response('Admin Settings');
    }
}
```

Class-level Route attributes apply a prefix to all method routes. This  
keeps your routing organized and reduces repetition. The final URL is the  
combination of class and method route paths.  

### Route Generation

Generating URLs from route names.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class NavigationController extends AbstractController
{
    #[Route('/navigation', name: 'navigation')]
    public function index(UrlGeneratorInterface $urlGenerator): Response
    {
        // Generate relative URL
        $relativePath = $this->generateUrl('product_show', ['id' => 42]);
        
        // Generate absolute URL
        $absoluteUrl = $this->generateUrl(
            'product_show',
            ['id' => 42],
            UrlGeneratorInterface::ABSOLUTE_URL
        );
        
        // Using the URL generator service directly
        $networkPath = $urlGenerator->generate(
            'product_show',
            ['id' => 42],
            UrlGeneratorInterface::NETWORK_PATH
        );

        return $this->json([
            'relative' => $relativePath,
            'absolute' => $absoluteUrl,
            'network' => $networkPath
        ]);
    }
}
```

Never hard-code URLs in your application. Use route names to generate URLs,  
making your code maintainable and allowing route changes without breaking  
links. The UrlGeneratorInterface provides different URL formats for  
various use cases.  

### Route Locale

Handling internationalization in routes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class LocalizedController extends AbstractController
{
    #[Route('/{_locale}/about', name: 'about', requirements: ['_locale' => 'en|fr|de'])]
    public function about(string $_locale): Response
    {
        return $this->render('about.html.twig', [
            'locale' => $_locale
        ]);
    }

    #[Route('/contact', name: 'contact', defaults: ['_locale' => 'en'])]
    public function contact(string $_locale): Response
    {
        return new Response(sprintf('Contact page - Locale: %s', $_locale));
    }
}
```

The special `_locale` parameter is automatically available in Twig and  
the request. Use requirements to limit valid locales. Setting a default  
ensures fallback behavior when no locale is specified in the URL.  

### Route Priority

Controlling route matching order.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class PriorityController extends AbstractController
{
    #[Route('/page/special', name: 'page_special', priority: 10)]
    public function special(): Response
    {
        return new Response('Special page');
    }

    #[Route('/page/{slug}', name: 'page_show', priority: 0)]
    public function show(string $slug): Response
    {
        return new Response(sprintf('Page: %s', $slug));
    }
}
```

Routes with higher priority are matched first. This prevents generic routes  
from catching specific URLs. Without priority control, /page/special might  
be caught by the slug route. Default priority is 0.  

## Controllers

### Request Handling

Accessing request data in controllers.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class RequestController extends AbstractController
{
    #[Route('/search', name: 'search')]
    public function search(Request $request): Response
    {
        // Query parameters (?q=value)
        $query = $request->query->get('q', '');
        $page = $request->query->getInt('page', 1);
        
        // Request body (POST data)
        $email = $request->request->get('email');
        
        // Headers
        $userAgent = $request->headers->get('User-Agent');
        $acceptLanguage = $request->headers->get('Accept-Language');
        
        // Server variables
        $method = $request->getMethod();
        $ip = $request->getClientIp();
        $isAjax = $request->isXmlHttpRequest();

        return $this->json([
            'query' => $query,
            'page' => $page,
            'method' => $method,
            'ip' => $ip,
            'ajax' => $isAjax
        ]);
    }
}
```

The Request object provides organized access to all request data. Use  
specific getters like getInt() for type safety. The query property holds  
GET parameters, request holds POST parameters, and headers provides access  
to HTTP headers.  


### JSON API Response

Creating JSON responses for APIs.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ApiController extends AbstractController
{
    #[Route('/api/users', name: 'api_users')]
    public function getUsers(): JsonResponse
    {
        $users = [
            ['id' => 1, 'name' => 'Alice Johnson', 'role' => 'admin'],
            ['id' => 2, 'name' => 'Bob Smith', 'role' => 'user']
        ];

        return $this->json($users);
    }

    #[Route('/api/user/{id}', name: 'api_user')]
    public function getUser(int $id): JsonResponse
    {
        $user = ['id' => $id, 'name' => 'User ' . $id];
        
        return $this->json($user, Response::HTTP_OK, [
            'X-Custom-Header' => 'value'
        ]);
    }

    #[Route('/api/error-example', name: 'api_error')]
    public function errorExample(): JsonResponse
    {
        return $this->json(
            ['error' => 'Resource not found'],
            Response::HTTP_NOT_FOUND
        );
    }
}
```

The json() helper automatically serializes data and sets proper headers.  
You can specify HTTP status codes and custom headers. For complex  
serialization needs, inject the Serializer service for more control.  

### Redirects

Redirecting users to different routes or URLs.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class RedirectController extends AbstractController
{
    #[Route('/old-page', name: 'old_page')]
    public function oldPage(): Response
    {
        // Redirect to a route
        return $this->redirectToRoute('new_page');
    }

    #[Route('/new-page', name: 'new_page')]
    public function newPage(): Response
    {
        return new Response('New page content');
    }

    #[Route('/redirect-with-params', name: 'redirect_params')]
    public function redirectWithParams(): Response
    {
        // Redirect with parameters and status code
        return $this->redirectToRoute('product_show', [
            'id' => 42
        ], Response::HTTP_MOVED_PERMANENTLY);
    }

    #[Route('/external-redirect', name: 'external_redirect')]
    public function externalRedirect(): Response
    {
        // Redirect to external URL
        return $this->redirect('https://symfony.com');
    }
}
```

Use redirectToRoute() to redirect to named routes for maintainability.  
Permanent redirects (301) tell search engines the page has moved. Temporary  
redirects (302) are the default. Never redirect to user-supplied URLs  
without validation.  

### Flash Messages

Displaying one-time messages to users.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class FlashController extends AbstractController
{
    #[Route('/contact-form', name: 'contact_form')]
    public function contactForm(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            // Process form...
            
            // Add flash messages
            $this->addFlash('success', 'Message sent successfully!');
            $this->addFlash('info', 'We will respond within 24 hours.');
            
            return $this->redirectToRoute('contact_form');
        }

        return $this->render('contact/form.html.twig');
    }

    #[Route('/flash-demo', name: 'flash_demo')]
    public function flashDemo(): Response
    {
        $this->addFlash('warning', 'This is a warning message');
        $this->addFlash('error', 'This is an error message');
        $this->addFlash('success', 'This is a success message');

        return $this->redirectToRoute('flash_display');
    }

    #[Route('/flash-display', name: 'flash_display')]
    public function flashDisplay(): Response
    {
        return $this->render('flash/display.html.twig');
    }
}
```

Flash messages are stored in the session and automatically cleared after  
being displayed once. Use different types (success, error, warning, info)  
for semantic messaging. Flash messages only persist across one request  
(typically used with redirects).  

### Template Rendering

Rendering Twig templates with data.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class TemplateController extends AbstractController
{
    #[Route('/profile', name: 'profile')]
    public function profile(): Response
    {
        $user = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'joined' => new \DateTime('2023-01-15')
        ];

        return $this->render('profile/show.html.twig', [
            'user' => $user,
            'title' => 'User Profile'
        ]);
    }

    #[Route('/dashboard', name: 'dashboard')]
    public function dashboard(): Response
    {
        $stats = [
            'users' => 1523,
            'orders' => 842,
            'revenue' => 45678.90
        ];

        // Custom response with headers
        $response = $this->render('dashboard/index.html.twig', [
            'stats' => $stats
        ]);
        
        $response->setSharedMaxAge(3600);
        
        return $response;
    }
}
```

The render() method compiles Twig templates and returns a Response object.  
Pass variables as an associative array. Template names use namespace  
notation relative to the templates directory. You can modify the response  
before returning it.  

### Parameter Conversion

Automatically converting route parameters to entities.  

```php
<?php

namespace App\Controller;

use App\Entity\Article;
use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ParamConverterController extends AbstractController
{
    #[Route('/article/{id}', name: 'article_show')]
    public function showArticle(Article $article): Response
    {
        // Article is automatically fetched from database
        return $this->render('article/show.html.twig', [
            'article' => $article
        ]);
    }

    #[Route('/user/{username}', name: 'user_profile')]
    public function userProfile(User $user): Response
    {
        // Fetches user by username property
        return $this->render('user/profile.html.twig', [
            'user' => $user
        ]);
    }

    #[Route('/article/{article}/user/{user}', name: 'article_author')]
    public function articleAuthor(Article $article, User $user): Response
    {
        // Multiple entities converted
        return $this->render('article/author.html.twig', [
            'article' => $article,
            'user' => $user
        ]);
    }
}
```

ParamConverter automatically queries the database when you type-hint an  
entity. By default, it uses the id field. For other fields, it matches  
parameter names to entity properties. If the entity is not found, a 404  
error is automatically thrown.  

### Error Handling

Handling exceptions and errors gracefully.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Routing\Annotation\Route;

class ErrorController extends AbstractController
{
    #[Route('/item/{id}', name: 'item_show')]
    public function show(int $id): Response
    {
        $item = null; // Simulated database lookup
        
        if (!$item) {
            throw $this->createNotFoundException('Item not found');
        }

        return new Response('Item: ' . $id);
    }

    #[Route('/restricted', name: 'restricted')]
    public function restricted(): Response
    {
        $hasAccess = false; // Check user permissions
        
        if (!$hasAccess) {
            throw new AccessDeniedHttpException('Access denied');
        }

        return new Response('Restricted content');
    }

    #[Route('/custom-error', name: 'custom_error')]
    public function customError(): Response
    {
        try {
            // Some operation that might fail
            throw new \RuntimeException('Something went wrong');
        } catch (\RuntimeException $e) {
            // Log error, notify admins, etc.
            
            return $this->render('error/custom.html.twig', [
                'message' => $e->getMessage()
            ], new Response('', Response::HTTP_INTERNAL_SERVER_ERROR));
        }
    }
}
```

Use specific HTTP exceptions for common errors. createNotFoundException()  
is a shortcut for NotFoundHttpException. In production, these exceptions  
are caught and rendered with custom error pages. Always log unexpected  
errors for debugging.  

### Session Management

Working with user sessions.  

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
    public function addToCart(int $productId, SessionInterface $session): Response
    {
        // Get cart from session or initialize
        $cart = $session->get('cart', []);
        
        // Add product to cart
        if (isset($cart[$productId])) {
            $cart[$productId]++;
        } else {
            $cart[$productId] = 1;
        }
        
        $session->set('cart', $cart);
        
        $this->addFlash('success', 'Product added to cart');
        
        return $this->redirectToRoute('cart_view');
    }

    #[Route('/cart', name: 'cart_view')]
    public function viewCart(SessionInterface $session): Response
    {
        $cart = $session->get('cart', []);
        
        return $this->render('cart/view.html.twig', [
            'cart' => $cart,
            'total' => count($cart)
        ]);
    }

    #[Route('/cart/clear', name: 'cart_clear')]
    public function clearCart(SessionInterface $session): Response
    {
        $session->remove('cart');
        
        $this->addFlash('info', 'Cart cleared');
        
        return $this->redirectToRoute('cart_view');
    }
}
```

Session data persists across requests for the same user. Use session  
storage for temporary data like shopping carts. For authenticated users,  
prefer storing data in the database. Session data should be serializable.  
Avoid storing large objects in sessions.  

## Services & Dependency Injection

### Creating a Service

Defining a custom service class.  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;

class EmailService
{
    public function __construct(
        private LoggerInterface $logger,
        private string $fromAddress
    ) {
    }

    public function send(string $to, string $subject, string $body): bool
    {
        $this->logger->info('Sending email', [
            'to' => $to,
            'subject' => $subject
        ]);

        // Email sending logic here
        $success = true;

        if ($success) {
            $this->logger->info('Email sent successfully', ['to' => $to]);
        } else {
            $this->logger->error('Failed to send email', ['to' => $to]);
        }

        return $success;
    }

    public function sendBatch(array $recipients, string $subject, string $body): int
    {
        $sent = 0;
        
        foreach ($recipients as $recipient) {
            if ($this->send($recipient, $subject, $body)) {
                $sent++;
            }
        }

        $this->logger->info('Batch email completed', ['sent' => $sent]);
        
        return $sent;
    }
}
```

Services encapsulate reusable business logic. They are automatically  
registered in the container with autowiring enabled. Use constructor  
injection for dependencies. Services should be stateless and focused on  
specific functionality.  

### Service Configuration

Configuring services with parameters.  

```php
<?php

// config/services.yaml
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

    App\Service\PaymentService:
        arguments:
            $apiKey: '%env(PAYMENT_API_KEY)%'
            $environment: '%kernel.environment%'
```

```php
<?php

namespace App\Service;

class PaymentService
{
    public function __construct(
        private string $apiKey,
        private string $environment
    ) {
    }

    public function charge(float $amount, string $currency): array
    {
        $isProduction = $this->environment === 'prod';
        
        // Use different API endpoints based on environment
        $endpoint = $isProduction 
            ? 'https://api.payment.com/charge'
            : 'https://sandbox.payment.com/charge';

        return [
            'success' => true,
            'amount' => $amount,
            'currency' => $currency,
            'environment' => $this->environment
        ];
    }
}
```

Environment variables and parameters are injected through configuration.  
Use autowire for automatic dependency resolution. The _defaults section  
applies settings to all services. Exclude directories that don't contain  
services.  

### Service Injection

Injecting services into controllers and other services.  

```php
<?php

namespace App\Controller;

use App\Service\EmailService;
use App\Service\PaymentService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class OrderController extends AbstractController
{
    public function __construct(
        private EmailService $emailService,
        private PaymentService $paymentService
    ) {
    }

    #[Route('/order/create', name: 'order_create', methods: ['POST'])]
    public function create(Request $request): Response
    {
        $amount = $request->request->get('amount');
        $email = $request->request->get('email');
        
        // Process payment
        $paymentResult = $this->paymentService->charge(
            (float)$amount,
            'USD'
        );
        
        if ($paymentResult['success']) {
            // Send confirmation email
            $this->emailService->send(
                $email,
                'Order Confirmation',
                'Your order has been processed successfully.'
            );
            
            $this->addFlash('success', 'Order created successfully');
        } else {
            $this->addFlash('error', 'Payment failed');
        }

        return $this->redirectToRoute('order_list');
    }
}
```

Constructor injection is preferred for required dependencies. Services  
are automatically wired when type-hinted in constructors. This promotes  
testability and clear dependencies. Use method injection for optional  
dependencies or when constructor injection isn't practical.  


### Service Decoration

Extending existing services without modifying them.  

```php
<?php

namespace App\Service;

use Psr\Log\LoggerInterface;

class LoggingEmailServiceDecorator implements EmailServiceInterface
{
    public function __construct(
        private EmailServiceInterface $inner,
        private LoggerInterface $logger
    ) {
    }

    public function send(string $to, string $subject, string $body): bool
    {
        $startTime = microtime(true);
        
        $this->logger->debug('Email sending started', [
            'to' => $to,
            'subject' => $subject
        ]);
        
        $result = $this->inner->send($to, $subject, $body);
        
        $duration = microtime(true) - $startTime;
        
        $this->logger->debug('Email sending completed', [
            'to' => $to,
            'duration' => $duration,
            'success' => $result
        ]);
        
        return $result;
    }
}
```

```yaml
# config/services.yaml
services:
    App\Service\EmailServiceInterface: '@App\Service\EmailService'
    
    App\Service\LoggingEmailServiceDecorator:
        decorates: App\Service\EmailServiceInterface
        arguments:
            $inner: '@.inner'
```

Service decoration follows the decorator pattern. The decorating service  
wraps the original, adding functionality without modification. Use for  
cross-cutting concerns like logging, caching, or monitoring. The .inner  
reference accesses the decorated service.  

### Service Tagging

Organizing services with tags for automatic registration.  

```php
<?php

namespace App\Handler;

use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('app.notification_handler')]
interface NotificationHandlerInterface
{
    public function handle(array $data): void;
    public function supports(string $type): bool;
}

class EmailNotificationHandler implements NotificationHandlerInterface
{
    public function handle(array $data): void
    {
        // Send email notification
    }

    public function supports(string $type): bool
    {
        return $type === 'email';
    }
}

class SmsNotificationHandler implements NotificationHandlerInterface
{
    public function handle(array $data): void
    {
        // Send SMS notification
    }

    public function supports(string $type): bool
    {
        return $type === 'sms';
    }
}
```

```php
<?php

namespace App\Service;

use App\Handler\NotificationHandlerInterface;
use Symfony\Component\DependencyInjection\Attribute\TaggedIterator;

class NotificationDispatcher
{
    public function __construct(
        #[TaggedIterator('app.notification_handler')]
        private iterable $handlers
    ) {
    }

    public function dispatch(string $type, array $data): void
    {
        foreach ($this->handlers as $handler) {
            if ($handler->supports($type)) {
                $handler->handle($data);
                return;
            }
        }

        throw new \RuntimeException("No handler for type: $type");
    }
}
```

Tags group related services for collection injection. Use TaggedIterator  
to inject all services with a specific tag. This pattern enables plugin  
architectures and strategy patterns. Services implementing the same  
interface can be automatically tagged.  

### Service Aliases

Creating aliases for service references.  

```php
<?php

// config/services.yaml
services:
    # Define the main service
    App\Service\FileStorage:
        class: App\Service\S3FileStorage
        arguments:
            $bucket: '%env(S3_BUCKET)%'

    # Create alias for interface
    App\Service\FileStorageInterface: '@App\Service\FileStorage'
    
    # Short alias
    file_storage: '@App\Service\FileStorage'
```

```php
<?php

namespace App\Controller;

use App\Service\FileStorageInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UploadController extends AbstractController
{
    #[Route('/upload', name: 'file_upload')]
    public function upload(
        Request $request,
        FileStorageInterface $storage
    ): Response {
        /** @var UploadedFile $file */
        $file = $request->files->get('file');
        
        if ($file) {
            $filename = $storage->store($file);
            
            return $this->json(['filename' => $filename]);
        }

        return $this->json(['error' => 'No file uploaded'], 400);
    }
}
```

Aliases provide alternative names for services. Use them to bind interfaces  
to implementations, making code depend on abstractions. This enables easy  
swapping of implementations. Type-hint interfaces instead of concrete  
classes for flexibility.  

### Factory Services

Creating services using factories for complex initialization.  

```php
<?php

namespace App\Factory;

use App\Service\CacheService;
use Symfony\Component\Cache\Adapter\RedisAdapter;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

class CacheServiceFactory
{
    public function __construct(
        private string $environment,
        private string $redisHost,
        private string $cacheDir
    ) {
    }

    public function create(): CacheService
    {
        if ($this->environment === 'prod') {
            $adapter = new RedisAdapter(
                RedisAdapter::createConnection(
                    'redis://' . $this->redisHost
                )
            );
        } else {
            $adapter = new FilesystemAdapter(
                '',
                0,
                $this->cacheDir
            );
        }

        return new CacheService($adapter);
    }
}
```

```yaml
# config/services.yaml
services:
    App\Factory\CacheServiceFactory:
        arguments:
            $environment: '%kernel.environment%'
            $redisHost: '%env(REDIS_HOST)%'
            $cacheDir: '%kernel.cache_dir%'

    App\Service\CacheService:
        factory: ['@App\Factory\CacheServiceFactory', 'create']
```

Factories handle complex object creation logic. Use them when service  
instantiation requires conditional logic, multiple steps, or environment-  
specific configuration. The factory method is called when the service is  
first requested.  

### Service Subscribers

Lazily loading services with service subscribers.  

```php
<?php

namespace App\Service;

use Psr\Container\ContainerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Contracts\Service\Attribute\Required;
use Symfony\Contracts\Service\ServiceSubscriberInterface;

class ReportGenerator implements ServiceSubscriberInterface
{
    private ContainerInterface $container;

    #[Required]
    public function setContainer(ContainerInterface $container): void
    {
        $this->container = $container;
    }

    public static function getSubscribedServices(): array
    {
        return [
            'mailer' => MailerInterface::class,
            'pdf.generator' => PdfGeneratorService::class,
        ];
    }

    public function generateAndSend(string $type, string $email): void
    {
        // Services are only loaded when accessed
        if ($type === 'pdf') {
            $pdf = $this->container->get('pdf.generator')->generate();
            
            $this->container->get('mailer')->send(/* email with PDF */);
        }
    }
}
```

Service subscribers enable lazy loading of dependencies. Services are only  
instantiated when accessed through the container. This improves performance  
when not all dependencies are needed for every execution path. Use for  
services with many optional dependencies.  

## Configuration

### Environment Variables

Using environment variables for configuration.  

```php
<?php

// .env
APP_ENV=dev
APP_SECRET=your-secret-key
DATABASE_URL="mysql://user:pass@localhost:3306/dbname"
MAILER_DSN=smtp://localhost:1025
REDIS_URL=redis://localhost:6379
API_KEY=your-api-key
```

```php
<?php

namespace App\Service;

class ApiClient
{
    public function __construct(
        private string $apiKey,
        private string $environment
    ) {
    }

    public function makeRequest(string $endpoint): array
    {
        $baseUrl = $this->environment === 'prod'
            ? 'https://api.production.com'
            : 'https://api.sandbox.com';

        // Make API request using $this->apiKey
        
        return ['data' => 'response'];
    }
}
```

```yaml
# config/services.yaml
services:
    App\Service\ApiClient:
        arguments:
            $apiKey: '%env(API_KEY)%'
            $environment: '%kernel.environment%'
```

Environment variables separate configuration from code. Use .env files for  
local development and real environment variables in production. Never commit  
sensitive data to version control. The env() processor resolves environment  
variables at runtime.  

### YAML Configuration

Configuring bundles and services with YAML.  

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
        
    cache:
        app: cache.adapter.filesystem
        system: cache.adapter.system
        
    mailer:
        dsn: '%env(MAILER_DSN)%'
```

```yaml
# config/routes.yaml
api_routes:
    resource: ../src/Controller/Api/
    type: attribute
    prefix: /api
    
admin_routes:
    resource: ../src/Controller/Admin/
    type: attribute
    prefix: /admin
```

YAML is the preferred format for configuration files. Organize configuration  
by bundle in the packages directory. Use parameters for values that change  
between environments. Route configuration can import entire directories of  
controllers.  

### Parameters

Defining and using parameters.  

```yaml
# config/services.yaml
parameters:
    app.supported_locales: ['en', 'fr', 'de', 'es']
    app.items_per_page: 20
    app.upload_dir: '%kernel.project_dir%/public/uploads'
    app.max_upload_size: 5242880  # 5 MB

services:
    App\Service\PaginationService:
        arguments:
            $itemsPerPage: '%app.items_per_page%'
            
    App\Service\FileUploadService:
        arguments:
            $uploadDir: '%app.upload_dir%'
            $maxSize: '%app.max_upload_size%'
```

```php
<?php

namespace App\Service;

class PaginationService
{
    public function __construct(
        private int $itemsPerPage
    ) {
    }

    public function paginate(array $items, int $page): array
    {
        $offset = ($page - 1) * $this->itemsPerPage;
        
        return [
            'items' => array_slice($items, $offset, $this->itemsPerPage),
            'total' => count($items),
            'per_page' => $this->itemsPerPage,
            'current_page' => $page,
            'total_pages' => ceil(count($items) / $this->itemsPerPage)
        ];
    }
}
```

Parameters store configuration values that don't change at runtime. Define  
them in services.yaml for application-wide access. Built-in parameters like  
kernel.project_dir provide path information. Use parameters for tuning  
application behavior.  

### Service-Specific Configuration

Creating configuration for custom services.  

```yaml
# config/packages/app_notification.yaml
app_notification:
    channels:
        email:
            enabled: true
            from: noreply@example.com
        sms:
            enabled: false
            provider: twilio
    retry_attempts: 3
    queue_enabled: true
```

```php
<?php

namespace App\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('app_notification');
        
        $treeBuilder->getRootNode()
            ->children()
                ->arrayNode('channels')
                    ->children()
                        ->arrayNode('email')
                            ->children()
                                ->booleanNode('enabled')->defaultTrue()->end()
                                ->scalarNode('from')->defaultValue('noreply@example.com')->end()
                            ->end()
                        ->end()
                        ->arrayNode('sms')
                            ->children()
                                ->booleanNode('enabled')->defaultFalse()->end()
                                ->scalarNode('provider')->defaultValue('twilio')->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->integerNode('retry_attempts')->defaultValue(3)->end()
                ->booleanNode('queue_enabled')->defaultTrue()->end()
            ->end();
        
        return $treeBuilder;
    }
}
```

Custom configuration provides type-safe settings with validation. Define  
a Configuration class to specify the structure and defaults. This enables  
IDE autocomplete and prevents configuration errors. Use for complex service  
configuration needs.  

### Per-Environment Configuration

Environment-specific configuration files.  

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
            level: debug
        console:
            type: console
            process_psr_3_messages: false
            channels: ["!event", "!doctrine"]
```

```yaml
# config/packages/dev/monolog.yaml
monolog:
    handlers:
        main:
            type: stream
            path: "%kernel.logs_dir%/%kernel.environment%.log"
            level: debug
            channels: ["!event"]
        console:
            type: console
            process_psr_3_messages: false
            channels: ["!event", "!doctrine", "!console"]
```

Environment-specific files override base configuration. Place files in  
config/packages/{env}/ directories. Development typically has verbose  
logging while production uses optimized settings. Test environment might  
disable external services.  


### Bundle Configuration

Configuring third-party bundles.  

```yaml
# config/packages/doctrine.yaml
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
                type: attribute
                is_bundle: false
                dir: '%kernel.project_dir%/src/Entity'
                prefix: 'App\Entity'
                alias: App
```

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
```

Bundle configuration goes in config/packages. Each bundle has its own  
configuration file. Check documentation for available options. Most bundles  
provide sensible defaults. Configuration is merged from all environment  
files.  

## Forms

### Basic Form Type

Creating a custom form type.  

```php
<?php

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints as Assert;

class ContactType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('name', TextType::class, [
                'label' => 'Your Name',
                'attr' => ['placeholder' => 'Enter your name'],
                'constraints' => [
                    new Assert\NotBlank(),
                    new Assert\Length(['min' => 2, 'max' => 100])
                ]
            ])
            ->add('email', EmailType::class, [
                'label' => 'Email Address',
                'constraints' => [
                    new Assert\NotBlank(),
                    new Assert\Email()
                ]
            ])
            ->add('subject', TextType::class, [
                'label' => 'Subject',
                'constraints' => [
                    new Assert\NotBlank(),
                    new Assert\Length(['max' => 200])
                ]
            ])
            ->add('message', TextareaType::class, [
                'label' => 'Message',
                'attr' => ['rows' => 5],
                'constraints' => [
                    new Assert\NotBlank(),
                    new Assert\Length(['min' => 10, 'max' => 1000])
                ]
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'csrf_protection' => true,
        ]);
    }
}
```

Form types encapsulate form structure and validation. They are reusable  
across controllers. Constraints can be added at the field level or entity  
level. CSRF protection is enabled by default. Form types promote separation  
of concerns.  

### Entity Form

Creating forms bound to Doctrine entities.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    #[Assert\NotBlank]
    #[Assert\Length(min: 3, max: 255)]
    private ?string $name = null;

    #[ORM\Column(type: 'decimal', precision: 10, scale: 2)]
    #[Assert\NotBlank]
    #[Assert\Positive]
    private ?string $price = null;

    #[ORM\Column(type: 'text', nullable: true)]
    #[Assert\Length(max: 1000)]
    private ?string $description = null;

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

    public function getPrice(): ?string
    {
        return $this->price;
    }

    public function setPrice(string $price): self
    {
        $this->price = $price;
        return $this;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function setDescription(?string $description): self
    {
        $this->description = $description;
        return $this;
    }
}
```

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
            ->add('name', TextType::class)
            ->add('price', MoneyType::class, [
                'currency' => 'USD'
            ])
            ->add('description', TextareaType::class, [
                'required' => false
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

Entity forms automatically map to entity properties. Set data_class to  
enable this binding. Validation constraints from the entity are  
automatically applied. Form data is bound directly to the entity after  
submission.  

### Form Handling in Controller

Processing form submissions.  

```php
<?php

namespace App\Controller;

use App\Entity\Product;
use App\Form\ProductType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProductController extends AbstractController
{
    #[Route('/product/new', name: 'product_new')]
    public function new(Request $request, EntityManagerInterface $em): Response
    {
        $product = new Product();
        $form = $this->createForm(ProductType::class, $product);
        
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $em->persist($product);
            $em->flush();

            $this->addFlash('success', 'Product created successfully!');
            
            return $this->redirectToRoute('product_show', [
                'id' => $product->getId()
            ]);
        }

        return $this->render('product/new.html.twig', [
            'form' => $form,
        ]);
    }

    #[Route('/product/{id}/edit', name: 'product_edit')]
    public function edit(
        Product $product,
        Request $request,
        EntityManagerInterface $em
    ): Response {
        $form = $this->createForm(ProductType::class, $product);
        
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $em->flush();

            $this->addFlash('success', 'Product updated successfully!');
            
            return $this->redirectToRoute('product_show', [
                'id' => $product->getId()
            ]);
        }

        return $this->render('product/edit.html.twig', [
            'form' => $form,
            'product' => $product,
        ]);
    }
}
```

The handleRequest() method processes both GET and POST requests. Check  
isSubmitted() and isValid() before processing. For new entities, call  
persist(). For existing entities, just flush(). Always redirect after  
successful submission to prevent duplicate submissions.  

### Form Collections

Handling dynamic form collections.  

```php
<?php

namespace App\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Order
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\OneToMany(
        mappedBy: 'order',
        targetEntity: OrderItem::class,
        cascade: ['persist', 'remove'],
        orphanRemoval: true
    )]
    private Collection $items;

    public function __construct()
    {
        $this->items = new ArrayCollection();
    }

    public function getItems(): Collection
    {
        return $this->items;
    }

    public function addItem(OrderItem $item): self
    {
        if (!$this->items->contains($item)) {
            $this->items[] = $item;
            $item->setOrder($this);
        }

        return $this;
    }

    public function removeItem(OrderItem $item): self
    {
        if ($this->items->removeElement($item)) {
            if ($item->getOrder() === $this) {
                $item->setOrder(null);
            }
        }

        return $this;
    }
}
```

```php
<?php

namespace App\Form;

use App\Entity\Order;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CollectionType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class OrderType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('items', CollectionType::class, [
                'entry_type' => OrderItemType::class,
                'entry_options' => ['label' => false],
                'allow_add' => true,
                'allow_delete' => true,
                'by_reference' => false,
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Order::class,
        ]);
    }
}
```

CollectionType handles arrays of embedded forms. Set allow_add and  
allow_delete to enable dynamic addition/removal. Use by_reference: false  
to ensure Doctrine detects changes. Requires JavaScript on the frontend  
for adding/removing items.  

### Form Validation Groups

Applying different validation rules for different scenarios.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity]
class User
{
    #[ORM\Column(length: 255)]
    #[Assert\NotBlank(groups: ['registration', 'profile'])]
    #[Assert\Email(groups: ['registration', 'profile'])]
    private ?string $email = null;

    #[ORM\Column(length: 255)]
    #[Assert\NotBlank(groups: ['registration'])]
    #[Assert\Length(min: 8, groups: ['registration'])]
    private ?string $plainPassword = null;

    #[ORM\Column(length: 255)]
    #[Assert\NotBlank(groups: ['profile'])]
    #[Assert\Length(min: 2, max: 100, groups: ['profile'])]
    private ?string $fullName = null;

    // Getters and setters...
}
```

```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserRegistrationType;
use App\Form\UserProfileType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    #[Route('/register', name: 'user_register')]
    public function register(Request $request, EntityManagerInterface $em): Response
    {
        $user = new User();
        $form = $this->createForm(UserRegistrationType::class, $user, [
            'validation_groups' => ['registration']
        ]);
        
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $em->persist($user);
            $em->flush();
            
            return $this->redirectToRoute('user_profile');
        }

        return $this->render('user/register.html.twig', [
            'form' => $form,
        ]);
    }

    #[Route('/profile/edit', name: 'user_profile_edit')]
    public function editProfile(Request $request, EntityManagerInterface $em): Response
    {
        $user = $this->getUser();
        $form = $this->createForm(UserProfileType::class, $user, [
            'validation_groups' => ['profile']
        ]);
        
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $em->flush();
            
            return $this->redirectToRoute('user_profile');
        }

        return $this->render('user/edit_profile.html.twig', [
            'form' => $form,
        ]);
    }
}
```

Validation groups allow different validation rules for different contexts.  
Assign groups to constraints in the entity. Specify which groups to  
validate when creating the form. Useful for registration vs. profile  
editing scenarios.  

### File Upload Form

Handling file uploads in forms.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity]
class Document
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $filename = null;

    #[Assert\NotNull]
    #[Assert\File(
        maxSize: '5M',
        mimeTypes: ['application/pdf', 'application/msword'],
        mimeTypesMessage: 'Please upload a valid document (PDF or Word)'
    )]
    private ?File $file = null;

    public function getFile(): ?File
    {
        return $this->file;
    }

    public function setFile(?File $file): self
    {
        $this->file = $file;
        return $this;
    }

    public function getFilename(): ?string
    {
        return $this->filename;
    }

    public function setFilename(?string $filename): self
    {
        $this->filename = $filename;
        return $this;
    }
}
```

```php
<?php

namespace App\Controller;

use App\Entity\Document;
use App\Form\DocumentType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\String\Slugger\SluggerInterface;

class DocumentController extends AbstractController
{
    #[Route('/document/upload', name: 'document_upload')]
    public function upload(
        Request $request,
        EntityManagerInterface $em,
        SluggerInterface $slugger
    ): Response {
        $document = new Document();
        $form = $this->createForm(DocumentType::class, $document);
        
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $file = $document->getFile();
            
            if ($file) {
                $originalFilename = pathinfo(
                    $file->getClientOriginalName(),
                    PATHINFO_FILENAME
                );
                $safeFilename = $slugger->slug($originalFilename);
                $newFilename = $safeFilename . '-' . uniqid() . '.' . 
                              $file->guessExtension();

                $file->move(
                    $this->getParameter('upload_directory'),
                    $newFilename
                );

                $document->setFilename($newFilename);
            }

            $em->persist($document);
            $em->flush();

            $this->addFlash('success', 'Document uploaded successfully!');
            
            return $this->redirectToRoute('document_list');
        }

        return $this->render('document/upload.html.twig', [
            'form' => $form,
        ]);
    }
}
```

File uploads use the File constraint for validation. Slugger creates safe  
filenames from user input. Always add a unique identifier to prevent  
filename collisions. Store uploaded files outside the web root when  
possible. Validate file types and sizes to prevent security issues.  

### Custom Form Field Type

Creating a reusable custom form field.  

```php
<?php

namespace App\Form\Type;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\OptionsResolver\OptionsResolver;

class CountryType extends AbstractType
{
    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'choices' => [
                'United States' => 'US',
                'United Kingdom' => 'UK',
                'Germany' => 'DE',
                'France' => 'FR',
                'Spain' => 'ES',
                'Italy' => 'IT',
            ],
            'placeholder' => 'Select a country',
            'attr' => [
                'class' => 'country-select'
            ]
        ]);
    }

    public function getParent(): string
    {
        return ChoiceType::class;
    }
}
```

```php
<?php

namespace App\Form;

use App\Form\Type\CountryType;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;

class AddressType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('street', TextType::class)
            ->add('city', TextType::class)
            ->add('country', CountryType::class);
    }
}
```

Custom form types encapsulate reusable form fields. Extend another type  
by defining getParent(). Set default options in configureOptions(). Use  
custom types across multiple forms for consistency. This promotes DRY  
principles in form building.  


### Form Events

Modifying forms dynamically based on data.  

```php
<?php

namespace App\Form;

use App\Entity\Task;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormEvent;
use Symfony\Component\Form\FormEvents;
use Symfony\Component\OptionsResolver\OptionsResolver;

class TaskType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('title', TextType::class)
            ->add('category', ChoiceType::class, [
                'choices' => [
                    'Personal' => 'personal',
                    'Work' => 'work',
                    'Shopping' => 'shopping',
                ],
                'placeholder' => 'Select category'
            ]);

        $builder->addEventListener(
            FormEvents::PRE_SET_DATA,
            function (FormEvent $event) {
                $task = $event->getData();
                $form = $event->getForm();

                if ($task && $task->getCategory() === 'work') {
                    $form->add('project', TextType::class, [
                        'required' => true
                    ]);
                }
            }
        );

        $builder->get('category')->addEventListener(
            FormEvents::POST_SUBMIT,
            function (FormEvent $event) {
                $category = $event->getForm()->getData();
                $form = $event->getForm()->getParent();

                if ($category === 'work') {
                    $form->add('project', TextType::class, [
                        'required' => true
                    ]);
                }
            }
        );
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Task::class,
        ]);
    }
}
```

Form events enable dynamic form modification. PRE_SET_DATA fires before  
data is set on the form. POST_SUBMIT fires after field submission. Use  
events to add/remove fields based on data or user choices. This enables  
complex conditional logic in forms.  

## Validation

### Basic Validation Constraints

Applying validation rules to entity properties.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity]
class Article
{
    #[ORM\Column(length: 255)]
    #[Assert\NotBlank(message: 'Title is required')]
    #[Assert\Length(
        min: 5,
        max: 255,
        minMessage: 'Title must be at least {{ limit }} characters',
        maxMessage: 'Title cannot exceed {{ limit }} characters'
    )]
    private ?string $title = null;

    #[ORM\Column(type: 'text')]
    #[Assert\NotBlank]
    #[Assert\Length(min: 50, max: 5000)]
    private ?string $content = null;

    #[ORM\Column(length: 255)]
    #[Assert\NotBlank]
    #[Assert\Url]
    private ?string $sourceUrl = null;

    #[ORM\Column]
    #[Assert\Range(
        min: 1,
        max: 5,
        notInRangeMessage: 'Rating must be between {{ min }} and {{ max }}'
    )]
    private ?int $rating = null;

    // Getters and setters...
}
```

Validation constraints ensure data integrity. Apply them directly to entity  
properties using attributes. Symfony validates automatically when processing  
forms. Constraints can have custom error messages with placeholders for  
dynamic values.  

### Custom Validation Constraint

Creating custom validation logic.  

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;

#[\Attribute]
class ValidUsername extends Constraint
{
    public string $message = 'The username "{{ value }}" is not valid. It must contain only letters and numbers.';
    
    public function validatedBy(): string
    {
        return static::class.'Validator';
    }
}
```

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

class ValidUsernameValidator extends ConstraintValidator
{
    public function validate(mixed $value, Constraint $constraint): void
    {
        if (!$constraint instanceof ValidUsername) {
            throw new UnexpectedTypeException($constraint, ValidUsername::class);
        }

        if (null === $value || '' === $value) {
            return;
        }

        if (!preg_match('/^[a-zA-Z0-9]+$/', $value)) {
            $this->context->buildViolation($constraint->message)
                ->setParameter('{{ value }}', $value)
                ->addViolation();
        }
    }
}
```

```php
<?php

namespace App\Entity;

use App\Validator\ValidUsername;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class User
{
    #[ORM\Column(length: 50)]
    #[ValidUsername]
    private ?string $username = null;
}
```

Custom constraints encapsulate complex validation logic. Create a  
constraint class and a validator class. The validator contains the actual  
logic. Use buildViolation() to add error messages. Validators are  
automatically registered as services.  

### Conditional Validation

Validating based on conditions.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

#[ORM\Entity]
class Event
{
    #[ORM\Column(type: 'datetime')]
    private ?\DateTimeInterface $startDate = null;

    #[ORM\Column(type: 'datetime', nullable: true)]
    private ?\DateTimeInterface $endDate = null;

    #[ORM\Column]
    private bool $isRecurring = false;

    #[ORM\Column(length: 50, nullable: true)]
    #[Assert\Choice(
        choices: ['daily', 'weekly', 'monthly'],
        message: 'Choose a valid recurrence pattern'
    )]
    private ?string $recurrencePattern = null;

    #[Assert\Callback]
    public function validate(ExecutionContextInterface $context): void
    {
        if ($this->endDate && $this->endDate < $this->startDate) {
            $context->buildViolation('End date must be after start date')
                ->atPath('endDate')
                ->addViolation();
        }

        if ($this->isRecurring && !$this->recurrencePattern) {
            $context->buildViolation('Recurrence pattern is required for recurring events')
                ->atPath('recurrencePattern')
                ->addViolation();
        }
    }

    // Getters and setters...
}
```

Callback validation enables complex multi-field validation. Use  
ExecutionContext to add violations. The atPath() method specifies which  
field the error belongs to. Callbacks are useful for business rules that  
involve multiple properties.  

### Unique Entity Validation

Ensuring uniqueness of entity values.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity]
#[UniqueEntity(
    fields: ['email'],
    message: 'This email is already registered'
)]
#[UniqueEntity(
    fields: ['username'],
    message: 'This username is already taken',
    errorPath: 'username'
)]
class User
{
    #[ORM\Column(length: 180, unique: true)]
    #[Assert\NotBlank]
    #[Assert\Email]
    private ?string $email = null;

    #[ORM\Column(length: 50, unique: true)]
    #[Assert\NotBlank]
    private ?string $username = null;

    // Getters and setters...
}
```

UniqueEntity validates uniqueness at the database level. Apply it at the  
class level, not property level. Specify which fields must be unique. Use  
errorPath to assign errors to specific fields. This prevents duplicate  
entries.  

### Validation in Services

Validating data programmatically.  

```php
<?php

namespace App\Service;

use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Component\Validator\Constraints as Assert;

class DataImportService
{
    public function __construct(
        private ValidatorInterface $validator
    ) {
    }

    public function importUser(array $data): array
    {
        $constraints = new Assert\Collection([
            'email' => [
                new Assert\NotBlank(),
                new Assert\Email()
            ],
            'age' => [
                new Assert\NotBlank(),
                new Assert\Type('integer'),
                new Assert\Positive()
            ],
            'country' => [
                new Assert\NotBlank(),
                new Assert\Country()
            ]
        ]);

        $violations = $this->validator->validate($data, $constraints);

        if (count($violations) > 0) {
            $errors = [];
            foreach ($violations as $violation) {
                $errors[$violation->getPropertyPath()] = $violation->getMessage();
            }
            
            return ['success' => false, 'errors' => $errors];
        }

        // Process valid data
        return ['success' => true, 'data' => $data];
    }
}
```

ValidatorInterface enables validation outside of forms and entities. Use  
Collection constraint for array validation. Iterate over violations to  
extract errors. This is useful for API validation, data imports, and  
service layer validation.  

### Sequential Validation

Stopping validation on first error.  

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraints as Assert;

class ProductDto
{
    #[Assert\Sequentially([
        new Assert\NotBlank(),
        new Assert\Type('string'),
        new Assert\Length(min: 3, max: 100)
    ])]
    public ?string $name = null;

    #[Assert\Sequentially([
        new Assert\NotBlank(),
        new Assert\Type('numeric'),
        new Assert\Positive(),
        new Assert\Range(min: 0.01, max: 999999.99)
    ])]
    public $price = null;
}
```

Sequentially constraint stops validation at first failure. This prevents  
cascading errors and improves error messages. Each constraint in the  
sequence is checked in order. Useful for type checking before applying  
other constraints.  

## Security

### User Entity

Creating a user entity for authentication.  

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

User entities must implement UserInterface for authentication.  
PasswordAuthenticatedUserInterface is needed for password-based login.  
getUserIdentifier() returns the unique identifier (usually email or  
username). Roles are stored as an array with ROLE_USER as default.  

### Password Hashing

Hashing user passwords securely.  

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

class RegistrationController extends AbstractController
{
    #[Route('/register', name: 'app_register')]
    public function register(
        Request $request,
        UserPasswordHasherInterface $passwordHasher,
        EntityManagerInterface $em
    ): Response {
        $user = new User();
        
        // In real app, use a form
        $plainPassword = $request->request->get('password');
        $user->setEmail($request->request->get('email'));
        
        // Hash the password
        $hashedPassword = $passwordHasher->hashPassword(
            $user,
            $plainPassword
        );
        $user->setPassword($hashedPassword);

        $em->persist($user);
        $em->flush();

        return $this->json(['message' => 'User registered']);
    }

    #[Route('/change-password', name: 'app_change_password')]
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
            return $this->json(['error' => 'Invalid current password'], 400);
        }

        // Hash and set new password
        $hashedPassword = $passwordHasher->hashPassword($user, $newPassword);
        $user->setPassword($hashedPassword);

        $em->flush();

        return $this->json(['message' => 'Password changed']);
    }
}
```

Never store plain-text passwords. UserPasswordHasherInterface provides  
secure hashing using bcrypt by default. Use hashPassword() for new  
passwords and isPasswordValid() for verification. The hasher automatically  
uses the configured algorithm.  

### Role-Based Authorization

Controlling access based on user roles.  

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
        // Only super admins can access
        return $this->render('admin/settings.html.twig');
    }

    #[Route('/content/edit', name: 'content_edit')]
    public function editContent(): Response
    {
        // Check access programmatically
        $this->denyAccessUnlessGranted('ROLE_EDITOR');

        return $this->render('content/edit.html.twig');
    }
}
```

IsGranted attribute restricts access to routes. Users without the required  
role get a 403 error. Use denyAccessUnlessGranted() for programmatic  
checks. Define role hierarchies in security.yaml to inherit permissions.  

### Voter-Based Authorization

Creating custom authorization logic.  

```php
<?php

namespace App\Security\Voter;

use App\Entity\Post;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class PostVoter extends Voter
{
    const EDIT = 'POST_EDIT';
    const DELETE = 'POST_DELETE';
    const VIEW = 'POST_VIEW';

    protected function supports(string $attribute, mixed $subject): bool
    {
        if (!in_array($attribute, [self::EDIT, self::DELETE, self::VIEW])) {
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
            self:EDIT => $this->canEdit($post, $user),
            self::DELETE => $this->canDelete($post, $user),
            default => false
        };
    }

    private function canView(Post $post, User $user): bool
    {
        // Anyone can view published posts
        if ($post->isPublished()) {
            return true;
        }

        // Only author can view drafts
        return $user === $post->getAuthor();
    }

    private function canEdit(Post $post, User $user): bool
    {
        // Only author and admins can edit
        return $user === $post->getAuthor() || 
               in_array('ROLE_ADMIN', $user->getRoles());
    }

    private function canDelete(Post $post, User $user): bool
    {
        // Only admins can delete
        return in_array('ROLE_ADMIN', $user->getRoles());
    }
}
```

```php
<?php

namespace App\Controller;

use App\Entity\Post;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class PostController extends AbstractController
{
    #[Route('/post/{id}/edit', name: 'post_edit')]
    public function edit(Post $post): Response
    {
        $this->denyAccessUnlessGranted('POST_EDIT', $post);

        return $this->render('post/edit.html.twig', ['post' => $post]);
    }

    #[Route('/post/{id}/delete', name: 'post_delete')]
    public function delete(Post $post): Response
    {
        $this->denyAccessUnlessGranted('POST_DELETE', $post);

        // Delete logic here

        return $this->redirectToRoute('post_list');
    }
}
```

Voters implement complex authorization logic. They decide whether users  
can perform actions on specific objects. Use supports() to determine if  
the voter handles the attribute and subject. voteOnAttribute() contains  
the actual logic. Voters are automatically registered.  


### Login Form Authentication

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
            return $this->redirectToRoute('dashboard');
        }

        // Get login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        
        // Last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(): void
    {
        // This method can be blank - it will be intercepted by the logout key
        // on your firewall
        throw new \LogicException('This should never be reached');
    }
}
```

```yaml
# config/packages/security.yaml
security:
    password_hashers:
        App\Entity\User:
            algorithm: auto

    providers:
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email

    firewalls:
        main:
            lazy: true
            provider: app_user_provider
            form_login:
                login_path: app_login
                check_path: app_login
                enable_csrf: true
            logout:
                path: app_logout
                target: app_login
```

Form login is configured in security.yaml. The login_path shows the form,  
check_path processes credentials. AuthenticationUtils provides error  
messages and preserves the username. Logout is handled automatically by  
the security component.  

### Remember Me Functionality

Enabling persistent login sessions.  

```yaml
# config/packages/security.yaml
security:
    firewalls:
        main:
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800  # 1 week in seconds
                path: /
                always_remember_me: false
                token_provider:
                    doctrine: true
```

```twig
{# templates/security/login.html.twig #}
<form method="post">
    <input type="email" name="_username" value="{{ last_username }}">
    <input type="password" name="_password">
    
    <label>
        <input type="checkbox" name="_remember_me"> Remember me
    </label>
    
    <button type="submit">Login</button>
</form>
```

Remember me creates a cookie for persistent authentication. Set the  
lifetime in seconds. Use token_provider for database-backed tokens (more  
secure). The checkbox name must be _remember_me. The secret should be a  
strong random string.  

### API Token Authentication

Authenticating API requests with tokens.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class ApiToken
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255, unique: true)]
    private ?string $token = null;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false)]
    private ?User $user = null;

    #[ORM\Column(type: 'datetime')]
    private ?\DateTimeInterface $expiresAt = null;

    public function __construct()
    {
        $this->token = bin2hex(random_bytes(32));
        $this->expiresAt = new \DateTime('+30 days');
    }

    public function isValid(): bool
    {
        return $this->expiresAt > new \DateTime();
    }

    // Getters and setters...
}
```

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
        private ApiTokenRepository $tokenRepository
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
                $apiToken = $this->tokenRepository->findOneBy(['token' => $token]);
                
                if (!$apiToken || !$apiToken->isValid()) {
                    throw new AuthenticationException('Invalid token');
                }
                
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
            'message' => $exception->getMessage()
        ], Response::HTTP_UNAUTHORIZED);
    }
}
```

Custom authenticators handle non-standard authentication. supports()  
determines if the authenticator should run. authenticate() validates  
credentials and returns a Passport. SelfValidatingPassport is for tokens  
that don't need password verification.  

### CSRF Protection

Protecting forms from cross-site request forgery.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class CsrfDemoController extends AbstractController
{
    #[Route('/delete-item/{id}', name: 'item_delete', methods: ['POST'])]
    public function deleteItem(
        int $id,
        Request $request,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response {
        $token = new CsrfToken('delete-item', $request->request->get('_token'));
        
        if (!$csrfTokenManager->isTokenValid($token)) {
            $this->addFlash('error', 'Invalid CSRF token');
            return $this->redirectToRoute('item_list');
        }

        // Proceed with deletion
        
        $this->addFlash('success', 'Item deleted');
        return $this->redirectToRoute('item_list');
    }

    #[Route('/item-list', name: 'item_list')]
    public function listItems(CsrfTokenManagerInterface $csrfTokenManager): Response
    {
        // Generate token for delete forms
        $deleteToken = $csrfTokenManager->getToken('delete-item')->getValue();

        return $this->render('item/list.html.twig', [
            'csrf_token' => $deleteToken
        ]);
    }
}
```

```twig
{# templates/item/list.html.twig #}
<form method="post" action="{{ path('item_delete', {id: item.id}) }}">
    <input type="hidden" name="_token" value="{{ csrf_token }}">
    <button type="submit">Delete</button>
</form>
```

CSRF tokens prevent unauthorized form submissions. Forms automatically  
include tokens. For manual forms, generate tokens with  
CsrfTokenManagerInterface. Validate tokens before processing sensitive  
actions. Use unique token IDs for different actions.  

### Security Events

Listening to authentication and authorization events.  

```php
<?php

namespace App\EventListener;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

#[AsEventListener(event: LoginSuccessEvent::class)]
class LoginSuccessListener
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    public function __invoke(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        $request = $event->getRequest();
        
        $this->logger->info('User logged in', [
            'user' => $user->getUserIdentifier(),
            'ip' => $request->getClientIp(),
            'user_agent' => $request->headers->get('User-Agent')
        ]);
    }
}

#[AsEventListener(event: LoginFailureEvent::class)]
class LoginFailureListener
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    public function __invoke(LoginFailureEvent $event): void
    {
        $request = $event->getRequest();
        $exception = $event->getException();
        
        $this->logger->warning('Login failed', [
            'username' => $request->request->get('_username'),
            'ip' => $request->getClientIp(),
            'reason' => $exception->getMessage()
        ]);
    }
}

#[AsEventListener(event: LogoutEvent::class)]
class LogoutListener
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $token = $event->getToken();
        
        if ($token && $token->getUser()) {
            $this->logger->info('User logged out', [
                'user' => $token->getUser()->getUserIdentifier()
            ]);
        }
    }
}
```

Security events enable logging, notifications, and custom logic on  
authentication events. Use AsEventListener to automatically register  
listeners. LoginSuccessEvent fires on successful login, LoginFailureEvent  
on failure, LogoutEvent on logout. Access user and request data from  
events.  

### Access Control Rules

Configuring URL-based access control.  

```yaml
# config/packages/security.yaml
security:
    access_control:
        # Allow public access to login page
        - { path: ^/login, roles: PUBLIC_ACCESS }
        - { path: ^/register, roles: PUBLIC_ACCESS }
        
        # Require authentication for profile pages
        - { path: ^/profile, roles: ROLE_USER }
        
        # Require admin role for admin area
        - { path: ^/admin, roles: ROLE_ADMIN }
        
        # API requires special role
        - { path: ^/api, roles: ROLE_API_USER }
        
        # Super admin only area
        - { path: ^/super-admin, roles: ROLE_SUPER_ADMIN }
        
        # Match specific methods
        - { path: ^/api/users, roles: ROLE_ADMIN, methods: [POST, PUT, DELETE] }

    role_hierarchy:
        ROLE_ADMIN: ROLE_USER
        ROLE_SUPER_ADMIN: [ROLE_ADMIN, ROLE_ALLOWED_TO_SWITCH]
```

Access control rules restrict URL patterns to specific roles. Rules are  
evaluated in order - first match wins. Use regular expressions for  
patterns. PUBLIC_ACCESS allows unauthenticated access. Role hierarchy  
grants higher roles all lower role permissions.  

## Templating with Twig

### Basic Template Rendering

Rendering templates with variables.  

```twig
{# templates/base.html.twig #}
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{% block title %}Welcome!{% endblock %}</title>
    {% block stylesheets %}{% endblock %}
</head>
<body>
    {% block body %}{% endblock %}
    {% block javascripts %}{% endblock %}
</body>
</html>
```

```twig
{# templates/product/show.html.twig #}
{% extends 'base.html.twig' %}

{% block title %}{{ product.name }}{% endblock %}

{% block body %}
    <h1>{{ product.name }}</h1>
    <p>Price: ${{ product.price }}</p>
    <p>{{ product.description }}</p>
    
    {% if product.inStock %}
        <span class="badge">In Stock</span>
    {% else %}
        <span class="badge badge-danger">Out of Stock</span>
    {% endif %}
{% endblock %}
```

Twig templates use double curly braces for output and curly braces with  
percent for logic. Templates extend base templates using block inheritance.  
Variables are automatically escaped for security. Use if/else for  
conditional rendering.  

### Template Loops and Filters

Iterating over collections and transforming data.  

```twig
{# templates/user/list.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    <h1>Users ({{ users|length }})</h1>
    
    {% if users is empty %}
        <p>No users found.</p>
    {% else %}
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Registered</th>
                </tr>
            </thead>
            <tbody>
                {% for user in users %}
                    <tr class="{{ cycle(['odd', 'even'], loop.index0) }}">
                        <td>{{ user.id }}</td>
                        <td>{{ user.name|upper }}</td>
                        <td>{{ user.email|lower }}</td>
                        <td>{{ user.createdAt|date('Y-m-d') }}</td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    {% endif %}
{% endblock %}
```

The for loop iterates over collections. Loop variable provides metadata  
like loop.index and loop.first. Filters transform values using the pipe  
operator. Common filters include upper, lower, date, and length. Use is  
empty to check for empty collections.  

### Path and URL Generation

Generating routes in templates.  

```twig
{# templates/navigation.html.twig #}
<nav>
    <ul>
        <li><a href="{{ path('home') }}">Home</a></li>
        <li><a href="{{ path('about') }}">About</a></li>
        <li><a href="{{ path('product_list') }}">Products</a></li>
        <li><a href="{{ path('product_show', {id: 42}) }}">Product #42</a></li>
        <li><a href="{{ url('contact') }}">Contact</a></li>
    </ul>
</nav>

{# Generating URLs with query parameters #}
<a href="{{ path('search', {q: 'symfony', page: 2}) }}">
    Search Results
</a>

{# Absolute URL generation #}
<link rel="canonical" href="{{ url('product_show', {id: product.id}) }}">
```

Use path() for relative URLs and url() for absolute URLs. Pass route  
parameters as a hash. Never hard-code URLs. Route names provide  
maintainability. Query parameters can be included in the parameter hash.  

### Template Includes and Embeds

Reusing template fragments.  

```twig
{# templates/_partials/alert.html.twig #}
<div class="alert alert-{{ type }}">
    {{ message }}
</div>
```

```twig
{# templates/product/show.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    {# Include partial template #}
    {% include '_partials/alert.html.twig' with {
        'type': 'success',
        'message': 'Product loaded successfully'
    } %}
    
    <h1>{{ product.name }}</h1>
    
    {# Include with only specific variables #}
    {% include '_partials/product_card.html.twig' with {
        'product': product
    } only %}
    
    {# Embed allows overriding blocks #}
    {% embed '_partials/card.html.twig' %}
        {% block title %}{{ product.name }}{% endblock %}
        {% block content %}
            <p>{{ product.description }}</p>
        {% endblock %}
    {% endembed %}
{% endblock %}
```

Include reuses template fragments. Pass variables with the with keyword.  
Use only to limit variable scope. Embed is like include but allows  
overriding blocks. This promotes DRY principles and component-based  
templates.  

### Flash Messages in Templates

Displaying one-time messages.  

```twig
{# templates/_partials/flashes.html.twig #}
{% for label, messages in app.flashes %}
    {% for message in messages %}
        <div class="alert alert-{{ label }}">
            {{ message }}
        </div>
    {% endfor %}
{% endfor %}
```

```twig
{# templates/base.html.twig #}
<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}My App{% endblock %}</title>
</head>
<body>
    <div class="container">
        {# Display flash messages #}
        {% include '_partials/flashes.html.twig' %}
        
        {% block body %}{% endblock %}
    </div>
</body>
</html>
```

Flash messages are available through app.flashes in templates. Iterate  
over message types and messages. Flash messages are automatically cleared  
after being displayed. Include flash display in your base template for  
site-wide availability.  

### Twig Extensions and Functions

Using built-in and custom Twig functions.  

```twig
{# templates/article/show.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    <h1>{{ article.title }}</h1>
    
    {# Date formatting #}
    <p>Published: {{ article.publishedAt|date('F j, Y') }}</p>
    
    {# String manipulation #}
    <p>{{ article.content|slice(0, 200) }}...</p>
    <p>Word count: {{ article.content|split(' ')|length }}</p>
    
    {# JSON encoding #}
    <script>
        const article = {{ article|json_encode|raw }};
    </script>
    
    {# Asset function for static files #}
    <img src="{{ asset('images/article/' ~ article.image) }}" 
         alt="{{ article.title }}">
    
    {# Absolute URL for assets #}
    <link rel="stylesheet" href="{{ absolute_url(asset('css/style.css')) }}">
    
    {# Current route and parameters #}
    {% if app.request.attributes.get('_route') == 'article_show' %}
        <p>Viewing article mode</p>
    {% endif %}
    
    {# User information #}
    {% if is_granted('ROLE_USER') %}
        <p>Welcome, {{ app.user.email }}!</p>
    {% endif %}
{% endblock %}
```

Twig provides many built-in functions and filters. asset() generates URLs  
for static files. date formats dates. json_encode serializes data. Use  
raw filter carefully to output unescaped HTML. app variable provides  
access to request, user, and environment.  


### Custom Twig Extensions

Creating custom Twig functions and filters.  

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
            new TwigFilter('highlight', [$this, 'highlightText'], ['is_safe' => ['html']]),
        ];
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('area', [$this, 'calculateArea']),
        ];
    }

    public function formatPrice(float $price, string $currency = 'USD'): string
    {
        return match($currency) {
            'USD' => '$' . number_format($price, 2),
            'EUR' => '€' . number_format($price, 2),
            default => number_format($price, 2) . ' ' . $currency
        };
    }

    public function highlightText(string $text, string $search): string
    {
        return str_replace(
            $search,
            '<mark>' . $search . '</mark>',
            $text
        );
    }

    public function calculateArea(float $width, float $height): float
    {
        return $width * $height;
    }
}
```

Custom extensions add application-specific functionality to Twig. Define  
filters with TwigFilter and functions with TwigFunction. Mark filters as  
safe when they output HTML. Extensions are automatically registered as  
services.  

### Form Rendering in Twig

Rendering forms with Twig.  

```twig
{# templates/product/new.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    <h1>Create Product</h1>
    
    {# Render entire form at once #}
    {{ form(form) }}
    
    {# Or render manually for more control #}
    {{ form_start(form) }}
        {{ form_errors(form) }}
        
        <div class="form-group">
            {{ form_label(form.name) }}
            {{ form_widget(form.name, {'attr': {'class': 'form-control'}}) }}
            {{ form_errors(form.name) }}
        </div>
        
        <div class="form-group">
            {{ form_label(form.price) }}
            {{ form_widget(form.price) }}
            {{ form_help(form.price) }}
        </div>
        
        {# Render remaining fields #}
        {{ form_rest(form) }}
        
        <button type="submit" class="btn btn-primary">Save</button>
    {{ form_end(form) }}
{% endblock %}
```

Form functions render form elements. form_start() opens the form tag.  
form_widget() renders input fields. form_label() renders labels.  
form_errors() displays validation errors. form_rest() renders any  
remaining fields. form_end() closes the form and adds hidden fields.  

## Event Dispatching

### Creating Custom Events

Defining application-specific events.  

```php
<?php

namespace App\Event;

use App\Entity\Order;
use Symfony\Contracts\EventDispatcher\Event;

class OrderPlacedEvent extends Event
{
    public const NAME = 'order.placed';

    public function __construct(
        private Order $order
    ) {
    }

    public function getOrder(): Order
    {
        return $this->order;
    }
}
```

```php
<?php

namespace App\Service;

use App\Entity\Order;
use App\Event\OrderPlacedEvent;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

class OrderService
{
    public function __construct(
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    public function placeOrder(Order $order): void
    {
        // Process order logic
        
        // Dispatch event
        $event = new OrderPlacedEvent($order);
        $this->eventDispatcher->dispatch($event, OrderPlacedEvent::NAME);
    }
}
```

Custom events decouple application logic. Events carry data relevant to  
the occurrence. Dispatch events at key points in your application.  
Multiple listeners can respond to the same event without coupling.  

### Event Listeners

Creating event listeners.  

```php
<?php

namespace App\EventListener;

use App\Event\OrderPlacedEvent;
use App\Service\EmailService;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener(event: OrderPlacedEvent::NAME, priority: 10)]
class OrderNotificationListener
{
    public function __construct(
        private EmailService $emailService
    ) {
    }

    public function __invoke(OrderPlacedEvent $event): void
    {
        $order = $event->getOrder();
        
        $this->emailService->send(
            $order->getCustomerEmail(),
            'Order Confirmation',
            'Your order #' . $order->getId() . ' has been placed.'
        );
    }
}

#[AsEventListener(event: OrderPlacedEvent::NAME, priority: 5)]
class OrderInventoryListener
{
    public function __invoke(OrderPlacedEvent $event): void
    {
        $order = $event->getOrder();
        
        // Update inventory
        foreach ($order->getItems() as $item) {
            // Decrease stock
        }
    }
}
```

Event listeners respond to events. Use AsEventListener for automatic  
registration. Priority controls execution order (higher runs first).  
Listeners should handle one specific task. Multiple listeners can process  
the same event independently.  

### Event Subscribers

Creating event subscribers for related listeners.  

```php
<?php

namespace App\EventSubscriber;

use App\Event\OrderPlacedEvent;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class OrderSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            OrderPlacedEvent::NAME => [
                ['logOrder', 10],
                ['sendNotification', 5],
            ],
            KernelEvents::REQUEST => 'onKernelRequest',
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }

    public function logOrder(OrderPlacedEvent $event): void
    {
        $this->logger->info('Order placed', [
            'order_id' => $event->getOrder()->getId()
        ]);
    }

    public function sendNotification(OrderPlacedEvent $event): void
    {
        // Send notification logic
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        // Request processing
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        // Response processing
    }
}
```

Event subscribers group related listeners. Implement EventSubscriberInterface  
and define getSubscribedEvents(). Multiple methods can handle the same  
event with different priorities. Subscribers are automatically registered.  
Use subscribers for cohesive event handling logic.  

### Kernel Events

Listening to HTTP request lifecycle events.  

```php
<?php

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class RequestResponseSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 10],
            KernelEvents::RESPONSE => ['onKernelResponse', 0],
            KernelEvents::EXCEPTION => ['onKernelException', 0],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        
        // Set locale from request
        if ($locale = $request->query->get('locale')) {
            $request->setLocale($locale);
        }
        
        // Add custom header tracking
        $request->attributes->set('request_time', microtime(true));
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $response = $event->getResponse();
        
        // Add custom headers
        $response->headers->set('X-Custom-Header', 'Symfony App');
        
        // Calculate request duration
        if ($startTime = $request->attributes->get('request_time')) {
            $duration = microtime(true) - $startTime;
            $response->headers->set('X-Request-Duration', $duration);
        }
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        $exception = $event->getThrowable();
        
        // Log exception, send notifications, etc.
    }
}
```

Kernel events provide hooks into the request/response lifecycle. REQUEST  
fires early in request handling. RESPONSE fires before sending the  
response. EXCEPTION fires when an exception occurs. Use isMainRequest()  
to distinguish main requests from sub-requests.  

### Stoppable Events

Preventing further event propagation.  

```php
<?php

namespace App\Event;

use Symfony\Contracts\EventDispatcher\Event;

class UserLoginEvent extends Event
{
    private bool $loginAllowed = true;

    public function __construct(
        private string $username,
        private string $ipAddress
    ) {
    }

    public function preventLogin(): void
    {
        $this->loginAllowed = false;
        $this->stopPropagation();
    }

    public function isLoginAllowed(): bool
    {
        return $this->loginAllowed;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getIpAddress(): string
    {
        return $this->ipAddress;
    }
}
```

```php
<?php

namespace App\EventListener;

use App\Event\UserLoginEvent;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener(event: UserLoginEvent::class, priority: 100)]
class IpBlockerListener
{
    private array $blockedIps = ['192.168.1.100'];

    public function __invoke(UserLoginEvent $event): void
    {
        if (in_array($event->getIpAddress(), $this->blockedIps)) {
            $event->preventLogin();
        }
    }
}

#[AsEventListener(event: UserLoginEvent::class, priority: 50)]
class RateLimitListener
{
    public function __invoke(UserLoginEvent $event): void
    {
        // This won't execute if IP is blocked
        // because propagation was stopped
    }
}
```

Stoppable events can halt listener execution. Call stopPropagation() to  
prevent subsequent listeners from running. Higher priority listeners run  
first and can stop lower priority ones. Useful for validation chains and  
authorization checks.  

### Event Dependency Injection

Injecting services into event listeners.  

```php
<?php

namespace App\EventListener;

use App\Event\OrderPlacedEvent;
use App\Service\EmailService;
use App\Service\SmsService;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener(event: OrderPlacedEvent::NAME)]
class OrderProcessingListener
{
    public function __construct(
        private EntityManagerInterface $entityManager,
        private EmailService $emailService,
        private SmsService $smsService,
        private LoggerInterface $logger
    ) {
    }

    public function __invoke(OrderPlacedEvent $event): void
    {
        $order = $event->getOrder();
        
        try {
            // Update order status
            $order->setStatus('processing');
            $this->entityManager->flush();
            
            // Send notifications
            $this->emailService->send(
                $order->getCustomerEmail(),
                'Order Processing',
                'Your order is being processed'
            );
            
            if ($order->getCustomer()->getSmsEnabled()) {
                $this->smsService->send(
                    $order->getCustomer()->getPhone(),
                    'Order processing started'
                );
            }
            
            $this->logger->info('Order processing complete', [
                'order_id' => $order->getId()
            ]);
            
        } catch (\Exception $e) {
            $this->logger->error('Order processing failed', [
                'order_id' => $order->getId(),
                'error' => $e->getMessage()
            ]);
        }
    }
}
```

Event listeners support full dependency injection. Constructor injection  
provides all needed services. Listeners are registered as services  
automatically. This enables complex event handling with access to all  
application services.  

## Doctrine ORM

### Entity Definition

Defining database entities.  

```php
<?php

namespace App\Entity;

use App\Repository\ProductRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: ProductRepository::class)]
#[ORM\Table(name: 'products')]
#[ORM\Index(columns: ['name'], name: 'product_name_idx')]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $name = null;

    #[ORM\Column(type: Types::DECIMAL, precision: 10, scale: 2)]
    private ?string $price = null;

    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $description = null;

    #[ORM\Column]
    private ?int $stock = 0;

    #[ORM\Column(type: Types::DATETIME_MUTABLE)]
    private ?\DateTimeInterface $createdAt = null;

    public function __construct()
    {
        $this->createdAt = new \DateTime();
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

    public function getPrice(): ?string
    {
        return $this->price;
    }

    public function setPrice(string $price): self
    {
        $this->price = $price;
        return $this;
    }
}
```

Entities are PHP classes mapped to database tables. Use ORM attributes  
to define mapping. Id and GeneratedValue mark auto-increment primary keys.  
Column defines table columns with types and constraints. Initialize  
default values in the constructor.  

### Entity Relationships

Defining one-to-many and many-to-one relationships.  

```php
<?php

namespace App\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Category
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 100)]
    private ?string $name = null;

    #[ORM\OneToMany(mappedBy: 'category', targetEntity: Product::class)]
    private Collection $products;

    public function __construct()
    {
        $this->products = new ArrayCollection();
    }

    public function getProducts(): Collection
    {
        return $this->products;
    }

    public function addProduct(Product $product): self
    {
        if (!$this->products->contains($product)) {
            $this->products[] = $product;
            $product->setCategory($this);
        }
        return $this;
    }

    public function removeProduct(Product $product): self
    {
        if ($this->products->removeElement($product)) {
            if ($product->getCategory() === $this) {
                $product->setCategory(null);
            }
        }
        return $this;
    }
}
```

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

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

OneToMany and ManyToOne define bidirectional relationships. The owning  
side (ManyToOne) has the JoinColumn. Initialize collections as  
ArrayCollection. Add helper methods for managing relationships. Use  
mappedBy and inversedBy to link both sides.  

### Persisting Entities

Saving entities to the database.  

```php
<?php

namespace App\Controller;

use App\Entity\Product;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProductController extends AbstractController
{
    #[Route('/product/create', name: 'product_create')]
    public function create(EntityManagerInterface $em): Response
    {
        $product = new Product();
        $product->setName('Laptop');
        $product->setPrice('999.99');
        $product->setDescription('High-performance laptop');
        $product->setStock(10);

        // Tell Doctrine to manage this entity
        $em->persist($product);
        
        // Execute the INSERT query
        $em->flush();

        return new Response('Product created with id: ' . $product->getId());
    }

    #[Route('/product/{id}/update', name: 'product_update')]
    public function update(Product $product, EntityManagerInterface $em): Response
    {
        // Modify entity
        $product->setPrice('899.99');
        $product->setStock($product->getStock() - 1);

        // No persist needed for existing entities
        $em->flush();

        return new Response('Product updated');
    }

    #[Route('/product/{id}/delete', name: 'product_delete')]
    public function delete(Product $product, EntityManagerInterface $em): Response
    {
        $em->remove($product);
        $em->flush();

        return new Response('Product deleted');
    }
}
```

persist() tells Doctrine to manage new entities. flush() executes all  
pending database operations. For updates, just modify and flush() - no  
persist() needed. remove() marks entities for deletion. flush() commits  
all changes in a single transaction.  

### Repository Queries

Querying the database with repositories.  

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

    public function findInStock(): array
    {
        return $this->createQueryBuilder('p')
            ->where('p.stock > 0')
            ->getQuery()
            ->getResult();
    }

    public function findOneByName(string $name): ?Product
    {
        return $this->createQueryBuilder('p')
            ->where('p.name = :name')
            ->setParameter('name', $name)
            ->getQuery()
            ->getOneOrNullResult();
    }

    public function getTotalValue(): float
    {
        $result = $this->createQueryBuilder('p')
            ->select('SUM(p.price * p.stock) as total')
            ->getQuery()
            ->getSingleScalarResult();

        return (float) $result;
    }
}
```

Repositories encapsulate database queries. Use QueryBuilder for dynamic  
queries. Always use parameters to prevent SQL injection. getResult()  
returns arrays, getOneOrNullResult() returns single entities or null.  
Repositories are automatically registered as services.  

### DQL Queries

Using Doctrine Query Language.  

```php
<?php

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
        $dql = 'SELECT o FROM App\Entity\Order o 
                WHERE o.status = :status 
                ORDER BY o.createdAt DESC';

        return $this->getEntityManager()
            ->createQuery($dql)
            ->setParameter('status', 'completed')
            ->setMaxResults($limit)
            ->getResult();
    }

    public function findOrdersWithItems(): array
    {
        $dql = 'SELECT o, i FROM App\Entity\Order o 
                JOIN o.items i 
                WHERE o.total > :amount';

        return $this->getEntityManager()
            ->createQuery($dql)
            ->setParameter('amount', 100)
            ->getResult();
    }

    public function getMonthlyRevenue(): array
    {
        $dql = 'SELECT YEAR(o.createdAt) as year, 
                       MONTH(o.createdAt) as month, 
                       SUM(o.total) as revenue 
                FROM App\Entity\Order o 
                GROUP BY year, month 
                ORDER BY year DESC, month DESC';

        return $this->getEntityManager()
            ->createQuery($dql)
            ->getResult();
    }
}
```

DQL is an object-oriented query language. Use class names instead of  
table names. Queries return entity objects, not arrays. JOIN fetches  
related entities. Aggregate functions like SUM and COUNT are supported.  
DQL provides database portability.  

### Query Pagination

Implementing pagination for large result sets.  

```php
<?php

namespace App\Controller;

use App\Repository\ProductRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Doctrine\ORM\Tools\Pagination\Paginator;

class ProductListController extends AbstractController
{
    #[Route('/products', name: 'product_list')]
    public function list(
        Request $request,
        ProductRepository $repository
    ): Response {
        $page = $request->query->getInt('page', 1);
        $limit = 20;

        $query = $repository->createQueryBuilder('p')
            ->orderBy('p.createdAt', 'DESC')
            ->getQuery()
            ->setFirstResult(($page - 1) * $limit)
            ->setMaxResults($limit);

        $paginator = new Paginator($query);
        $totalItems = count($paginator);
        $totalPages = ceil($totalItems / $limit);

        return $this->render('product/list.html.twig', [
            'products' => $paginator,
            'currentPage' => $page,
            'totalPages' => $totalPages,
            'totalItems' => $totalItems
        ]);
    }
}
```

Paginator efficiently handles large result sets. setFirstResult() and  
setMaxResults() define the slice. count($paginator) gets total rows  
without loading all data. Calculate total pages for navigation. Always  
paginate lists to prevent performance issues.  


### Doctrine Lifecycle Callbacks

Automating entity operations with lifecycle events.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;

#[ORM\Entity]
#[ORM\HasLifecycleCallbacks]
class Article
{
    #[ORM\Column(type: 'datetime')]
    private ?\DateTimeInterface $createdAt = null;

    #[ORM\Column(type: 'datetime', nullable: true)]
    private ?\DateTimeInterface $updatedAt = null;

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->createdAt = new \DateTime();
    }

    #[ORM\PreUpdate]
    public function onPreUpdate(): void
    {
        $this->updatedAt = new \DateTime();
    }
}
```

Lifecycle callbacks automate common entity operations. PrePersist fires  
before INSERT. PreUpdate fires before UPDATE. Add HasLifecycleCallbacks  
to enable. Use for timestamps, slug generation, and validation.  

### Entity Listeners

Separating lifecycle logic into listeners.  

```php
<?php

namespace App\EntityListener;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Attribute\AsEntityListener;
use Doctrine\ORM\Events;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

#[AsEntityListener(event: Events::prePersist, entity: User::class)]
#[AsEntityListener(event: Events::preUpdate, entity: User::class)]
class UserListener
{
    public function __construct(
        private UserPasswordHasherInterface $passwordHasher
    ) {
    }

    public function prePersist(User $user): void
    {
        $this->hashPassword($user);
    }

    public function preUpdate(User $user): void
    {
        $this->hashPassword($user);
    }

    private function hashPassword(User $user): void
    {
        if ($user->getPlainPassword()) {
            $user->setPassword(
                $this->passwordHasher->hashPassword($user, $user->getPlainPassword())
            );
            $user->eraseCredentials();
        }
    }
}
```

Entity listeners separate concerns and support dependency injection.  
AsEntityListener registers listeners automatically. Multiple listeners  
can handle the same entity. Listeners are services with full DI support.  

## Console Commands

### Basic Console Command

Creating custom CLI commands.  

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:hello',
    description: 'Greets the user',
)]
class HelloCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Hello Command');
        $io->success('Hello there!');
        
        return Command::SUCCESS;
    }
}
```

Commands extend Command class. AsCommand defines name and description.  
execute() contains the logic. SymfonyStyle provides formatted output.  
Return Command::SUCCESS or Command::FAILURE. Commands are automatically  
registered.  

### Command Arguments and Options

Accepting user input in commands.  

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

#[AsCommand(name: 'app:user:create')]
class CreateUserCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument('email', InputArgument::REQUIRED, 'User email')
            ->addArgument('name', InputArgument::OPTIONAL, 'User name')
            ->addOption('admin', 'a', InputOption::VALUE_NONE, 'Create as admin')
            ->addOption('role', 'r', InputOption::VALUE_REQUIRED, 'User role', 'ROLE_USER');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $email = $input->getArgument('email');
        $name = $input->getArgument('name') ?? 'User';
        $isAdmin = $input->getOption('admin');
        $role = $input->getOption('role');
        
        $io->section('Creating user');
        $io->listing([
            'Email: ' . $email,
            'Name: ' . $name,
            'Admin: ' . ($isAdmin ? 'Yes' : 'No'),
            'Role: ' . $role
        ]);
        
        return Command::SUCCESS;
    }
}
```

Arguments are positional values. Options are named flags. REQUIRED  
arguments must be provided. VALUE_NONE for boolean flags. VALUE_REQUIRED  
for options needing values. Default values are supported.  

### Interactive Commands

Creating interactive command prompts.  

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:interactive')]
class InteractiveCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        // Simple question
        $name = $io->ask('What is your name?');
        
        // Question with default
        $age = $io->ask('What is your age?', '18');
        
        // Hidden input (for passwords)
        $password = $io->askHidden('Enter password');
        
        // Confirmation
        $confirmed = $io->confirm('Continue?', true);
        
        // Choice question
        $role = $io->choice('Select role', ['admin', 'user', 'editor'], 'user');
        
        $io->success('Interaction complete!');
        
        return Command::SUCCESS;
    }
}
```

SymfonyStyle provides convenient interactive methods. ask() for text  
input. askHidden() for passwords. confirm() for yes/no. choice() for  
selection lists. All methods support default values.  

### Command with Services

Injecting services into commands.  

```php
<?php

namespace App\Command;

use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:user:cleanup')]
class UserCleanupCommand extends Command
{
    public function __construct(
        private UserRepository $userRepository,
        private EntityManagerInterface $em
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('User Cleanup');
        
        // Find inactive users
        $inactiveUsers = $this->userRepository->findInactiveUsers(90);
        
        if (empty($inactiveUsers)) {
            $io->success('No inactive users found');
            return Command::SUCCESS;
        }
        
        $io->note(sprintf('Found %d inactive users', count($inactiveUsers)));
        
        foreach ($inactiveUsers as $user) {
            $this->em->remove($user);
            $io->writeln('Removed: ' . $user->getEmail());
        }
        
        $this->em->flush();
        
        $io->success('Cleanup complete');
        
        return Command::SUCCESS;
    }
}
```

Commands support dependency injection like controllers. Inject services  
in constructor. Call parent::__construct(). Access all application  
services. Ideal for maintenance tasks, imports, and batch processing.  

### Progress Bars

Displaying progress for long-running tasks.  

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'app:import')]
class ImportCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $items = range(1, 100);
        
        $progressBar = new ProgressBar($output, count($items));
        $progressBar->start();
        
        foreach ($items as $item) {
            // Process item
            usleep(50000); // Simulate work
            
            $progressBar->advance();
        }
        
        $progressBar->finish();
        $output->writeln('');
        $output->writeln('Import complete!');
        
        return Command::SUCCESS;
    }
}
```

Progress bars visualize long operations. Create with total items count.  
advance() moves the bar forward. finish() completes it. Add newline after  
finish(). Improves user experience for batch operations.  

### Scheduled Commands

Running commands on schedule with cron.  

```bash
# crontab -e

# Run every hour
0 * * * * cd /path/to/project && php bin/console app:cleanup >> /var/log/cron.log 2>&1

# Run daily at midnight
0 0 * * * cd /path/to/project && php bin/console app:daily-report >> /var/log/cron.log 2>&1

# Run every 5 minutes
*/5 * * * * cd /path/to/project && php bin/console app:process-queue >> /var/log/cron.log 2>&1
```

Use cron to schedule command execution. Always use absolute paths. Log  
output for debugging. Consider lock files to prevent concurrent execution.  
Commands are perfect for scheduled maintenance and batch jobs.  

## API Development

### JSON API Endpoint

Creating RESTful API endpoints.  

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

#[Route('/api/products')]
class ProductApiController extends AbstractController
{
    #[Route('', methods: ['GET'])]
    public function list(ProductRepository $repository): JsonResponse
    {
        $products = $repository->findAll();
        
        return $this->json($products, Response::HTTP_OK, [], [
            'groups' => ['product:read']
        ]);
    }

    #[Route('/{id}', methods: ['GET'])]
    public function show(Product $product): JsonResponse
    {
        return $this->json($product, Response::HTTP_OK, [], [
            'groups' => ['product:read', 'product:detail']
        ]);
    }

    #[Route('', methods: ['POST'])]
    public function create(Request $request, EntityManagerInterface $em): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        
        $product = new Product();
        $product->setName($data['name']);
        $product->setPrice($data['price']);
        $product->setDescription($data['description'] ?? null);
        
        $em->persist($product);
        $em->flush();
        
        return $this->json($product, Response::HTTP_CREATED, [], [
            'groups' => ['product:read']
        ]);
    }

    #[Route('/{id}', methods: ['PUT'])]
    public function update(Product $product, Request $request, EntityManagerInterface $em): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        
        $product->setName($data['name'] ?? $product->getName());
        $product->setPrice($data['price'] ?? $product->getPrice());
        
        $em->flush();
        
        return $this->json($product, Response::HTTP_OK, [], [
            'groups' => ['product:read']
        ]);
    }

    #[Route('/{id}', methods: ['DELETE'])]
    public function delete(Product $product, EntityManagerInterface $em): JsonResponse
    {
        $em->remove($product);
        $em->flush();
        
        return $this->json(null, Response::HTTP_NO_CONTENT);
    }
}
```

RESTful APIs use HTTP methods semantically. GET for retrieval, POST for  
creation, PUT for updates, DELETE for removal. Return appropriate status  
codes. Use serialization groups to control output. Parse JSON from  
request body.  

### Serialization Groups

Controlling JSON output with serialization groups.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Serializer\Annotation\Groups;

#[ORM\Entity]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    #[Groups(['product:read'])]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    #[Groups(['product:read', 'product:write'])]
    private ?string $name = null;

    #[ORM\Column(type: 'decimal', precision: 10, scale: 2)]
    #[Groups(['product:read', 'product:write'])]
    private ?string $price = null;

    #[ORM\Column(type: 'text', nullable: true)]
    #[Groups(['product:detail'])]
    private ?string $description = null;

    #[ORM\Column]
    #[Groups(['product:admin'])]
    private ?int $stock = null;
}
```

Serialization groups control which properties are serialized. Assign  
groups to properties. Specify groups when calling json(). Different  
endpoints can expose different data. Prevents over-exposure of sensitive  
data.  

### API Validation

Validating API request data.  

```php
<?php

namespace App\Controller\Api;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Component\Validator\Constraints as Assert;

#[Route('/api')]
class ValidationController extends AbstractController
{
    #[Route('/validate', methods: ['POST'])]
    public function validate(Request $request, ValidatorInterface $validator): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        
        $constraints = new Assert\Collection([
            'email' => [
                new Assert\NotBlank(),
                new Assert\Email()
            ],
            'age' => [
                new Assert\NotBlank(),
                new Assert\Type('integer'),
                new Assert\Range(['min' => 18, 'max' => 120])
            ],
            'name' => [
                new Assert\NotBlank(),
                new Assert\Length(['min' => 2, 'max' => 100])
            ]
        ]);
        
        $violations = $validator->validate($data, $constraints);
        
        if (count($violations) > 0) {
            $errors = [];
            foreach ($violations as $violation) {
                $errors[$violation->getPropertyPath()] = $violation->getMessage();
            }
            
            return $this->json([
                'errors' => $errors
            ], Response::HTTP_BAD_REQUEST);
        }
        
        return $this->json([
            'message' => 'Data is valid',
            'data' => $data
        ]);
    }
}
```

Validate API input before processing. Use Collection constraint for  
arrays. Return validation errors as JSON with 400 status. Provide clear  
error messages. Validate all user input to prevent invalid data.  

### API Rate Limiting

Implementing rate limiting for API endpoints.  

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\RateLimiter\RateLimiterFactory;

#[AsEventListener(event: KernelEvents::REQUEST, priority: 10)]
class RateLimitListener
{
    public function __construct(
        private RateLimiterFactory $apiLimiter
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();
        
        if (!str_starts_with($request->getPathInfo(), '/api/')) {
            return;
        }
        
        $limiter = $this->apiLimiter->create($request->getClientIp());
        
        if (false === $limiter->consume(1)->isAccepted()) {
            $response = new JsonResponse([
                'error' => 'Too many requests'
            ], Response::HTTP_TOO_MANY_REQUESTS);
            
            $event->setResponse($response);
        }
    }
}
```

```yaml
# config/packages/rate_limiter.yaml
framework:
    rate_limiter:
        api:
            policy: 'sliding_window'
            limit: 100
            interval: '1 hour'
```

Rate limiting prevents API abuse. Configure limits in framework config.  
Use RateLimiterFactory to check limits. Return 429 status when exceeded.  
Limit by IP, user, or API key. Essential for public APIs.  

### CORS Configuration

Enabling cross-origin requests.  

```yaml
# config/packages/nelmio_cors.yaml
nelmio_cors:
    defaults:
        origin_regex: true
        allow_origin: ['*']
        allow_methods: ['GET', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']
        allow_headers: ['Content-Type', 'Authorization']
        expose_headers: ['Link']
        max_age: 3600
    paths:
        '^/api/':
            allow_origin: ['https://example.com']
            allow_headers: ['X-Custom-Auth', 'Content-Type']
            allow_methods: ['POST', 'PUT', 'GET', 'DELETE']
            max_age: 3600
```

CORS allows cross-domain API requests. Configure allowed origins,  
methods, and headers. Use specific origins in production. Wildcards  
are convenient but less secure. OPTIONS requests are automatically  
handled.  

### API Documentation

Documenting API endpoints.  

```php
<?php

namespace App\Controller\Api;

use OpenApi\Attributes as OA;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/api/products')]
#[OA\Tag(name: 'Products')]
class ProductApiController extends AbstractController
{
    #[Route('', methods: ['GET'])]
    #[OA\Get(
        path: '/api/products',
        summary: 'List all products',
        tags: ['Products']
    )]
    #[OA\Response(
        response: 200,
        description: 'Returns list of products'
    )]
    public function list(): JsonResponse
    {
        return $this->json([]);
    }

    #[Route('/{id}', methods: ['GET'])]
    #[OA\Get(
        path: '/api/products/{id}',
        summary: 'Get product by ID',
        tags: ['Products']
    )]
    #[OA\Parameter(
        name: 'id',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'integer')
    )]
    #[OA\Response(
        response: 200,
        description: 'Returns product details'
    )]
    #[OA\Response(
        response: 404,
        description: 'Product not found'
    )]
    public function show(int $id): JsonResponse
    {
        return $this->json(['id' => $id]);
    }
}
```

OpenAPI attributes document your API. Use OA\Get, OA\Post for methods.  
OA\Parameter describes path/query parameters. OA\Response documents  
responses. Generate interactive documentation with Swagger UI. Good  
documentation improves API adoption.  

### API Versioning

Implementing API versioning.  

```php
<?php

namespace App\Controller\Api\V1;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/api/v1/products')]
class ProductController extends AbstractController
{
    #[Route('', methods: ['GET'])]
    public function list(): JsonResponse
    {
        return $this->json(['version' => 1]);
    }
}
```

```php
<?php

namespace App\Controller\Api\V2;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/api/v2/products')]
class ProductController extends AbstractController
{
    #[Route('', methods: ['GET'])]
    public function list(): JsonResponse
    {
        return $this->json(['version' => 2, 'enhanced' => true]);
    }
}
```

Version APIs through URL paths. Organize controllers by version. Maintain  
backward compatibility. Deprecate old versions gradually. Document version  
differences. Versioning enables API evolution without breaking clients.  

## Advanced Integration

### Caching Strategies

Implementing application caching.  

```php
<?php

namespace App\Service;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class DataService
{
    public function __construct(
        private CacheInterface $cache
    ) {
    }

    public function getExpensiveData(): array
    {
        return $this->cache->get('expensive_data', function (ItemInterface $item) {
            $item->expiresAfter(3600);
            
            // Expensive operation
            return $this->computeExpensiveData();
        });
    }

    public function getUserStats(int $userId): array
    {
        $key = sprintf('user_stats_%d', $userId);
        
        return $this->cache->get($key, function (ItemInterface $item) use ($userId) {
            $item->expiresAfter(300);
            $item->tag(['user_' . $userId, 'stats']);
            
            return $this->calculateUserStats($userId);
        });
    }

    public function invalidateUserCache(int $userId): void
    {
        $this->cache->delete(sprintf('user_stats_%d', $userId));
    }

    private function computeExpensiveData(): array
    {
        return ['data' => 'computed'];
    }

    private function calculateUserStats(int $userId): array
    {
        return ['user' => $userId, 'stats' => []];
    }
}
```

Cache expensive operations to improve performance. Set expiration times.  
Use tags for grouped invalidation. Delete specific keys when data changes.  
Cache at appropriate layers: HTTP, application, or database.  

### Message Queue Integration

Processing async tasks with Messenger.  

```php
<?php

namespace App\Message;

class SendEmailMessage
{
    public function __construct(
        private string $to,
        private string $subject,
        private string $body
    ) {
    }

    public function getTo(): string
    {
        return $this->to;
    }

    public function getSubject(): string
    {
        return $this->subject;
    }

    public function getBody(): string
    {
        return $this->body;
    }
}
```

```php
<?php

namespace App\MessageHandler;

use App\Message\SendEmailMessage;
use App\Service\EmailService;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
class SendEmailMessageHandler
{
    public function __construct(
        private EmailService $emailService
    ) {
    }

    public function __invoke(SendEmailMessage $message): void
    {
        $this->emailService->send(
            $message->getTo(),
            $message->getSubject(),
            $message->getBody()
        );
    }
}
```

```php
<?php

namespace App\Controller;

use App\Message\SendEmailMessage;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Routing\Annotation\Route;

class NotificationController extends AbstractController
{
    #[Route('/notify', methods: ['POST'])]
    public function notify(MessageBusInterface $bus): Response
    {
        $message = new SendEmailMessage(
            'user@example.com',
            'Notification',
            'You have a new message'
        );
        
        $bus->dispatch($message);
        
        return $this->json(['status' => 'queued']);
    }
}
```

Messenger handles async processing. Messages are simple data objects.  
Handlers process messages. Dispatch messages to the bus. Configure  
transports for different queues. Improves response times by deferring  
slow operations.  

### Workflow Component

Managing state machines.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class BlogPost
{
    #[ORM\Column(length: 50)]
    private string $status = 'draft';

    public function getStatus(): string
    {
        return $this->status;
    }

    public function setStatus(string $status): self
    {
        $this->status = $status;
        return $this;
    }
}
```

```yaml
# config/packages/workflow.yaml
framework:
    workflows:
        blog_post:
            type: 'state_machine'
            marking_store:
                type: 'method'
                property: 'status'
            supports:
                - App\Entity\BlogPost
            initial_marking: draft
            places:
                - draft
                - review
                - published
                - rejected
            transitions:
                submit:
                    from: draft
                    to: review
                approve:
                    from: review
                    to: published
                reject:
                    from: review
                    to: rejected
                revise:
                    from: [published, rejected]
                    to: draft
```

```php
<?php

namespace App\Controller;

use App\Entity\BlogPost;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Workflow\WorkflowInterface;

class BlogPostController extends AbstractController
{
    #[Route('/post/{id}/publish', methods: ['POST'])]
    public function publish(
        BlogPost $post,
        WorkflowInterface $blogPostStateMachine
    ): Response {
        if ($blogPostStateMachine->can($post, 'approve')) {
            $blogPostStateMachine->apply($post, 'approve');
            
            $this->addFlash('success', 'Post published');
        } else {
            $this->addFlash('error', 'Cannot publish post');
        }
        
        return $this->redirectToRoute('post_show', ['id' => $post->getId()]);
    }
}
```

Workflows manage complex state transitions. Define places and transitions  
in YAML. Use can() to check valid transitions. apply() executes  
transitions. Guards and event listeners add custom logic. Perfect for  
order processing, content moderation, and approval workflows.  

This comprehensive guide covered 100 essential Symfony snippets across  
routing, controllers, services, configuration, forms, validation,  
security, templating, events, Doctrine, console commands, API development,  
and advanced integrations. Each snippet demonstrates best practices and  
real-world use cases for building robust Symfony applications.  
