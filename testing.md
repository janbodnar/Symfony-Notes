# Symfony Testing

This comprehensive guide demonstrates 80 testing techniques for Symfony  
applications. It covers unit testing, functional testing, integration  
testing, mocking, and testing various Symfony components using PHPUnit,  
WebTestCase, and Symfony's testing tools.  

## Unit Testing Basics

### Simple Service Unit Test

Testing a service with PHPUnit TestCase.  

```php
<?php

namespace App\Tests\Service;

use App\Service\CalculatorService;
use PHPUnit\Framework\TestCase;

class CalculatorServiceTest extends TestCase
{
    private CalculatorService $calculator;

    protected function setUp(): void
    {
        $this->calculator = new CalculatorService();
    }

    public function testAdd(): void
    {
        $result = $this->calculator->add(5, 3);
        
        $this->assertEquals(8, $result);
    }

    public function testSubtract(): void
    {
        $result = $this->calculator->subtract(10, 4);
        
        $this->assertSame(6, $result);
    }
}
```

Use PHPUnit's TestCase for pure unit tests that don't require Symfony's  
container. The setUp() method initializes dependencies before each test.  
Use assertEquals for value comparison and assertSame for strict equality.  

### Testing with Data Providers

Using data providers for testing multiple scenarios.  

```php
<?php

namespace App\Tests\Service;

use App\Service\ValidationService;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

class ValidationServiceTest extends TestCase
{
    private ValidationService $validator;

    protected function setUp(): void
    {
        $this->validator = new ValidationService();
    }

    #[DataProvider('emailProvider')]
    public function testEmailValidation(string $email, bool $expected): void
    {
        $result = $this->validator->isValidEmail($email);
        
        $this->assertSame($expected, $result);
    }

    public static function emailProvider(): array
    {
        return [
            'valid email' => ['user@example.com', true],
            'invalid format' => ['invalid-email', false],
            'missing domain' => ['user@', false],
            'empty string' => ['', false],
        ];
    }
}
```

Data providers allow testing multiple inputs efficiently. Use static  
methods that return arrays of test cases. Each array entry represents  
one test execution with labeled keys for better readability.  

### Testing Exceptions

Verifying that code throws expected exceptions.  

```php
<?php

namespace App\Tests\Service;

use App\Exception\InsufficientFundsException;
use App\Service\PaymentService;
use PHPUnit\Framework\TestCase;

class PaymentServiceTest extends TestCase
{
    public function testInsufficientFundsThrowsException(): void
    {
        $this->expectException(InsufficientFundsException::class);
        $this->expectExceptionMessage('Insufficient funds');
        
        $payment = new PaymentService();
        $payment->processPayment(100.00, 50.00);
    }

    public function testSuccessfulPayment(): void
    {
        $payment = new PaymentService();
        $result = $payment->processPayment(100.00, 150.00);
        
        $this->assertTrue($result);
    }
}
```

Use expectException() and expectExceptionMessage() to test exception  
handling. Place these assertions before the code that should throw.  
Test both success and failure scenarios for complete coverage.  

### Testing with Mocks

Creating mock objects to isolate units under test.  

```php
<?php

namespace App\Tests\Service;

use App\Repository\UserRepository;
use App\Service\UserService;
use App\Entity\User;
use PHPUnit\Framework\TestCase;

class UserServiceTest extends TestCase
{
    public function testGetActiveUsersCount(): void
    {
        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->once())
            ->method('count')
            ->with(['status' => 'active'])
            ->willReturn(42);
        
        $service = new UserService($mockRepository);
        $count = $service->getActiveUsersCount();
        
        $this->assertEquals(42, $count);
    }
}
```

Mock dependencies to isolate the unit under test. Use expects() to  
verify method calls, with() to check arguments, and willReturn() to  
control return values. This ensures tests focus on single units.  

### Testing Abstract Classes

Testing abstract classes through concrete implementations.  

```php
<?php

namespace App\Tests\Service;

use App\Service\AbstractNotificationService;
use PHPUnit\Framework\TestCase;

class AbstractNotificationServiceTest extends TestCase
{
    public function testFormatMessage(): void
    {
        $notification = new class extends AbstractNotificationService {
            public function send(string $recipient, string $message): bool
            {
                return true;
            }
        };
        
        $formatted = $notification->formatMessage('Test', 'user@example.com');
        
        $this->assertStringContainsString('Test', $formatted);
        $this->assertStringContainsString('user@example.com', $formatted);
    }
}
```

Use anonymous classes to test abstract classes and their concrete  
methods. This allows testing abstract class logic without creating  
permanent test doubles or fixtures.  

### Testing Private Methods

Testing private methods through reflection.  

```php
<?php

namespace App\Tests\Service;

use App\Service\EncryptionService;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class EncryptionServiceTest extends TestCase
{
    public function testPrivateKeyGeneration(): void
    {
        $service = new EncryptionService();
        $reflection = new ReflectionClass($service);
        $method = $reflection->getMethod('generateKey');
        $method->setAccessible(true);
        
        $key = $method->invoke($service, 32);
        
        $this->assertEquals(32, strlen($key));
    }
}
```

Use reflection to test private methods when necessary. However, prefer  
testing through public interfaces. Private method testing is useful for  
critical internal logic that needs verification independently.  

### Testing Static Methods

Testing static methods and utility classes.  

```php
<?php

namespace App\Tests\Util;

use App\Util\StringHelper;
use PHPUnit\Framework\TestCase;

class StringHelperTest extends TestCase
{
    public function testSlugify(): void
    {
        $result = StringHelper::slugify('Hello There! 123');
        
        $this->assertEquals('hello-there-123', $result);
    }

    public function testTruncate(): void
    {
        $text = 'This is a very long text that needs truncation';
        $result = StringHelper::truncate($text, 20);
        
        $this->assertEquals('This is a very lo...', $result);
        $this->assertEquals(20, strlen($result));
    }
}
```

Static methods can be tested directly without instantiation. Test edge  
cases like empty strings, special characters, and boundary conditions.  
Utility classes often need comprehensive test coverage.  

### Testing Value Objects

Testing immutable value objects and their equality.  

```php
<?php

namespace App\Tests\ValueObject;

use App\ValueObject\Money;
use PHPUnit\Framework\TestCase;

class MoneyTest extends TestCase
{
    public function testMoneyCreation(): void
    {
        $money = new Money(100, 'USD');
        
        $this->assertEquals(100, $money->getAmount());
        $this->assertEquals('USD', $money->getCurrency());
    }

    public function testMoneyEquality(): void
    {
        $money1 = new Money(100, 'USD');
        $money2 = new Money(100, 'USD');
        $money3 = new Money(100, 'EUR');
        
        $this->assertTrue($money1->equals($money2));
        $this->assertFalse($money1->equals($money3));
    }

    public function testMoneyAddition(): void
    {
        $money1 = new Money(100, 'USD');
        $money2 = new Money(50, 'USD');
        $result = $money1->add($money2);
        
        $this->assertEquals(150, $result->getAmount());
    }
}
```

Value objects should be tested for immutability, equality comparisons,  
and operations. Each operation should return new instances without  
modifying the original objects.  

## Kernel Test Case

### Testing Services from Container

Using KernelTestCase to test services with dependencies.  

```php
<?php

namespace App\Tests\Service;

use App\Service\EmailService;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class EmailServiceTest extends KernelTestCase
{
    public function testServiceExists(): void
    {
        self::bootKernel();
        $container = static::getContainer();
        
        $this->assertTrue($container->has(EmailService::class));
    }

    public function testSendEmail(): void
    {
        self::bootKernel();
        $emailService = self::getContainer()->get(EmailService::class);
        
        $result = $emailService->send(
            'test@example.com',
            'Test Subject',
            'Test body'
        );
        
        $this->assertTrue($result);
    }
}
```

KernelTestCase boots the Symfony kernel and provides access to the  
service container. Use this for testing services that require Symfony  
infrastructure like dependency injection and configuration.  

### Testing with Custom Environment

Testing services in different environments.  

```php
<?php

namespace App\Tests\Service;

use App\Service\CacheService;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class CacheServiceTest extends KernelTestCase
{
    protected static function getKernelClass(): string
    {
        return \App\Kernel::class;
    }

    public function testCacheInTestEnvironment(): void
    {
        self::bootKernel(['environment' => 'test']);
        $cacheService = self::getContainer()->get(CacheService::class);
        
        $cacheService->set('test_key', 'test_value');
        $value = $cacheService->get('test_key');
        
        $this->assertEquals('test_value', $value);
    }
}
```

Override getKernelClass() to use custom kernel configurations. Boot  
the kernel with specific environment settings to test environment-  
dependent behavior. This ensures services work correctly in production.  

### Testing Configuration Values

Verifying service configuration from container parameters.  

```php
<?php

namespace App\Tests\Service;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class ConfigurationTest extends KernelTestCase
{
    public function testAppEnvironment(): void
    {
        self::bootKernel();
        $container = static::getContainer();
        
        $env = $container->getParameter('kernel.environment');
        
        $this->assertEquals('test', $env);
    }

    public function testCustomParameter(): void
    {
        self::bootKernel();
        $container = static::getContainer();
        
        $this->assertTrue($container->hasParameter('app.version'));
        $version = $container->getParameter('app.version');
        
        $this->assertIsString($version);
    }
}
```

Test that configuration parameters are correctly loaded and accessible.  
Verify custom parameters exist and have expected values. This prevents  
configuration issues in production environments.  

### Testing Event Dispatching

Verifying events are dispatched correctly.  

```php
<?php

namespace App\Tests\Service;

use App\Event\UserRegisteredEvent;
use App\Service\RegistrationService;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class RegistrationServiceTest extends KernelTestCase
{
    public function testUserRegistrationDispatchesEvent(): void
    {
        self::bootKernel();
        $container = static::getContainer();
        
        $dispatcher = $this->createMock(EventDispatcherInterface::class);
        $dispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->isInstanceOf(UserRegisteredEvent::class));
        
        $service = new RegistrationService($dispatcher);
        $service->register('test@example.com', 'password123');
    }
}
```

Test that services dispatch events when expected. Mock the event  
dispatcher to verify event dispatching without triggering actual  
listeners. Verify event types and properties.  

## Functional Testing

### Basic Controller Test

Testing controller responses with WebTestCase.  

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

    public function testAboutPageStatus(): void
    {
        $client = static::createClient();
        $client->request('GET', '/about');
        
        $this->assertResponseStatusCodeSame(200);
    }
}
```

WebTestCase creates a test client that simulates HTTP requests. Use  
assertResponseIsSuccessful() for 2xx responses and assertSelector  
methods to verify HTML content and structure.  

### Testing JSON API Endpoints

Testing API responses and JSON structure.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ApiControllerTest extends WebTestCase
{
    public function testGetUsers(): void
    {
        $client = static::createClient();
        $client->request('GET', '/api/users');
        
        $this->assertResponseIsSuccessful();
        $this->assertResponseHeaderSame('Content-Type', 
            'application/json');
        
        $data = json_decode($client->getResponse()->getContent(), true);
        
        $this->assertIsArray($data);
        $this->assertArrayHasKey('users', $data);
    }

    public function testGetUser(): void
    {
        $client = static::createClient();
        $client->request('GET', '/api/users/1');
        
        $this->assertResponseIsSuccessful();
        
        $data = json_decode($client->getResponse()->getContent(), true);
        
        $this->assertArrayHasKey('id', $data);
        $this->assertEquals(1, $data['id']);
    }
}
```

Decode JSON responses to verify structure and data. Check response  
headers for correct content types. Validate that all expected fields  
are present and have correct types.  

### Testing Form Submissions

Testing HTML form submissions and validation.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ContactControllerTest extends WebTestCase
{
    public function testSubmitContactForm(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/contact');
        
        $form = $crawler->selectButton('Send')->form([
            'contact[name]' => 'John Doe',
            'contact[email]' => 'john@example.com',
            'contact[message]' => 'Test message',
        ]);
        
        $client->submit($form);
        
        $this->assertResponseRedirects('/contact/success');
        $client->followRedirect();
        
        $this->assertSelectorTextContains('.alert-success', 
            'Message sent');
    }
}
```

Use crawler to select and fill forms. Submit forms and follow redirects  
to verify success messages. Test complete user workflows from form  
display to submission confirmation.  

### Testing Authentication

Testing login and authentication flows.  

```php
<?php

namespace App\Tests\Controller;

use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class SecurityControllerTest extends WebTestCase
{
    public function testLogin(): void
    {
        $client = static::createClient();
        $userRepository = static::getContainer()->get(UserRepository::class);
        $testUser = $userRepository->findOneByEmail('test@example.com');
        
        $client->loginUser($testUser);
        
        $client->request('GET', '/profile');
        
        $this->assertResponseIsSuccessful();
        $this->assertSelectorTextContains('h1', 'My Profile');
    }

    public function testProtectedPageRedirects(): void
    {
        $client = static::createClient();
        $client->request('GET', '/admin');
        
        $this->assertResponseRedirects('/login');
    }
}
```

Use loginUser() to authenticate test users without going through the  
login form. Test that protected pages are accessible when authenticated  
and redirect to login when not authenticated.  

### Testing POST Requests

Testing API POST requests with JSON data.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class UserApiControllerTest extends WebTestCase
{
    public function testCreateUser(): void
    {
        $client = static::createClient();
        $client->request('POST', '/api/users', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], json_encode([
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
        ]));
        
        $this->assertResponseStatusCodeSame(201);
        
        $data = json_decode($client->getResponse()->getContent(), true);
        
        $this->assertArrayHasKey('id', $data);
        $this->assertEquals('Jane Doe', $data['name']);
    }
}
```

Send JSON data by encoding arrays and setting proper content type  
headers. Verify response status codes match expected values (201 for  
creation). Check that created resources return correct data.  

### Testing PUT and PATCH Requests

Testing resource updates via HTTP methods.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ProductApiControllerTest extends WebTestCase
{
    public function testUpdateProduct(): void
    {
        $client = static::createClient();
        $client->request('PUT', '/api/products/1', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], json_encode([
            'name' => 'Updated Product',
            'price' => 99.99,
        ]));
        
        $this->assertResponseIsSuccessful();
        
        $data = json_decode($client->getResponse()->getContent(), true);
        
        $this->assertEquals('Updated Product', $data['name']);
    }

    public function testPartialUpdate(): void
    {
        $client = static::createClient();
        $client->request('PATCH', '/api/products/1', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], json_encode(['price' => 79.99]));
        
        $this->assertResponseIsSuccessful();
    }
}
```

Use PUT for full updates and PATCH for partial updates. Verify that  
only specified fields are updated and others remain unchanged. Test  
both complete and partial update scenarios.  

### Testing DELETE Requests

Testing resource deletion endpoints.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class CommentApiControllerTest extends WebTestCase
{
    public function testDeleteComment(): void
    {
        $client = static::createClient();
        $client->request('DELETE', '/api/comments/1');
        
        $this->assertResponseStatusCodeSame(204);
    }

    public function testDeleteNonexistentComment(): void
    {
        $client = static::createClient();
        $client->request('DELETE', '/api/comments/99999');
        
        $this->assertResponseStatusCodeSame(404);
    }
}
```

Test successful deletion returns 204 No Content. Verify that deleting  
nonexistent resources returns 404. Ensure deleted resources can't be  
accessed afterward in subsequent tests.  

### Testing with Custom Headers

Testing endpoints that require specific headers.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ApiAuthControllerTest extends WebTestCase
{
    public function testApiWithAuthToken(): void
    {
        $client = static::createClient();
        $client->request('GET', '/api/protected', [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer test-token-123',
            'HTTP_ACCEPT' => 'application/json',
        ]);
        
        $this->assertResponseIsSuccessful();
    }

    public function testApiWithoutAuthToken(): void
    {
        $client = static::createClient();
        $client->request('GET', '/api/protected');
        
        $this->assertResponseStatusCodeSame(401);
    }
}
```

Set custom HTTP headers using the HTTP_ prefix in server parameters.  
Test both authenticated and unauthenticated requests. Verify proper  
status codes for missing or invalid headers.  

### Testing Redirects

Testing redirect responses and following redirects.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class RedirectControllerTest extends WebTestCase
{
    public function testRedirect(): void
    {
        $client = static::createClient();
        $client->request('GET', '/old-url');
        
        $this->assertResponseRedirects('/new-url', 301);
    }

    public function testFollowRedirect(): void
    {
        $client = static::createClient();
        $client->request('GET', '/old-url');
        $client->followRedirect();
        
        $this->assertResponseIsSuccessful();
        $this->assertRouteSame('new_route');
    }
}
```

Use assertResponseRedirects() to verify redirect URLs and status codes.  
Call followRedirect() to navigate to the destination. Verify final  
destination using assertRouteSame() for route names.  

### Testing with Session Data

Testing endpoints that depend on session state.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class CartControllerTest extends WebTestCase
{
    public function testAddToCart(): void
    {
        $client = static::createClient();
        
        $client->request('POST', '/cart/add/1');
        $this->assertResponseRedirects('/cart');
        
        $session = $client->getRequest()->getSession();
        $cart = $session->get('cart', []);
        
        $this->assertContains(1, $cart);
    }

    public function testCartPersistsAcrossRequests(): void
    {
        $client = static::createClient();
        
        $client->request('POST', '/cart/add/1');
        $client->request('GET', '/cart');
        
        $this->assertSelectorTextContains('.cart-items', '1 item');
    }
}
```

Access session data through the request object. Verify session state  
changes across multiple requests. Test that session data persists  
correctly between client requests.  

### Testing File Uploads

Testing file upload functionality.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\File\UploadedFile;

class UploadControllerTest extends WebTestCase
{
    public function testFileUpload(): void
    {
        $client = static::createClient();
        
        $file = new UploadedFile(
            __DIR__ . '/fixtures/test.txt',
            'test.txt',
            'text/plain',
            null,
            true
        );
        
        $client->request('POST', '/upload', [], ['file' => $file]);
        
        $this->assertResponseIsSuccessful();
        $this->assertSelectorTextContains('.success', 'File uploaded');
    }
}
```

Create UploadedFile instances for testing uploads. Place test files in  
fixtures directories. Set the test flag to true to prevent file  
validation errors. Verify successful upload responses.  

### Testing AJAX Requests

Testing AJAX endpoints and XMLHttpRequest handling.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class AjaxControllerTest extends WebTestCase
{
    public function testAjaxRequest(): void
    {
        $client = static::createClient();
        $client->request('POST', '/ajax/search', [], [], [
            'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
            'CONTENT_TYPE' => 'application/json',
        ], json_encode(['query' => 'test']));
        
        $this->assertResponseIsSuccessful();
        $this->assertTrue($client->getRequest()->isXmlHttpRequest());
        
        $data = json_decode($client->getResponse()->getContent(), true);
        $this->assertArrayHasKey('results', $data);
    }
}
```

Set X-Requested-With header to simulate AJAX requests. Verify that  
isXmlHttpRequest() returns true. Test that AJAX endpoints return  
appropriate JSON responses without full page HTML.  

### Testing Error Pages

Testing custom error page rendering.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ErrorControllerTest extends WebTestCase
{
    public function test404Page(): void
    {
        $client = static::createClient();
        $client->request('GET', '/nonexistent-page');
        
        $this->assertResponseStatusCodeSame(404);
    }

    public function test500ErrorHandling(): void
    {
        $client = static::createClient();
        $client->catchExceptions(false);
        
        $this->expectException(\RuntimeException::class);
        
        $client->request('GET', '/error-trigger');
    }
}
```

Test that nonexistent routes return 404 responses. Use catchExceptions  
to prevent exception handling and verify exceptions are thrown. Test  
custom error templates render correctly.  

## Database Testing

### Testing with Database Fixtures

Loading test data using Doctrine fixtures.  

```php
<?php

namespace App\Tests\Repository;

use App\Entity\Product;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class ProductRepositoryTest extends KernelTestCase
{
    private EntityManagerInterface $entityManager;

    protected function setUp(): void
    {
        $kernel = self::bootKernel();
        $this->entityManager = $kernel->getContainer()
            ->get('doctrine')
            ->getManager();
        
        $this->loadFixtures();
    }

    private function loadFixtures(): void
    {
        $product1 = new Product();
        $product1->setName('Product 1');
        $product1->setPrice(99.99);
        
        $product2 = new Product();
        $product2->setName('Product 2');
        $product2->setPrice(149.99);
        
        $this->entityManager->persist($product1);
        $this->entityManager->persist($product2);
        $this->entityManager->flush();
    }

    public function testFindAllProducts(): void
    {
        $products = $this->entityManager
            ->getRepository(Product::class)
            ->findAll();
        
        $this->assertCount(2, $products);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        $this->entityManager->close();
    }
}
```

Create fixtures in setUp() for consistent test data. Clean up in  
tearDown() to prevent data leakage between tests. Test repository  
methods with known fixture data.  

### Testing Repository Methods

Testing custom repository query methods.  

```php
<?php

namespace App\Tests\Repository;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class UserRepositoryMethodsTest extends KernelTestCase
{
    private EntityManagerInterface $entityManager;
    private UserRepository $repository;

    protected function setUp(): void
    {
        $kernel = self::bootKernel();
        $this->entityManager = $kernel->getContainer()
            ->get('doctrine')
            ->getManager();
        $this->repository = $this->entityManager
            ->getRepository(User::class);
    }

    public function testFindActiveUsers(): void
    {
        $activeUser = new User();
        $activeUser->setEmail('active@example.com');
        $activeUser->setStatus('active');
        
        $inactiveUser = new User();
        $inactiveUser->setEmail('inactive@example.com');
        $inactiveUser->setStatus('inactive');
        
        $this->entityManager->persist($activeUser);
        $this->entityManager->persist($inactiveUser);
        $this->entityManager->flush();
        
        $activeUsers = $this->repository->findBy(['status' => 'active']);
        
        $this->assertCount(1, $activeUsers);
        $this->assertEquals('active', $activeUsers[0]->getStatus());
    }
}
```

Test repository methods with real database interactions. Create test  
entities and persist them for query testing. Verify that custom query  
methods return expected results.  

### Testing Entity Validation

Testing entity validation constraints.  

```php
<?php

namespace App\Tests\Entity;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class UserValidationTest extends KernelTestCase
{
    private ValidatorInterface $validator;

    protected function setUp(): void
    {
        self::bootKernel();
        $this->validator = static::getContainer()->get(ValidatorInterface::class);
    }

    public function testValidUser(): void
    {
        $user = new User();
        $user->setEmail('valid@example.com');
        $user->setPassword('SecurePass123!');
        
        $errors = $this->validator->validate($user);
        
        $this->assertCount(0, $errors);
    }

    public function testInvalidEmail(): void
    {
        $user = new User();
        $user->setEmail('invalid-email');
        $user->setPassword('SecurePass123!');
        
        $errors = $this->validator->validate($user);
        
        $this->assertGreaterThan(0, count($errors));
        $this->assertEquals('email', $errors[0]->getPropertyPath());
    }
}
```

Use the validator service to test entity constraints. Create entities  
with invalid data and verify validation errors are produced. Check  
specific error properties and messages.  

### Testing Database Transactions

Testing that operations are properly rolled back.  

```php
<?php

namespace App\Tests\Service;

use App\Entity\Order;
use App\Service\OrderService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class OrderServiceTransactionTest extends KernelTestCase
{
    private EntityManagerInterface $entityManager;
    private OrderService $orderService;

    protected function setUp(): void
    {
        $kernel = self::bootKernel();
        $this->entityManager = $kernel->getContainer()
            ->get('doctrine')
            ->getManager();
        $this->orderService = static::getContainer()
            ->get(OrderService::class);
    }

    public function testFailedOrderRollsBack(): void
    {
        $initialCount = $this->entityManager
            ->getRepository(Order::class)
            ->count([]);
        
        try {
            $this->orderService->createOrderWithError();
        } catch (\Exception $e) {
            // Expected exception
        }
        
        $this->entityManager->clear();
        
        $finalCount = $this->entityManager
            ->getRepository(Order::class)
            ->count([]);
        
        $this->assertEquals($initialCount, $finalCount);
    }
}
```

Test that failed operations don't leave partial data in the database.  
Clear the entity manager to reload data from database. Verify counts  
before and after operations match.  

### Testing Entity Relationships

Testing entity associations and cascading.  

```php
<?php

namespace App\Tests\Entity;

use App\Entity\Author;
use App\Entity\Book;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class EntityRelationshipTest extends KernelTestCase
{
    private EntityManagerInterface $entityManager;

    protected function setUp(): void
    {
        $kernel = self::bootKernel();
        $this->entityManager = $kernel->getContainer()
            ->get('doctrine')
            ->getManager();
    }

    public function testAuthorBooksRelationship(): void
    {
        $author = new Author();
        $author->setName('John Writer');
        
        $book1 = new Book();
        $book1->setTitle('First Book');
        $book1->setAuthor($author);
        
        $book2 = new Book();
        $book2->setTitle('Second Book');
        $book2->setAuthor($author);
        
        $this->entityManager->persist($author);
        $this->entityManager->persist($book1);
        $this->entityManager->persist($book2);
        $this->entityManager->flush();
        
        $this->entityManager->clear();
        
        $loadedAuthor = $this->entityManager
            ->getRepository(Author::class)
            ->find($author->getId());
        
        $this->assertCount(2, $loadedAuthor->getBooks());
    }
}
```

Test bidirectional relationships by persisting and reloading entities.  
Clear the entity manager to ensure data is loaded from database. Verify  
collection counts and relationships are maintained.  

## Mocking and Stubbing

### Mocking Repository in Service Test

Isolating service logic from database dependencies.  

```php
<?php

namespace App\Tests\Service;

use App\Entity\Product;
use App\Repository\ProductRepository;
use App\Service\ProductService;
use PHPUnit\Framework\TestCase;

class ProductServiceMockTest extends TestCase
{
    public function testGetProductsByCategory(): void
    {
        $product1 = new Product();
        $product1->setName('Product 1');
        
        $product2 = new Product();
        $product2->setName('Product 2');
        
        $mockRepository = $this->createMock(ProductRepository::class);
        $mockRepository->expects($this->once())
            ->method('findBy')
            ->with(['category' => 'electronics'])
            ->willReturn([$product1, $product2]);
        
        $service = new ProductService($mockRepository);
        $products = $service->getProductsByCategory('electronics');
        
        $this->assertCount(2, $products);
    }
}
```

Mock repositories to test service logic without database access. Define  
expected method calls with parameters and return values. Verify service  
processes repository results correctly.  

### Stubbing External Services

Testing services that depend on external APIs.  

```php
<?php

namespace App\Tests\Service;

use App\Service\ExternalApiClient;
use App\Service\WeatherService;
use PHPUnit\Framework\TestCase;

class WeatherServiceTest extends TestCase
{
    public function testGetCurrentWeather(): void
    {
        $apiClient = $this->createStub(ExternalApiClient::class);
        $apiClient->method('get')
            ->willReturn([
                'temperature' => 72,
                'condition' => 'sunny',
            ]);
        
        $weatherService = new WeatherService($apiClient);
        $weather = $weatherService->getCurrentWeather('New York');
        
        $this->assertEquals(72, $weather['temperature']);
        $this->assertEquals('sunny', $weather['condition']);
    }
}
```

Use stubs when you only need to return specific values without  
verifying method calls. Stubs are simpler than mocks when you don't  
need to assert on interactions.  

### Partial Mocks

Mocking only specific methods of a class.  

```php
<?php

namespace App\Tests\Service;

use App\Service\ReportService;
use PHPUnit\Framework\TestCase;

class ReportServiceTest extends TestCase
{
    public function testGenerateReport(): void
    {
        $service = $this->getMockBuilder(ReportService::class)
            ->onlyMethods(['fetchData'])
            ->getMock();
        
        $service->expects($this->once())
            ->method('fetchData')
            ->willReturn(['item1', 'item2', 'item3']);
        
        $report = $service->generateReport();
        
        $this->assertStringContainsString('3 items', $report);
    }
}
```

Partial mocks allow testing concrete methods while mocking dependencies.  
Use getMockBuilder() with onlyMethods() to specify which methods to  
mock. Real methods execute normally while mocked ones return set values.  

### Mock Builder with Arguments

Creating mocks that require constructor arguments.  

```php
<?php

namespace App\Tests\Service;

use App\Service\NotificationService;
use App\Service\EmailSender;
use PHPUnit\Framework\TestCase;

class NotificationServiceWithArgsTest extends TestCase
{
    public function testSendNotification(): void
    {
        $emailSender = $this->createMock(EmailSender::class);
        $emailSender->expects($this->once())
            ->method('send')
            ->with(
                $this->equalTo('user@example.com'),
                $this->stringContains('Notification')
            );
        
        $service = new NotificationService($emailSender, 'from@example.com');
        $service->sendNotification('user@example.com', 'Test message');
    }
}
```

Pass mock objects as constructor arguments to the class under test.  
Use assertion methods like equalTo() and stringContains() to verify  
argument values flexibly.  

### Mocking Multiple Methods

Setting expectations for multiple method calls.  

```php
<?php

namespace App\Tests\Service;

use App\Repository\UserRepository;
use App\Service\UserAnalyticsService;
use PHPUnit\Framework\TestCase;

class UserAnalyticsServiceTest extends TestCase
{
    public function testCalculateStatistics(): void
    {
        $mockRepository = $this->createMock(UserRepository::class);
        $mockRepository->expects($this->exactly(3))
            ->method('count')
            ->willReturnMap([
                [[], 100],
                [['status' => 'active'], 75],
                [['status' => 'inactive'], 25],
            ]);
        
        $service = new UserAnalyticsService($mockRepository);
        $stats = $service->calculateStatistics();
        
        $this->assertEquals(100, $stats['total']);
        $this->assertEquals(75, $stats['active']);
        $this->assertEquals(25, $stats['inactive']);
    }
}
```

Use willReturnMap() to return different values based on different  
arguments. Verify exact number of calls with exactly(). Test complex  
interactions between service and repository.  

### Mocking with Callbacks

Using callbacks for dynamic mock behavior.  

```php
<?php

namespace App\Tests\Service;

use App\Service\PricingService;
use App\Service\TaxCalculator;
use PHPUnit\Framework\TestCase;

class PricingServiceTest extends TestCase
{
    public function testCalculateFinalPrice(): void
    {
        $taxCalculator = $this->createMock(TaxCalculator::class);
        $taxCalculator->method('calculate')
            ->willReturnCallback(function ($amount) {
                return $amount * 0.1;
            });
        
        $service = new PricingService($taxCalculator);
        $finalPrice = $service->calculateFinalPrice(100.00);
        
        $this->assertEquals(110.00, $finalPrice);
    }
}
```

Use willReturnCallback() for dynamic return values based on arguments.  
Callbacks allow complex logic in mocks without creating real  
implementations. Useful for mathematical or conditional operations.  

### Spy Objects

Tracking method calls without changing behavior.  

```php
<?php

namespace App\Tests\Service;

use App\Service\LoggerService;
use App\Service\PaymentProcessor;
use PHPUnit\Framework\TestCase;

class PaymentProcessorTest extends TestCase
{
    public function testLoggingDuringPayment(): void
    {
        $logger = $this->createMock(LoggerService::class);
        $logger->expects($this->atLeastOnce())
            ->method('log')
            ->with($this->stringContains('Payment'));
        
        $processor = new PaymentProcessor($logger);
        $processor->process(100.00, 'credit_card');
    }
}
```

Verify that methods are called during execution without affecting the  
test flow. Use atLeastOnce() when exact call count isn't important.  
Verify log messages and side effects.  

## Form Testing

### Testing Form Type

Testing custom form types in isolation.  

```php
<?php

namespace App\Tests\Form;

use App\Entity\Product;
use App\Form\ProductType;
use Symfony\Component\Form\Test\TypeTestCase;

class ProductTypeTest extends TypeTestCase
{
    public function testSubmitValidData(): void
    {
        $formData = [
            'name' => 'Test Product',
            'price' => 99.99,
            'description' => 'Product description',
        ];
        
        $product = new Product();
        $form = $this->factory->create(ProductType::class, $product);
        
        $form->submit($formData);
        
        $this->assertTrue($form->isSynchronized());
        $this->assertTrue($form->isValid());
        $this->assertEquals('Test Product', $product->getName());
        $this->assertEquals(99.99, $product->getPrice());
    }
}
```

Extend TypeTestCase to test form types. Submit data to forms and verify  
synchronization and validation. Check that data is properly bound to  
entities.  

### Testing Form Validation

Testing that form validation rules work correctly.  

```php
<?php

namespace App\Tests\Form;

use App\Entity\User;
use App\Form\UserType;
use Symfony\Component\Form\Extension\Validator\ValidatorExtension;
use Symfony\Component\Form\Test\TypeTestCase;
use Symfony\Component\Validator\Validation;

class UserTypeValidationTest extends TypeTestCase
{
    protected function getExtensions(): array
    {
        $validator = Validation::createValidator();
        
        return [
            new ValidatorExtension($validator),
        ];
    }

    public function testInvalidEmail(): void
    {
        $formData = [
            'email' => 'invalid-email',
            'password' => 'password123',
        ];
        
        $user = new User();
        $form = $this->factory->create(UserType::class, $user);
        
        $form->submit($formData);
        
        $this->assertFalse($form->isValid());
        $this->assertTrue($form->get('email')->getErrors()->count() > 0);
    }
}
```

Include ValidatorExtension to enable validation in form tests. Submit  
invalid data and verify validation errors occur. Check specific field  
errors for detailed validation testing.  

### Testing Form Rendering

Testing form view and field configuration.  

```php
<?php

namespace App\Tests\Form;

use App\Form\ContactType;
use Symfony\Component\Form\Test\TypeTestCase;

class ContactTypeRenderTest extends TypeTestCase
{
    public function testFormHasExpectedFields(): void
    {
        $form = $this->factory->create(ContactType::class);
        $view = $form->createView();
        
        $this->assertArrayHasKey('name', $view->children);
        $this->assertArrayHasKey('email', $view->children);
        $this->assertArrayHasKey('message', $view->children);
    }

    public function testFieldAttributes(): void
    {
        $form = $this->factory->create(ContactType::class);
        $view = $form->createView();
        
        $emailAttrs = $view->children['email']->vars['attr'];
        
        $this->assertArrayHasKey('placeholder', $emailAttrs);
    }
}
```

Test form view structure and field presence. Verify field attributes  
and configurations are correctly set. Check that forms render with  
expected structure without actual HTTP requests.  

## Console Command Testing

### Basic Command Test

Testing console command execution and output.  

```php
<?php

namespace App\Tests\Command;

use App\Command\GreetCommand;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Tester\CommandTester;

class GreetCommandTest extends KernelTestCase
{
    public function testExecute(): void
    {
        $kernel = static::createKernel();
        $application = new Application($kernel);
        
        $command = $application->find('app:greet');
        $commandTester = new CommandTester($command);
        
        $commandTester->execute([
            'name' => 'World',
        ]);
        
        $output = $commandTester->getDisplay();
        
        $this->assertStringContainsString('Hello there, World', $output);
        $this->assertEquals(0, $commandTester->getStatusCode());
    }
}
```

Use CommandTester to execute commands and capture output. Pass command  
arguments as array. Verify output contains expected text and command  
returns success status code (0).  

### Testing Command with Options

Testing commands with optional parameters.  

```php
<?php

namespace App\Tests\Command;

use App\Command\ExportCommand;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Tester\CommandTester;

class ExportCommandTest extends KernelTestCase
{
    public function testExecuteWithFormat(): void
    {
        $kernel = static::createKernel();
        $application = new Application($kernel);
        
        $command = $application->find('app:export');
        $commandTester = new CommandTester($command);
        
        $commandTester->execute([
            '--format' => 'json',
            '--output' => '/tmp/export.json',
        ]);
        
        $this->assertEquals(0, $commandTester->getStatusCode());
        $this->assertFileExists('/tmp/export.json');
    }
}
```

Test commands with various option combinations. Verify that options  
affect command behavior as expected. Check file creation and other  
side effects of command execution.  

### Testing Interactive Commands

Testing commands that prompt for user input.  

```php
<?php

namespace App\Tests\Command;

use App\Command\SetupCommand;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Tester\CommandTester;

class SetupCommandTest extends KernelTestCase
{
    public function testInteractiveInput(): void
    {
        $kernel = static::createKernel();
        $application = new Application($kernel);
        
        $command = $application->find('app:setup');
        $commandTester = new CommandTester($command);
        
        $commandTester->setInputs(['localhost', '3306', 'mydb']);
        $commandTester->execute([]);
        
        $output = $commandTester->getDisplay();
        
        $this->assertStringContainsString('Setup complete', $output);
    }
}
```

Use setInputs() to provide responses to interactive prompts. Array  
order matches question order. Test that commands handle user input  
correctly and produce expected results.  

### Testing Command Error Handling

Testing command failure scenarios.  

```php
<?php

namespace App\Tests\Command;

use App\Command\ImportCommand;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Tester\CommandTester;

class ImportCommandErrorTest extends KernelTestCase
{
    public function testMissingFile(): void
    {
        $kernel = static::createKernel();
        $application = new Application($kernel);
        
        $command = $application->find('app:import');
        $commandTester = new CommandTester($command);
        
        $commandTester->execute([
            'file' => '/nonexistent/file.csv',
        ]);
        
        $this->assertEquals(1, $commandTester->getStatusCode());
        $this->assertStringContainsString('File not found', 
            $commandTester->getDisplay());
    }
}
```

Test error conditions and verify appropriate error codes are returned.  
Check that error messages are helpful and descriptive. Non-zero exit  
codes indicate command failures.  

## Event Testing

### Testing Event Listeners

Testing that event listeners handle events correctly.  

```php
<?php

namespace App\Tests\EventListener;

use App\Entity\User;
use App\Event\UserRegisteredEvent;
use App\EventListener\UserRegistrationListener;
use App\Service\EmailService;
use PHPUnit\Framework\TestCase;

class UserRegistrationListenerTest extends TestCase
{
    public function testOnUserRegistered(): void
    {
        $emailService = $this->createMock(EmailService::class);
        $emailService->expects($this->once())
            ->method('send')
            ->with(
                $this->equalTo('new@example.com'),
                $this->stringContains('Welcome')
            );
        
        $listener = new UserRegistrationListener($emailService);
        
        $user = new User();
        $user->setEmail('new@example.com');
        
        $event = new UserRegisteredEvent($user);
        $listener->onUserRegistered($event);
    }
}
```

Test event listeners by creating event instances and invoking listener  
methods directly. Mock dependencies to verify listener behavior. Check  
that listeners perform expected actions.  

### Testing Event Subscribers

Testing event subscribers and priority.  

```php
<?php

namespace App\Tests\EventSubscriber;

use App\EventSubscriber\ExceptionSubscriber;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\KernelEvents;

class ExceptionSubscriberTest extends TestCase
{
    public function testGetSubscribedEvents(): void
    {
        $subscriber = new ExceptionSubscriber();
        $events = $subscriber::getSubscribedEvents();
        
        $this->assertArrayHasKey(KernelEvents::EXCEPTION, $events);
    }

    public function testSubscriberPriority(): void
    {
        $events = ExceptionSubscriber::getSubscribedEvents();
        $exceptionConfig = $events[KernelEvents::EXCEPTION];
        
        $this->assertEquals('onKernelException', $exceptionConfig[0]);
        $this->assertEquals(10, $exceptionConfig[1]);
    }
}
```

Verify that subscribers listen to correct events with appropriate  
priorities. Test getSubscribedEvents() returns expected configuration.  
Ensure event handlers are properly registered.  

### Testing Event Propagation

Testing that events can be stopped from propagating.  

```php
<?php

namespace App\Tests\Event;

use App\Event\DataProcessingEvent;
use App\EventListener\ValidationListener;
use PHPUnit\Framework\TestCase;

class EventPropagationTest extends TestCase
{
    public function testStopPropagation(): void
    {
        $event = new DataProcessingEvent(['invalid' => 'data']);
        $listener = new ValidationListener();
        
        $listener->validate($event);
        
        $this->assertTrue($event->isPropagationStopped());
    }

    public function testContinuePropagation(): void
    {
        $event = new DataProcessingEvent(['valid' => 'data']);
        $listener = new ValidationListener();
        
        $listener->validate($event);
        
        $this->assertFalse($event->isPropagationStopped());
    }
}
```

Test that listeners can stop event propagation when conditions are met.  
Verify isPropagationStopped() returns correct values. Test both cases  
where propagation continues and where it stops.  

## Security Testing

### Testing Password Encoding

Testing password hashing and verification.  

```php
<?php

namespace App\Tests\Security;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use App\Entity\User;

class PasswordHashingTest extends KernelTestCase
{
    public function testPasswordHashing(): void
    {
        self::bootKernel();
        $hasher = static::getContainer()
            ->get(UserPasswordHasherInterface::class);
        
        $user = new User();
        $plainPassword = 'SecurePassword123!';
        
        $hashedPassword = $hasher->hashPassword($user, $plainPassword);
        
        $this->assertNotEquals($plainPassword, $hashedPassword);
        $this->assertTrue($hasher->isPasswordValid($user->setPassword(
            $hashedPassword
        ), $plainPassword));
    }
}
```

Test password hashing produces different output than input. Verify that  
hashed passwords can be validated against original passwords. Ensure  
password security mechanisms work correctly.  

### Testing Access Control

Testing role-based access control.  

```php
<?php

namespace App\Tests\Security;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class AccessControlTest extends WebTestCase
{
    public function testAdminAccess(): void
    {
        $client = static::createClient();
        
        $user = new User();
        $user->setEmail('admin@example.com');
        $user->setRoles(['ROLE_ADMIN']);
        
        $client->loginUser($user);
        $client->request('GET', '/admin/dashboard');
        
        $this->assertResponseIsSuccessful();
    }

    public function testUserDeniedAccess(): void
    {
        $client = static::createClient();
        
        $user = new User();
        $user->setEmail('user@example.com');
        $user->setRoles(['ROLE_USER']);
        
        $client->loginUser($user);
        $client->request('GET', '/admin/dashboard');
        
        $this->assertResponseStatusCodeSame(403);
    }
}
```

Test that different roles have appropriate access levels. Verify admin  
routes are protected from regular users. Test both successful access  
and access denial scenarios.  

### Testing CSRF Protection

Testing CSRF token validation in forms.  

```php
<?php

namespace App\Tests\Security;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class CsrfProtectionTest extends WebTestCase
{
    public function testFormWithoutCsrfToken(): void
    {
        $client = static::createClient();
        
        $client->request('POST', '/contact', [
            'contact' => [
                'name' => 'Test User',
                'email' => 'test@example.com',
            ],
        ]);
        
        $this->assertResponseStatusCodeSame(400);
    }

    public function testFormWithValidCsrfToken(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/contact');
        
        $form = $crawler->selectButton('Submit')->form();
        $client->submit($form);
        
        $this->assertResponseIsSuccessful();
    }
}
```

Test that forms reject submissions without valid CSRF tokens. Verify  
that forms with proper tokens are accepted. CSRF protection prevents  
cross-site request forgery attacks.  

## Performance Testing

### Testing Query Performance

Testing database query efficiency and N+1 problems.  

```php
<?php

namespace App\Tests\Performance;

use App\Repository\PostRepository;
use Doctrine\ORM\Tools\Pagination\Paginator;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class QueryPerformanceTest extends KernelTestCase
{
    public function testEagerLoadingPreventNPlusOne(): void
    {
        self::bootKernel();
        $repository = static::getContainer()
            ->get(PostRepository::class);
        
        $posts = $repository->findAllWithAuthors();
        
        $queryCount = count(
            $this->getContainer()
                ->get('doctrine')
                ->getManager()
                ->getConnection()
                ->getConfiguration()
                ->getSQLLogger()
                ->queries ?? []
        );
        
        foreach ($posts as $post) {
            $authorName = $post->getAuthor()->getName();
        }
        
        $this->assertLessThan(5, $queryCount);
    }
}
```

Monitor query counts to detect N+1 problems. Test that eager loading  
reduces query counts. Verify performance optimizations work as expected  
in tests before production deployment.  

This comprehensive collection of 80 Symfony testing snippets covers all  
essential testing scenarios and techniques for building robust Symfony  
applications with comprehensive test coverage.  

### Testing Cache Behavior

Testing cache service interactions and invalidation.  

```php
<?php

namespace App\Tests\Service;

use App\Service\CachedDataService;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Contracts\Cache\CacheInterface;

class CacheServiceTest extends KernelTestCase
{
    public function testCacheHit(): void
    {
        self::bootKernel();
        $cache = static::getContainer()->get(CacheInterface::class);
        $service = new CachedDataService($cache);
        
        $result1 = $service->getExpensiveData('key1');
        $result2 = $service->getExpensiveData('key1');
        
        $this->assertEquals($result1, $result2);
    }

    public function testCacheInvalidation(): void
    {
        self::bootKernel();
        $cache = static::getContainer()->get(CacheInterface::class);
        $service = new CachedDataService($cache);
        
        $service->getExpensiveData('key1');
        $service->invalidateCache('key1');
        
        $cache->get('key1', function () {
            return null;
        });
        
        $this->assertNull($cache->getItem('key1')->get());
    }
}
```

Test that caching works correctly and data is retrieved from cache.  
Verify cache invalidation clears stored values. Test cache hit and  
miss scenarios for complete coverage.  

### Testing Multiple Assertions

Grouping related assertions in single test.  

```php
<?php

namespace App\Tests\Entity;

use App\Entity\Article;
use PHPUnit\Framework\TestCase;

class ArticleTest extends TestCase
{
    public function testArticleProperties(): void
    {
        $article = new Article();
        $article->setTitle('Test Article');
        $article->setContent('Article content');
        $article->setPublished(true);
        
        $this->assertEquals('Test Article', $article->getTitle());
        $this->assertEquals('Article content', $article->getContent());
        $this->assertTrue($article->isPublished());
        $this->assertInstanceOf(\DateTimeInterface::class, 
            $article->getCreatedAt());
    }
}
```

Group related assertions to test entity state comprehensively. Verify  
all properties are set correctly. Test default values and computed  
properties in the same test.  

### Testing with Fixtures Files

Loading test data from fixture files.  

```php
<?php

namespace App\Tests\Service;

use App\Service\CsvImportService;
use PHPUnit\Framework\TestCase;

class CsvImportServiceTest extends TestCase
{
    public function testImportFromCsv(): void
    {
        $service = new CsvImportService();
        $filePath = __DIR__ . '/fixtures/users.csv';
        
        $users = $service->import($filePath);
        
        $this->assertCount(3, $users);
        $this->assertEquals('John Doe', $users[0]['name']);
        $this->assertEquals('john@example.com', $users[0]['email']);
    }

    public function testImportWithInvalidFile(): void
    {
        $service = new CsvImportService();
        
        $this->expectException(\RuntimeException::class);
        $service->import('/nonexistent.csv');
    }
}
```

Store test data in fixture files within tests directory. Load and  
verify data processing from files. Test file handling and error cases  
for missing or malformed files.  

### Testing DateTime Handling

Testing date and time operations.  

```php
<?php

namespace App\Tests\Service;

use App\Service\DateTimeService;
use PHPUnit\Framework\TestCase;

class DateTimeServiceTest extends TestCase
{
    public function testFormatDate(): void
    {
        $service = new DateTimeService();
        $date = new \DateTime('2024-01-15 14:30:00');
        
        $formatted = $service->format($date, 'Y-m-d');
        
        $this->assertEquals('2024-01-15', $formatted);
    }

    public function testDateDifference(): void
    {
        $service = new DateTimeService();
        $date1 = new \DateTime('2024-01-01');
        $date2 = new \DateTime('2024-01-10');
        
        $diff = $service->getDaysBetween($date1, $date2);
        
        $this->assertEquals(9, $diff);
    }
}
```

Test date formatting and calculations. Verify timezone handling and  
date arithmetic. Test edge cases like leap years and daylight saving  
time transitions.  

### Testing Array Operations

Testing services that manipulate arrays and collections.  

```php
<?php

namespace App\Tests\Util;

use App\Util\ArrayHelper;
use PHPUnit\Framework\TestCase;

class ArrayHelperTest extends TestCase
{
    public function testFlatten(): void
    {
        $nested = [
            'a' => [1, 2, 3],
            'b' => [4, 5],
            'c' => 6,
        ];
        
        $result = ArrayHelper::flatten($nested);
        
        $this->assertEquals([1, 2, 3, 4, 5, 6], $result);
    }

    public function testGroupBy(): void
    {
        $items = [
            ['type' => 'fruit', 'name' => 'apple'],
            ['type' => 'fruit', 'name' => 'banana'],
            ['type' => 'vegetable', 'name' => 'carrot'],
        ];
        
        $grouped = ArrayHelper::groupBy($items, 'type');
        
        $this->assertCount(2, $grouped['fruit']);
        $this->assertCount(1, $grouped['vegetable']);
    }
}
```

Test array manipulation utilities thoroughly. Verify edge cases like  
empty arrays and deeply nested structures. Test sorting, filtering,  
and transformation operations.  

### Testing Translation Service

Testing internationalization and translations.  

```php
<?php

namespace App\Tests\Service;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Contracts\Translation\TranslatorInterface;

class TranslationTest extends KernelTestCase
{
    public function testTranslation(): void
    {
        self::bootKernel();
        $translator = static::getContainer()
            ->get(TranslatorInterface::class);
        
        $translated = $translator->trans('welcome.message', [], 'messages', 'en');
        
        $this->assertEquals('Welcome!', $translated);
    }

    public function testTranslationWithParameters(): void
    {
        self::bootKernel();
        $translator = static::getContainer()
            ->get(TranslatorInterface::class);
        
        $translated = $translator->trans('hello.user', 
            ['%name%' => 'John'], 'messages', 'en');
        
        $this->assertStringContainsString('John', $translated);
    }
}
```

Test translation keys return expected values. Verify parameter  
replacement in translated strings. Test multiple locales for  
internationalization support.  

### Testing Email Sending

Testing email services and mailer integration.  

```php
<?php

namespace App\Tests\Service;

use App\Service\NotificationMailer;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

class NotificationMailerTest extends KernelTestCase
{
    public function testSendEmail(): void
    {
        $mailer = $this->createMock(MailerInterface::class);
        $mailer->expects($this->once())
            ->method('send')
            ->with($this->callback(function (Email $email) {
                return $email->getTo()[0]->getAddress() === 'user@example.com'
                    && $email->getSubject() === 'Notification';
            }));
        
        $notificationMailer = new NotificationMailer($mailer);
        $notificationMailer->sendNotification('user@example.com', 'Test');
    }
}
```

Mock the mailer to verify email sending without actually sending emails.  
Use callbacks to validate email properties like recipients and subject.  
Test email composition and sending logic.  

### Testing Serialization

Testing data serialization and deserialization.  

```php
<?php

namespace App\Tests\Service;

use App\Entity\Product;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Serializer\SerializerInterface;

class SerializationTest extends KernelTestCase
{
    public function testSerializeEntity(): void
    {
        self::bootKernel();
        $serializer = static::getContainer()
            ->get(SerializerInterface::class);
        
        $product = new Product();
        $product->setName('Test Product');
        $product->setPrice(99.99);
        
        $json = $serializer->serialize($product, 'json');
        
        $this->assertJson($json);
        $this->assertStringContainsString('Test Product', $json);
    }

    public function testDeserializeJson(): void
    {
        self::bootKernel();
        $serializer = static::getContainer()
            ->get(SerializerInterface::class);
        
        $json = '{"name":"Product","price":49.99}';
        $product = $serializer->deserialize($json, Product::class, 'json');
        
        $this->assertEquals('Product', $product->getName());
        $this->assertEquals(49.99, $product->getPrice());
    }
}
```

Test entity serialization to JSON and other formats. Verify  
deserialization reconstructs objects correctly. Test normalization  
and denormalization processes.  

### Testing File System Operations

Testing file reading, writing, and manipulation.  

```php
<?php

namespace App\Tests\Service;

use App\Service\FileService;
use PHPUnit\Framework\TestCase;

class FileServiceTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/test_' . uniqid();
        mkdir($this->tempDir);
    }

    public function testWriteFile(): void
    {
        $service = new FileService();
        $filePath = $this->tempDir . '/test.txt';
        
        $service->write($filePath, 'Test content');
        
        $this->assertFileExists($filePath);
        $this->assertEquals('Test content', file_get_contents($filePath));
    }

    public function testReadFile(): void
    {
        $service = new FileService();
        $filePath = $this->tempDir . '/read.txt';
        file_put_contents($filePath, 'Content to read');
        
        $content = $service->read($filePath);
        
        $this->assertEquals('Content to read', $content);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob($this->tempDir . '/*'));
        rmdir($this->tempDir);
    }
}
```

Create temporary directories for file operation tests. Clean up files  
in tearDown() to maintain test isolation. Test file reading, writing,  
and error handling for missing files.  

### Testing Pagination

Testing paginated results and pagination logic.  

```php
<?php

namespace App\Tests\Service;

use App\Service\PaginationService;
use PHPUnit\Framework\TestCase;

class PaginationServiceTest extends TestCase
{
    public function testPaginateResults(): void
    {
        $items = range(1, 100);
        $service = new PaginationService();
        
        $page1 = $service->paginate($items, 1, 10);
        
        $this->assertCount(10, $page1['items']);
        $this->assertEquals([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 
            $page1['items']);
        $this->assertEquals(10, $page1['total_pages']);
    }

    public function testLastPage(): void
    {
        $items = range(1, 95);
        $service = new PaginationService();
        
        $lastPage = $service->paginate($items, 10, 10);
        
        $this->assertCount(5, $lastPage['items']);
    }
}
```

Test pagination logic with various page sizes and total counts. Verify  
first page, middle pages, and last page calculations. Test edge cases  
like empty results and single-page results.  

### Testing Rate Limiting

Testing rate limiter service and throttling.  

```php
<?php

namespace App\Tests\Service;

use App\Service\RateLimiter;
use PHPUnit\Framework\TestCase;

class RateLimiterTest extends TestCase
{
    public function testRateLimitNotExceeded(): void
    {
        $limiter = new RateLimiter(5, 60);
        
        for ($i = 0; $i < 5; $i++) {
            $result = $limiter->attempt('user123');
            $this->assertTrue($result);
        }
    }

    public function testRateLimitExceeded(): void
    {
        $limiter = new RateLimiter(3, 60);
        
        $limiter->attempt('user123');
        $limiter->attempt('user123');
        $limiter->attempt('user123');
        $result = $limiter->attempt('user123');
        
        $this->assertFalse($result);
    }
}
```

Test rate limiting allows requests under the limit. Verify that  
exceeding limits returns false. Test different users are tracked  
separately and limits reset after time windows.  

### Testing URL Generation

Testing router URL generation and routing.  

```php
<?php

namespace App\Tests\Routing;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class UrlGenerationTest extends KernelTestCase
{
    public function testGenerateUrl(): void
    {
        self::bootKernel();
        $router = static::getContainer()
            ->get(UrlGeneratorInterface::class);
        
        $url = $router->generate('user_profile', ['id' => 123]);
        
        $this->assertEquals('/user/123/profile', $url);
    }

    public function testGenerateAbsoluteUrl(): void
    {
        self::bootKernel();
        $router = static::getContainer()
            ->get(UrlGeneratorInterface::class);
        
        $url = $router->generate('home', [], 
            UrlGeneratorInterface::ABSOLUTE_URL);
        
        $this->assertStringStartsWith('http', $url);
    }
}
```

Test route name to URL conversion with parameters. Verify absolute  
URLs include protocol and domain. Test URL generation for various  
route configurations.  

### Testing HTTP Client

Testing external API calls with HTTP client.  

```php
<?php

namespace App\Tests\Service;

use App\Service\ApiClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

class ApiClientTest extends TestCase
{
    public function testFetchData(): void
    {
        $mockResponse = new MockResponse(
            json_encode(['data' => 'test']),
            ['http_code' => 200]
        );
        
        $httpClient = new MockHttpClient($mockResponse);
        $apiClient = new ApiClient($httpClient);
        
        $result = $apiClient->fetch('https://api.example.com/data');
        
        $this->assertEquals(['data' => 'test'], $result);
    }

    public function testHandleErrorResponse(): void
    {
        $mockResponse = new MockResponse('', ['http_code' => 500]);
        $httpClient = new MockHttpClient($mockResponse);
        $apiClient = new ApiClient($httpClient);
        
        $this->expectException(\RuntimeException::class);
        $apiClient->fetch('https://api.example.com/error');
    }
}
```

Use MockHttpClient to test external API interactions without real  
requests. Configure mock responses with status codes and bodies. Test  
both successful and error responses.  

### Testing Messenger Component

Testing message bus and message handlers.  

```php
<?php

namespace App\Tests\MessageHandler;

use App\Message\SendEmailMessage;
use App\MessageHandler\SendEmailMessageHandler;
use App\Service\EmailService;
use PHPUnit\Framework\TestCase;

class SendEmailMessageHandlerTest extends TestCase
{
    public function testHandleMessage(): void
    {
        $emailService = $this->createMock(EmailService::class);
        $emailService->expects($this->once())
            ->method('send')
            ->with('test@example.com', 'Subject', 'Body');
        
        $handler = new SendEmailMessageHandler($emailService);
        $message = new SendEmailMessage('test@example.com', 'Subject', 'Body');
        
        $handler($message);
    }
}
```

Test message handlers process messages correctly. Mock dependencies  
to verify handler behavior. Test that handlers invoke appropriate  
services with message data.  

### Testing Workflow Component

Testing workflow transitions and state changes.  

```php
<?php

namespace App\Tests\Workflow;

use App\Entity\Order;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Workflow\WorkflowInterface;

class OrderWorkflowTest extends KernelTestCase
{
    public function testWorkflowTransition(): void
    {
        self::bootKernel();
        $workflow = static::getContainer()->get('workflow.order');
        
        $order = new Order();
        
        $this->assertTrue($workflow->can($order, 'to_processing'));
        
        $workflow->apply($order, 'to_processing');
        
        $this->assertEquals('processing', 
            $workflow->getMarking($order)->getPlaces());
    }

    public function testInvalidTransition(): void
    {
        self::bootKernel();
        $workflow = static::getContainer()->get('workflow.order');
        
        $order = new Order();
        
        $this->assertFalse($workflow->can($order, 'to_completed'));
    }
}
```

Test workflow transitions between states. Verify that valid transitions  
are allowed and invalid ones are rejected. Test state changes and  
workflow rules enforcement.  

### Testing with Environment Variables

Testing code that depends on environment configuration.  

```php
<?php

namespace App\Tests\Service;

use App\Service\ConfigService;
use PHPUnit\Framework\TestCase;

class ConfigServiceTest extends TestCase
{
    public function testGetApiKey(): void
    {
        $_ENV['API_KEY'] = 'test-key-123';
        
        $service = new ConfigService();
        $apiKey = $service->getApiKey();
        
        $this->assertEquals('test-key-123', $apiKey);
    }

    public function testMissingEnvironmentVariable(): void
    {
        unset($_ENV['API_KEY']);
        
        $service = new ConfigService();
        
        $this->expectException(\RuntimeException::class);
        $service->getApiKey();
    }
}
```

Set environment variables in tests to control configuration. Test  
behavior with different environment values. Verify error handling  
for missing required environment variables.  

### Testing Twig Extensions

Testing custom Twig filters and functions.  

```php
<?php

namespace App\Tests\Twig;

use App\Twig\AppExtension;
use PHPUnit\Framework\TestCase;

class AppExtensionTest extends TestCase
{
    public function testPriceFilter(): void
    {
        $extension = new AppExtension();
        
        $result = $extension->formatPrice(1234.56, 'USD');
        
        $this->assertEquals('$1,234.56', $result);
    }

    public function testMarkdownFunction(): void
    {
        $extension = new AppExtension();
        
        $result = $extension->markdown('**bold text**');
        
        $this->assertStringContainsString('<strong>bold text</strong>', $result);
    }
}
```

Test custom Twig extensions independently from templates. Verify  
filters and functions produce expected output. Test edge cases and  
various input formats.  

### Testing API Rate Limiting

Testing API endpoint rate limiting enforcement.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class RateLimitedApiTest extends WebTestCase
{
    public function testRateLimitEnforcement(): void
    {
        $client = static::createClient();
        
        for ($i = 0; $i < 10; $i++) {
            $client->request('GET', '/api/limited-endpoint');
        }
        
        $client->request('GET', '/api/limited-endpoint');
        
        $this->assertResponseStatusCodeSame(429);
        $this->assertResponseHeaderSame('Retry-After', '60');
    }
}
```

Test that API rate limiting returns 429 status when limit exceeded.  
Verify Retry-After headers provide correct wait time. Test limits  
reset after time window expires.  

### Testing Content Negotiation

Testing API content type negotiation.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ContentNegotiationTest extends WebTestCase
{
    public function testJsonResponse(): void
    {
        $client = static::createClient();
        $client->request('GET', '/api/users', [], [], [
            'HTTP_ACCEPT' => 'application/json',
        ]);
        
        $this->assertResponseHeaderSame('Content-Type', 
            'application/json');
    }

    public function testXmlResponse(): void
    {
        $client = static::createClient();
        $client->request('GET', '/api/users', [], [], [
            'HTTP_ACCEPT' => 'application/xml',
        ]);
        
        $this->assertResponseHeaderSame('Content-Type', 
            'application/xml; charset=utf-8');
    }
}
```

Test that API returns content in requested format. Verify Accept  
headers are respected. Test multiple content types and default  
fallback behavior.  

### Testing Middleware

Testing custom middleware and kernel events.  

```php
<?php

namespace App\Tests\EventListener;

use App\EventListener\ApiVersionListener;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ApiVersionListenerTest extends TestCase
{
    public function testApiVersionHeader(): void
    {
        $listener = new ApiVersionListener();
        
        $kernel = $this->createMock(HttpKernelInterface::class);
        $request = new Request();
        $request->headers->set('X-API-Version', '2.0');
        
        $event = new RequestEvent($kernel, $request, 
            HttpKernelInterface::MAIN_REQUEST);
        
        $listener->onKernelRequest($event);
        
        $this->assertEquals('2.0', $request->attributes->get('api_version'));
    }
}
```

Test middleware by creating kernel events manually. Verify request  
and response modifications. Test that middleware processes requests  
correctly and sets expected attributes.  

### Testing GraphQL Queries

Testing GraphQL API endpoints.  

```php
<?php

namespace App\Tests\GraphQL;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class GraphQLQueryTest extends WebTestCase
{
    public function testUserQuery(): void
    {
        $client = static::createClient();
        
        $query = '
            query {
                user(id: 1) {
                    id
                    name
                    email
                }
            }
        ';
        
        $client->request('POST', '/graphql', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], json_encode(['query' => $query]));
        
        $this->assertResponseIsSuccessful();
        
        $response = json_decode($client->getResponse()->getContent(), true);
        
        $this->assertArrayHasKey('data', $response);
        $this->assertArrayHasKey('user', $response['data']);
    }
}
```

Test GraphQL endpoints with query strings. Verify response structure  
matches GraphQL schema. Test queries, mutations, and error handling  
in GraphQL APIs.  

### Testing Background Jobs

Testing asynchronous job processing.  

```php
<?php

namespace App\Tests\Job;

use App\Job\DataProcessingJob;
use App\Service\DataProcessor;
use PHPUnit\Framework\TestCase;

class DataProcessingJobTest extends TestCase
{
    public function testJobExecution(): void
    {
        $processor = $this->createMock(DataProcessor::class);
        $processor->expects($this->once())
            ->method('process')
            ->with(['batch' => 1]);
        
        $job = new DataProcessingJob($processor);
        $job->handle(['batch' => 1]);
    }

    public function testJobRetryOnFailure(): void
    {
        $processor = $this->createMock(DataProcessor::class);
        $processor->expects($this->exactly(3))
            ->method('process')
            ->willThrowException(new \RuntimeException('Temporary error'));
        
        $job = new DataProcessingJob($processor);
        
        for ($i = 0; $i < 3; $i++) {
            try {
                $job->handle(['batch' => 1]);
            } catch (\RuntimeException $e) {
                // Expected
            }
        }
    }
}
```

Test background job execution logic. Verify jobs process data  
correctly and handle failures. Test retry mechanisms and error  
handling in asynchronous processing.  

### Testing Request Validation

Testing request DTO validation.  

```php
<?php

namespace App\Tests\DTO;

use App\DTO\CreateUserRequest;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class CreateUserRequestTest extends KernelTestCase
{
    private ValidatorInterface $validator;

    protected function setUp(): void
    {
        self::bootKernel();
        $this->validator = static::getContainer()
            ->get(ValidatorInterface::class);
    }

    public function testValidRequest(): void
    {
        $request = new CreateUserRequest();
        $request->email = 'user@example.com';
        $request->password = 'SecurePass123!';
        $request->name = 'John Doe';
        
        $errors = $this->validator->validate($request);
        
        $this->assertCount(0, $errors);
    }

    public function testInvalidEmail(): void
    {
        $request = new CreateUserRequest();
        $request->email = 'invalid';
        $request->password = 'SecurePass123!';
        
        $errors = $this->validator->validate($request);
        
        $this->assertGreaterThan(0, count($errors));
    }
}
```

Test Data Transfer Objects with validation constraints. Verify valid  
data passes validation and invalid data produces errors. Test all  
validation rules comprehensively.  

### Testing Custom Constraints

Testing custom validation constraints.  

```php
<?php

namespace App\Tests\Validator;

use App\Entity\Product;
use App\Validator\UniqueSku;
use App\Validator\UniqueSkuValidator;
use App\Repository\ProductRepository;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

class UniqueSkuValidatorTest extends TestCase
{
    public function testValidSkuValidation(): void
    {
        $repository = $this->createMock(ProductRepository::class);
        $repository->method('findOneBy')
            ->with(['sku' => 'NEW-SKU'])
            ->willReturn(null);
        
        $validator = new UniqueSkuValidator($repository);
        
        $context = $this->createMock(ExecutionContextInterface::class);
        $context->expects($this->never())
            ->method('addViolation');
        
        $validator->initialize($context);
        $validator->validate('NEW-SKU', new UniqueSku());
    }

    public function testDuplicateSkuValidation(): void
    {
        $existingProduct = new Product();
        
        $repository = $this->createMock(ProductRepository::class);
        $repository->method('findOneBy')
            ->with(['sku' => 'EXISTING-SKU'])
            ->willReturn($existingProduct);
        
        $validator = new UniqueSkuValidator($repository);
        
        $context = $this->createMock(ExecutionContextInterface::class);
        $context->expects($this->once())
            ->method('addViolation');
        
        $validator->initialize($context);
        $validator->validate('EXISTING-SKU', new UniqueSku());
    }
}
```

Test custom validators by mocking execution context and repositories.  
Verify validators add violations for invalid data. Test that valid  
data passes without violations.  

### Testing Doctrine Lifecycle Callbacks

Testing entity lifecycle events and callbacks.  

```php
<?php

namespace App\Tests\Entity;

use App\Entity\Post;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class PostLifecycleTest extends KernelTestCase
{
    private EntityManagerInterface $entityManager;

    protected function setUp(): void
    {
        $kernel = self::bootKernel();
        $this->entityManager = $kernel->getContainer()
            ->get('doctrine')
            ->getManager();
    }

    public function testPrePersistSetsCreatedAt(): void
    {
        $post = new Post();
        $post->setTitle('Test Post');
        $post->setContent('Content');
        
        $this->entityManager->persist($post);
        $this->entityManager->flush();
        
        $this->assertInstanceOf(\DateTimeInterface::class, 
            $post->getCreatedAt());
    }

    public function testPreUpdateSetsUpdatedAt(): void
    {
        $post = new Post();
        $post->setTitle('Original Title');
        $post->setContent('Content');
        
        $this->entityManager->persist($post);
        $this->entityManager->flush();
        
        $originalUpdatedAt = $post->getUpdatedAt();
        
        sleep(1);
        $post->setTitle('Updated Title');
        $this->entityManager->flush();
        
        $this->assertNotEquals($originalUpdatedAt, $post->getUpdatedAt());
    }
}
```

Test Doctrine lifecycle callbacks set timestamps automatically. Verify  
prePersist and preUpdate callbacks execute correctly. Test that entity  
modifications trigger appropriate lifecycle events.  

### Testing Doctrine Filters

Testing global query filters.  

```php
<?php

namespace App\Tests\Filter;

use App\Entity\Product;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class SoftDeleteFilterTest extends KernelTestCase
{
    private EntityManagerInterface $entityManager;

    protected function setUp(): void
    {
        $kernel = self::bootKernel();
        $this->entityManager = $kernel->getContainer()
            ->get('doctrine')
            ->getManager();
    }

    public function testSoftDeletedProductsAreFiltered(): void
    {
        $product = new Product();
        $product->setName('Test Product');
        $product->setDeleted(true);
        
        $this->entityManager->persist($product);
        $this->entityManager->flush();
        $this->entityManager->clear();
        
        $this->entityManager->getFilters()->enable('soft_delete');
        
        $products = $this->entityManager
            ->getRepository(Product::class)
            ->findAll();
        
        $this->assertCount(0, $products);
    }

    public function testDisabledFilterShowsDeleted(): void
    {
        $this->entityManager->getFilters()->disable('soft_delete');
        
        $products = $this->entityManager
            ->getRepository(Product::class)
            ->findAll();
        
        $this->assertGreaterThan(0, $products);
    }
}
```

Test Doctrine filters hide soft-deleted records. Verify filters can  
be enabled and disabled. Test that filtered queries return expected  
results based on filter state.  

### Testing Custom Doctrine Functions

Testing custom DQL functions.  

```php
<?php

namespace App\Tests\Repository;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class CustomDqlFunctionTest extends KernelTestCase
{
    private EntityManagerInterface $entityManager;

    protected function setUp(): void
    {
        $kernel = self::bootKernel();
        $this->entityManager = $kernel->getContainer()
            ->get('doctrine')
            ->getManager();
    }

    public function testJsonExtractFunction(): void
    {
        $qb = $this->entityManager->createQueryBuilder();
        $qb->select('u')
            ->from(User::class, 'u')
            ->where("JSON_EXTRACT(u.metadata, '$.role') = :role")
            ->setParameter('role', 'admin');
        
        $query = $qb->getQuery();
        $users = $query->getResult();
        
        $this->assertIsArray($users);
    }
}
```

Test custom DQL functions work in queries. Verify function syntax and  
return values. Test integration with Doctrine query builder and  
parameter binding.  

### Testing API Versioning

Testing multiple API versions coexist.  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ApiVersioningTest extends WebTestCase
{
    public function testV1ApiEndpoint(): void
    {
        $client = static::createClient();
        $client->request('GET', '/api/v1/users');
        
        $this->assertResponseIsSuccessful();
        
        $data = json_decode($client->getResponse()->getContent(), true);
        
        $this->assertArrayHasKey('users', $data);
    }

    public function testV2ApiEndpoint(): void
    {
        $client = static::createClient();
        $client->request('GET', '/api/v2/users');
        
        $this->assertResponseIsSuccessful();
        
        $data = json_decode($client->getResponse()->getContent(), true);
        
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('meta', $data);
    }
}
```

Test different API versions return appropriate response structures.  
Verify version-specific behavior and backward compatibility. Test  
that old versions continue working when new versions are added.  

This comprehensive collection of 80 Symfony testing snippets provides  
complete coverage of testing techniques for building robust, well-tested  
Symfony applications across all layers and components.  

### Testing JWT Authentication

Testing JWT token generation and validation.  

```php
<?php

namespace App\Tests\Security;

use App\Service\JwtTokenService;
use PHPUnit\Framework\TestCase;

class JwtTokenServiceTest extends TestCase
{
    public function testGenerateToken(): void
    {
        $service = new JwtTokenService('secret-key');
        
        $token = $service->generate(['user_id' => 123, 'email' => 'user@example.com']);
        
        $this->assertIsString($token);
        $this->assertNotEmpty($token);
    }

    public function testValidateToken(): void
    {
        $service = new JwtTokenService('secret-key');
        
        $token = $service->generate(['user_id' => 123]);
        $payload = $service->validate($token);
        
        $this->assertEquals(123, $payload['user_id']);
    }

    public function testInvalidTokenThrowsException(): void
    {
        $service = new JwtTokenService('secret-key');
        
        $this->expectException(\RuntimeException::class);
        $service->validate('invalid.jwt.token');
    }
}
```

Test JWT token generation creates valid tokens. Verify token validation  
extracts correct payload data. Test that invalid or tampered tokens  
are rejected with appropriate exceptions.  
