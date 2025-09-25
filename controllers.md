# Symfony Controllers

Controllers in Symfony are responsible for handling HTTP requests and  
returning responses. They act as the bridge between the HTTP layer and  
your application logic.  

## Basic Controller

A simple controller that returns a basic response.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class HomeController extends AbstractController
{
    #[Route('/', name: 'home')]
    public function index(): Response
    {
        return new Response('Hello there!');
    }
}
```

This controller extends AbstractController and uses PHP 8 attributes for  
routing. The index method returns a simple text response when accessing  
the root URL.  

## Route Parameters

Handling dynamic route parameters in controller methods.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    #[Route('/user/{id}', name: 'user_show')]
    public function show(int $id): Response
    {
        return new Response(sprintf('User ID: %d', $id));
    }

    #[Route('/user/{name}/profile', name: 'user_profile')]
    public function profile(string $name): Response
    {
        return new Response(sprintf('Profile for: %s', $name));
    }
}
```

Route parameters are automatically injected as method parameters. Symfony  
performs type conversion based on the parameter type hints.  

## JSON Response

Returning JSON data from controllers for API endpoints.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

class ApiController extends AbstractController
{
    #[Route('/api/users', name: 'api_users')]
    public function getUsers(): JsonResponse
    {
        $users = [
            ['id' => 1, 'name' => 'John Doe', 'email' => 'john@example.com'],
            ['id' => 2, 'name' => 'Jane Smith', 'email' => 'jane@example.com']
        ];

        return $this->json($users);
    }

    #[Route('/api/user/{id}', name: 'api_user_show')]
    public function getUser(int $id): JsonResponse
    {
        $user = ['id' => $id, 'name' => 'User ' . $id];
        
        return $this->json($user, 200, [
            'Content-Type' => 'application/json'
        ]);
    }
}
```

The json() method is a shortcut for creating JsonResponse objects. You can  
specify status codes and custom headers as additional parameters.  

## Request Object

Accessing request data including query parameters, POST data, and headers.  

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
        $query = $request->query->get('q', '');
        $page = $request->query->getInt('page', 1);
        
        return new Response(sprintf(
            'Search query: %s, Page: %d', 
            $query, 
            $page
        ));
    }

    #[Route('/contact', methods: ['POST'])]
    public function contact(Request $request): Response
    {
        $name = $request->request->get('name');
        $email = $request->request->get('email');
        $message = $request->request->get('message');
        
        // Process contact form data
        
        return new Response('Message received from: ' . $name);
    }
}
```

The Request object provides access to all HTTP request data including query  
parameters, POST data, cookies, files, and headers.  

## Template Rendering

Rendering Twig templates from controllers with data.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class PageController extends AbstractController
{
    #[Route('/about', name: 'about')]
    public function about(): Response
    {
        return $this->render('page/about.html.twig', [
            'title' => 'About Us',
            'company' => 'Acme Corporation'
        ]);
    }

    #[Route('/products', name: 'products')]
    public function products(): Response
    {
        $products = [
            ['name' => 'Laptop', 'price' => 999.99],
            ['name' => 'Mouse', 'price' => 29.99],
            ['name' => 'Keyboard', 'price' => 79.99]
        ];

        return $this->render('product/list.html.twig', [
            'products' => $products,
            'total_count' => count($products)
        ]);
    }
}
```

The render() method loads Twig templates and passes variables to them.  
Templates should be stored in the templates/ directory.  

## Redirects

Redirecting users to different routes or external URLs.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class RedirectController extends AbstractController
{
    #[Route('/old-page', name: 'old_page')]
    public function oldPage(): RedirectResponse
    {
        return $this->redirectToRoute('new_page');
    }

    #[Route('/new-page', name: 'new_page')]
    public function newPage(): Response
    {
        return new Response('This is the new page!');
    }

    #[Route('/external-redirect', name: 'external_redirect')]
    public function externalRedirect(): RedirectResponse
    {
        return $this->redirect('https://symfony.com');
    }

    #[Route('/dashboard', name: 'dashboard')]
    public function dashboard(): RedirectResponse
    {
        // Redirect with parameters
        return $this->redirectToRoute('user_profile', [
            'name' => 'admin'
        ]);
    }
}
```

Use redirectToRoute() for internal redirects and redirect() for external  
URLs. You can pass route parameters as an array.  

## Dependency Injection

Injecting services into controller methods and constructors.  

```php
<?php

namespace App\Controller;

use App\Service\EmailService;
use App\Service\LoggerService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ServiceController extends AbstractController
{
    public function __construct(
        private LoggerService $logger
    ) {
    }

    #[Route('/send-email', name: 'send_email')]
    public function sendEmail(EmailService $emailService): Response
    {
        $this->logger->info('Email sending requested');
        
        $result = $emailService->send(
            'user@example.com',
            'Welcome!',
            'Welcome to our service!'
        );

        if ($result) {
            return new Response('Email sent successfully');
        }

        return new Response('Failed to send email', 500);
    }

    #[Route('/users/create', name: 'user_create')]
    public function createUser(EntityManagerInterface $em): Response
    {
        // Create new user entity
        // $user = new User();
        // $em->persist($user);
        // $em->flush();

        return new Response('User created');
    }
}
```

Services can be injected through constructor injection or method injection.  
Symfony automatically resolves dependencies based on type hints.  

## Form Handling

Processing forms with Symfony's Form component.  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class FormController extends AbstractController
{
    #[Route('/user/new', name: 'user_new')]
    public function new(
        Request $request, 
        EntityManagerInterface $em
    ): Response {
        $user = new User();
        $form = $this->createForm(UserType::class, $user);
        
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $em->persist($user);
            $em->flush();

            $this->addFlash('success', 'User created successfully!');
            
            return $this->redirectToRoute('user_show', [
                'id' => $user->getId()
            ]);
        }

        return $this->render('user/new.html.twig', [
            'form' => $form->createView(),
        ]);
    }

    #[Route('/user/{id}/edit', name: 'user_edit')]
    public function edit(
        User $user, 
        Request $request,
        EntityManagerInterface $em
    ): Response {
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $em->flush();
            $this->addFlash('success', 'User updated successfully!');
            
            return $this->redirectToRoute('user_show', [
                'id' => $user->getId()
            ]);
        }

        return $this->render('user/edit.html.twig', [
            'form' => $form->createView(),
            'user' => $user,
        ]);
    }
}
```

Forms handle request processing, validation, and data binding automatically.  
Flash messages provide user feedback across redirects.  

## Session Management

Working with user sessions to store temporary data.  

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
    public function addToCart(
        int $productId, 
        SessionInterface $session
    ): Response {
        $cart = $session->get('cart', []);
        
        if (isset($cart[$productId])) {
            $cart[$productId]['quantity']++;
        } else {
            $cart[$productId] = [
                'id' => $productId,
                'quantity' => 1,
                'name' => 'Product ' . $productId
            ];
        }
        
        $session->set('cart', $cart);
        $this->addFlash('info', 'Product added to cart');

        return $this->redirectToRoute('cart_view');
    }

    #[Route('/cart', name: 'cart_view')]
    public function viewCart(SessionInterface $session): Response
    {
        $cart = $session->get('cart', []);
        $total = array_sum(array_column($cart, 'quantity'));

        return $this->render('cart/view.html.twig', [
            'cart_items' => $cart,
            'total_items' => $total
        ]);
    }

    #[Route('/cart/clear', name: 'cart_clear')]
    public function clearCart(SessionInterface $session): Response
    {
        $session->remove('cart');
        $this->addFlash('success', 'Cart cleared');

        return $this->redirectToRoute('cart_view');
    }
}
```

Sessions store data server-side and are perfect for shopping carts, user  
preferences, and temporary data that persists across requests.  

## Parameter Conversion

Automatic conversion of route parameters to entities.  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Entity\Post;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ConversionController extends AbstractController
{
    #[Route('/user/{id}', name: 'user_detail')]
    public function userDetail(User $user): Response
    {
        // Symfony automatically converts {id} parameter to User entity
        return $this->render('user/detail.html.twig', [
            'user' => $user
        ]);
    }

    #[Route('/user/{user}/posts/{post}', name: 'user_post_show')]
    public function userPostShow(User $user, Post $post): Response
    {
        // Multiple entity conversions in single route
        return $this->render('post/show.html.twig', [
            'user' => $user,
            'post' => $post
        ]);
    }

    #[Route('/posts/{slug}', name: 'post_by_slug')]
    public function postBySlug(Post $post): Response
    {
        // Entity conversion can work with any unique field
        // Configure in Post entity or use ParamConverter
        return $this->render('post/detail.html.twig', [
            'post' => $post
        ]);
    }
}
```

ParamConverter automatically queries the database and converts route  
parameters to entity objects. Returns 404 if entity is not found.  

## Error Handling

Handling exceptions and returning appropriate error responses.  

```php
<?php

namespace App\Controller;

use App\Exception\UserNotFoundException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Annotation\Route;

class ErrorController extends AbstractController
{
    #[Route('/user/find/{id}', name: 'user_find')]
    public function findUser(int $id): Response
    {
        try {
            // Simulated user lookup
            if ($id <= 0) {
                throw new \InvalidArgumentException('Invalid user ID');
            }
            
            if ($id > 1000) {
                throw new UserNotFoundException(
                    sprintf('User with ID %d not found', $id)
                );
            }
            
            return new Response(sprintf('Found user: %d', $id));
            
        } catch (\InvalidArgumentException $e) {
            throw new NotFoundHttpException($e->getMessage());
        } catch (UserNotFoundException $e) {
            return new Response($e->getMessage(), 404);
        }
    }

    #[Route('/api/user/{id}', name: 'api_user_find')]
    public function apiUserFind(int $id): JsonResponse
    {
        try {
            if ($id <= 0) {
                return $this->json([
                    'error' => 'Invalid user ID',
                    'code' => 'INVALID_ID'
                ], 400);
            }
            
            // Simulate user data
            $user = ['id' => $id, 'name' => 'User ' . $id];
            
            return $this->json(['data' => $user]);
            
        } catch (\Exception $e) {
            return $this->json([
                'error' => 'Internal server error',
                'message' => $e->getMessage()
            ], 500);
        }
    }
}
```

Controllers can handle exceptions gracefully and return appropriate HTTP  
status codes and error messages for both web and API endpoints.  

## File Upload

Handling file uploads with validation and storage.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\File\Exception\FileException;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\String\Slugger\SluggerInterface;

class UploadController extends AbstractController
{
    #[Route('/upload', name: 'file_upload')]
    public function upload(
        Request $request, 
        SluggerInterface $slugger
    ): Response {
        if ($request->isMethod('POST')) {
            /** @var UploadedFile $uploadedFile */
            $uploadedFile = $request->files->get('document');
            
            if ($uploadedFile) {
                $originalFilename = pathinfo(
                    $uploadedFile->getClientOriginalName(), 
                    PATHINFO_FILENAME
                );
                
                $safeFilename = $slugger->slug($originalFilename);
                $newFilename = $safeFilename . '-' . uniqid() . '.' . 
                               $uploadedFile->guessExtension();

                try {
                    $uploadedFile->move(
                        $this->getParameter('uploads_directory'),
                        $newFilename
                    );
                    
                    $this->addFlash('success', 'File uploaded successfully!');
                    
                } catch (FileException $e) {
                    $this->addFlash('error', 'Upload failed: ' . $e->getMessage());
                }
                
                return $this->redirectToRoute('file_upload');
            }
        }

        return $this->render('upload/form.html.twig');
    }

    #[Route('/gallery', name: 'image_gallery')]
    public function gallery(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            $uploadedFiles = $request->files->get('images');
            
            foreach ($uploadedFiles as $uploadedFile) {
                if ($uploadedFile && $uploadedFile->isValid()) {
                    // Validate image type
                    if (!in_array($uploadedFile->getMimeType(), [
                        'image/jpeg', 'image/png', 'image/gif'
                    ])) {
                        continue;
                    }
                    
                    $filename = uniqid() . '.' . $uploadedFile->guessExtension();
                    
                    $uploadedFile->move(
                        $this->getParameter('images_directory'),
                        $filename
                    );
                }
            }
            
            $this->addFlash('success', 'Images uploaded successfully!');
        }

        return $this->render('upload/gallery.html.twig');
    }
}
```

File uploads should be validated for type, size, and security. Use unique  
filenames to prevent conflicts and potential security issues.  

## HTTP Methods

Handling different HTTP methods in controllers.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class HttpMethodController extends AbstractController
{
    #[Route('/articles', name: 'articles', methods: ['GET'])]
    public function index(): Response
    {
        // GET - List all articles
        return $this->json(['articles' => []]);
    }

    #[Route('/articles', name: 'articles_create', methods: ['POST'])]
    public function create(Request $request): Response
    {
        // POST - Create new article
        $title = $request->request->get('title');
        $content = $request->request->get('content');
        
        // Create article logic here
        
        return $this->json(['message' => 'Article created'], 201);
    }

    #[Route('/articles/{id}', name: 'articles_show', methods: ['GET'])]
    public function show(int $id): Response
    {
        // GET - Show specific article
        return $this->json(['article' => ['id' => $id]]);
    }

    #[Route('/articles/{id}', name: 'articles_update', methods: ['PUT', 'PATCH'])]
    public function update(int $id, Request $request): Response
    {
        // PUT/PATCH - Update article
        $data = json_decode($request->getContent(), true);
        
        // Update article logic here
        
        return $this->json(['message' => 'Article updated']);
    }

    #[Route('/articles/{id}', name: 'articles_delete', methods: ['DELETE'])]
    public function delete(int $id): Response
    {
        // DELETE - Remove article
        
        // Delete article logic here
        
        return $this->json(['message' => 'Article deleted']);
    }

    #[Route('/articles/search', name: 'articles_search', methods: ['GET', 'POST'])]
    public function search(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            // Handle POST search with form data
            $query = $request->request->get('query');
        } else {
            // Handle GET search with query parameters
            $query = $request->query->get('q');
        }
        
        return $this->json(['results' => [], 'query' => $query]);
    }
}
```

REST controllers typically use different HTTP methods for different actions:  
GET for reading, POST for creating, PUT/PATCH for updating, DELETE for removing.  

## Security and Authorization

Implementing security checks in controllers.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class SecurityController extends AbstractController
{
    #[Route('/admin', name: 'admin_dashboard')]
    #[IsGranted('ROLE_ADMIN')]
    public function adminDashboard(): Response
    {
        return $this->render('admin/dashboard.html.twig');
    }

    #[Route('/profile', name: 'user_profile')]
    #[IsGranted('ROLE_USER')]
    public function profile(): Response
    {
        $user = $this->getUser();
        
        return $this->render('user/profile.html.twig', [
            'user' => $user
        ]);
    }

    #[Route('/post/{id}/edit', name: 'post_edit')]
    public function editPost(int $id): Response
    {
        // Manual security check
        $this->denyAccessUnlessGranted('ROLE_EDITOR');
        
        // Or check specific permissions
        // $this->denyAccessUnlessGranted('EDIT', $post);
        
        return $this->render('post/edit.html.twig');
    }

    #[Route('/sensitive-data', name: 'sensitive_data')]
    public function sensitiveData(): Response
    {
        if (!$this->isGranted('ROLE_ADMIN')) {
            return $this->json(['error' => 'Access denied'], 403);
        }
        
        $user = $this->getUser();
        if (!$user) {
            return $this->json(['error' => 'Authentication required'], 401);
        }
        
        return $this->json(['sensitive' => 'data']);
    }

    #[Route('/owner/{userId}/settings', name: 'user_settings')]
    public function userSettings(int $userId): Response
    {
        $currentUser = $this->getUser();
        
        // Check if user can access their own settings or is admin
        if ($currentUser->getId() !== $userId && 
            !$this->isGranted('ROLE_ADMIN')) {
            throw $this->createAccessDeniedException('Access denied');
        }
        
        return $this->render('user/settings.html.twig');
    }
}
```

Security can be enforced using attributes, manual checks, or voters.  
Always validate user permissions before performing sensitive operations.  

## Custom Response Headers

Setting custom headers and response metadata.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Routing\Annotation\Route;

class HeaderController extends AbstractController
{
    #[Route('/api/data', name: 'api_data')]
    public function apiData(): Response
    {
        $data = ['message' => 'Hello there!', 'timestamp' => time()];
        
        $response = $this->json($data);
        $response->headers->set('X-API-Version', '1.0');
        $response->headers->set('X-Rate-Limit', '1000');
        $response->headers->set('Cache-Control', 'max-age=3600');
        
        return $response;
    }

    #[Route('/download/report', name: 'download_report')]
    public function downloadReport(): Response
    {
        $csvData = "Name,Email,Status\n";
        $csvData .= "John Doe,john@example.com,Active\n";
        $csvData .= "Jane Smith,jane@example.com,Inactive\n";
        
        $response = new Response($csvData);
        
        $disposition = $response->headers->makeDisposition(
            ResponseHeaderBag::DISPOSITION_ATTACHMENT,
            'user_report.csv'
        );
        
        $response->headers->set('Content-Disposition', $disposition);
        $response->headers->set('Content-Type', 'text/csv');
        
        return $response;
    }

    #[Route('/cors-enabled', name: 'cors_enabled')]
    public function corsEnabled(): Response
    {
        $response = $this->json(['message' => 'CORS enabled endpoint']);
        
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        
        return $response;
    }

    #[Route('/cached-content', name: 'cached_content')]
    public function cachedContent(): Response
    {
        $content = 'This content is cached for 1 hour';
        
        $response = new Response($content);
        $response->setPublic();
        $response->setMaxAge(3600);
        $response->setEtag(md5($content));
        
        return $response;
    }
}
```

Custom headers control caching, CORS, content disposition, and API metadata.  
Use headers to improve performance and client integration.  

## Route Constraints

Advanced routing with parameter constraints and requirements.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class RouteController extends AbstractController
{
    #[Route('/product/{id}', name: 'product_show', requirements: ['id' => '\d+'])]
    public function showProduct(int $id): Response
    {
        // id must be numeric
        return new Response('Product ID: ' . $id);
    }

    #[Route('/user/{username}', name: 'user_profile_show', 
           requirements: ['username' => '[a-zA-Z0-9_]+'])]
    public function showUserProfile(string $username): Response
    {
        // username can only contain letters, numbers, and underscores
        return new Response('User: ' . $username);
    }

    #[Route('/article/{year}/{month}/{slug}', name: 'article_show',
           requirements: [
               'year' => '\d{4}',
               'month' => '\d{2}', 
               'slug' => '[a-z0-9-]+'
           ])]
    public function showArticle(int $year, int $month, string $slug): Response
    {
        return new Response(
            sprintf('Article: %s from %d-%02d', $slug, $year, $month)
        );
    }

    #[Route('/category/{category}/page/{page}', name: 'category_list',
           requirements: ['page' => '\d+'],
           defaults: ['page' => 1])]
    public function categoryList(string $category, int $page): Response
    {
        return new Response(
            sprintf('Category: %s, Page: %d', $category, $page)
        );
    }

    #[Route('/api/{version}/users', name: 'api_users',
           requirements: ['version' => 'v[1-9]'],
           defaults: ['version' => 'v1'])]
    public function apiUsers(string $version): Response
    {
        return $this->json([
            'version' => $version,
            'users' => []
        ]);
    }

    #[Route('/{locale}/home', name: 'localized_home',
           requirements: ['locale' => 'en|fr|de|es'],
           defaults: ['locale' => 'en'])]
    public function localizedHome(string $locale): Response
    {
        $messages = [
            'en' => 'Hello there!',
            'fr' => 'Bonjour!',
            'de' => 'Hallo!',
            'es' => '¡Hola!'
        ];
        
        return new Response($messages[$locale]);
    }
}
```

Route requirements ensure parameters match specific patterns. Use defaults  
for optional parameters and constraints for validation.  

## Event Dispatching

Dispatching custom events from controllers.  

```php
<?php

namespace App\Controller;

use App\Event\UserRegisteredEvent;
use App\Event\OrderCompletedEvent;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class EventController extends AbstractController
{
    #[Route('/register', name: 'user_register')]
    public function register(EventDispatcherInterface $dispatcher): Response
    {
        // Simulate user registration
        $userId = 123;
        $userEmail = 'user@example.com';
        
        // Create and dispatch custom event
        $event = new UserRegisteredEvent($userId, $userEmail);
        $dispatcher->dispatch($event, UserRegisteredEvent::NAME);
        
        $this->addFlash('success', 'Registration completed!');
        
        return $this->redirectToRoute('home');
    }

    #[Route('/order/complete/{orderId}', name: 'order_complete')]
    public function completeOrder(
        int $orderId, 
        EventDispatcherInterface $dispatcher
    ): Response {
        // Process order completion
        
        $event = new OrderCompletedEvent($orderId, [
            'total' => 99.99,
            'items' => 3,
            'customer_id' => 456
        ]);
        
        $dispatcher->dispatch($event);
        
        return $this->json([
            'status' => 'completed',
            'order_id' => $orderId
        ]);
    }

    #[Route('/notification/send', name: 'send_notification')]
    public function sendNotification(EventDispatcherInterface $dispatcher): Response
    {
        // Multiple events can be dispatched
        $events = [
            new UserRegisteredEvent(789, 'new@example.com'),
            new OrderCompletedEvent(101, ['total' => 149.99])
        ];
        
        foreach ($events as $event) {
            $dispatcher->dispatch($event);
        }
        
        return new Response('Notifications dispatched');
    }
}
```

Events decouple controllers from business logic and enable extensible  
applications. Event listeners can handle cross-cutting concerns like  
logging, notifications, and analytics.  

## Caching

Implementing HTTP and application-level caching in controllers.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class CacheController extends AbstractController
{
    #[Route('/cached-page', name: 'cached_page')]
    public function cachedPage(): Response
    {
        $response = $this->render('page/expensive.html.twig', [
            'data' => 'This page is cached'
        ]);
        
        // Cache response for 1 hour
        $response->setPublic();
        $response->setMaxAge(3600);
        $response->setSharedMaxAge(3600);
        
        // Set ETag for conditional requests
        $response->setEtag(md5($response->getContent()));
        
        return $response;
    }

    #[Route('/api/expensive-data', name: 'expensive_data')]
    public function expensiveData(CacheInterface $cache): Response
    {
        $data = $cache->get('expensive_calculation', function (ItemInterface $item) {
            $item->expiresAfter(3600); // Cache for 1 hour
            
            // Simulate expensive operation
            sleep(2);
            
            return [
                'result' => 'Complex calculation result',
                'timestamp' => time(),
                'value' => rand(1000, 9999)
            ];
        });
        
        return $this->json($data);
    }

    #[Route('/user/{id}/dashboard', name: 'user_dashboard')]
    public function userDashboard(
        int $id, 
        Request $request,
        CacheInterface $cache
    ): Response {
        // Conditional caching based on user
        if ($request->isNotModified($response = new Response())) {
            return $response;
        }
        
        $cacheKey = 'user_dashboard_' . $id;
        
        $dashboardData = $cache->get($cacheKey, function (ItemInterface $item) use ($id) {
            $item->expiresAfter(1800); // 30 minutes
            
            return [
                'user_id' => $id,
                'stats' => ['views' => 42, 'posts' => 15],
                'recent_activity' => []
            ];
        });
        
        $response = $this->render('user/dashboard.html.twig', $dashboardData);
        $response->setLastModified(new \DateTime('5 minutes ago'));
        
        return $response;
    }

    #[Route('/invalidate-cache/{key}', name: 'invalidate_cache')]
    public function invalidateCache(
        string $key, 
        CacheInterface $cache
    ): Response {
        $cache->delete($key);
        
        return $this->json(['message' => 'Cache invalidated for key: ' . $key]);
    }
}
```

HTTP caching improves performance through browser and proxy caching.  
Application caching reduces database queries and expensive calculations.  

## Testing Controllers

Examples of how controllers can be structured for easy testing.  

```php
<?php

namespace App\Controller;

use App\Service\UserService;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class TestableController extends AbstractController
{
    public function __construct(
        private UserService $userService,
        private UserRepository $userRepository
    ) {
    }

    #[Route('/users/stats', name: 'user_stats')]
    public function userStats(): Response
    {
        $stats = $this->userService->getUserStatistics();
        
        return $this->json([
            'total_users' => $stats['total'],
            'active_users' => $stats['active'],
            'new_users_today' => $stats['new_today']
        ]);
    }

    #[Route('/user/search', name: 'user_search')]
    public function searchUsers(Request $request): Response
    {
        $query = $request->query->get('q', '');
        $limit = $request->query->getInt('limit', 10);
        
        if (empty($query)) {
            return $this->json(['error' => 'Query parameter required'], 400);
        }
        
        $users = $this->userRepository->searchByName($query, $limit);
        
        return $this->json([
            'query' => $query,
            'results' => array_map(fn($user) => [
                'id' => $user->getId(),
                'name' => $user->getName(),
                'email' => $user->getEmail()
            ], $users)
        ]);
    }

    #[Route('/user/validate/{id}', name: 'validate_user')]
    public function validateUser(int $id): Response
    {
        try {
            $isValid = $this->userService->validateUser($id);
            
            return $this->json([
                'user_id' => $id,
                'is_valid' => $isValid,
                'validated_at' => (new \DateTime())->format('Y-m-d H:i:s')
            ]);
            
        } catch (\Exception $e) {
            return $this->json([
                'error' => 'Validation failed',
                'message' => $e->getMessage()
            ], 500);
        }
    }

    #[Route('/health', name: 'health_check')]
    public function healthCheck(): Response
    {
        $checks = [
            'database' => $this->checkDatabase(),
            'cache' => $this->checkCache(),
            'storage' => $this->checkStorage()
        ];
        
        $allHealthy = !in_array(false, $checks, true);
        
        return $this->json([
            'status' => $allHealthy ? 'healthy' : 'unhealthy',
            'checks' => $checks,
            'timestamp' => time()
        ], $allHealthy ? 200 : 503);
    }

    private function checkDatabase(): bool
    {
        try {
            $this->userRepository->findOneBy([], ['id' => 'ASC']);
            return true;
        } catch (\Exception) {
            return false;
        }
    }

    private function checkCache(): bool
    {
        return true; // Implement cache check
    }

    private function checkStorage(): bool
    {
        return is_writable($this->getParameter('uploads_directory'));
    }
}
```

Controllers should delegate business logic to services for better testability.  
Keep controllers thin and focused on HTTP concerns like request/response  
handling, validation, and routing.  

## Sub-requests and ESI

Creating sub-requests and using Edge Side Includes for fragment composition.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Routing\Annotation\Route;

class FragmentController extends AbstractController
{
    #[Route('/page-with-fragments', name: 'page_fragments')]
    public function pageWithFragments(): Response
    {
        return $this->render('page/fragments.html.twig', [
            'title' => 'Page with Fragments'
        ]);
    }

    #[Route('/fragment/user-info/{userId}', name: 'fragment_user_info')]
    public function userInfoFragment(int $userId): Response
    {
        // Fetch user data (simulated)
        $userData = [
            'id' => $userId,
            'name' => 'User ' . $userId,
            'email' => 'user' . $userId . '@example.com',
            'last_login' => '2024-01-15 10:30:00'
        ];

        $response = $this->render('fragments/user_info.html.twig', [
            'user' => $userData
        ]);
        
        // Cache fragment for 5 minutes
        $response->setSharedMaxAge(300);
        
        return $response;
    }

    #[Route('/fragment/recent-posts/{limit}', name: 'fragment_recent_posts')]
    public function recentPostsFragment(int $limit = 5): Response
    {
        // Simulated post data
        $posts = [];
        for ($i = 1; $i <= $limit; $i++) {
            $posts[] = [
                'id' => $i,
                'title' => 'Post Title ' . $i,
                'created_at' => date('Y-m-d H:i:s', strtotime("-{$i} days"))
            ];
        }

        $response = $this->render('fragments/recent_posts.html.twig', [
            'posts' => $posts
        ]);
        
        // Cache for 10 minutes
        $response->setSharedMaxAge(600);
        
        return $response;
    }

    #[Route('/internal/subrequest-example', name: 'subrequest_example')]
    public function subRequestExample(
        HttpKernelInterface $httpKernel,
        Request $request
    ): Response {
        // Create a sub-request
        $subRequest = $request->duplicate(
            ['userId' => 42], // Query parameters
            null,             // Request parameters
            ['_route' => 'fragment_user_info', 'userId' => 42] // Route parameters
        );
        
        // Execute the sub-request
        $response = $httpKernel->handle($subRequest, HttpKernelInterface::SUB_REQUEST);
        
        return new Response(
            'Main content with embedded: ' . $response->getContent()
        );
    }

    #[Route('/esi-example', name: 'esi_example')]
    public function esiExample(): Response
    {
        // This would typically be rendered with ESI tags in the template
        // <esi:include src="/fragment/user-info/123" />
        
        $response = $this->render('page/esi_example.html.twig');
        
        // Enable ESI processing
        $response->setPublic();
        $response->setMaxAge(3600);
        
        return $response;
    }
}
```

Sub-requests allow you to embed one controller's response into another.  
ESI (Edge Side Includes) enables fragment caching and composition at the  
reverse proxy level for improved performance.