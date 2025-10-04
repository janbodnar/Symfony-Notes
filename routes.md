# Symfony Routing

Routing in Symfony is the mechanism that maps incoming HTTP requests to  
specific controller actions. It acts as the dispatcher, analyzing the URL  
and determining which code should handle the request. The routing system  
is powerful, flexible, and supports multiple configuration methods.  

## Introduction to Routing

The Symfony routing component connects URLs to controller methods. When a  
user visits a URL, the router matches it against defined routes and  
executes the corresponding controller action. Routes can be defined using  
PHP attributes (the modern approach), YAML configuration files, or XML.  

Routes consist of several key elements: a path pattern (the URL), a route  
name (for reference), and optional parameters like HTTP methods,  
requirements, and defaults. Understanding routing is fundamental to  
building any Symfony application.  

## Basic Route with Attributes

Defining a simple route using PHP 8 attributes.  

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

The Route attribute maps the root URL (/) to the index method. The name  
parameter provides a unique identifier for generating URLs later. This is  
the most common and recommended way to define routes in modern Symfony.  

## Route with Parameters

Capturing dynamic values from the URL.  

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
}
```

Route parameters are defined in curly braces and automatically injected  
into the controller method. Type hints ensure proper conversion - here the  
id is cast to an integer. If conversion fails, Symfony returns a 404.  

## Multiple Route Parameters

Handling routes with multiple dynamic segments.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ArticleController extends AbstractController
{
    #[Route('/article/{year}/{month}/{slug}', name: 'article_show')]
    public function show(int $year, int $month, string $slug): Response
    {
        return new Response(
            sprintf('Article: %s from %d-%02d', $slug, $year, $month)
        );
    }
}
```

Multiple parameters are extracted in order and type-converted based on  
method signatures. This allows for clean, hierarchical URL structures that  
are both user-friendly and SEO-optimized.  

## Route Requirements

Adding regex constraints to route parameters.  

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
}
```

Requirements use regular expressions to validate parameters. If a  
parameter doesn't match, the route won't be selected, and Symfony tries  
the next route. This prevents invalid data from reaching your controller.  

## Complex Requirements

Using advanced regex patterns for validation.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    #[Route(
        '/user/{username}',
        name: 'user_profile',
        requirements: ['username' => '[a-zA-Z0-9_]{3,20}']
    )]
    public function profile(string $username): Response
    {
        return new Response(sprintf('User: %s', $username));
    }
}
```

Complex patterns ensure usernames contain only alphanumeric characters  
and underscores, with a length between 3 and 20 characters. This provides  
input validation at the routing level before reaching your controller.  

## Optional Parameters

Defining routes with optional segments.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class CategoryController extends AbstractController
{
    #[Route('/category/{name}/{page}', name: 'category_list', defaults: ['page' => 1])]
    public function list(string $name, int $page): Response
    {
        return new Response(
            sprintf('Category: %s, Page: %d', $name, $page)
        );
    }
}
```

The defaults parameter makes route segments optional. Users can visit  
/category/books or /category/books/2. When omitted, the default value is  
used. This keeps URLs clean while maintaining flexibility.  

## HTTP Method Constraints

Restricting routes to specific HTTP verbs.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ApiController extends AbstractController
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
}
```

The methods parameter limits which HTTP methods trigger the route. This is  
essential for RESTful APIs where the same URL has different behaviors  
based on the request method. Requests with other methods get a 405 error.  

## Multiple HTTP Methods

Handling multiple methods in a single route.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ResourceController extends AbstractController
{
    #[Route(
        '/api/resource/{id}',
        name: 'api_resource_update',
        methods: ['PUT', 'PATCH']
    )]
    public function update(int $id, Request $request): Response
    {
        $method = $request->getMethod();
        return $this->json(['method' => $method, 'id' => $id]);
    }
}
```

Multiple methods can be specified as an array when the same controller  
logic handles several HTTP verbs. Use Request::getMethod() to determine  
which method was used if different handling is needed.  

## Route Prefixes

Grouping routes with a common path prefix.  

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
        return new Response('Settings Panel');
    }
}
```

Class-level Route attributes prefix all method routes. The admin_users  
route maps to /admin/users. This reduces repetition and keeps related  
routes organized, making maintenance easier.  

## Route Name Prefixes

Combining path and name prefixes for consistency.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/api/v1', name: 'api_v1_')]
class ApiV1Controller extends AbstractController
{
    #[Route('/users', name: 'users_list', methods: ['GET'])]
    public function usersList(): Response
    {
        return $this->json(['users' => []]);
    }

    #[Route('/products', name: 'products_list', methods: ['GET'])]
    public function productsList(): Response
    {
        return $this->json(['products' => []]);
    }
}
```

The name parameter at class level prefixes all route names. The users  
route becomes api_v1_users_list. This naming convention makes routes easy  
to identify and prevents naming conflicts across controllers.  

## Route Generation

Creating URLs from route names.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class NavigationController extends AbstractController
{
    #[Route('/navigation', name: 'navigation')]
    public function index(): Response
    {
        $productUrl = $this->generateUrl('product_show', ['id' => 42]);
        
        return new Response(
            sprintf('Product URL: %s', $productUrl)
        );
    }
}
```

Never hard-code URLs. Use generateUrl() with route names to create links.  
This makes your application maintainable - you can change route paths  
without breaking links throughout your codebase.  

## Absolute URL Generation

Generating complete URLs with domain and protocol.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class EmailController extends AbstractController
{
    #[Route('/email/send', name: 'email_send')]
    public function send(): Response
    {
        $absoluteUrl = $this->generateUrl(
            'product_show',
            ['id' => 42],
            UrlGeneratorInterface::ABSOLUTE_URL
        );
        
        // Returns: https://example.com/product/42
        return new Response(sprintf('Absolute URL: %s', $absoluteUrl));
    }
}
```

Absolute URLs are required for emails, external redirects, and API  
responses. The ABSOLUTE_URL parameter tells the generator to include the  
scheme (http/https) and domain name in the generated URL.  

## Network Path URLs

Generating protocol-relative URLs.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class AssetController extends AbstractController
{
    #[Route('/assets/info', name: 'assets_info')]
    public function info(UrlGeneratorInterface $urlGenerator): Response
    {
        $networkPath = $urlGenerator->generate(
            'product_show',
            ['id' => 42],
            UrlGeneratorInterface::NETWORK_PATH
        );
        
        // Returns: //example.com/product/42
        return new Response(sprintf('Network path: %s', $networkPath));
    }
}
```

Network paths (//example.com/path) inherit the current protocol. This is  
useful when mixing HTTP and HTTPS content, though HTTPS everywhere is now  
the standard practice for web applications.  

## Route Locale

Handling internationalization in routes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class LocalizedController extends AbstractController
{
    #[Route(
        '/{_locale}/about',
        name: 'about',
        requirements: ['_locale' => 'en|fr|de|es']
    )]
    public function about(string $_locale): Response
    {
        $messages = [
            'en' => 'About us',
            'fr' => 'À propos de nous',
            'de' => 'Über uns',
            'es' => 'Acerca de nosotros'
        ];
        
        return new Response($messages[$_locale]);
    }
}
```

The special _locale parameter is automatically available in the request  
and Twig. Requirements restrict valid locales. This enables clean,  
language-specific URLs for international applications.  

## Default Locale

Setting a fallback locale for routes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class HomePageController extends AbstractController
{
    #[Route(
        '/{_locale}',
        name: 'homepage',
        requirements: ['_locale' => 'en|fr|de'],
        defaults: ['_locale' => 'en']
    )]
    public function index(string $_locale): Response
    {
        return new Response(sprintf('Homepage - Locale: %s', $_locale));
    }
}
```

Defaults ensure the locale parameter works even when omitted from the URL.  
Visiting / uses 'en' while /fr uses 'fr'. This provides flexibility while  
maintaining clean default URLs.  

## Route Priority

Controlling route matching order.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class PriorityController extends AbstractController
{
    #[Route('/blog/{slug}', name: 'blog_post', priority: 0)]
    public function post(string $slug): Response
    {
        return new Response(sprintf('Post: %s', $slug));
    }

    #[Route('/blog/latest', name: 'blog_latest', priority: 10)]
    public function latest(): Response
    {
        return new Response('Latest posts');
    }
}
```

Higher priority routes are checked first. Without priority, /blog/latest  
would match the first route with slug='latest'. Priority ensures specific  
routes take precedence over generic patterns.  

## Route Conditions

Using expressions to control route matching.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ConditionalController extends AbstractController
{
    #[Route(
        '/api/data',
        name: 'api_data',
        condition: "request.headers.get('X-Api-Version') === 'v2'"
    )]
    public function data(): Response
    {
        return $this->json(['version' => 'v2', 'data' => []]);
    }
}
```

Conditions use Symfony's Expression Language to add complex matching  
logic. This route only matches when the X-Api-Version header equals 'v2'.  
Useful for API versioning and feature flags.  

## Host Constraints

Restricting routes to specific domains.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class DomainController extends AbstractController
{
    #[Route(
        '/',
        name: 'admin_home',
        host: 'admin.example.com'
    )]
    public function adminHome(): Response
    {
        return new Response('Admin Site');
    }

    #[Route(
        '/',
        name: 'main_home',
        host: 'www.example.com'
    )]
    public function mainHome(): Response
    {
        return new Response('Main Site');
    }
}
```

Host constraints match routes based on the domain name. This enables  
multiple sites in one application, each with its own route set. Useful for  
multi-tenant applications or separating admin/public interfaces.  

## Dynamic Host Parameters

Using placeholders in host constraints.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class TenantController extends AbstractController
{
    #[Route(
        '/',
        name: 'tenant_home',
        host: '{subdomain}.example.com',
        requirements: ['subdomain' => '[a-z]+']
    )]
    public function home(string $subdomain): Response
    {
        return new Response(sprintf('Tenant: %s', $subdomain));
    }
}
```

Dynamic host parameters work like path parameters. Each subdomain can be  
extracted and used in the controller. Perfect for Software-as-a-Service  
applications where each customer gets their own subdomain.  

## Scheme Requirements

Enforcing HTTPS for sensitive routes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SecureController extends AbstractController
{
    #[Route(
        '/account/settings',
        name: 'account_settings',
        schemes: ['https']
    )]
    public function settings(): Response
    {
        return new Response('Secure Settings Page');
    }
}
```

The schemes parameter enforces protocol requirements. HTTP requests are  
automatically redirected to HTTPS. Critical for protecting sensitive data  
like login forms, payment pages, and personal information.  

## YAML Route Configuration

Defining routes in YAML configuration files.  

```yaml
# config/routes.yaml
home:
    path: /
    controller: App\Controller\HomeController::index

product_show:
    path: /product/{id}
    controller: App\Controller\ProductController::show
    requirements:
        id: '\d+'
    methods: [GET]

api_users:
    path: /api/users
    controller: App\Controller\ApiController::users
    methods: [GET, POST]
    defaults:
        _format: json
```

YAML configuration centralizes routes in one file. Useful for legacy  
projects or when you prefer configuration over annotations. Each route  
specifies path, controller, and optional parameters like requirements.  

## YAML Route Imports

Organizing routes with imports.  

```yaml
# config/routes.yaml
controllers:
    resource: ../src/Controller/
    type: attribute

api:
    resource: routes/api.yaml
    prefix: /api

admin:
    resource: routes/admin.yaml
    prefix: /admin

# config/routes/api.yaml
api_products:
    path: /products
    controller: App\Controller\Api\ProductController::list
    methods: [GET]

api_product_show:
    path: /products/{id}
    controller: App\Controller\Api\ProductController::show
    methods: [GET]
```

Import statements load routes from other files or directories. This keeps  
configuration organized and manageable. The type: attribute tells Symfony  
to scan controllers for Route attributes.  

## YAML Route Prefixes

Applying prefixes to imported routes.  

```yaml
# config/routes.yaml
blog:
    resource: routes/blog.yaml
    prefix: /blog
    name_prefix: 'blog_'

# config/routes/blog.yaml
list:
    path: /
    controller: App\Controller\BlogController::list

post:
    path: /{slug}
    controller: App\Controller\BlogController::post
    requirements:
        slug: '[a-z0-9-]+'
```

Prefixes in import statements apply to all routes in the imported file.  
The list route becomes /blog/ and blog_list. This creates clean namespacing  
for related route groups.  

## XML Route Configuration

Using XML for route definitions.  

```xml
<!-- config/routes.xml -->
<?xml version="1.0" encoding="UTF-8" ?>
<routes xmlns="http://symfony.com/schema/routing"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://symfony.com/schema/routing
        https://symfony.com/schema/routing/routing-1.0.xsd">

    <route id="home" path="/"
           controller="App\Controller\HomeController::index">
    </route>

    <route id="product_show" path="/product/{id}"
           controller="App\Controller\ProductController::show"
           methods="GET">
        <requirement key="id">\d+</requirement>
    </route>
</routes>
```

XML configuration offers strong validation through XSD schemas. Less  
common than YAML or attributes but useful when working with tools that  
generate or validate routing configuration programmatically.  

## XML Route Requirements

Adding constraints in XML format.  

```xml
<!-- config/routes.xml -->
<?xml version="1.0" encoding="UTF-8" ?>
<routes xmlns="http://symfony.com/schema/routing"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://symfony.com/schema/routing
        https://symfony.com/schema/routing/routing-1.0.xsd">

    <route id="article_show" 
           path="/article/{year}/{month}/{slug}"
           controller="App\Controller\ArticleController::show">
        <requirement key="year">\d{4}</requirement>
        <requirement key="month">\d{2}</requirement>
        <requirement key="slug">[a-z0-9-]+</requirement>
    </route>
</routes>
```

XML requirement elements validate route parameters just like in attributes  
or YAML. Each parameter gets its own requirement element with a key  
attribute matching the parameter name.  

## Route Debugging

Using console commands to inspect routes.  

```bash
# List all routes
php bin/console debug:router

# Show details of a specific route
php bin/console debug:router product_show

# Match a URL to find which route handles it
php bin/console router:match /product/42

# List routes matching a pattern
php bin/console debug:router --show-controllers
```

The debug:router command shows all registered routes with their paths,  
names, and controllers. The router:match command tests which route will  
handle a specific URL. Essential for debugging routing issues.  

## Route Information Display

Understanding router debug output.  

```bash
# Output format from debug:router
# Name                Method   Scheme   Host   Path
# home                ANY      ANY      ANY    /
# product_show        GET      ANY      ANY    /product/{id}
# api_products_list   GET      ANY      ANY    /api/products
# admin_dashboard     ANY      ANY      ANY    /admin/

# Output from router:match /product/42
# Route "product_show" matches
# Route Name: product_show
# Path: /product/{id}
# Controller: App\Controller\ProductController::show
# Route Parameters:
#   _controller: App\Controller\ProductController::show
#   id: 42
```

Route debugging shows all matching criteria: HTTP methods, schemes, hosts,  
and paths. The router:match output displays which parameters are extracted  
from the URL and their values.  

## Route Caching

Improving performance with route compilation.  

```bash
# Clear the route cache
php bin/console cache:clear

# Warm up the cache (precompiles routes)
php bin/console cache:warmup

# View the cached route file
cat var/cache/dev/url_matching_routes.php
```

Symfony compiles routes into optimized PHP code for faster matching. In  
production, routes are cached automatically. During development, the cache  
is rebuilt when routes change. Clear cache if routes aren't updating.  

## Custom Route Loader

Creating a programmatic route loader.  

```php
<?php

namespace App\Routing;

use Symfony\Component\Config\Loader\Loader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

class CustomRouteLoader extends Loader
{
    private bool $isLoaded = false;

    public function load($resource, string $type = null): RouteCollection
    {
        if (true === $this->isLoaded) {
            throw new \RuntimeException('Routes already loaded');
        }

        $routes = new RouteCollection();

        $route = new Route(
            '/custom/{id}',
            ['_controller' => 'App\Controller\CustomController::show'],
            ['id' => '\d+']
        );
        
        $routes->add('custom_route', $route);

        $this->isLoaded = true;

        return $routes;
    }

    public function supports($resource, string $type = null): bool
    {
        return 'custom' === $type;
    }
}
```

Custom loaders generate routes programmatically. Useful for loading routes  
from databases, APIs, or creating dynamic routing systems. The loader must  
implement load() and supports() methods.  

## Route Matching Logic

Understanding how Symfony selects routes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class MatchingController extends AbstractController
{
    // Checked first due to exact match
    #[Route('/blog/about', name: 'blog_about')]
    public function about(): Response
    {
        return new Response('About the blog');
    }

    // Checked second - pattern match
    #[Route('/blog/{slug}', name: 'blog_post', requirements: ['slug' => '[a-z-]+'])]
    public function post(string $slug): Response
    {
        return new Response(sprintf('Post: %s', $slug));
    }

    // Checked last - most general pattern
    #[Route('/blog/{id}', name: 'blog_id', requirements: ['id' => '\d+'])]
    public function byId(int $id): Response
    {
        return new Response(sprintf('Post ID: %d', $id));
    }
}
```

Symfony evaluates routes in the order they're defined. More specific  
routes should come before generic ones. Routes with requirements are  
matched based on whether the URL satisfies the constraint pattern.  

## Trailing Slash Handling

Managing URL trailing slashes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class TrailingSlashController extends AbstractController
{
    #[Route('/page', name: 'page')]
    public function page(): Response
    {
        return new Response('Page content');
    }

    #[Route('/folder/', name: 'folder')]
    public function folder(): Response
    {
        return new Response('Folder content');
    }
}
```

By default, /page and /page/ are different routes. Configure Symfony to  
redirect trailing slashes in framework.yaml with router.strict_requirements  
setting. Consistency in URL structure improves SEO and user experience.  

## Route Collection

Building routes programmatically in a controller.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\RouterInterface;

class RouteInfoController extends AbstractController
{
    #[Route('/route-info', name: 'route_info')]
    public function info(RouterInterface $router): Response
    {
        $collection = $router->getRouteCollection();
        $routes = [];

        foreach ($collection->all() as $name => $route) {
            $routes[] = [
                'name' => $name,
                'path' => $route->getPath(),
                'methods' => $route->getMethods(),
            ];
        }

        return $this->json($routes);
    }
}
```

RouterInterface provides access to the entire route collection at runtime.  
Useful for building admin interfaces, documentation generators, or  
debugging tools that need to introspect available routes.  

## Special Route Parameters

Using Symfony's reserved parameters.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SpecialParamsController extends AbstractController
{
    #[Route(
        '/download/{file}.{_format}',
        name: 'file_download',
        requirements: ['_format' => 'json|xml|csv'],
        defaults: ['_format' => 'json']
    )]
    public function download(string $file, string $_format): Response
    {
        return new Response(
            sprintf('Downloading %s as %s', $file, $_format)
        );
    }

    #[Route('/content', name: 'content', defaults: ['_format' => 'html'])]
    public function content(Request $request): Response
    {
        $format = $request->getRequestFormat();
        return new Response(sprintf('Format: %s', $format));
    }
}
```

Parameters starting with underscore are special. _format determines  
response format, _locale sets language, and _controller specifies the  
handler. These integrate with Symfony's internals for powerful behavior.  

## Route Attribute Inheritance

Inheriting route configuration from parent classes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/base', name: 'base_')]
abstract class BaseApiController extends AbstractController
{
    protected function jsonResponse(array $data): Response
    {
        return $this->json($data);
    }
}

#[Route('/users', name: 'users_')]
class UserApiController extends BaseApiController
{
    #[Route('/', name: 'list', methods: ['GET'])]
    public function list(): Response
    {
        return $this->jsonResponse(['users' => []]);
    }

    #[Route('/{id}', name: 'show', methods: ['GET'])]
    public function show(int $id): Response
    {
        return $this->jsonResponse(['id' => $id]);
    }
}
```

Route prefixes combine across inheritance. The list route becomes  
/base/users/ with name base_users_list. This pattern promotes code reuse  
and consistent API structure across related controllers.  

## Stateless Routes

Disabling sessions for API routes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/api', stateless: true)]
class StatelessApiController extends AbstractController
{
    #[Route('/status', name: 'api_status')]
    public function status(): Response
    {
        return $this->json([
            'status' => 'operational',
            'timestamp' => time()
        ]);
    }

    #[Route('/data', name: 'api_data')]
    public function data(): Response
    {
        return $this->json(['data' => 'example']);
    }
}
```

The stateless parameter prevents session initialization for these routes.  
This improves performance for APIs that use token authentication instead  
of sessions. Reduces overhead when sessions aren't needed.  

## Route Deprecation

Marking routes as deprecated.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class DeprecatedController extends AbstractController
{
    #[Route(
        '/old-api/data',
        name: 'old_api_data'
    )]
    public function oldApi(): Response
    {
        trigger_error(
            'Route old_api_data is deprecated, use api_v2_data instead',
            E_USER_DEPRECATED
        );
        
        return $this->json(['data' => 'legacy']);
    }

    #[Route('/api/v2/data', name: 'api_v2_data')]
    public function newApi(): Response
    {
        return $this->json(['data' => 'current']);
    }
}
```

While there's no built-in deprecation marker, trigger warnings to inform  
developers. This helps manage API migrations by alerting users before  
removing old routes. Document deprecation in comments and API docs.  

## Sub-domain Routing

Routing based on subdomain patterns.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class MultiTenantController extends AbstractController
{
    #[Route(
        '/dashboard',
        name: 'tenant_dashboard',
        host: '{tenant}.myapp.com',
        requirements: ['tenant' => '[a-z0-9-]+']
    )]
    public function dashboard(string $tenant): Response
    {
        return new Response(
            sprintf('Dashboard for tenant: %s', $tenant)
        );
    }

    #[Route(
        '/settings',
        name: 'tenant_settings',
        host: '{tenant}.myapp.com'
    )]
    public function settings(string $tenant): Response
    {
        return new Response(
            sprintf('Settings for tenant: %s', $tenant)
        );
    }
}
```

Host parameters enable multi-tenant applications where each customer has  
their own subdomain. The tenant identifier is extracted and can be used to  
load customer-specific data and configuration.  

## Route Environment Restrictions

Making routes available only in specific environments.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class DebugController extends AbstractController
{
    #[Route(
        '/_debug/routes',
        name: 'debug_routes',
        condition: "context.getParameter('kernel.environment') === 'dev'"
    )]
    public function routes(): Response
    {
        return new Response('Debug information');
    }
}
```

Condition expressions can check the environment. This route only works in  
dev mode. Alternatively, load routes conditionally in routing configuration  
based on environment to prevent exposure in production.  

## API Version Routing

Managing multiple API versions with routes.  

```php
<?php

namespace App\Controller\Api\V1;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/api/v1', name: 'api_v1_')]
class ProductController extends AbstractController
{
    #[Route('/products', name: 'products', methods: ['GET'])]
    public function list(): Response
    {
        return $this->json(['version' => 1, 'products' => []]);
    }
}
```

```php
<?php

namespace App\Controller\Api\V2;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/api/v2', name: 'api_v2_')]
class ProductController extends AbstractController
{
    #[Route('/products', name: 'products', methods: ['GET'])]
    public function list(): Response
    {
        return $this->json(['version' => 2, 'products' => []]);
    }
}
```

Version prefixes let multiple API versions coexist. Each version lives in  
its own namespace with dedicated controllers. This enables gradual  
migration while maintaining backward compatibility.  

## Route Parameter Conversion

Automatic entity conversion with ParamConverter.  

```php
<?php

namespace App\Controller;

use App\Entity\Product;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProductViewController extends AbstractController
{
    #[Route('/product/{id}', name: 'product_view')]
    public function view(Product $product): Response
    {
        return $this->render('product/view.html.twig', [
            'product' => $product
        ]);
    }

    #[Route('/product/slug/{slug}', name: 'product_by_slug')]
    public function bySlug(Product $product): Response
    {
        return $this->render('product/view.html.twig', [
            'product' => $product
        ]);
    }
}
```

ParamConverter automatically queries the database and converts route  
parameters to entities. If the entity isn't found, Symfony returns 404.  
Works with any unique field when properly configured in the entity.  

## Optional Route Parameters with Null

Handling truly optional parameters.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SearchController extends AbstractController
{
    #[Route('/search/{query}', name: 'search', defaults: ['query' => null])]
    public function search(?string $query): Response
    {
        if ($query === null) {
            return new Response('Enter a search term');
        }
        
        return new Response(sprintf('Searching for: %s', $query));
    }
}
```

Setting a parameter default to null and using nullable types makes it  
truly optional. The route matches both /search and /search/term. Useful  
for search pages that can show different content without a query.  

## Route Configuration Reference

Understanding route attribute parameters.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ReferenceController extends AbstractController
{
    #[Route(
        path: '/reference/{id}',
        name: 'reference_example',
        requirements: ['id' => '\d+'],
        defaults: ['id' => 1],
        methods: ['GET', 'POST'],
        schemes: ['https'],
        host: 'example.com',
        condition: "request.headers.get('Accept') matches '/json/'",
        priority: 5,
        locale: 'en',
        format: 'json',
        stateless: true
    )]
    public function example(int $id): Response
    {
        return $this->json(['id' => $id]);
    }
}
```

This comprehensive example shows all major route parameters. Each controls  
a different aspect of routing behavior. Most routes only need path, name,  
and occasionally methods or requirements.  

## Redirecting Routes

Creating redirect-only routes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class RedirectController extends AbstractController
{
    #[Route('/old-path', name: 'old_path')]
    public function oldPath(): Response
    {
        return $this->redirectToRoute('new_path', [], 301);
    }

    #[Route('/new-path', name: 'new_path')]
    public function newPath(): Response
    {
        return new Response('Current page');
    }

    #[Route('/external', name: 'external_redirect')]
    public function external(): RedirectResponse
    {
        return $this->redirect('https://symfony.com', 302);
    }
}
```

Use redirectToRoute() for internal redirects and redirect() for external  
URLs. Status 301 indicates permanent relocation (good for SEO), while 302  
is temporary. Never redirect to untrusted user input.  

## Route Metadata

Attaching custom data to routes.  

```yaml
# config/routes.yaml
admin_panel:
    path: /admin
    controller: App\Controller\AdminController::index
    options:
        permissions: ['ROLE_ADMIN']
        feature_flag: 'admin_panel'

public_page:
    path: /page
    controller: App\Controller\PageController::index
    options:
        cache: 3600
        public: true
```

The options key stores custom metadata. Access via  
$request->attributes->get('_route_params'). Useful for storing permissions,  
caching hints, or feature flags that event listeners can check.  

## Console Route Testing

Testing routes from the command line.  

```bash
# Test if a route exists and what it matches
php bin/console router:match /product/42

# Expected output:
# Route "product_show" matches
# 
# Route Name: product_show
# Path: /product/{id}
# Host: ANY
# Scheme: ANY
# Method: GET
# Requirements: id: \d+
# Options: compiler_class: Symfony\Component\Routing\RouteCompiler
# Defaults: _controller: App\Controller\ProductController::show

# Test with HTTP method
php bin/console router:match /api/products --method=POST

# Test with custom headers
php bin/console router:match /api/data --header="X-Api-Version: v2"
```

The router:match command simulates requests to test routing behavior. Use  
--method to test method constraints and --header for condition expressions.  
Essential for debugging routing issues without running the full app.  

## Performance Best Practices

Optimizing route definitions for speed.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

// Good: Specific requirements reduce regex matching overhead
class OptimizedController extends AbstractController
{
    #[Route('/product/{id}', name: 'product', requirements: ['id' => '\d{1,8}'])]
    public function product(int $id): Response
    {
        return new Response(sprintf('Product: %d', $id));
    }

    // Good: Exact paths are fastest
    #[Route('/about', name: 'about')]
    public function about(): Response
    {
        return new Response('About page');
    }

    // Good: Method constraints eliminate non-matching routes quickly
    #[Route('/api/create', name: 'api_create', methods: ['POST'])]
    public function create(): Response
    {
        return $this->json(['created' => true]);
    }
}
```

Place exact match routes before patterns. Add specific requirements to  
limit regex backtracking. Use method constraints to eliminate routes  
early. In production, Symfony compiles routes to optimized matchers.  

## Route Organization Strategies

Structuring routes for maintainability.  

```php
<?php

// Strategy 1: Group by feature area
namespace App\Controller\Blog;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/blog', name: 'blog_')]
class BlogController extends AbstractController
{
    // All blog routes together
}

// Strategy 2: Separate by access level  
namespace App\Controller\Admin;

#[Route('/admin', name: 'admin_')]
class AdminController extends AbstractController
{
    // All admin routes together
}

// Strategy 3: API versioning in namespaces
namespace App\Controller\Api\V1;

#[Route('/api/v1', name: 'api_v1_')]
class ApiController extends AbstractController
{
    // Version 1 API routes
}
```

Organize controllers by feature, access level, or API version. Use  
namespaces and prefixes consistently. This makes routes easy to find and  
reduces naming conflicts across large applications.  

## Common Routing Pitfalls

Avoiding typical routing mistakes.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class PitfallsController extends AbstractController
{
    // WRONG: Generic route before specific
    #[Route('/page/{slug}', name: 'page_generic')]
    public function generic(string $slug): Response
    {
        return new Response($slug);
    }

    // This will never match because the above catches it
    #[Route('/page/about', name: 'page_about')]
    public function about(): Response
    {
        return new Response('About');
    }

    // RIGHT: Use priority or reorder routes
    #[Route('/page/about', name: 'page_about_fixed', priority: 10)]
    public function aboutFixed(): Response
    {
        return new Response('About');
    }

    #[Route('/page/{slug}', name: 'page_generic_fixed', priority: 0)]
    public function genericFixed(string $slug): Response
    {
        return new Response($slug);
    }
}
```

Always place specific routes before generic patterns. Use priority when  
route order matters. Test routes with router:match to verify they work as  
expected. Remember that route order determines matching precedence.  

## Profiler Integration

Using the Symfony Profiler for route debugging.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProfilerDemoController extends AbstractController
{
    #[Route('/demo', name: 'demo')]
    public function demo(): Response
    {
        return $this->render('demo.html.twig');
    }
}
```

When you visit /demo in development mode, the web debug toolbar appears at  
the bottom of the page. Click the route tab to see matched route details,  
parameters, and requirements. The profiler shows route matching time and  
helps identify performance issues.  

Access the full profiler at /_profiler to see detailed route information  
for any request. The routing panel shows all routes, which one matched,  
and why others didn't match. Essential for debugging complex routing.  

## Best Practices Summary

Guidelines for effective routing.  

1. Use PHP attributes for new projects - they keep routes close to  
controllers, making code easier to understand and maintain.  

2. Always name your routes - this enables URL generation and makes  
refactoring safer. Names should be descriptive and follow conventions.  

3. Use requirements liberally - validate parameters at the routing level  
to prevent invalid data from reaching controllers.  

4. Leverage route prefixes - group related routes to reduce repetition and  
improve organization.  

5. Never hard-code URLs - always use generateUrl() or the path() Twig  
function to create links.  

6. Be specific with HTTP methods - restrict routes to appropriate verbs  
for better API design and security.  

7. Test routes thoroughly - use router:match and automated tests to ensure  
routes work as expected.  

8. Document complex routes - add comments explaining non-obvious  
requirements or conditions.  

9. Monitor performance - use the Profiler in development to identify slow  
route matching.  

10. Keep it simple - only use advanced features like conditions and hosts  
when necessary. Simple routes are easier to maintain.  

## Advanced Debugging Techniques

Deep diving into route matching problems.  

```bash
# Export all routes to a file for analysis
php bin/console debug:router --format=json > routes.json

# Find routes by name pattern
php bin/console debug:router | grep admin

# Show all routes for a specific controller
php bin/console debug:router --show-controllers | grep ProductController

# Analyze route compilation and caching
php bin/console cache:pool:clear routing.cache
php bin/console router:match /test-path -vvv
```

The -vvv flag provides verbose output showing exactly how Symfony matches  
routes. Export routes to JSON for processing with external tools. Clear  
routing cache when routes don't update as expected.  

```php
<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Psr\Log\LoggerInterface;

#[AsEventListener(event: KernelEvents::REQUEST, priority: 33)]
class RouteDebugListener
{
    public function __construct(
        private LoggerInterface $logger
    ) {}

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        
        $this->logger->debug('Route matched', [
            'route' => $request->attributes->get('_route'),
            'controller' => $request->attributes->get('_controller'),
            'params' => $request->attributes->get('_route_params'),
        ]);
    }
}
```

Create event listeners to log route matching in production. This helps  
diagnose issues without access to the Profiler. Log route names,  
controllers, and parameters for each request.  

## Conclusion

Routing is the foundation of Symfony applications, connecting URLs to  
controller logic. Master route definitions, parameters, constraints, and  
generation to build maintainable applications. Use debugging tools  
liberally during development. Follow best practices for organization and  
performance. The routing component's flexibility supports everything from  
simple websites to complex multi-tenant SaaS platforms.  

With these 60 examples, you have a comprehensive reference covering all  
major routing concepts. Start with basic attributes for simple projects,  
then add requirements, HTTP methods, and prefixes as needed. Use YAML or  
XML when configuration management demands it. Always test routes  
thoroughly and leverage Symfony's excellent debugging tools to ensure your  
routing works exactly as intended.  
