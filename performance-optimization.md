# Symfony Performance Optimization

Performance optimization is crucial for delivering fast, responsive Symfony  
applications that provide excellent user experience and scale efficiently.  
This guide covers identifying performance bottlenecks, profiling tools,  
caching strategies, database optimization, and front-end performance  
improvements.  

## Common Performance Bottlenecks

Understanding where performance issues typically occur helps you identify  
and resolve them quickly.  

### Slow Database Queries

Database queries are often the primary performance bottleneck in web  
applications.  

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

    // BAD: N+1 query problem
    public function findAllWithCategories(): array
    {
        // This loads all products, then makes separate query for each category
        return $this->findAll();
    }

    // GOOD: Single query with JOIN
    public function findAllWithCategoriesOptimized(): array
    {
        return $this->createQueryBuilder('p')
            ->leftJoin('p.category', 'c')
            ->addSelect('c')
            ->getQuery()
            ->getResult();
    }
}
```

The N+1 query problem occurs when loading related entities. Instead of one  
query, the application executes one query for the main entities plus N  
additional queries for each relationship. Use JOINs with addSelect() to  
load related data in a single query.  

### Excessive HTTP Requests

Too many HTTP requests for assets slow down page loading.  

```php
<?php

// templates/base.html.twig
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>{% block title %}Welcome{% endblock %}</title>
        
        {# BAD: Multiple separate CSS files #}
        {# <link rel="stylesheet" href="{{ asset('css/bootstrap.css') }}"> #}
        {# <link rel="stylesheet" href="{{ asset('css/components.css') }}"> #}
        {# <link rel="stylesheet" href="{{ asset('css/custom.css') }}"> #}
        
        {# GOOD: Combined and minified assets #}
        {% block stylesheets %}
            {{ importmap('app') }}
        {% endblock %}
    </head>
    <body>
        {% block body %}{% endblock %}
    </body>
</html>
```

Use AssetMapper or Webpack Encore to bundle and minify assets. Enable  
HTTP/2 to allow parallel asset loading. Implement resource hints like  
preload and prefetch for critical resources.  

### Template Rendering Issues

Complex templates with heavy logic can slow response times.  

```php
<?php

namespace App\Controller;

use App\Repository\ProductRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProductController extends AbstractController
{
    // BAD: Heavy computation in template
    #[Route('/products/slow', name: 'products_slow')]
    public function slowList(ProductRepository $repository): Response
    {
        $products = $repository->findAll();
        
        return $this->render('product/slow_list.html.twig', [
            'products' => $products,
            // Template will calculate statistics for each product
        ]);
    }

    // GOOD: Prepare data in controller
    #[Route('/products/fast', name: 'products_fast')]
    public function fastList(ProductRepository $repository): Response
    {
        $products = $repository->findAll();
        
        $productsWithStats = array_map(function($product) {
            return [
                'product' => $product,
                'discountedPrice' => $product->getPrice() * 0.9,
                'inStock' => $product->getStock() > 0,
            ];
        }, $products);
        
        return $this->render('product/fast_list.html.twig', [
            'productsWithStats' => $productsWithStats,
        ]);
    }
}
```

Move complex calculations from templates to controllers or services.  
Templates should focus on presentation, not business logic. Use Twig  
extensions for reusable template logic.  

### Memory-Intensive Operations

Processing large datasets can exhaust available memory.  

```php
<?php

namespace App\Service;

use App\Entity\Product;
use Doctrine\ORM\EntityManagerInterface;

class ProductExportService
{
    public function __construct(
        private EntityManagerInterface $entityManager
    ) {}

    // BAD: Load all records into memory
    public function exportAllBad(): array
    {
        $products = $this->entityManager
            ->getRepository(Product::class)
            ->findAll();
        
        // This loads thousands of entities into memory
        return array_map(fn($p) => $p->toArray(), $products);
    }

    // GOOD: Stream results to avoid memory issues
    public function exportAllGood(): iterable
    {
        $query = $this->entityManager
            ->createQueryBuilder()
            ->select('p')
            ->from(Product::class, 'p')
            ->getQuery();
        
        // Iterate results one at a time
        foreach ($query->toIterable() as $product) {
            yield $product->toArray();
        }
    }
}
```

Use streaming, pagination, or batch processing for large datasets. Doctrine's  
toIterable() method processes results one at a time without loading everything  
into memory. Clear the entity manager periodically during batch operations.  

## Profiling and Debugging Tools

Symfony provides powerful tools for identifying performance issues and  
understanding application behavior.  

### Symfony Profiler

The Web Profiler Toolbar and Profiler panel provide detailed insights into  
each request.  

```php
<?php

// config/packages/dev/web_profiler.yaml
web_profiler:
    toolbar: true
    intercept_redirects: false

framework:
    profiler:
        only_exceptions: false
        collect_serializer_data: true
```

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Doctrine\ORM\EntityManagerInterface;
use App\Entity\Product;

class DebugController extends AbstractController
{
    #[Route('/debug/performance', name: 'debug_performance')]
    public function performance(EntityManagerInterface $em): Response
    {
        // The profiler will track this query
        $products = $em->getRepository(Product::class)
            ->createQueryBuilder('p')
            ->leftJoin('p.category', 'c')
            ->addSelect('c')
            ->setMaxResults(100)
            ->getQuery()
            ->getResult();
        
        return $this->render('debug/performance.html.twig', [
            'products' => $products,
        ]);
    }
}
```

The profiler toolbar appears at the bottom of each page in development mode.  
It shows execution time, memory usage, database queries, cache hits, and  
more. Click any section to open the detailed profiler panel. The database  
panel shows all queries with execution time and parameters.  

### Web Debug Toolbar

Quick access to critical performance metrics during development.  

```yaml
# config/packages/dev/web_profiler.yaml
web_profiler:
    toolbar: true
    intercept_redirects: false
    
framework:
    profiler:
        only_exceptions: false
```

The toolbar displays:  
- **Request/Response**: HTTP status, route, controller  
- **Performance**: Execution time, memory usage  
- **Database**: Number of queries, total query time  
- **Cache**: Cache hits and misses  
- **Events**: Dispatched events and listeners  
- **Logs**: Application logs and errors  

Click the toolbar icon to access the full profiler with detailed information  
about each metric. The profiler stores recent requests for comparison.  

### Blackfire Integration

Blackfire provides advanced profiling for production environments.  

```php
<?php

// composer require blackfire/php-sdk

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Blackfire\Client;
use Blackfire\Profile\Configuration;

class BlackfireController extends AbstractController
{
    #[Route('/blackfire/test', name: 'blackfire_test')]
    public function test(): Response
    {
        // Expensive operation to profile
        $data = [];
        for ($i = 0; $i < 10000; $i++) {
            $data[] = [
                'id' => $i,
                'value' => md5((string)$i),
            ];
        }
        
        return $this->json([
            'count' => count($data),
            'sample' => array_slice($data, 0, 5),
        ]);
    }
}
```

```bash
# Install Blackfire CLI
wget -O - https://packages.blackfire.io/gpg.key | sudo apt-key add -
echo "deb http://packages.blackfire.io/debian any main" | \
    sudo tee /etc/apt/sources.list.d/blackfire.list
sudo apt-get update
sudo apt-get install blackfire-agent blackfire-php

# Profile a URL
blackfire curl https://example.com/blackfire/test

# Profile specific function calls
blackfire run php bin/console app:import-data
```

Blackfire creates detailed call graphs showing where time is spent. It  
identifies hotspots in your code, compares profile runs, and provides  
recommendations. Use it to profile production traffic without impacting  
performance.  

### Stopwatch Component

Measure execution time of specific code sections.  

```php
<?php

namespace App\Service;

use Symfony\Component\Stopwatch\Stopwatch;

class DataProcessingService
{
    public function __construct(
        private Stopwatch $stopwatch
    ) {}

    public function processData(array $data): array
    {
        $this->stopwatch->start('data_processing');
        
        // Validation phase
        $this->stopwatch->start('validation');
        $validData = $this->validateData($data);
        $this->stopwatch->stop('validation');
        
        // Transformation phase
        $this->stopwatch->start('transformation');
        $transformedData = $this->transformData($validData);
        $this->stopwatch->stop('transformation');
        
        $event = $this->stopwatch->stop('data_processing');
        
        // Log performance metrics
        error_log(sprintf(
            'Data processing: %d ms, %d MB',
            $event->getDuration(),
            $event->getMemory() / 1024 / 1024
        ));
        
        return $transformedData;
    }

    private function validateData(array $data): array
    {
        // Validation logic
        return array_filter($data, fn($item) => isset($item['id']));
    }

    private function transformData(array $data): array
    {
        // Transformation logic
        return array_map(fn($item) => [
            'id' => $item['id'],
            'processed' => true,
        ], $data);
    }
}
```

The Stopwatch component measures code execution time and memory usage. Start  
events before code blocks and stop them afterward. Events appear in the  
profiler timeline. Use for identifying slow operations in complex workflows.  

## Caching Strategies

Caching dramatically improves performance by avoiding repeated expensive  
operations.  

### HTTP Cache

Browser and reverse proxy caching reduces server load.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class CachedController extends AbstractController
{
    #[Route('/public/page', name: 'public_page')]
    public function publicPage(): Response
    {
        $response = $this->render('public/page.html.twig', [
            'content' => 'This page is publicly cached',
        ]);
        
        // Cache for 1 hour in browser and proxy
        $response->setPublic();
        $response->setMaxAge(3600);
        $response->setSharedMaxAge(3600);
        
        return $response;
    }

    #[Route('/conditional/page', name: 'conditional_page')]
    public function conditionalPage(Request $request): Response
    {
        $response = new Response();
        $response->setLastModified(new \DateTime('10 minutes ago'));
        
        // Check if client has current version
        if ($response->isNotModified($request)) {
            return $response;
        }
        
        $response->setContent(
            $this->renderView('conditional/page.html.twig', [
                'data' => 'Fresh content',
            ])
        );
        
        return $response;
    }

    #[Route('/etag/page', name: 'etag_page')]
    public function etagPage(Request $request): Response
    {
        $content = 'Content that rarely changes';
        $etag = md5($content);
        
        $response = new Response();
        $response->setEtag($etag);
        $response->setPublic();
        
        if ($response->isNotModified($request)) {
            return $response;
        }
        
        $response->setContent($content);
        return $response;
    }
}
```

HTTP caching allows browsers and proxies to store responses. Use setPublic()  
for content that can be cached by anyone. setMaxAge() controls browser cache  
duration. setSharedMaxAge() controls proxy cache duration. ETags and  
Last-Modified headers enable conditional requests.  

### Symfony Cache Component

Application-level caching for expensive operations.  

```php
<?php

namespace App\Service;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use App\Repository\ProductRepository;

class ProductStatsService
{
    public function __construct(
        private CacheInterface $cache,
        private ProductRepository $repository
    ) {}

    public function getStatistics(): array
    {
        return $this->cache->get('product_statistics', function (ItemInterface $item) {
            $item->expiresAfter(3600); // Cache for 1 hour
            
            // Expensive calculation
            $totalProducts = $this->repository->count([]);
            $avgPrice = $this->repository->getAveragePrice();
            $topCategories = $this->repository->getTopCategories(5);
            
            return [
                'total' => $totalProducts,
                'average_price' => $avgPrice,
                'top_categories' => $topCategories,
                'generated_at' => new \DateTime(),
            ];
        });
    }

    public function invalidateCache(): void
    {
        $this->cache->delete('product_statistics');
    }

    public function getUserDashboard(int $userId): array
    {
        $cacheKey = "user_dashboard_{$userId}";
        
        return $this->cache->get($cacheKey, function (ItemInterface $item) use ($userId) {
            $item->expiresAfter(1800); // 30 minutes
            $item->tag(['user', "user_{$userId}"]);
            
            // Build dashboard data
            return [
                'user_id' => $userId,
                'stats' => $this->calculateUserStats($userId),
                'recent_orders' => $this->getRecentOrders($userId),
            ];
        });
    }

    private function calculateUserStats(int $userId): array
    {
        // Simulate expensive operation
        return ['orders' => 10, 'total_spent' => 1500];
    }

    private function getRecentOrders(int $userId): array
    {
        return [];
    }
}
```

```yaml
# config/packages/cache.yaml
framework:
    cache:
        app: cache.adapter.redis
        default_redis_provider: 'redis://localhost'
        
        pools:
            cache.app:
                adapter: cache.adapter.redis
                default_lifetime: 3600
                
            cache.expensive_operations:
                adapter: cache.adapter.redis
                default_lifetime: 86400
```

The Cache component provides a simple interface for caching any data. Use  
get() with a callback to compute values only when not cached. Configure  
different cache adapters (Redis, Memcached, APCu) for different use cases.  
Tag cache items for easier invalidation.  

### Doctrine Result Cache

Cache query results to avoid database hits.  

```php
<?php

namespace App\Repository;

use App\Entity\Category;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class CategoryRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Category::class);
    }

    public function findActiveCategories(): array
    {
        return $this->createQueryBuilder('c')
            ->where('c.active = :active')
            ->setParameter('active', true)
            ->orderBy('c.name', 'ASC')
            ->getQuery()
            ->enableResultCache(3600, 'active_categories')
            ->getResult();
    }

    public function getCategoryStats(int $categoryId): array
    {
        $query = $this->createQueryBuilder('c')
            ->select('c.id, c.name, COUNT(p.id) as productCount')
            ->leftJoin('c.products', 'p')
            ->where('c.id = :id')
            ->setParameter('id', $categoryId)
            ->groupBy('c.id, c.name')
            ->getQuery();
        
        $query->enableResultCache(1800, "category_stats_{$categoryId}");
        
        return $query->getSingleResult();
    }
}
```

```yaml
# config/packages/doctrine.yaml
doctrine:
    orm:
        result_cache_driver:
            type: pool
            pool: doctrine.result_cache_pool
            
framework:
    cache:
        pools:
            doctrine.result_cache_pool:
                adapter: cache.adapter.redis
```

Result cache stores query results using the specified cache driver. Use  
enableResultCache() with a TTL and unique cache key. Clear result cache  
when underlying data changes. Second-level cache provides entity-level  
caching for frequently accessed data.  

### Twig Template Cache

Compiled templates are automatically cached in production.  

```yaml
# config/packages/twig.yaml
twig:
    cache: '%kernel.cache_dir%/twig'
    auto_reload: '%kernel.debug%'
```

```php
<?php

namespace App\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class CachedExtension extends AbstractExtension
{
    public function __construct(
        private CacheInterface $cache
    ) {}

    public function getFunctions(): array
    {
        return [
            new TwigFunction('expensive_function', [$this, 'expensiveFunction']),
        ];
    }

    public function expensiveFunction(string $key): string
    {
        return $this->cache->get("twig_function_{$key}", function (ItemInterface $item) use ($key) {
            $item->expiresAfter(3600);
            
            // Expensive calculation
            return strtoupper(md5($key));
        });
    }
}
```

Twig automatically caches compiled templates. In production, set  
auto_reload to false to avoid checking file modifications. For expensive  
Twig functions, implement caching within the function. Use fragment caching  
with ESI for caching parts of templates.  

### Opcache Configuration

PHP opcache significantly improves performance by caching compiled code.  

```ini
; php.ini configuration for production
[opcache]
opcache.enable=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=20000
opcache.validate_timestamps=0
opcache.save_comments=1
opcache.fast_shutdown=1
opcache.enable_cli=1

; For development
opcache.validate_timestamps=1
opcache.revalidate_freq=0
```

```bash
# Clear opcache in production after deployment
php -r "opcache_reset();"

# Or use a script
echo "<?php opcache_reset(); echo 'Opcache cleared';" | php
```

Opcache stores compiled PHP code in memory, avoiding repeated compilation.  
Set validate_timestamps to 0 in production to skip file modification checks.  
Increase memory_consumption and max_accelerated_files for large applications.  
Clear opcache after deployments.  

## Database Optimization

Database performance is critical for application speed.  

### Query Optimization

Write efficient queries and avoid common pitfalls.  

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

    // BAD: Loading unnecessary data
    public function getOrderCountBad(): int
    {
        $orders = $this->findAll();
        return count($orders);
    }

    // GOOD: Use COUNT query
    public function getOrderCount(): int
    {
        return $this->createQueryBuilder('o')
            ->select('COUNT(o.id)')
            ->getQuery()
            ->getSingleScalarResult();
    }

    // BAD: N+1 problem with related entities
    public function findOrdersWithItemsBad(): array
    {
        return $this->findAll();
        // Template will trigger queries for each order's items
    }

    // GOOD: Eager load related entities
    public function findOrdersWithItems(): array
    {
        return $this->createQueryBuilder('o')
            ->leftJoin('o.items', 'i')
            ->addSelect('i')
            ->leftJoin('o.customer', 'c')
            ->addSelect('c')
            ->getQuery()
            ->getResult();
    }

    // GOOD: Partial objects when you don't need all fields
    public function getOrderSummaries(): array
    {
        return $this->createQueryBuilder('o')
            ->select('o.id, o.orderNumber, o.total, o.createdAt')
            ->where('o.status = :status')
            ->setParameter('status', 'completed')
            ->getQuery()
            ->getArrayResult();
    }

    // GOOD: Pagination for large result sets
    public function findRecentOrders(int $page = 1, int $limit = 20): array
    {
        return $this->createQueryBuilder('o')
            ->orderBy('o.createdAt', 'DESC')
            ->setFirstResult(($page - 1) * $limit)
            ->setMaxResults($limit)
            ->getQuery()
            ->getResult();
    }
}
```

Use COUNT queries instead of loading entities to count. Always use JOINs  
with addSelect() to prevent N+1 problems. Select only needed fields with  
partial objects. Implement pagination for large datasets. Use indexes on  
frequently queried columns.  

### Database Indexing

Proper indexes dramatically speed up queries.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'products')]
#[ORM\Index(name: 'idx_product_sku', columns: ['sku'])]
#[ORM\Index(name: 'idx_product_status', columns: ['status'])]
#[ORM\Index(name: 'idx_product_category', columns: ['category_id'])]
#[ORM\Index(name: 'idx_product_created', columns: ['created_at'])]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 100, unique: true)]
    private ?string $sku = null;

    #[ORM\Column(length: 255)]
    private ?string $name = null;

    #[ORM\Column(length: 50)]
    private ?string $status = null;

    #[ORM\ManyToOne(targetEntity: Category::class)]
    #[ORM\JoinColumn(nullable: false)]
    private ?Category $category = null;

    #[ORM\Column(type: 'datetime')]
    private ?\DateTimeInterface $createdAt = null;

    // Getters and setters
}
```

```sql
-- Create indexes for common query patterns
CREATE INDEX idx_product_search ON products(name, status);
CREATE INDEX idx_product_price_range ON products(price, status);

-- Composite index for sorting and filtering
CREATE INDEX idx_order_user_date ON orders(user_id, created_at DESC);

-- Analyze query performance
EXPLAIN SELECT * FROM products 
WHERE status = 'active' 
ORDER BY created_at DESC 
LIMIT 20;
```

Add indexes to columns used in WHERE, JOIN, and ORDER BY clauses. Use  
composite indexes for queries filtering on multiple columns. Monitor index  
usage and remove unused indexes. Be cautious with too many indexes as they  
slow down writes.  

### Batch Processing

Process large datasets efficiently without memory issues.  

```php
<?php

namespace App\Command;

use App\Entity\Product;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(
    name: 'app:update-products',
    description: 'Update all products in batches'
)]
class UpdateProductsCommand extends Command
{
    private const BATCH_SIZE = 100;

    public function __construct(
        private EntityManagerInterface $em
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $query = $this->em->createQuery(
            'SELECT p FROM App\Entity\Product p'
        );
        
        $iterableResult = $query->toIterable();
        $processed = 0;
        
        foreach ($iterableResult as $product) {
            // Update product
            $product->setUpdatedAt(new \DateTime());
            
            $processed++;
            
            // Flush and clear every BATCH_SIZE entities
            if ($processed % self::BATCH_SIZE === 0) {
                $this->em->flush();
                $this->em->clear();
                
                $output->writeln("Processed {$processed} products");
            }
        }
        
        // Flush remaining entities
        $this->em->flush();
        $this->em->clear();
        
        $output->writeln("Completed: {$processed} products updated");
        
        return Command::SUCCESS;
    }
}
```

```php
<?php

namespace App\Service;

use App\Entity\Product;
use Doctrine\ORM\EntityManagerInterface;

class BulkProductService
{
    public function __construct(
        private EntityManagerInterface $em
    ) {}

    public function bulkUpdatePrices(array $updates): void
    {
        // Use DQL for bulk updates
        $query = $this->em->createQuery(
            'UPDATE App\Entity\Product p 
             SET p.price = p.price * :multiplier 
             WHERE p.category = :category'
        );
        
        $query->setParameter('multiplier', 1.1);
        $query->setParameter('category', $updates['category']);
        $query->execute();
    }

    public function batchInsert(array $products): void
    {
        foreach ($products as $i => $productData) {
            $product = new Product();
            $product->setName($productData['name']);
            $product->setPrice($productData['price']);
            
            $this->em->persist($product);
            
            // Flush every 50 entities
            if ($i % 50 === 0) {
                $this->em->flush();
                $this->em->clear();
            }
        }
        
        $this->em->flush();
        $this->em->clear();
    }
}
```

Process large datasets in batches to avoid memory exhaustion. Use  
toIterable() to stream results. Call flush() and clear() periodically to  
free memory. Use DQL UPDATE/DELETE for bulk operations instead of loading  
entities.  

### Connection Pooling

Reuse database connections for better performance.  

```yaml
# config/packages/doctrine.yaml
doctrine:
    dbal:
        default_connection: default
        connections:
            default:
                url: '%env(resolve:DATABASE_URL)%'
                driver: 'pdo_mysql'
                server_version: '8.0'
                charset: utf8mb4
                
                # Connection pooling options
                options:
                    # Keep connections alive
                    1002: 'SET sql_mode=(SELECT REPLACE(@@sql_mode, "ONLY_FULL_GROUP_BY", ""))'
                
                # Performance options
                use_savepoints: true
                
            read_only:
                url: '%env(resolve:DATABASE_READ_URL)%'
                driver: 'pdo_mysql'
                server_version: '8.0'
                charset: utf8mb4
```

Configure connection pooling in your database server. Use persistent  
connections when appropriate. Consider read replicas for read-heavy  
applications. Monitor connection usage and adjust pool sizes.  

## Asset Delivery and Front-End Performance

Optimize how assets are delivered to browsers.  

### Asset Optimization with AssetMapper

Use AssetMapper for modern asset management without Node.js.  

```yaml
# config/packages/asset_mapper.yaml
framework:
    asset_mapper:
        paths:
            - assets/
        excluded_patterns:
            - '*/tests/*'
            - '*.spec.js'
```

```yaml
# config/packages/prod/asset_mapper.yaml
framework:
    asset_mapper:
        paths:
            - assets/
        
    assets:
        version_strategy: 'json_manifest'
        json_manifest_path: '%kernel.project_dir%/public/assets/manifest.json'
```

```php
<?php

// templates/base.html.twig
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>{% block title %}Welcome{% endblock %}</title>
        
        {# Preload critical assets #}
        <link rel="preload" href="{{ asset('styles/critical.css') }}" as="style">
        <link rel="preload" href="{{ asset('app.js', 'app') }}" as="script">
        
        {% block stylesheets %}
            {{ importmap('app') }}
        {% endblock %}
    </head>
    <body>
        {% block body %}{% endblock %}
    </body>
</html>
```

AssetMapper automatically handles versioning and imports. Use content hashes  
for cache busting. Enable preloading for critical resources. Implement lazy  
loading for non-critical assets.  

### HTTP/2 and Server Push

Enable HTTP/2 for parallel asset loading.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\WebLink\Link;

class OptimizedPageController extends AbstractController
{
    #[Route('/optimized', name: 'optimized_page')]
    public function index(): Response
    {
        $response = $this->render('optimized/index.html.twig');
        
        // Add Link headers for preload
        $this->addLink($response, new Link('preload', '/assets/app.css'));
        $this->addLink($response, new Link('preload', '/assets/app.js'));
        
        return $response;
    }

    private function addLink(Response $response, Link $link): void
    {
        $response->headers->set(
            'Link',
            sprintf('<%s>; rel="%s"', $link->getHref(), $link->getRel())
        );
    }
}
```

```apache
# .htaccess for Apache with HTTP/2
<IfModule mod_http2.c>
    Protocols h2 http/1.1
    H2Push on
    H2PushPriority * after
    H2PushPriority text/css before
    H2PushPriority image/jpeg after 32
    H2PushPriority image/png after 32
</IfModule>
```

HTTP/2 allows multiple resources to load in parallel over a single  
connection. Use server push for critical resources. Configure proper  
priorities. Monitor actual performance improvements as over-pushing can  
hurt performance.  

### Compression

Enable compression to reduce transfer sizes.  

```apache
# .htaccess for Apache
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css
    AddOutputFilterByType DEFLATE text/javascript application/javascript application/x-javascript
    AddOutputFilterByType DEFLATE application/json application/xml
    AddOutputFilterByType DEFLATE image/svg+xml
</IfModule>
```

```nginx
# nginx.conf
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css text/xml text/javascript 
           application/json application/javascript application/xml+rss 
           application/rss+xml image/svg+xml;
gzip_disable "msie6";
```

Enable Gzip or Brotli compression for text-based assets. Configure  
compression levels (6 is usually optimal). Don't compress already  
compressed formats like JPEG or PNG. Use Brotli for better compression  
ratios on modern browsers.  

### CDN Integration

Use Content Delivery Networks for global asset distribution.  

```yaml
# config/packages/framework.yaml
framework:
    assets:
        base_urls:
            - 'https://cdn.example.com'
```

```php
<?php

namespace App\Service;

class AssetUrlGenerator
{
    public function __construct(
        private string $cdnUrl
    ) {}

    public function generateUrl(string $path): string
    {
        // Use CDN for production
        if ($_ENV['APP_ENV'] === 'prod') {
            return $this->cdnUrl . '/' . ltrim($path, '/');
        }
        
        return $path;
    }
}
```

CDNs serve assets from geographically distributed servers, reducing latency.  
Configure asset base URLs to point to your CDN. Use domain sharding  
sparingly as HTTP/2 reduces its benefits. Implement proper cache headers  
for CDN caching.  

### Image Optimization

Optimize images for faster loading.  

```php
<?php

namespace App\Service;

class ImageOptimizationService
{
    public function optimizeImage(string $path): void
    {
        // Get image info
        $info = getimagesize($path);
        $mime = $info['mime'];
        
        // Load image based on type
        $image = match($mime) {
            'image/jpeg' => imagecreatefromjpeg($path),
            'image/png' => imagecreatefrompng($path),
            'image/gif' => imagecreatefromgif($path),
            default => throw new \Exception('Unsupported image type'),
        };
        
        // Save optimized version
        if ($mime === 'image/jpeg') {
            imagejpeg($image, $path, 85); // 85% quality
        } elseif ($mime === 'image/png') {
            imagepng($image, $path, 6); // Compression level 6
        }
        
        imagedestroy($image);
    }

    public function createResponsiveVersions(string $path): array
    {
        $versions = [];
        $sizes = [320, 640, 1024, 1920];
        
        $info = getimagesize($path);
        $image = imagecreatefromjpeg($path);
        
        foreach ($sizes as $width) {
            $height = (int)($info[1] * ($width / $info[0]));
            $resized = imagescale($image, $width, $height);
            
            $filename = pathinfo($path, PATHINFO_FILENAME);
            $ext = pathinfo($path, PATHINFO_EXTENSION);
            $newPath = pathinfo($path, PATHINFO_DIRNAME) . 
                       "/{$filename}-{$width}w.{$ext}";
            
            imagejpeg($resized, $newPath, 85);
            $versions[$width] = $newPath;
            
            imagedestroy($resized);
        }
        
        imagedestroy($image);
        
        return $versions;
    }
}
```

Optimize image quality and size. Use appropriate formats (WebP for photos,  
SVG for icons). Implement responsive images with srcset. Lazy load  
off-screen images. Consider using image CDNs with automatic optimization.  

### Minification

Minify CSS and JavaScript for production.  

```bash
# Using AssetMapper with importmap
php bin/console importmap:install

# Assets are automatically optimized in production
php bin/console cache:clear --env=prod
```

```yaml
# config/packages/prod/framework.yaml
framework:
    assets:
        # Enable versioning for cache busting
        version: 'v1'
        version_format: '%%s?version=%%s'
```

Minification removes whitespace and shortens variable names. AssetMapper  
handles this automatically. For Webpack Encore, enable minification in  
production mode. Remove source maps in production unless needed for  
debugging.  

## Best Practices Summary

Key takeaways for Symfony performance optimization:  

**Profiling First**: Always profile before optimizing. Use Symfony Profiler  
and Blackfire to identify actual bottlenecks rather than guessing. Measure  
before and after changes to verify improvements.  

**Database Optimization**: Prevent N+1 queries with JOINs and addSelect().  
Use indexes on frequently queried columns. Implement pagination for large  
datasets. Use query result caching for expensive queries.  

**Caching Strategy**: Implement HTTP caching with proper headers. Use  
application caching for expensive operations. Enable Doctrine result cache.  
Configure opcache for PHP bytecode caching. Use Redis or Memcached for  
distributed caching.  

**Asset Optimization**: Bundle and minify assets. Use AssetMapper or Webpack  
Encore. Enable compression (Gzip/Brotli). Implement CDN for static assets.  
Use HTTP/2 for parallel loading.  

**Code Efficiency**: Move logic from templates to controllers. Use  
streaming for large datasets. Implement batch processing for bulk  
operations. Avoid loading unnecessary data.  

**Monitoring**: Set up performance monitoring in production. Track response  
times and error rates. Monitor database query performance. Use APM tools  
like New Relic or Datadog.  

**Production Configuration**: Enable opcache with optimal settings. Disable  
debug mode in production. Use production-optimized cache adapters. Configure  
proper error handling.  

**Continuous Improvement**: Regularly review slow requests. Optimize based  
on real user data. Keep dependencies updated. Follow Symfony performance  
best practices.  

## Conclusion

Performance optimization is an ongoing process requiring measurement,  
analysis, and incremental improvements. Start with profiling to identify  
bottlenecks, then apply targeted optimizations. Focus on high-impact areas  
like database queries, caching, and asset delivery.  

Symfony provides excellent tools for performance optimization, from the Web  
Debug Toolbar for development to advanced profiling with Blackfire. Combine  
these tools with proper caching strategies, database optimization, and  
front-end best practices to build fast, scalable applications.  

Remember that premature optimization can waste time and complicate code.  
Profile first, optimize second, and always measure the impact of changes.  
With the right approach and tools, you can build Symfony applications that  
deliver exceptional performance at scale.  
