
# Symfony Doctrine Console Commands

This comprehensive guide covers all Doctrine console commands available in  
Symfony, progressing from basic schema management to advanced database  
operations.  

## What is Doctrine?

Doctrine is a powerful Object-Relational Mapping (ORM) library for PHP that  
provides a high-level abstraction for database interactions. It is the  
default database management solution in Symfony and consists of two main  
components:  

**Doctrine DBAL (Database Abstraction Layer)**: A lightweight database  
abstraction layer that sits on top of PDO and provides a consistent API for  
database operations across different database systems (MySQL, PostgreSQL,  
SQLite, etc.).  

**Doctrine ORM (Object-Relational Mapper)**: A sophisticated ORM that allows  
developers to work with databases using PHP objects instead of writing SQL  
queries. It maps database tables to PHP classes (entities) and handles the  
conversion between object-oriented code and relational database structures.  

### Doctrine's Role in Symfony

Doctrine integrates seamlessly with Symfony through the DoctrineBundle,  
providing several key benefits:  

**Entity Management**: Define database tables as PHP classes with attributes,  
making database schemas version-controlled and type-safe. Entities are plain  
PHP objects (POPOs) that can be easily tested and manipulated.  

**Database Abstraction**: Write database-agnostic code that works across  
different database systems without changing application logic. Switch from  
MySQL to PostgreSQL with minimal configuration changes.  

**Query Building**: Use the QueryBuilder API or Doctrine Query Language (DQL)  
to construct complex queries in a programmatic, object-oriented way. This  
provides better IDE support and type safety compared to raw SQL strings.  

**Migrations**: Track database schema changes over time with migration files,  
enabling version control of database structure and easy deployment to  
different environments.  

**Repository Pattern**: Encapsulate database query logic in repository classes,  
promoting clean architecture and separation of concerns. Repositories provide  
a centralized location for all queries related to a specific entity.  

**Performance Optimization**: Leverage lazy loading, eager loading, caching,  
and batch processing to optimize database performance. Doctrine provides  
tools to identify and resolve N+1 query problems.  

### How Doctrine Facilitates Database Management

**Schema Synchronization**: Automatically generate and update database schemas  
based on entity definitions. Changes to entity classes can be reflected in  
the database through console commands.  

**Data Validation**: Integrate with Symfony's Validator component to ensure  
data integrity before persistence. Entity constraints are defined using PHP  
attributes.  

**Lifecycle Events**: Hook into entity lifecycle events (prePersist,  
postUpdate, etc.) to execute custom logic when entities are created,  
updated, or deleted.  

**Transaction Management**: Automatically wrap operations in database  
transactions to ensure data consistency. Doctrine's Unit of Work pattern  
tracks entity changes and executes all operations in a single transaction.  

**Database Portability**: Support for multiple database vendors with minimal  
code changes. Doctrine handles vendor-specific SQL syntax differences  
automatically.  

## Doctrine Console Commands Reference

The following table lists all available Doctrine-related console commands  
in Symfony. These commands are provided by the DoctrineBundle and  
DoctrineMigrationsBundle.  

| Command | Description |
|---------|-------------|
| `doctrine:database:create` | Creates the configured database |
| `doctrine:database:drop` | Drops the configured database |
| `doctrine:schema:create` | Creates database schema based on entities |
| `doctrine:schema:update` | Updates database schema based on entity changes |
| `doctrine:schema:drop` | Drops the complete database schema |
| `doctrine:schema:validate` | Validates the mapping files and database schema |
| `doctrine:query:sql` | Executes arbitrary SQL from the command line |
| `doctrine:query:dql` | Executes arbitrary DQL from the command line |
| `doctrine:mapping:info` | Shows all mapped entities and their classes |
| `doctrine:cache:clear-metadata` | Clears all metadata cache |
| `doctrine:cache:clear-query` | Clears all query cache |
| `doctrine:cache:clear-result` | Clears all result cache |
| `doctrine:fixtures:load` | Loads data fixtures to database |
| `doctrine:migrations:current` | Shows the current migration version |
| `doctrine:migrations:diff` | Generates a migration by comparing schema |
| `doctrine:migrations:execute` | Executes a single migration |
| `doctrine:migrations:generate` | Generates a blank migration class |
| `doctrine:migrations:latest` | Shows the latest migration version |
| `doctrine:migrations:list` | Lists all available migrations |
| `doctrine:migrations:migrate` | Executes migrations to a specified version |
| `doctrine:migrations:rollup` | Rolls up migrations by deleting all tracked versions |
| `doctrine:migrations:status` | Shows the status of migrations |
| `doctrine:migrations:sync-metadata-storage` | Syncs the metadata storage |
| `doctrine:migrations:up-to-date` | Checks if schema is up to date |
| `doctrine:migrations:version` | Manually adds/deletes migration versions |
| `make:entity` | Creates or updates a Doctrine entity |
| `make:migration` | Creates a new migration based on database changes |

## Database Creation and Removal

### Creating a Database

Creating the database configured in your Symfony application.  

```php
<?php

// config/packages/doctrine.yaml
doctrine:
    dbal:
        url: '%env(resolve:DATABASE_URL)%'
        driver: 'pdo_mysql'
        server_version: '8.0'
        charset: utf8mb4
```

```bash
# Create the database
php bin/console doctrine:database:create

# Create a test database
php bin/console doctrine:database:create --env=test
```

This command reads the database configuration from your environment variables  
and creates the database on your database server. It's typically the first  
command you run when setting up a new project. The `--env` option allows  
creating databases for different environments (dev, test, prod).  

### Dropping a Database

Removing an existing database completely.  

```bash
# Drop the database (requires confirmation)
php bin/console doctrine:database:drop

# Force drop without confirmation
php bin/console doctrine:database:drop --force

# Drop test database
php bin/console doctrine:database:drop --env=test --force
```

The `drop` command completely removes the database and all its data. The  
`--force` flag bypasses the confirmation prompt, useful for automated  
scripts. Use with caution in production environments.  

## Schema Management

### Creating Database Schema

Generating database tables from entity definitions.  

```php
<?php

namespace App\Entity;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'products')]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: Types::INTEGER)]
    private ?int $id = null;

    #[ORM\Column(type: Types::STRING, length: 255)]
    private ?string $name = null;

    #[ORM\Column(type: Types::DECIMAL, precision: 10, scale: 2)]
    private ?string $price = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE)]
    private ?\DateTimeInterface $createdAt = null;

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

    public function getCreatedAt(): ?\DateTimeInterface
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeInterface $createdAt): self
    {
        $this->createdAt = $createdAt;
        return $this;
    }
}
```

```bash
# Create all database tables from entities
php bin/console doctrine:schema:create

# Create schema with SQL output
php bin/console doctrine:schema:create --dump-sql
```

The `schema:create` command generates all necessary tables, indexes, and  
foreign key constraints based on your entity definitions. The `--dump-sql`  
option shows the SQL statements without executing them, useful for reviewing  
changes before applying them.  

### Updating Database Schema

Synchronizing database schema with entity changes.  

```php
<?php

namespace App\Entity;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'products')]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: Types::INTEGER)]
    private ?int $id = null;

    #[ORM\Column(type: Types::STRING, length: 255)]
    private ?string $name = null;

    #[ORM\Column(type: Types::DECIMAL, precision: 10, scale: 2)]
    private ?string $price = null;

    // New field added
    #[ORM\Column(type: Types::INTEGER)]
    private ?int $stock = 0;

    // New field added
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $description = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE)]
    private ?\DateTimeInterface $createdAt = null;

    // Getters and setters...
}
```

```bash
# Show SQL for schema update
php bin/console doctrine:schema:update --dump-sql

# Execute schema update
php bin/console doctrine:schema:update --force

# Complete schema update (safer for production)
php bin/console doctrine:schema:update --complete --dump-sql
```

The `schema:update` command detects differences between your entities and  
the current database schema. It generates ALTER TABLE statements to add new  
columns, modify existing ones, or add indexes. Always use `--dump-sql` first  
to review changes. In production, use migrations instead of direct schema  
updates.  

### Dropping Database Schema

Removing all database tables.  

```bash
# Drop all tables (requires confirmation)
php bin/console doctrine:schema:drop

# Force drop all tables
php bin/console doctrine:schema:drop --force

# Drop and show SQL
php bin/console doctrine:schema:drop --dump-sql --force

# Full reset: drop and recreate
php bin/console doctrine:schema:drop --force --full-database
```

The `schema:drop` command removes all tables managed by Doctrine. The  
`--full-database` option also removes tables not managed by Doctrine,  
effectively emptying the entire database. Useful for development  
environments when starting fresh.  

### Validating Schema

Checking entity mappings and database consistency.  

```bash
# Validate mapping and database schema
php bin/console doctrine:schema:validate

# Validate in production environment
php bin/console doctrine:schema:validate --env=prod
```

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Doctrine\DBAL\Types\Types;

#[ORM\Entity]
#[ORM\Table(name: 'users')]
#[ORM\Index(name: 'email_idx', columns: ['email'])]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: Types::INTEGER)]
    private ?int $id = null;

    #[ORM\Column(type: Types::STRING, length: 180, unique: true)]
    private ?string $email = null;

    #[ORM\Column(type: Types::STRING, length: 255)]
    private ?string $name = null;

    #[ORM\Column(type: Types::JSON)]
    private array $roles = [];

    // Getters and setters...
}
```

The `validate` command checks two things: whether entity mappings are valid  
(correct syntax, proper annotations) and whether the database schema matches  
entity definitions. It reports any mismatches or configuration errors. Run  
this regularly during development to catch issues early.  

## Database Migrations

### Generating Migration from Schema Diff

Creating migration files based on entity changes.  

```php
<?php

namespace App\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'categories')]
class Category
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: Types::INTEGER)]
    private ?int $id = null;

    #[ORM\Column(type: Types::STRING, length: 100)]
    private ?string $name = null;

    #[ORM\OneToMany(targetEntity: Product::class, mappedBy: 'category')]
    private Collection $products;

    public function __construct()
    {
        $this->products = new ArrayCollection();
    }

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
}
```

```bash
# Generate migration from current entity changes
php bin/console make:migration

# Alternative: generate migration using migrations:diff
php bin/console doctrine:migrations:diff

# Preview migration SQL without creating file
php bin/console doctrine:migrations:diff --formatted
```

These commands compare your entity metadata with the current database schema  
and generate a migration file containing the necessary SQL statements to  
synchronize them. The `make:migration` command is from MakerBundle and  
provides a more user-friendly experience. Always review generated migrations  
before executing them.  

### Executing Migrations

Running migration files to update the database.  

```php
<?php

// Example generated migration file
// migrations/Version20240101120000.php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20240101120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Add category table and relationship to products';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('CREATE TABLE categories (
            id INT AUTO_INCREMENT NOT NULL, 
            name VARCHAR(100) NOT NULL, 
            PRIMARY KEY(id)
        ) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci ENGINE = InnoDB');
        
        $this->addSql('ALTER TABLE products ADD category_id INT DEFAULT NULL');
        $this->addSql('ALTER TABLE products ADD CONSTRAINT FK_PRODUCTS_CATEGORY 
            FOREIGN KEY (category_id) REFERENCES categories (id)');
        $this->addSql('CREATE INDEX IDX_CATEGORY ON products (category_id)');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('ALTER TABLE products DROP FOREIGN KEY FK_PRODUCTS_CATEGORY');
        $this->addSql('DROP INDEX IDX_CATEGORY ON products');
        $this->addSql('ALTER TABLE products DROP category_id');
        $this->addSql('DROP TABLE categories');
    }
}
```

```bash
# Execute all pending migrations
php bin/console doctrine:migrations:migrate

# Migrate without confirmation
php bin/console doctrine:migrations:migrate --no-interaction

# Migrate to specific version
php bin/console doctrine:migrations:migrate Version20240101120000

# Dry run - show SQL without executing
php bin/console doctrine:migrations:migrate --dry-run

# Execute single migration up
php bin/console doctrine:migrations:execute Version20240101120000 --up

# Execute single migration down
php bin/console doctrine:migrations:execute Version20240101120000 --down
```

The `migrate` command executes all migrations that haven't been run yet. It  
tracks executed migrations in a special table (usually `doctrine_migration_  
versions`). The `--dry-run` option shows what would be executed without  
making changes. Use `execute` for running individual migrations.  

### Checking Migration Status

Viewing the state of database migrations.  

```bash
# Show detailed migration status
php bin/console doctrine:migrations:status

# Check if database is up to date
php bin/console doctrine:migrations:up-to-date

# Show current migration version
php bin/console doctrine:migrations:current

# Show latest available migration
php bin/console doctrine:migrations:latest

# List all available migrations
php bin/console doctrine:migrations:list
```

The `status` command provides comprehensive information about migrations:  
total number of migrations, executed migrations, pending migrations, and  
database configuration. The `up-to-date` command returns exit code 0 if all  
migrations are executed, useful for CI/CD pipelines.  

### Generating Blank Migration

Creating an empty migration for custom SQL.  

```bash
# Generate blank migration file
php bin/console doctrine:migrations:generate
```

```php
<?php

// Manually edit the generated migration
declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20240101130000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Add custom indexes and optimize table structure';
    }

    public function up(Schema $schema): void
    {
        // Custom SQL for performance optimization
        $this->addSql('CREATE INDEX products_name_price_idx 
            ON products (name, price)');
        $this->addSql('CREATE FULLTEXT INDEX products_description_fulltext 
            ON products (description)');
        
        // Add stored procedure
        $this->addSql('CREATE PROCEDURE update_product_stock(
            IN product_id INT, 
            IN quantity INT
        )
        BEGIN
            UPDATE products SET stock = stock + quantity WHERE id = product_id;
        END');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP INDEX products_name_price_idx ON products');
        $this->addSql('DROP INDEX products_description_fulltext ON products');
        $this->addSql('DROP PROCEDURE IF EXISTS update_product_stock');
    }
}
```

Use blank migrations for custom SQL that can't be generated automatically,  
such as stored procedures, views, triggers, or complex data transformations.  
Always implement both `up()` and `down()` methods to ensure migrations are  
reversible.  

### Rolling Back Migrations

Reverting database changes to previous versions.  

```bash
# Rollback to previous version
php bin/console doctrine:migrations:migrate prev

# Rollback to first migration
php bin/console doctrine:migrations:migrate first

# Rollback all migrations
php bin/console doctrine:migrations:migrate first --no-interaction

# Execute specific migration down
php bin/console doctrine:migrations:execute Version20240101120000 --down
```

Rolling back migrations executes the `down()` method of migration classes.  
The `prev` alias rolls back one migration, while `first` rolls back to the  
initial state. Use these commands carefully in production environments and  
always backup data first.  

## Entity and Mapping Information

### Viewing Mapped Entities

Listing all entities known to Doctrine.  

```bash
# Show all mapped entities
php bin/console doctrine:mapping:info

# Detailed output
php bin/console doctrine:mapping:info -v
```

```php
<?php

namespace App\Entity;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'orders')]
class Order
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: Types::INTEGER)]
    private ?int $id = null;

    #[ORM\Column(type: Types::STRING, length: 50)]
    private ?string $orderNumber = null;

    #[ORM\Column(type: Types::DECIMAL, precision: 10, scale: 2)]
    private ?string $total = null;

    #[ORM\Column(type: Types::STRING, length: 20)]
    private ?string $status = null;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false)]
    private ?User $customer = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE)]
    private ?\DateTimeInterface $createdAt = null;

    // Getters and setters...
}
```

The `mapping:info` command displays all entities that Doctrine is aware of,  
their fully qualified class names, and any configuration issues. It's useful  
for verifying that new entities are properly registered and mapped. The  
verbose flag shows additional details about entity configuration.  

## Query Execution

### Executing SQL Queries

Running raw SQL from the command line.  

```bash
# Execute SELECT query
php bin/console doctrine:query:sql "SELECT * FROM products WHERE price > 100"

# Execute INSERT query
php bin/console doctrine:query:sql "INSERT INTO categories (name) VALUES ('Electronics')"

# Execute UPDATE query
php bin/console doctrine:query:sql "UPDATE products SET stock = stock + 10 WHERE id = 1"

# Execute DELETE query
php bin/console doctrine:query:sql "DELETE FROM products WHERE stock = 0"

# Execute with formatted output
php bin/console doctrine:query:sql "SELECT id, name, price FROM products" --format=json
```

```php
<?php

namespace App\Command;

use Doctrine\DBAL\Connection;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:products:report')]
class ProductReportCommand extends Command
{
    public function __construct(
        private Connection $connection
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        // Execute raw SQL for complex reporting
        $sql = 'SELECT 
                    c.name as category,
                    COUNT(p.id) as product_count,
                    AVG(p.price) as avg_price,
                    SUM(p.stock) as total_stock
                FROM products p
                JOIN categories c ON p.category_id = c.id
                GROUP BY c.id, c.name
                ORDER BY product_count DESC';

        $results = $this->connection->fetchAllAssociative($sql);

        $io->table(
            ['Category', 'Products', 'Avg Price', 'Total Stock'],
            array_map(fn($row) => [
                $row['category'],
                $row['product_count'],
                '$' . number_format($row['avg_price'], 2),
                $row['total_stock']
            ], $results)
        );

        return Command::SUCCESS;
    }
}
```

The `query:sql` command executes arbitrary SQL against your configured  
database. It's useful for quick data inspection, bulk updates, or one-off  
data migrations. Use with caution as it bypasses entity validation and  
lifecycle events.  

### Executing DQL Queries

Running Doctrine Query Language queries from command line.  

```bash
# Execute DQL SELECT query
php bin/console doctrine:query:dql "SELECT p FROM App\Entity\Product p WHERE p.price > 100"

# DQL with JOIN
php bin/console doctrine:query:dql "SELECT p, c FROM App\Entity\Product p JOIN p.category c"

# DQL with aggregation
php bin/console doctrine:query:dql "SELECT COUNT(p.id) FROM App\Entity\Product p WHERE p.stock > 0"

# DQL UPDATE query
php bin/console doctrine:query:dql "UPDATE App\Entity\Product p SET p.stock = 0 WHERE p.stock < 0"

# DQL DELETE query
php bin/console doctrine:query:dql "DELETE FROM App\Entity\Product p WHERE p.createdAt < '2024-01-01'"
```

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

    public function findLowStockProducts(int $threshold = 10): array
    {
        // Using DQL for complex queries
        $dql = 'SELECT p, c 
                FROM App\Entity\Product p
                JOIN p.category c
                WHERE p.stock <= :threshold
                ORDER BY p.stock ASC, p.name ASC';

        return $this->getEntityManager()
            ->createQuery($dql)
            ->setParameter('threshold', $threshold)
            ->getResult();
    }

    public function findTopSellingProducts(int $limit = 10): array
    {
        $dql = 'SELECT p, SUM(oi.quantity) as total_sold
                FROM App\Entity\Product p
                JOIN p.orderItems oi
                JOIN oi.order o
                WHERE o.status = :status
                GROUP BY p.id
                ORDER BY total_sold DESC';

        return $this->getEntityManager()
            ->createQuery($dql)
            ->setParameter('status', 'completed')
            ->setMaxResults($limit)
            ->getResult();
    }

    public function updatePricesByCategory(int $categoryId, float $percentage): int
    {
        $dql = 'UPDATE App\Entity\Product p
                SET p.price = p.price * :multiplier
                WHERE p.category = :category';

        return $this->getEntityManager()
            ->createQuery($dql)
            ->setParameter('multiplier', 1 + ($percentage / 100))
            ->setParameter('category', $categoryId)
            ->execute();
    }
}
```

DQL (Doctrine Query Language) is an object-oriented query language similar  
to SQL but operates on entities instead of tables. It supports SELECT,  
UPDATE, and DELETE operations. DQL queries return entity objects with  
proper hydration, making them preferable to raw SQL for most use cases.  

## Cache Management

### Clearing Metadata Cache

Removing cached entity mapping information.  

```bash
# Clear metadata cache
php bin/console doctrine:cache:clear-metadata

# Clear metadata for specific entity manager
php bin/console doctrine:cache:clear-metadata --em=default

# Clear in production environment
php bin/console doctrine:cache:clear-metadata --env=prod
```

```php
<?php

// config/packages/doctrine.yaml
doctrine:
    orm:
        auto_generate_proxy_classes: false
        enable_lazy_ghost_objects: true
        metadata_cache_driver:
            type: pool
            pool: doctrine.system_cache_pool
        query_cache_driver:
            type: pool
            pool: doctrine.query_cache_pool
        result_cache_driver:
            type: pool
            pool: doctrine.result_cache_pool

framework:
    cache:
        pools:
            doctrine.system_cache_pool:
                adapter: cache.adapter.redis
                provider: redis://localhost
            doctrine.query_cache_pool:
                adapter: cache.adapter.redis
                provider: redis://localhost
            doctrine.result_cache_pool:
                adapter: cache.adapter.redis
                provider: redis://localhost
```

Metadata cache stores entity mapping information. Clearing it is necessary  
after modifying entity annotations or attributes. In production, metadata  
caching significantly improves performance by avoiding repeated parsing of  
entity metadata.  

### Clearing Query Cache

Removing cached query parsing results.  

```bash
# Clear query cache
php bin/console doctrine:cache:clear-query

# Clear for specific entity manager
php bin/console doctrine:cache:clear-query --em=default

# Clear in production
php bin/console doctrine:cache:clear-query --env=prod
```

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

    public function findActiveProducts(): array
    {
        $query = $this->createQueryBuilder('p')
            ->where('p.stock > 0')
            ->orderBy('p.name', 'ASC')
            ->getQuery();

        // Enable query cache for this specific query
        $query->useQueryCache(true);
        $query->setQueryCacheLifetime(3600); // 1 hour

        return $query->getResult();
    }

    public function getCategoryStatistics(int $categoryId): array
    {
        $dql = 'SELECT 
                    COUNT(p.id) as product_count,
                    AVG(p.price) as avg_price,
                    MIN(p.price) as min_price,
                    MAX(p.price) as max_price
                FROM App\Entity\Product p
                WHERE p.category = :category';

        $query = $this->getEntityManager()
            ->createQuery($dql)
            ->setParameter('category', $categoryId);

        // Cache the parsed query
        $query->useQueryCache(true);

        return $query->getSingleResult();
    }
}
```

Query cache stores parsed DQL queries. It improves performance by avoiding  
repeated parsing of the same queries. Clear this cache when deploying new  
code that modifies queries or when troubleshooting query-related issues.  

### Clearing Result Cache

Removing cached query results.  

```bash
# Clear result cache
php bin/console doctrine:cache:clear-result

# Clear for specific entity manager
php bin/console doctrine:cache:clear-result --em=default

# Clear in production
php bin/console doctrine:cache:clear-result --env=prod
```

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

    public function findAllWithCaching(): array
    {
        $query = $this->createQueryBuilder('c')
            ->orderBy('c.name', 'ASC')
            ->getQuery();

        // Enable result cache for query results
        $query->useResultCache(true);
        $query->setResultCacheLifetime(3600); // Cache for 1 hour
        $query->setResultCacheId('all_categories');

        return $query->getResult();
    }

    public function findPopularCategories(): array
    {
        $dql = 'SELECT c, COUNT(p.id) as product_count
                FROM App\Entity\Category c
                JOIN c.products p
                GROUP BY c.id
                HAVING product_count > 10
                ORDER BY product_count DESC';

        $query = $this->getEntityManager()
            ->createQuery($dql);

        // Cache expensive query results
        $query->useResultCache(true);
        $query->setResultCacheLifetime(1800); // 30 minutes
        $query->setResultCacheId('popular_categories');

        return $query->getResult();
    }
}
```

Result cache stores the actual results of queries. It's the most impactful  
cache for performance as it eliminates database round trips entirely. Use  
result caching for expensive queries that don't change frequently. Always  
set a cache ID for important queries to allow selective cache invalidation.  

## Data Fixtures

### Loading Test Data

Populating database with sample data for development and testing.  

```bash
# Install doctrine/data-fixtures first
composer require --dev doctrine/doctrine-fixtures-bundle
```

```php
<?php

namespace App\DataFixtures;

use App\Entity\Category;
use App\Entity\Product;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;

class AppFixtures extends Fixture
{
    public function load(ObjectManager $manager): void
    {
        // Create categories
        $electronics = new Category();
        $electronics->setName('Electronics');
        $manager->persist($electronics);

        $books = new Category();
        $books->setName('Books');
        $manager->persist($books);

        $clothing = new Category();
        $clothing->setName('Clothing');
        $manager->persist($clothing);

        // Create products
        $products = [
            ['Laptop', '999.99', 15, $electronics],
            ['Smartphone', '699.99', 25, $electronics],
            ['Headphones', '149.99', 50, $electronics],
            ['Programming Book', '49.99', 100, $books],
            ['Fiction Novel', '19.99', 75, $books],
            ['T-Shirt', '24.99', 200, $clothing],
            ['Jeans', '59.99', 80, $clothing],
        ];

        foreach ($products as [$name, $price, $stock, $category]) {
            $product = new Product();
            $product->setName($name);
            $product->setPrice($price);
            $product->setStock($stock);
            $product->setCategory($category);
            $product->setCreatedAt(new \DateTime());
            $manager->persist($product);
        }

        $manager->flush();
    }
}
```

```bash
# Load fixtures into database
php bin/console doctrine:fixtures:load

# Load without confirmation
php bin/console doctrine:fixtures:load --no-interaction

# Append fixtures without purging
php bin/console doctrine:fixtures:load --append

# Load specific fixture group
php bin/console doctrine:fixtures:load --group=dev
```

Fixtures provide a way to load predefined data into your database. They're  
essential for development, testing, and demo environments. The default  
behavior purges the database before loading, ensuring a clean state. Use  
`--append` to add data without removing existing records.  

### Creating Fixture Groups

Organizing fixtures into logical groups for selective loading.  

```php
<?php

namespace App\DataFixtures;

use App\Entity\User;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Bundle\FixturesBundle\FixtureGroupInterface;
use Doctrine\Persistence\ObjectManager;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class UserFixtures extends Fixture implements FixtureGroupInterface
{
    public function __construct(
        private UserPasswordHasherInterface $passwordHasher
    ) {
    }

    public static function getGroups(): array
    {
        return ['dev', 'test'];
    }

    public function load(ObjectManager $manager): void
    {
        $users = [
            ['admin@example.com', 'Admin User', ['ROLE_ADMIN']],
            ['user@example.com', 'Regular User', ['ROLE_USER']],
            ['editor@example.com', 'Editor User', ['ROLE_EDITOR']],
        ];

        foreach ($users as [$email, $name, $roles]) {
            $user = new User();
            $user->setEmail($email);
            $user->setName($name);
            $user->setRoles($roles);
            $user->setPassword(
                $this->passwordHasher->hashPassword($user, 'password123')
            );
            $manager->persist($user);
        }

        $manager->flush();
    }
}
```

```php
<?php

namespace App\DataFixtures;

use App\Entity\Product;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Bundle\FixturesBundle\FixtureGroupInterface;
use Doctrine\Persistence\ObjectManager;

class ProductionFixtures extends Fixture implements FixtureGroupInterface
{
    public static function getGroups(): array
    {
        return ['production'];
    }

    public function load(ObjectManager $manager): void
    {
        // Load only essential data for production
        $essentialCategories = ['Uncategorized', 'Featured', 'Sale'];
        
        foreach ($essentialCategories as $categoryName) {
            $category = new Category();
            $category->setName($categoryName);
            $manager->persist($category);
        }

        $manager->flush();
    }
}
```

```bash
# Load only development fixtures
php bin/console doctrine:fixtures:load --group=dev

# Load only test fixtures
php bin/console doctrine:fixtures:load --group=test

# Load only production fixtures
php bin/console doctrine:fixtures:load --group=production
```

Fixture groups allow organizing fixtures by environment or purpose. This  
enables loading different datasets for development, testing, and production.  
Implementing `FixtureGroupInterface` makes fixtures opt-in rather than  
loading by default.  

### Fixture Dependencies

Controlling the order of fixture execution.  

```php
<?php

namespace App\DataFixtures;

use App\Entity\Category;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;

class CategoryFixtures extends Fixture
{
    public const ELECTRONICS_REFERENCE = 'category-electronics';
    public const BOOKS_REFERENCE = 'category-books';

    public function load(ObjectManager $manager): void
    {
        $electronics = new Category();
        $electronics->setName('Electronics');
        $manager->persist($electronics);
        $this->addReference(self::ELECTRONICS_REFERENCE, $electronics);

        $books = new Category();
        $books->setName('Books');
        $manager->persist($books);
        $this->addReference(self::BOOKS_REFERENCE, $books);

        $manager->flush();
    }
}
```

```php
<?php

namespace App\DataFixtures;

use App\Entity\Product;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Common\DataFixtures\DependentFixtureInterface;
use Doctrine\Persistence\ObjectManager;

class ProductFixtures extends Fixture implements DependentFixtureInterface
{
    public function load(ObjectManager $manager): void
    {
        $electronics = $this->getReference(CategoryFixtures::ELECTRONICS_REFERENCE);
        $books = $this->getReference(CategoryFixtures::BOOKS_REFERENCE);

        $products = [
            ['Laptop Pro', '1299.99', 10, $electronics],
            ['Wireless Mouse', '29.99', 100, $electronics],
            ['PHP Design Patterns', '44.99', 50, $books],
            ['Clean Code', '39.99', 75, $books],
        ];

        foreach ($products as [$name, $price, $stock, $category]) {
            $product = new Product();
            $product->setName($name);
            $product->setPrice($price);
            $product->setStock($stock);
            $product->setCategory($category);
            $product->setCreatedAt(new \DateTime());
            $manager->persist($product);
        }

        $manager->flush();
    }

    public function getDependencies(): array
    {
        return [
            CategoryFixtures::class,
        ];
    }
}
```

```bash
# Load fixtures - dependencies are handled automatically
php bin/console doctrine:fixtures:load
```

Dependencies ensure fixtures are loaded in the correct order. Use references  
to share data between fixtures. The `getDependencies()` method specifies  
which fixtures must be loaded first. This is essential when fixtures create  
related entities.  

## Advanced Migration Techniques

### Custom Migration with Data Transformation

Implementing complex data migrations with business logic.  

```php
<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20240101140000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Split full_name into first_name and last_name';
    }

    public function up(Schema $schema): void
    {
        // Add new columns
        $this->addSql('ALTER TABLE users ADD first_name VARCHAR(100) DEFAULT NULL');
        $this->addSql('ALTER TABLE users ADD last_name VARCHAR(100) DEFAULT NULL');

        // Migrate data - this is executed after schema changes
        $this->connection->executeQuery(
            'UPDATE users SET 
                first_name = SUBSTRING_INDEX(full_name, " ", 1),
                last_name = SUBSTRING_INDEX(full_name, " ", -1)
            WHERE full_name IS NOT NULL'
        );

        // Make columns non-nullable after migration
        $this->addSql('ALTER TABLE users MODIFY first_name VARCHAR(100) NOT NULL');
        $this->addSql('ALTER TABLE users MODIFY last_name VARCHAR(100) NOT NULL');

        // Drop old column
        $this->addSql('ALTER TABLE users DROP full_name');
    }

    public function down(Schema $schema): void
    {
        // Add back old column
        $this->addSql('ALTER TABLE users ADD full_name VARCHAR(255) DEFAULT NULL');

        // Restore data
        $this->connection->executeQuery(
            'UPDATE users SET full_name = CONCAT(first_name, " ", last_name)'
        );

        $this->addSql('ALTER TABLE users MODIFY full_name VARCHAR(255) NOT NULL');
        $this->addSql('ALTER TABLE users DROP first_name, DROP last_name');
    }
}
```

This migration demonstrates data transformation during schema changes. It  
safely splits a name field by first adding nullable columns, migrating data,  
then making columns required. The `down()` method reverses all changes,  
ensuring the migration is fully reversible.  

### Migration Version Management

Manually managing migration version tracking.  

```bash
# Mark migration as executed without running it
php bin/console doctrine:migrations:version Version20240101120000 --add

# Mark migration as not executed
php bin/console doctrine:migrations:version Version20240101120000 --delete

# Mark all migrations as executed
php bin/console doctrine:migrations:version --add --all

# Mark all migrations as not executed
php bin/console doctrine:migrations:version --delete --all

# Synchronize metadata storage
php bin/console doctrine:migrations:sync-metadata-storage
```

```php
<?php

namespace App\Command;

use Doctrine\Migrations\DependencyFactory;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:migrations:check')]
class MigrationsCheckCommand extends Command
{
    public function __construct(
        private DependencyFactory $dependencyFactory
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $planCalculator = $this->dependencyFactory->getMigrationPlanCalculator();
        $plan = $planCalculator->getPlanForVersions(
            $this->dependencyFactory->getVersionAliasResolver()->resolveVersionAlias('latest')
        );

        $io->title('Migration Status Check');

        if (count($plan) === 0) {
            $io->success('Database is up to date!');
            return Command::SUCCESS;
        }

        $io->warning(sprintf('Found %d pending migration(s)', count($plan)));

        $migrations = [];
        foreach ($plan as $item) {
            $migrations[] = [
                (string) $item->getVersion(),
                $item->getMigration()->getDescription(),
            ];
        }

        $io->table(['Version', 'Description'], $migrations);

        return Command::FAILURE;
    }
}
```

Version management commands are useful when synchronizing databases across  
environments or recovering from failed migrations. Use `--add` to mark  
migrations as executed on databases that were updated manually. The  
`sync-metadata-storage` command ensures the migrations table schema matches  
the expected structure.  

## Troubleshooting and Optimization

### Debugging Entity Hydration

Understanding how Doctrine converts database rows to objects.  

```php
<?php

namespace App\Command;

use App\Entity\Product;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:debug:hydration')]
class DebugHydrationCommand extends Command
{
    public function __construct(
        private EntityManagerInterface $entityManager
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        // Enable SQL logging
        $config = $this->entityManager->getConnection()->getConfiguration();
        $logger = new \Doctrine\DBAL\Logging\DebugStack();
        $config->setSQLLogger($logger);

        // Fetch products
        $products = $this->entityManager
            ->getRepository(Product::class)
            ->findAll();

        $io->title('SQL Queries Executed');

        foreach ($logger->queries as $query) {
            $io->section(sprintf('Query (%.2f ms)', $query['executionMS'] * 1000));
            $io->writeln($query['sql']);
            if ($query['params']) {
                $io->writeln('Parameters: ' . json_encode($query['params']));
            }
            $io->newLine();
        }

        $io->success(sprintf('Loaded %d products with %d queries', 
            count($products), 
            count($logger->queries)
        ));

        return Command::SUCCESS;
    }
}
```

```bash
# Use built-in debugging commands
php bin/console doctrine:query:sql "SELECT * FROM products LIMIT 1" -v

# Check query count and performance
php bin/console debug:container doctrine --show-arguments
```

Hydration is the process of converting database result sets into entity  
objects. Understanding hydration helps identify performance issues like the  
N+1 query problem. The DebugStack logger captures all SQL queries executed  
during a request.  

### Performance Profiling

Analyzing and optimizing database performance.  

```php
<?php

namespace App\Repository;

use App\Entity\Product;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\Query;
use Doctrine\Persistence\ManagerRegistry;

class ProductRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Product::class);
    }

    public function findWithCategoryBad(): array
    {
        // BAD: N+1 query problem
        // This loads products, then for each product makes separate query for category
        return $this->findAll();
    }

    public function findWithCategoryGood(): array
    {
        // GOOD: Single query with JOIN
        return $this->createQueryBuilder('p')
            ->leftJoin('p.category', 'c')
            ->addSelect('c')
            ->getQuery()
            ->getResult();
    }

    public function findForExport(): array
    {
        // Optimize for large result sets
        return $this->createQueryBuilder('p')
            ->select('p', 'c')
            ->leftJoin('p.category', 'c')
            ->getQuery()
            ->setHint(Query::HINT_FORCE_PARTIAL_LOAD, true)
            ->getResult();
    }

    public function streamLargeDataset(): iterable
    {
        // Stream results to avoid memory issues
        $query = $this->createQueryBuilder('p')
            ->getQuery();

        return $query->toIterable();
    }

    public function countProducts(): int
    {
        return $this->createQueryBuilder('p')
            ->select('COUNT(p.id)')
            ->getQuery()
            ->getSingleScalarResult();
    }
}
```

```bash
# Profile queries in production
php bin/console debug:config doctrine

# Check connection and driver info
php bin/console doctrine:query:sql "SELECT VERSION()"
```

Performance profiling identifies slow queries and optimization opportunities.  
Always use JOINs with addSelect() to prevent N+1 problems. Use streaming  
for large datasets to avoid memory exhaustion. Use COUNT queries instead of  
loading entities when you only need counts.  

## Conclusion

Doctrine console commands provide powerful tools for managing database  
schemas, executing migrations, loading fixtures, and debugging database  
interactions. Understanding these commands is essential for effective  
Symfony development.  

Key takeaways:  

**Use migrations in production**: Always use migrations instead of  
`schema:update` for production deployments. Migrations are versioned,  
reversible, and can include data transformations.  

**Validate regularly**: Run `doctrine:schema:validate` frequently during  
development to catch configuration issues early.  

**Cache management**: Clear caches after entity changes in production.  
Proper cache configuration significantly improves performance.  

**Fixtures for testing**: Use fixtures to create consistent test data.  
Organize fixtures with groups and dependencies for maintainability.  

**Profile and optimize**: Use query logging and profiling tools to identify  
performance bottlenecks. Optimize queries with JOINs and proper indexing.  

**Raw SQL when needed**: Use `doctrine:query:sql` for one-off tasks and  
`doctrine:query:dql` for object-oriented queries during development.  

**Backup before migrations**: Always backup production databases before  
running migrations, especially those that modify or delete data.  

The Doctrine console commands ecosystem provides a complete toolkit for  
database management throughout the application lifecycle, from initial  
development through testing and production deployment.  
