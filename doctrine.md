
# Doctrine PHP Tutorial

This comprehensive tutorial covers Doctrine ORM with 20 practical examples,  
progressing from basic concepts to advanced features.  

Doctrine is a set of PHP libraries primarily focused on providing persistence  
services in PHP. Its main projects are an object-relational mapper (ORM) and  
the database abstraction layer (DBAL). Doctrine is an open source project  
made available for free under the MIT license.  

## Installation

First, create a new project and install Doctrine:  

```bash
mkdir doctrine-tutorial
cd doctrine-tutorial
composer init
composer require doctrine/orm
composer require symfony/var-dumper
```

Create the basic directory structure:  

```bash
mkdir -p src/Entity
mkdir config
```

## Project Setup

Create a `composer.json` file:  

```json
{
    "require": {
        "doctrine/orm": "^3.0",
        "symfony/var-dumper": "^7.0"
    },
    "autoload": {
        "psr-4": {
            "App\\": "src/"
        }
    },
    "require-dev": {
        "doctrine/dbal": "^4.0"
    }
}
```

Create a bootstrap configuration file:  

**config/bootstrap.php**

```php
<?php

use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;

require_once __DIR__ . '/../vendor/autoload.php';

$paths = [__DIR__ . '/../src/Entity'];
$isDevMode = true;

$config = ORMSetup::createAttributeMetadataConfiguration(
    $paths, 
    $isDevMode
);

$connectionParams = [
    'driver'   => 'pdo_sqlite',
    'path'     => __DIR__ . '/../database.sqlite',
];

$connection = DriverManager::getConnection($connectionParams);
$entityManager = new EntityManager($connection, $config);

return $entityManager;
```

This bootstrap file sets up Doctrine with SQLite database for simplicity.  
In production, you would typically use MySQL or PostgreSQL.  

## Basic Entity

Create your first entity class:  

**src/Entity/User.php**

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'users')]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private int $id;

    #[ORM\Column(type: 'string', length: 255)]
    private string $name;

    #[ORM\Column(type: 'string', length: 255)]
    private string $email;

    public function getId(): int
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): void
    {
        $this->email = $email;
    }
}
```

This entity uses PHP 8.4 attributes instead of annotations for mapping.  
The #[ORM\Entity] attribute marks this class as a Doctrine entity.  

## Database Schema Creation

Create a script to generate the database schema:  

**bin/create-schema.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

$tool = new \Doctrine\ORM\Tools\SchemaTool($entityManager);
$classes = $entityManager->getMetadataFactory()->getAllMetadata();

$tool->createSchema($classes);

echo "Database schema created successfully!\n";
```

Run this script to create your database tables:  

```bash
php bin/create-schema.php
```

## Creating and Persisting Entities

**examples/01-basic-persist.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\User;

$user = new User();
$user->setName('John Doe');
$user->setEmail('john@example.com');

$entityManager->persist($user);
$entityManager->flush();

echo "User created with ID: " . $user->getId() . "\n";
```

This example demonstrates basic entity creation and persistence.  
The persist() method tells Doctrine to manage the entity.  
The flush() method executes the actual SQL INSERT statement.  

## Finding Entities by ID

**examples/02-find-by-id.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\User;

$userId = 1;
$user = $entityManager->find(User::class, $userId);

if ($user === null) {
    echo "User with ID $userId not found.\n";
    exit;
}

echo "Found user: " . $user->getName() . " (" . $user->getEmail() . ")\n";
```

The find() method retrieves an entity by its primary key.  
Returns null if no entity is found with the given ID.  

## Repository Pattern

**examples/03-repository-usage.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\User;

$userRepository = $entityManager->getRepository(User::class);

// Find all users
$users = $userRepository->findAll();
echo "Total users: " . count($users) . "\n";

// Find by specific criteria
$user = $userRepository->findOneBy(['email' => 'john@example.com']);
if ($user) {
    echo "Found user by email: " . $user->getName() . "\n";
}

// Find multiple users by criteria
$users = $userRepository->findBy(['name' => 'John Doe']);
foreach ($users as $user) {
    echo "User: " . $user->getName() . "\n";
}
```

Repositories provide convenient methods for querying entities.  
Each entity has an associated repository for database operations.  

## Entity with More Data Types

**src/Entity/Product.php**

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'products')]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private int $id;

    #[ORM\Column(type: 'string', length: 255)]
    private string $name;

    #[ORM\Column(type: 'text', nullable: true)]
    private ?string $description;

    #[ORM\Column(type: 'decimal', precision: 10, scale: 2)]
    private string $price;

    #[ORM\Column(type: 'boolean')]
    private bool $active = true;

    #[ORM\Column(type: 'datetime')]
    private \DateTime $createdAt;

    public function __construct()
    {
        $this->createdAt = new \DateTime();
    }

    // Getters and setters
    public function getId(): int
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function setDescription(?string $description): void
    {
        $this->description = $description;
    }

    public function getPrice(): string
    {
        return $this->price;
    }

    public function setPrice(string $price): void
    {
        $this->price = $price;
    }

    public function isActive(): bool
    {
        return $this->active;
    }

    public function setActive(bool $active): void
    {
        $this->active = $active;
    }

    public function getCreatedAt(): \DateTime
    {
        return $this->createdAt;
    }
}
```

This entity demonstrates various column types including text, decimal,  
boolean, and datetime. Notice the nullable property for optional fields.  

## Working with Different Data Types

**examples/04-data-types.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;

$product = new Product();
$product->setName('Laptop Computer');
$product->setDescription('High-performance laptop for professionals');
$product->setPrice('1299.99');
$product->setActive(true);

$entityManager->persist($product);
$entityManager->flush();

echo "Product created with ID: " . $product->getId() . "\n";
echo "Created at: " . $product->getCreatedAt()->format('Y-m-d H:i:s') . "\n";
```

## Updating Entities

**examples/05-update-entities.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;

$productId = 1;
$product = $entityManager->find(Product::class, $productId);

if ($product === null) {
    echo "Product not found\n";
    exit;
}

// Update properties
$product->setPrice('1199.99');
$product->setDescription('Updated: Premium laptop with discount');

// No need to call persist() for existing entities
$entityManager->flush();

echo "Product updated successfully\n";
echo "New price: " . $product->getPrice() . "\n";
```

For existing entities, you only need to modify properties and call flush().  
Doctrine automatically tracks changes to managed entities.  

## Removing Entities

**examples/06-remove-entities.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\User;

$userId = 1;
$user = $entityManager->find(User::class, $userId);

if ($user === null) {
    echo "User not found\n";
    exit;
}

$entityManager->remove($user);
$entityManager->flush();

echo "User removed successfully\n";
```

The remove() method marks an entity for deletion.  
The actual DELETE SQL is executed when flush() is called.  

## Query Builder Basics

**examples/07-query-builder.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\User;

$queryBuilder = $entityManager->createQueryBuilder();

$users = $queryBuilder
    ->select('u')
    ->from(User::class, 'u')
    ->where('u.name LIKE :name')
    ->setParameter('name', '%John%')
    ->orderBy('u.name', 'ASC')
    ->getQuery()
    ->getResult();

echo "Found " . count($users) . " users with 'John' in name:\n";
foreach ($users as $user) {
    echo "- " . $user->getName() . " (" . $user->getEmail() . ")\n";
}
```

QueryBuilder provides a fluent interface for building complex queries.  
Always use parameters to prevent SQL injection attacks.  

## Custom Repository Methods

**src/Repository/UserRepository.php**

```php
<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\ORM\EntityRepository;

class UserRepository extends EntityRepository
{
    public function findByDomain(string $domain): array
    {
        return $this->createQueryBuilder('u')
            ->where('u.email LIKE :domain')
            ->setParameter('domain', '%@' . $domain)
            ->orderBy('u.name', 'ASC')
            ->getQuery()
            ->getResult();
    }

    public function findActiveUsers(): array
    {
        // Assuming we add an 'active' field to User entity
        return $this->createQueryBuilder('u')
            ->where('u.active = :active')
            ->setParameter('active', true)
            ->getQuery()
            ->getResult();
    }

    public function countUsers(): int
    {
        return $this->createQueryBuilder('u')
            ->select('COUNT(u.id)')
            ->getQuery()
            ->getSingleScalarResult();
    }
}
```

Update the User entity to use the custom repository:  

```php
#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'users')]
class User
{
    // ... existing code
}
```

## Using Custom Repository

**examples/08-custom-repository.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\User;
use App\Repository\UserRepository;

/** @var UserRepository $userRepository */
$userRepository = $entityManager->getRepository(User::class);

// Use custom methods
$gmailUsers = $userRepository->findByDomain('gmail.com');
echo "Gmail users: " . count($gmailUsers) . "\n";

$totalUsers = $userRepository->countUsers();
echo "Total users: " . $totalUsers . "\n";
```

Custom repositories encapsulate complex query logic and promote code reuse.  

## One-to-Many Relationships

**src/Entity/Category.php**

```php
<?php

namespace App\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'categories')]
class Category
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private int $id;

    #[ORM\Column(type: 'string', length: 255)]
    private string $name;

    #[ORM\OneToMany(
        mappedBy: 'category', 
        targetEntity: Product::class,
        cascade: ['persist', 'remove']
    )]
    private Collection $products;

    public function __construct()
    {
        $this->products = new ArrayCollection();
    }

    public function getId(): int
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getProducts(): Collection
    {
        return $this->products;
    }

    public function addProduct(Product $product): void
    {
        if (!$this->products->contains($product)) {
            $this->products[] = $product;
            $product->setCategory($this);
        }
    }

    public function removeProduct(Product $product): void
    {
        if ($this->products->removeElement($product)) {
            if ($product->getCategory() === $this) {
                $product->setCategory(null);
            }
        }
    }
}
```

Update the Product entity to include the relationship:  

```php
#[ORM\ManyToOne(targetEntity: Category::class, inversedBy: 'products')]
#[ORM\JoinColumn(name: 'category_id', referencedColumnName: 'id')]
private ?Category $category = null;

public function getCategory(): ?Category
{
    return $this->category;
}

public function setCategory(?Category $category): void
{
    $this->category = $category;
}
```

## Working with Relationships

**examples/09-relationships.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Category;
use App\Entity\Product;

// Create category
$category = new Category();
$category->setName('Electronics');

// Create products
$laptop = new Product();
$laptop->setName('Gaming Laptop');
$laptop->setPrice('1599.99');

$phone = new Product();
$phone->setName('Smartphone');
$phone->setPrice('899.99');

// Establish relationships
$category->addProduct($laptop);
$category->addProduct($phone);

$entityManager->persist($category);
$entityManager->flush();

echo "Category created with " . $category->getProducts()->count() . " products\n";

// Retrieve and display
$retrievedCategory = $entityManager->find(Category::class, $category->getId());
foreach ($retrievedCategory->getProducts() as $product) {
    echo "Product: " . $product->getName() . " - $" . $product->getPrice() . "\n";
}
```

## Many-to-One Queries

**examples/10-many-to-one-queries.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;

// Find products with their categories
$products = $entityManager->createQueryBuilder()
    ->select('p', 'c')
    ->from(Product::class, 'p')
    ->leftJoin('p.category', 'c')
    ->getQuery()
    ->getResult();

foreach ($products as $product) {
    $categoryName = $product->getCategory() ? 
        $product->getCategory()->getName() : 'No Category';
    echo $product->getName() . " - Category: " . $categoryName . "\n";
}
```

The leftJoin ensures we fetch products even if they don't have a category.  
Selecting both 'p' and 'c' prevents additional queries (N+1 problem).  

## Many-to-Many Relationships

**src/Entity/Tag.php**

```php
<?php

namespace App\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'tags')]
class Tag
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private int $id;

    #[ORM\Column(type: 'string', length: 100)]
    private string $name;

    #[ORM\ManyToMany(
        targetEntity: Product::class, 
        mappedBy: 'tags'
    )]
    private Collection $products;

    public function __construct()
    {
        $this->products = new ArrayCollection();
    }

    public function getId(): int
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getProducts(): Collection
    {
        return $this->products;
    }
}
```

Update Product entity for many-to-many:  

```php
#[ORM\ManyToMany(targetEntity: Tag::class, inversedBy: 'products')]
#[ORM\JoinTable(name: 'product_tags')]
private Collection $tags;

public function __construct()
{
    $this->createdAt = new \DateTime();
    $this->tags = new ArrayCollection();
}

public function getTags(): Collection
{
    return $this->tags;
}

public function addTag(Tag $tag): void
{
    if (!$this->tags->contains($tag)) {
        $this->tags[] = $tag;
    }
}

public function removeTag(Tag $tag): void
{
    $this->tags->removeElement($tag);
}
```

## Working with Many-to-Many

**examples/11-many-to-many.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;
use App\Entity\Tag;

// Create tags
$newTag = new Tag();
$newTag->setName('New');

$saleTag = new Tag();
$saleTag->setName('On Sale');

$featuredTag = new Tag();
$featuredTag->setName('Featured');

// Find a product and add tags
$product = $entityManager->find(Product::class, 1);
if ($product) {
    $product->addTag($newTag);
    $product->addTag($saleTag);
    $product->addTag($featuredTag);

    $entityManager->persist($newTag);
    $entityManager->persist($saleTag);
    $entityManager->persist($featuredTag);
    $entityManager->flush();

    echo "Added " . $product->getTags()->count() . " tags to product\n";
    
    foreach ($product->getTags() as $tag) {
        echo "Tag: " . $tag->getName() . "\n";
    }
}
```

## DQL (Doctrine Query Language)

**examples/12-dql-queries.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;

// Basic DQL query
$dql = "SELECT p FROM App\Entity\Product p WHERE p.price > :price";
$query = $entityManager->createQuery($dql);
$query->setParameter('price', '1000.00');
$products = $query->getResult();

echo "Expensive products (>" . '$1000' . "):\n";
foreach ($products as $product) {
    echo "- " . $product->getName() . ": $" . $product->getPrice() . "\n";
}

// DQL with joins
$dql = "SELECT p, c FROM App\Entity\Product p JOIN p.category c WHERE c.name = :category";
$query = $entityManager->createQuery($dql);
$query->setParameter('category', 'Electronics');
$products = $query->getResult();

echo "\nElectronics products:\n";
foreach ($products as $product) {
    echo "- " . $product->getName() . " (Category: " . 
         $product->getCategory()->getName() . ")\n";
}
```

DQL is similar to SQL but works with entities and their properties.  
It's database-agnostic and provides better performance than simple find methods.  

## Pagination

**examples/13-pagination.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;

$page = 1;
$limit = 5;
$offset = ($page - 1) * $limit;

$queryBuilder = $entityManager->createQueryBuilder();
$products = $queryBuilder
    ->select('p')
    ->from(Product::class, 'p')
    ->orderBy('p.name', 'ASC')
    ->setFirstResult($offset)
    ->setMaxResults($limit)
    ->getQuery()
    ->getResult();

// Get total count for pagination info
$totalQuery = $entityManager->createQueryBuilder()
    ->select('COUNT(p.id)')
    ->from(Product::class, 'p')
    ->getQuery();
$total = $totalQuery->getSingleScalarResult();

$totalPages = ceil($total / $limit);

echo "Page $page of $totalPages (Total: $total products)\n";
echo "Products on this page:\n";

foreach ($products as $product) {
    echo "- " . $product->getName() . "\n";
}
```

## Advanced Query Features

**examples/14-advanced-queries.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;

// Subquery example
$subQuery = $entityManager->createQueryBuilder()
    ->select('AVG(p2.price)')
    ->from(Product::class, 'p2');

$queryBuilder = $entityManager->createQueryBuilder();
$expensiveProducts = $queryBuilder
    ->select('p')
    ->from(Product::class, 'p')
    ->where($queryBuilder->expr()->gt('p.price', '(' . $subQuery->getDQL() . ')'))
    ->getQuery()
    ->getResult();

echo "Products above average price:\n";
foreach ($expensiveProducts as $product) {
    echo "- " . $product->getName() . ": $" . $product->getPrice() . "\n";
}

// Aggregation example
$stats = $entityManager->createQueryBuilder()
    ->select('COUNT(p.id) as total, AVG(p.price) as avgPrice, MAX(p.price) as maxPrice')
    ->from(Product::class, 'p')
    ->where('p.active = :active')
    ->setParameter('active', true)
    ->getQuery()
    ->getSingleResult();

echo "\nProduct Statistics:\n";
echo "Total products: " . $stats['total'] . "\n";
echo "Average price: $" . number_format($stats['avgPrice'], 2) . "\n";
echo "Max price: $" . $stats['maxPrice'] . "\n";
```

## Entity Lifecycle Events

**src/Entity/AuditableEntity.php**

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\MappedSuperclass]
#[ORM\HasLifecycleCallbacks]
abstract class AuditableEntity
{
    #[ORM\Column(type: 'datetime')]
    protected \DateTime $createdAt;

    #[ORM\Column(type: 'datetime')]
    protected \DateTime $updatedAt;

    public function __construct()
    {
        $this->createdAt = new \DateTime();
        $this->updatedAt = new \DateTime();
    }

    #[ORM\PreUpdate]
    public function updateTimestamp(): void
    {
        $this->updatedAt = new \DateTime();
    }

    public function getCreatedAt(): \DateTime
    {
        return $this->createdAt;
    }

    public function getUpdatedAt(): \DateTime
    {
        return $this->updatedAt;
    }
}
```

Update Product to extend AuditableEntity:  

```php
class Product extends AuditableEntity
{
    // Remove the createdAt property and constructor
    // Keep other properties and methods
}
```

## Event Listeners

**examples/15-lifecycle-events.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;

// Create a new product
$product = new Product();
$product->setName('Smart Watch');
$product->setPrice('299.99');

echo "Before persist - Created: " . $product->getCreatedAt()->format('H:i:s') . "\n";
echo "Before persist - Updated: " . $product->getUpdatedAt()->format('H:i:s') . "\n";

$entityManager->persist($product);
$entityManager->flush();

// Wait a moment and update
sleep(1);
$product->setPrice('279.99');
$entityManager->flush();

echo "After update - Created: " . $product->getCreatedAt()->format('H:i:s') . "\n";
echo "After update - Updated: " . $product->getUpdatedAt()->format('H:i:s') . "\n";
```

Lifecycle callbacks automatically execute at specific entity events.  
PreUpdate callback runs before the entity is updated in the database.  

## Inheritance Strategies

**src/Entity/Person.php**

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'persons')]
#[ORM\InheritanceType('SINGLE_TABLE')]
#[ORM\DiscriminatorColumn(name: 'person_type', type: 'string')]
#[ORM\DiscriminatorMap(['customer' => 'Customer', 'employee' => 'Employee'])]
abstract class Person
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    protected int $id;

    #[ORM\Column(type: 'string', length: 255)]
    protected string $name;

    #[ORM\Column(type: 'string', length: 255)]
    protected string $email;

    public function getId(): int
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): void
    {
        $this->email = $email;
    }
}
```

**src/Entity/Customer.php**

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Customer extends Person
{
    #[ORM\Column(type: 'string', length: 100, nullable: true)]
    private ?string $customerNumber = null;

    #[ORM\Column(type: 'decimal', precision: 10, scale: 2)]
    private string $creditLimit = '0.00';

    public function getCustomerNumber(): ?string
    {
        return $this->customerNumber;
    }

    public function setCustomerNumber(?string $customerNumber): void
    {
        $this->customerNumber = $customerNumber;
    }

    public function getCreditLimit(): string
    {
        return $this->creditLimit;
    }

    public function setCreditLimit(string $creditLimit): void
    {
        $this->creditLimit = $creditLimit;
    }
}
```

**src/Entity/Employee.php**

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Employee extends Person
{
    #[ORM\Column(type: 'string', length: 100)]
    private string $department;

    #[ORM\Column(type: 'decimal', precision: 10, scale: 2)]
    private string $salary;

    public function getDepartment(): string
    {
        return $this->department;
    }

    public function setDepartment(string $department): void
    {
        $this->department = $department;
    }

    public function getSalary(): string
    {
        return $this->salary;
    }

    public function setSalary(string $salary): void
    {
        $this->salary = $salary;
    }
}
```

## Working with Inheritance

**examples/16-inheritance.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Customer;
use App\Entity\Employee;
use App\Entity\Person;

// Create a customer
$customer = new Customer();
$customer->setName('Alice Johnson');
$customer->setEmail('alice@example.com');
$customer->setCustomerNumber('CUST001');
$customer->setCreditLimit('5000.00');

// Create an employee
$employee = new Employee();
$employee->setName('Bob Smith');
$employee->setEmail('bob@company.com');
$employee->setDepartment('IT');
$employee->setSalary('75000.00');

$entityManager->persist($customer);
$entityManager->persist($employee);
$entityManager->flush();

// Query all persons
$persons = $entityManager->getRepository(Person::class)->findAll();
echo "All persons:\n";
foreach ($persons as $person) {
    $type = $person instanceof Customer ? 'Customer' : 'Employee';
    echo "- " . $person->getName() . " ($type)\n";
}

// Query specific types
$customers = $entityManager->getRepository(Customer::class)->findAll();
echo "\nCustomers only:\n";
foreach ($customers as $customer) {
    echo "- " . $customer->getName() . " (Credit: $" . $customer->getCreditLimit() . ")\n";
}
```

Single table inheritance stores all entities in one table with a discriminator  
column to identify the entity type. This is efficient for queries but can  
result in sparse tables with many nullable columns.  

## Native SQL Queries

**examples/17-native-sql.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;

// Native SQL query returning entities
$sql = 'SELECT p.* FROM products p WHERE p.price > ? ORDER BY p.price DESC';
$query = $entityManager->createNativeQuery($sql, $rsm = new \Doctrine\ORM\Query\ResultSetMapping());

// Map the result set
$rsm->addEntityResult(Product::class, 'p');
$rsm->addFieldResult('p', 'id', 'id');
$rsm->addFieldResult('p', 'name', 'name');
$rsm->addFieldResult('p', 'description', 'description');
$rsm->addFieldResult('p', 'price', 'price');
$rsm->addFieldResult('p', 'active', 'active');
$rsm->addFieldResult('p', 'created_at', 'createdAt');
$rsm->addFieldResult('p', 'updated_at', 'updatedAt');
$rsm->addFieldResult('p', 'category_id', 'category');

$query->setParameter(1, '500.00');
$expensiveProducts = $query->getResult();

echo "Expensive products (using native SQL):\n";
foreach ($expensiveProducts as $product) {
    echo "- " . $product->getName() . ": $" . $product->getPrice() . "\n";
}

// Raw SQL for scalar results
$sql = 'SELECT COUNT(*) as total, AVG(price) as avg_price FROM products WHERE active = 1';
$query = $entityManager->getConnection()->executeQuery($sql);
$result = $query->fetchAssociative();

echo "\nProduct statistics (scalar result):\n";
echo "Total active products: " . $result['total'] . "\n";
echo "Average price: $" . number_format($result['avg_price'], 2) . "\n";
```

Native SQL queries are useful when you need database-specific features  
or complex queries that are difficult to express in DQL.  

## Transaction Management

**examples/18-transactions.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\User;
use App\Entity\Product;

$entityManager->beginTransaction();

try {
    // Create user
    $user = new User();
    $user->setName('Transaction User');
    $user->setEmail('transaction@example.com');
    $entityManager->persist($user);

    // Create multiple products
    for ($i = 1; $i <= 3; $i++) {
        $product = new Product();
        $product->setName("Transaction Product $i");
        $product->setPrice(rand(100, 1000) . '.99');
        $entityManager->persist($product);
    }

    // Simulate an error condition
    $riskyOperation = rand(1, 10);
    if ($riskyOperation > 7) {
        throw new \Exception('Simulated error occurred!');
    }

    $entityManager->flush();
    $entityManager->commit();

    echo "Transaction completed successfully!\n";
    echo "Created user: " . $user->getName() . "\n";

} catch (\Exception $e) {
    $entityManager->rollback();
    echo "Transaction failed: " . $e->getMessage() . "\n";
    echo "All changes have been rolled back.\n";
}
```

Transactions ensure data consistency by grouping multiple operations.  
If any operation fails, all changes are rolled back.  

## Batch Processing

**examples/19-batch-processing.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;

$batchSize = 100;
$totalRecords = 1000;

echo "Creating $totalRecords products in batches of $batchSize...\n";

$startTime = microtime(true);

for ($i = 1; $i <= $totalRecords; $i++) {
    $product = new Product();
    $product->setName("Batch Product $i");
    $product->setDescription("Product created in batch processing");
    $product->setPrice(rand(10, 1000) . '.99');
    $product->setActive(rand(0, 1) === 1);

    $entityManager->persist($product);

    // Flush and clear every batch
    if ($i % $batchSize === 0) {
        $entityManager->flush();
        $entityManager->clear(); // Free memory
        echo "Processed $i products...\n";
    }
}

// Flush remaining entities
$entityManager->flush();
$entityManager->clear();

$endTime = microtime(true);
$executionTime = round($endTime - $startTime, 2);

echo "Batch processing completed in {$executionTime} seconds\n";

// Verify the count
$totalProducts = $entityManager->createQueryBuilder()
    ->select('COUNT(p.id)')
    ->from(Product::class, 'p')
    ->getQuery()
    ->getSingleScalarResult();

echo "Total products in database: $totalProducts\n";
```

Batch processing is essential for handling large datasets efficiently.  
Regular calls to flush() and clear() prevent memory issues.  

## Performance Optimization

**examples/20-performance-tips.php**

```php
<?php

$entityManager = require __DIR__ . '/../config/bootstrap.php';

use App\Entity\Product;
use App\Entity\Category;

// 1. Eager loading with joins to avoid N+1 problem
echo "1. Eager loading example:\n";
$productsWithCategories = $entityManager->createQueryBuilder()
    ->select('p', 'c')  // Select both product and category
    ->from(Product::class, 'p')
    ->leftJoin('p.category', 'c')
    ->where('p.active = :active')
    ->setParameter('active', true)
    ->getQuery()
    ->getResult();

foreach ($productsWithCategories as $product) {
    $categoryName = $product->getCategory() ? 
        $product->getCategory()->getName() : 'No Category';
    echo "Product: " . $product->getName() . " - Category: $categoryName\n";
}

// 2. Using partial objects for better performance
echo "\n2. Partial objects example:\n";
$lightweightProducts = $entityManager->createQueryBuilder()
    ->select('partial p.{id, name, price}')
    ->from(Product::class, 'p')
    ->where('p.active = :active')
    ->setParameter('active', true)
    ->setMaxResults(5)
    ->getQuery()
    ->getResult();

foreach ($lightweightProducts as $product) {
    echo "ID: " . $product->getId() . " - " . $product->getName() . 
         " - $" . $product->getPrice() . "\n";
}

// 3. Query result caching
echo "\n3. Query caching example:\n";
$query = $entityManager->createQueryBuilder()
    ->select('COUNT(p.id)')
    ->from(Product::class, 'p')
    ->where('p.active = :active')
    ->setParameter('active', true)
    ->getQuery()
    ->enableResultCache(3600, 'active_products_count'); // Cache for 1 hour

$activeProductCount = $query->getSingleScalarResult();
echo "Active products count (cached): $activeProductCount\n";

// 4. Using EXTRA_LAZY collections for large datasets
echo "\n4. Collection optimization tips:\n";
$category = $entityManager->find(Category::class, 1);
if ($category) {
    // This will only execute a COUNT query, not load all products
    $productCount = $category->getProducts()->count();
    echo "Products in category: $productCount\n";
    
    // Use slice() for pagination without loading all entities
    $firstTwoProducts = $category->getProducts()->slice(0, 2);
    echo "First 2 products:\n";
    foreach ($firstTwoProducts as $product) {
        echo "- " . $product->getName() . "\n";
    }
}

// 5. Bulk operations for better performance
echo "\n5. Bulk update example:\n";
$updatedCount = $entityManager->createQueryBuilder()
    ->update(Product::class, 'p')
    ->set('p.updatedAt', ':now')
    ->where('p.active = :active')
    ->setParameter('active', true)
    ->setParameter('now', new \DateTime())
    ->getQuery()
    ->execute();

echo "Updated $updatedCount products with bulk operation\n";
```

This final example demonstrates key performance optimization techniques:  
- Eager loading prevents N+1 query problems  
- Partial objects reduce memory usage  
- Query caching improves repeated query performance  
- Collection optimizations handle large datasets efficiently  
- Bulk operations are faster than individual entity updates  

## Conclusion

This tutorial covered 20 comprehensive examples of Doctrine ORM usage,  
from basic entity operations to advanced performance optimization techniques.  

Key takeaways:  
- Use proper entity relationships to model your domain  
- Leverage QueryBuilder and DQL for complex queries  
- Implement batch processing for large datasets  
- Use transactions for data consistency  
- Apply performance optimizations to avoid common pitfalls  

Doctrine ORM provides a powerful abstraction layer that makes database  
operations in PHP both efficient and maintainable when used correctly.  
