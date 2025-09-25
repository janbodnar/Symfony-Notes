<!DOCTYPE html>
<html lang="en">
<head>
<title>Symfony repositories tutorial</title>
<link rel="stylesheet" href="/cfg/style.css" type="text/css">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="keywords" content="Symfony, PHP, repositories, Doctrine, ORM, databases, programming">
<meta name="description" content="Symfony repositories tutorial with 25 comprehensive examples covering all aspects of repository patterns in Symfony applications.">
<meta name="author" content="Jan Bodnar">

<script>
  (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
  (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
  m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
  })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

  ga('create', 'UA-5536206-1', 'auto');
  ga('send', 'pageview');

</script>

<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-9706709751191532"
     crossorigin="anonymous"></script>
</head>

<body>

<header>

<div>
<a href="/" title="Home">ZetCode</a>
</div>

<nav>
    <a title="All tutorials" href="/all/">All</a>
    <a title="Go tutorials" href="/golang/">Golang</a>
    <a title="Python tutorials" href="/python/">Python</a>
    <a title="C# tutorials" href="/csharp/">C#</a>
    <a title="Java tutorials" href="/java/">Java</a>
    <a title="JavaScript tutorials" href="/javascript/">JavaScript</a>
    <a title="Subscribe to ZetCode news" href="http://zetcode.us13.list-manage.com/subscribe?u=9def9ccd4c70dbbaf691f90fc&id=6556210f80">Subscribe</a>
</nav>

</header>

<div class="container">

<div class="ltow">
    
<div id="ebooks">

<h2 class="blu">Ebooks</h2>

<ul>
<li><a href="/ebooks/advancedpyqt5/">PyQt5 ebook</a></li>
<li><a href="/ebooks/tkinter/">Tkinter ebook</a></li>
<li><a href="/ebooks/sqlitepython/">SQLite Python</a></li>
<li><a href="/ebooks/advancedwxpython/">wxPython ebook</a></li>
<li><a href="/ebooks/windowsapi/">Windows API ebook</a></li>
<li><a href="/ebooks/advancedjavaswing/">Java Swing ebook</a></li>
<li><a href="/ebooks/javagames/">Java games ebook</a></li>
<li><a href="/ebooks/mysql/">MySQL ebook</a></li>
</ul>

</div>

</div> <!-- ltow -->

<div class="content">


<h1>Symfony repositories</h1>

<p>
In this tutorial, we show how to work with repositories in Symfony.  
Repositories provide a centralized location for database queries and  
encapsulate data access logic. They act as in-memory collections of  
domain objects, making code more maintainable and testable.  
</p>

<h2>What is a Repository</h2>

<p>
A <dfn>Repository</dfn> is a design pattern that encapsulates the logic  
needed to access data sources. It centralizes common data access  
functionality, providing better maintainability and decoupling the  
infrastructure or technology used to access databases from the domain  
model layer.  
</p>

<p>
In Symfony with Doctrine ORM, repositories are classes that contain  
methods for retrieving entities from the database. Each entity has a  
corresponding repository class that extends  
<code>Doctrine\ORM\EntityRepository</code>.  
</p>

<h2>Basic Repository Usage</h2>

<p>
Let's start with basic repository operations. First, we need an entity  
to work with.  
</p>

<div class="codehead">src/Entity/User.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'users')]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 180)]
    private ?string $name = null;

    #[ORM\Column(length: 255)]
    private ?string $email = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $createdAt = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): static
    {
        $this->name = $name;
        return $this;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;
        return $this;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeImmutable $createdAt): static
    {
        $this->createdAt = $createdAt;
        return $this;
    }
}
</pre>

<p>
This is a basic User entity with modern PHP 8.4 attributes instead of  
annotations. The entity specifies its repository class which we'll  
create next.  
</p>

<h2>Finding Entities by ID</h2>

<p>
The most basic repository operation is finding an entity by its primary  
key identifier.  
</p>

<div class="codehead">src/Repository/UserRepository.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findUserById(int $id): ?User
    {
        return $this->find($id);
    }
}
</pre>

<p>
The repository extends <code>ServiceEntityRepository</code> which provides  
the basic CRUD operations. The <code>find()</code> method retrieves a  
single entity by its primary key.  
</p>

<div class="codehead">src/Controller/UserController.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Controller;

use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class UserController extends AbstractController
{
    #[Route('/user/{id}', name: 'user_show')]
    public function show(int $id, UserRepository $userRepository): Response
    {
        $user = $userRepository->findUserById($id);
        
        if (!$user) {
            throw $this->createNotFoundException('User not found');
        }
        
        return $this->json([
            'id' => $user->getId(),
            'name' => $user->getName(),
            'email' => $user->getEmail()
        ]);
    }
}
</pre>

<p>
In the controller, we inject the UserRepository and use our custom  
method to find a user. Symfony's dependency injection automatically  
provides the repository instance.  
</p>

<h2>Finding Entities by Criteria</h2>

<p>
Repositories provide methods to find entities based on specific criteria  
rather than just the primary key.  
</p>

<div class="codehead">UserRepository.php (additional methods)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function findByEmail(string $email): ?User
{
    return $this->findOneBy(['email' => $email]);
}

public function findByName(string $name): array
{
    return $this->findBy(['name' => $name]);
}

public function findByCreatedAfter(\DateTimeImmutable $date): array
{
    return $this->findBy([], ['createdAt' => 'DESC'], null, 0);
}
</pre>

<p>
The <code>findOneBy()</code> method returns a single entity or null,  
while <code>findBy()</code> returns an array of entities. The second  
parameter allows ordering, third for limit, and fourth for offset.  
</p>

<h2>Using findBy and findOneBy Methods</h2>

<p>
The built-in methods provide flexible ways to query entities with  
various parameters for ordering, limiting, and offsetting results.  
</p>

<div class="codehead">UserRepository.php (findBy examples)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function findRecentUsers(int $limit = 10): array
{
    return $this->findBy(
        [], // no criteria (all users)
        ['createdAt' => 'DESC'], // order by creation date
        $limit // limit results
    );
}

public function findUsersPaginated(int $page = 1, int $limit = 20): array
{
    $offset = ($page - 1) * $limit;
    
    return $this->findBy(
        [],
        ['name' => 'ASC'],
        $limit,
        $offset
    );
}

public function findActiveUsersWithEmail(): array
{
    return $this->findBy([
        'email' => ['!=', null]
    ], ['name' => 'ASC']);
}
</pre>

<p>
These methods demonstrate different use cases: finding recent users,  
implementing pagination, and filtering by non-null values. The findBy  
method signature is: findBy(criteria, orderBy, limit, offset).  
</p>

<h2>Counting Entities</h2>

<p>
Counting entities is essential for pagination and statistics. Repositories  
provide methods to count entities efficiently.  
</p>

<div class="codehead">UserRepository.php (counting methods)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function countUsers(): int
{
    return $this->count([]);
}

public function countUsersByName(string $name): int
{
    return $this->count(['name' => $name]);
}

public function countUsersCreatedAfter(\DateTimeImmutable $date): int
{
    return $this->createQueryBuilder('u')
        ->select('COUNT(u.id)')
        ->where('u.createdAt > :date')
        ->setParameter('date', $date)
        ->getQuery()
        ->getSingleScalarResult();
}
</pre>

<p>
The <code>count()</code> method provides a simple way to count entities  
with basic criteria. For more complex counting, we use the Query Builder  
with COUNT() aggregate function.  
</p>

<h2>Custom Repository Methods</h2>

<p>
Custom repository methods encapsulate complex business logic and provide  
a clean interface for controllers and services.  
</p>

<div class="codehead">UserRepository.php (custom methods)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function findUsersWithRecentActivity(int $days = 30): array
{
    $date = new \DateTimeImmutable("-{$days} days");
    
    return $this->createQueryBuilder('u')
        ->where('u.createdAt >= :date')
        ->setParameter('date', $date)
        ->orderBy('u.createdAt', 'DESC')
        ->getQuery()
        ->getResult();
}

public function searchUsersByKeyword(string $keyword): array
{
    return $this->createQueryBuilder('u')
        ->where('u.name LIKE :keyword OR u.email LIKE :keyword')
        ->setParameter('keyword', '%' . $keyword . '%')
        ->orderBy('u.name', 'ASC')
        ->getQuery()
        ->getResult();
}

public function findUsersByEmailDomain(string $domain): array
{
    return $this->createQueryBuilder('u')
        ->where('u.email LIKE :domain')
        ->setParameter('domain', '%@' . $domain . '%')
        ->getQuery()
        ->getResult();
}
</pre>

<p>
Custom methods provide meaningful names for complex queries and hide  
implementation details from the calling code. They make the repository  
interface more expressive and maintainable.  
</p>

<h2>Query Builder Basics</h2>

<p>
The Query Builder provides a programmatic way to construct DQL queries  
with a fluent interface that's more readable than raw DQL strings.  
</p>

<div class="codehead">UserRepository.php (Query Builder examples)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function findUsersByComplex(): array
{
    $qb = $this->createQueryBuilder('u');
    
    return $qb
        ->select('u')
        ->where($qb->expr()->isNotNull('u.email'))
        ->andWhere($qb->expr()->gte('u.createdAt', ':minDate'))
        ->orderBy('u.name', 'ASC')
        ->addOrderBy('u.createdAt', 'DESC')
        ->setParameter('minDate', new \DateTimeImmutable('-1 year'))
        ->getQuery()
        ->getResult();
}

public function findUsersWithConditionalFilters(?string $name, ?string $email): array
{
    $qb = $this->createQueryBuilder('u');
    
    if ($name) {
        $qb->andWhere('u.name LIKE :name')
           ->setParameter('name', '%' . $name . '%');
    }
    
    if ($email) {
        $qb->andWhere('u.email = :email')
           ->setParameter('email', $email);
    }
    
    return $qb->getQuery()->getResult();
}
</pre>

<p>
The Query Builder allows for conditional query construction and complex  
expressions using the expression builder. This is particularly useful  
for search functionality with optional filters.  
</p>

<h2>Repository with DQL Queries</h2>

<p>
DQL (Doctrine Query Language) provides a SQL-like syntax for querying  
entities. It's useful for complex queries that are difficult to express  
with the Query Builder.  
</p>

<div class="codehead">UserRepository.php (DQL examples)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function findUserStatistics(): array
{
    $dql = '
        SELECT 
            COUNT(u.id) as total_users,
            MIN(u.createdAt) as first_user_date,
            MAX(u.createdAt) as last_user_date
        FROM App\Entity\User u
    ';
    
    return $this->getEntityManager()
        ->createQuery($dql)
        ->getSingleResult();
}

public function findUsersCreatedInMonth(int $year, int $month): array
{
    $dql = '
        SELECT u 
        FROM App\Entity\User u 
        WHERE YEAR(u.createdAt) = :year 
        AND MONTH(u.createdAt) = :month
        ORDER BY u.createdAt DESC
    ';
    
    return $this->getEntityManager()
        ->createQuery($dql)
        ->setParameters([
            'year' => $year,
            'month' => $month
        ])
        ->getResult();
}
</pre>

<p>
DQL queries can access date functions like YEAR() and MONTH() and  
provide aggregate functions. They're compiled to efficient SQL queries  
by Doctrine.  
</p>

<h2>Using Repository Services</h2>

<p>
Repositories can be used as services and injected into other services  
for building complex business logic layers.  
</p>

<div class="codehead">src/Service/UserService.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Service;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;

class UserService
{
    public function __construct(
        private UserRepository $userRepository,
        private EntityManagerInterface $entityManager
    ) {}

    public function createUser(string $name, string $email): User
    {
        $user = new User();
        $user->setName($name);
        $user->setEmail($email);
        $user->setCreatedAt(new \DateTimeImmutable());
        
        $this->entityManager->persist($user);
        $this->entityManager->flush();
        
        return $user;
    }

    public function findUserByEmailOrFail(string $email): User
    {
        $user = $this->userRepository->findByEmail($email);
        
        if (!$user) {
            throw new \InvalidArgumentException("User with email {$email} not found");
        }
        
        return $user;
    }

    public function getUserStatistics(): array
    {
        return [
            'total' => $this->userRepository->countUsers(),
            'recent' => count($this->userRepository->findUsersWithRecentActivity(7)),
            'statistics' => $this->userRepository->findUserStatistics()
        ];
    }
}
</pre>

<p>
Service classes use repositories to implement business logic while  
keeping controllers thin. They can combine multiple repository calls  
and add validation or business rules.  
</p>

<h2>Repository Inheritance</h2>

<p>
You can create a base repository class with common functionality that  
can be shared across multiple entity repositories.  
</p>

<div class="codehead">src/Repository/BaseRepository.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Repository;

use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

abstract class BaseRepository extends ServiceEntityRepository
{
    public function findByIds(array $ids): array
    {
        if (empty($ids)) {
            return [];
        }
        
        return $this->createQueryBuilder('e')
            ->where('e.id IN (:ids)')
            ->setParameter('ids', $ids)
            ->getQuery()
            ->getResult();
    }

    public function findRandomEntities(int $limit = 5): array
    {
        $count = $this->count([]);
        
        if ($count <= $limit) {
            return $this->findAll();
        }
        
        $offset = random_int(0, max(0, $count - $limit));
        
        return $this->findBy([], null, $limit, $offset);
    }

    protected function paginate(int $page, int $limit, array $criteria = [], array $orderBy = []): array
    {
        $offset = ($page - 1) * $limit;
        
        return $this->findBy($criteria, $orderBy, $limit, $offset);
    }
}
</pre>

<div class="codehead">UserRepository.php (extending BaseRepository)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
class UserRepository extends BaseRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findRandomUsers(int $count = 3): array
    {
        return $this->findRandomEntities($count);
    }

    public function findUsersByPage(int $page, int $limit = 20): array
    {
        return $this->paginate($page, $limit, [], ['name' => 'ASC']);
    }
}
</pre>

<p>
Repository inheritance allows sharing common patterns like pagination,  
bulk operations, and utility methods across different entity repositories,  
promoting code reuse and consistency.  
</p>

<h2>Criteria API Usage</h2>

<p>
The Criteria API provides an object-oriented way to build query conditions  
that can be reused and combined dynamically.  
</p>

<div class="codehead">UserRepository.php (Criteria examples)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
use Doctrine\Common\Collections\Criteria;

public function findUsersByCriteria(array $filters): array
{
    $criteria = new Criteria();
    
    if (!empty($filters['name'])) {
        $criteria->andWhere(
            Criteria::expr()->contains('name', $filters['name'])
        );
    }
    
    if (!empty($filters['email_domain'])) {
        $criteria->andWhere(
            Criteria::expr()->contains('email', '@' . $filters['email_domain'])
        );
    }
    
    if (!empty($filters['created_after'])) {
        $criteria->andWhere(
            Criteria::expr()->gte('createdAt', $filters['created_after'])
        );
    }
    
    $criteria->orderBy(['name' => 'ASC']);
    
    return $this->matching($criteria)->toArray();
}

public function createSearchCriteria(string $query): Criteria
{
    return Criteria::create()
        ->where(
            Criteria::expr()->orX(
                Criteria::expr()->contains('name', $query),
                Criteria::expr()->contains('email', $query)
            )
        )
        ->orderBy(['name' => 'ASC']);
}
</pre>

<p>
The Criteria API is particularly useful for building dynamic search  
functionality where query conditions depend on user input or  
configuration parameters.  
</p>

<h2>Repository with Joins</h2>

<p>
When working with related entities, repositories can efficiently load  
related data using joins to avoid the N+1 query problem.  
</p>

<div class="codehead">src/Entity/Post.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: PostRepository::class)]
#[ORM\Table(name: 'posts')]
class Post
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $title = null;

    #[ORM\Column(type: 'text')]
    private ?string $content = null;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false)]
    private ?User $author = null;

    // getters and setters...
}
</pre>

<div class="codehead">src/Repository/PostRepository.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Repository;

use App\Entity\Post;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class PostRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Post::class);
    }

    public function findPostsWithAuthors(): array
    {
        return $this->createQueryBuilder('p')
            ->innerJoin('p.author', 'u')
            ->addSelect('u')
            ->orderBy('p.title', 'ASC')
            ->getQuery()
            ->getResult();
    }

    public function findPostsByAuthorName(string $authorName): array
    {
        return $this->createQueryBuilder('p')
            ->innerJoin('p.author', 'u')
            ->where('u.name LIKE :name')
            ->setParameter('name', '%' . $authorName . '%')
            ->orderBy('p.title', 'ASC')
            ->getQuery()
            ->getResult();
    }
}
</pre>

<p>
Using joins in repositories ensures that related entities are loaded  
in a single query, improving performance by avoiding lazy loading  
issues in loops.  
</p>

<h2>Pagination with Repositories</h2>

<p>
Implementing efficient pagination requires both the data and total count  
to calculate pages and navigation elements.  
</p>

<div class="codehead">UserRepository.php (pagination methods)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
use Doctrine\ORM\Tools\Pagination\Paginator;

public function findPaginated(int $page, int $limit): Paginator
{
    $query = $this->createQueryBuilder('u')
        ->orderBy('u.name', 'ASC')
        ->getQuery()
        ->setFirstResult(($page - 1) * $limit)
        ->setMaxResults($limit);
        
    return new Paginator($query);
}

public function getPaginationData(int $page, int $limit): array
{
    $paginator = $this->findPaginated($page, $limit);
    
    $totalItems = count($paginator);
    $totalPages = ceil($totalItems / $limit);
    
    return [
        'data' => iterator_to_array($paginator),
        'pagination' => [
            'current_page' => $page,
            'total_pages' => $totalPages,
            'total_items' => $totalItems,
            'items_per_page' => $limit,
            'has_previous' => $page > 1,
            'has_next' => $page < $totalPages
        ]
    ];
}
</pre>

<p>
The Doctrine Paginator automatically handles counting queries and  
provides an efficient way to implement pagination without loading  
all results into memory.  
</p>

<h2>Bulk Operations</h2>

<p>
For performance-critical operations affecting many entities, bulk  
operations provide efficient alternatives to loading and modifying  
entities individually.  
</p>

<div class="codehead">UserRepository.php (bulk operations)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function bulkUpdateUserStatus(array $userIds, string $status): int
{
    return $this->createQueryBuilder('u')
        ->update()
        ->set('u.status', ':status')
        ->where('u.id IN (:ids)')
        ->setParameters([
            'status' => $status,
            'ids' => $userIds
        ])
        ->getQuery()
        ->execute();
}

public function deleteInactiveUsers(int $daysSinceLastActivity): int
{
    $date = new \DateTimeImmutable("-{$daysSinceLastActivity} days");
    
    return $this->createQueryBuilder('u')
        ->delete()
        ->where('u.lastActivityAt < :date OR u.lastActivityAt IS NULL')
        ->setParameter('date', $date)
        ->getQuery()
        ->execute();
}

public function batchInsertUsers(array $users): void
{
    $batchSize = 100;
    $em = $this->getEntityManager();
    
    foreach (array_chunk($users, $batchSize) as $batch) {
        foreach ($batch as $userData) {
            $user = new User();
            $user->setName($userData['name']);
            $user->setEmail($userData['email']);
            $user->setCreatedAt(new \DateTimeImmutable());
            
            $em->persist($user);
        }
        
        $em->flush();
        $em->clear(); // Free memory
    }
}
</pre>

<p>
Bulk operations execute directly in the database without loading  
entities into memory, making them much more efficient for large-scale  
data operations.  
</p>

<h2>Repository with Custom SQL</h2>

<p>
Sometimes complex queries require native SQL for optimal performance  
or to use database-specific features not available in DQL.  
</p>

<div class="codehead">UserRepository.php (native SQL examples)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function findUsersWithComplexStats(): array
{
    $sql = '
        SELECT 
            u.id,
            u.name,
            u.email,
            COUNT(p.id) as post_count,
            MAX(p.created_at) as last_post_date,
            EXTRACT(EPOCH FROM (NOW() - u.created_at))/86400 as days_since_registration
        FROM users u
        LEFT JOIN posts p ON u.id = p.author_id
        GROUP BY u.id, u.name, u.email, u.created_at
        ORDER BY post_count DESC, u.name ASC
    ';
    
    return $this->getEntityManager()
        ->getConnection()
        ->executeQuery($sql)
        ->fetchAllAssociative();
}

public function findUsersByLocationRadius(float $lat, float $lng, int $radiusKm): array
{
    $sql = '
        SELECT u.*, 
        (6371 * acos(cos(radians(:lat)) * cos(radians(u.latitude)) * 
         cos(radians(u.longitude) - radians(:lng)) + 
         sin(radians(:lat)) * sin(radians(u.latitude)))) AS distance
        FROM users u
        HAVING distance <= :radius
        ORDER BY distance ASC
    ';
    
    return $this->getEntityManager()
        ->getConnection()
        ->executeQuery($sql, [
            'lat' => $lat,
            'lng' => $lng,
            'radius' => $radiusKm
        ])
        ->fetchAllAssociative();
}
</pre>

<p>
Native SQL is useful for complex calculations, window functions, or  
database-specific operations that would be difficult or inefficient  
to express in DQL.  
</p>

<h2>Repository with Specifications Pattern</h2>

<p>
The Specification pattern allows building complex query logic in  
reusable, composable objects that can be combined and tested independently.  
</p>

<div class="codehead">src/Specification/UserSpecification.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Specification;

use Doctrine\ORM\QueryBuilder;

interface UserSpecificationInterface
{
    public function apply(QueryBuilder $qb, string $alias): void;
}

class ActiveUsersSpecification implements UserSpecificationInterface
{
    public function apply(QueryBuilder $qb, string $alias): void
    {
        $qb->andWhere("$alias.status = :active_status")
           ->setParameter('active_status', 'active');
    }
}

class RecentUsersSpecification implements UserSpecificationInterface
{
    public function __construct(private int $days = 30) {}
    
    public function apply(QueryBuilder $qb, string $alias): void
    {
        $date = new \DateTimeImmutable("-{$this->days} days");
        $qb->andWhere("$alias.createdAt >= :recent_date")
           ->setParameter('recent_date', $date);
    }
}

class UserNameSpecification implements UserSpecificationInterface
{
    public function __construct(private string $name) {}
    
    public function apply(QueryBuilder $qb, string $alias): void
    {
        $qb->andWhere("$alias.name LIKE :user_name")
           ->setParameter('user_name', '%' . $this->name . '%');
    }
}
</pre>

<div class="codehead">UserRepository.php (with specifications)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
use App\Specification\UserSpecificationInterface;

public function findBySpecifications(UserSpecificationInterface ...$specifications): array
{
    $qb = $this->createQueryBuilder('u');
    
    foreach ($specifications as $specification) {
        $specification->apply($qb, 'u');
    }
    
    return $qb->getQuery()->getResult();
}

// Usage example in a service
public function findActiveRecentUsers(string $nameFilter = null): array
{
    $specifications = [
        new ActiveUsersSpecification(),
        new RecentUsersSpecification(7)
    ];
    
    if ($nameFilter) {
        $specifications[] = new UserNameSpecification($nameFilter);
    }
    
    return $this->userRepository->findBySpecifications(...$specifications);
}
</pre>

<p>
The Specification pattern makes complex query logic testable and  
reusable while keeping repository methods clean and focused.  
</p>

<h2>Repository with Caching</h2>

<p>
Caching frequently accessed data can significantly improve application  
performance, especially for queries that don't change often.  
</p>

<div class="codehead">UserRepository.php (with caching)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(
        ManagerRegistry $registry,
        private CacheInterface $cache
    ) {
        parent::__construct($registry, User::class);
    }

    public function findPopularUsers(): array
    {
        return $this->cache->get('popular_users', function (ItemInterface $item) {
            $item->expiresAfter(3600); // Cache for 1 hour
            
            return $this->createQueryBuilder('u')
                ->where('u.followerCount > :minFollowers')
                ->setParameter('minFollowers', 1000)
                ->orderBy('u.followerCount', 'DESC')
                ->setMaxResults(10)
                ->getQuery()
                ->getResult();
        });
    }

    public function getUserStats(): array
    {
        return $this->cache->get('user_statistics', function (ItemInterface $item) {
            $item->expiresAfter(1800); // Cache for 30 minutes
            
            return [
                'total_users' => $this->count([]),
                'active_users' => $this->count(['status' => 'active']),
                'new_users_today' => $this->countUsersCreatedAfter(
                    new \DateTimeImmutable('today')
                )
            ];
        });
    }

    public function invalidateUserCaches(): void
    {
        $this->cache->delete('popular_users');
        $this->cache->delete('user_statistics');
    }
}
</pre>

<p>
Repository-level caching should be used judiciously and include cache  
invalidation strategies to ensure data consistency. Consider cache  
warming for critical queries during low-traffic periods.  
</p>

<h2>Repository with Events</h2>

<p>
Doctrine events allow repositories to respond to entity lifecycle  
events and implement cross-cutting concerns like auditing or  
cache invalidation.  
</p>

<div class="codehead">src/EventListener/UserEventListener.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\EventListener;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\Event\PostPersistEventArgs;
use Doctrine\ORM\Event\PostUpdateEventArgs;
use Doctrine\ORM\Event\PreRemoveEventArgs;

class UserEventListener
{
    public function __construct(private UserRepository $userRepository) {}

    public function postPersist(PostPersistEventArgs $args): void
    {
        $entity = $args->getObject();
        
        if ($entity instanceof User) {
            $this->userRepository->invalidateUserCaches();
            // Log user creation
            // Send welcome email
            // Update statistics
        }
    }

    public function postUpdate(PostUpdateEventArgs $args): void
    {
        $entity = $args->getObject();
        
        if ($entity instanceof User) {
            $this->userRepository->invalidateUserCaches();
        }
    }

    public function preRemove(PreRemoveEventArgs $args): void
    {
        $entity = $args->getObject();
        
        if ($entity instanceof User) {
            // Archive user data before deletion
            // Clean up related entities
        }
    }
}
</pre>

<div class="codehead">config/services.yaml
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
services:
    App\EventListener\UserEventListener:
        tags:
            - { name: doctrine.event_listener, event: postPersist }
            - { name: doctrine.event_listener, event: postUpdate }
            - { name: doctrine.event_listener, event: preRemove }
</pre>

<p>
Events provide a clean way to implement repository-related side effects  
without cluttering the main business logic. They're particularly useful  
for auditing, caching, and notification systems.  
</p>

<h2>Repository Testing</h2>

<p>
Testing repositories ensures that query logic works correctly and  
helps prevent regressions when refactoring database access code.  
</p>

<div class="codehead">tests/Repository/UserRepositoryTest.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Tests\Repository;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class UserRepositoryTest extends KernelTestCase
{
    private UserRepository $repository;

    protected function setUp(): void
    {
        self::bootKernel();
        $this->repository = static::getContainer()->get(UserRepository::class);
    }

    public function testFindByEmail(): void
    {
        $user = new User();
        $user->setName('Test User');
        $user->setEmail('test@example.com');
        $user->setCreatedAt(new \DateTimeImmutable());

        $em = static::getContainer()->get('doctrine')->getManager();
        $em->persist($user);
        $em->flush();

        $foundUser = $this->repository->findByEmail('test@example.com');
        
        $this->assertInstanceOf(User::class, $foundUser);
        $this->assertEquals('test@example.com', $foundUser->getEmail());
        $this->assertEquals('Test User', $foundUser->getName());
    }

    public function testFindUsersWithRecentActivity(): void
    {
        // Create test data
        $oldUser = new User();
        $oldUser->setName('Old User');
        $oldUser->setEmail('old@example.com');
        $oldUser->setCreatedAt(new \DateTimeImmutable('-60 days'));

        $newUser = new User();
        $newUser->setName('New User');
        $newUser->setEmail('new@example.com');
        $newUser->setCreatedAt(new \DateTimeImmutable('-5 days'));

        $em = static::getContainer()->get('doctrine')->getManager();
        $em->persist($oldUser);
        $em->persist($newUser);
        $em->flush();

        $recentUsers = $this->repository->findUsersWithRecentActivity(30);
        
        $this->assertCount(1, $recentUsers);
        $this->assertEquals('New User', $recentUsers[0]->getName());
    }
}
</pre>

<p>
Repository tests should use the real database or an in-memory database  
for integration testing. They verify that queries return expected  
results and handle edge cases correctly.  
</p>

<h2>Repository with DTOs</h2>

<p>
Data Transfer Objects (DTOs) can improve performance by selecting only  
needed fields and provide a stable API for controllers and views.  
</p>

<div class="codehead">src/DTO/UserSummaryDTO.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\DTO;

class UserSummaryDTO
{
    public function __construct(
        public readonly int $id,
        public readonly string $name,
        public readonly string $email,
        public readonly \DateTimeImmutable $createdAt,
        public readonly int $postCount = 0
    ) {}
}

class UserStatsDTO
{
    public function __construct(
        public readonly int $totalUsers,
        public readonly int $activeUsers,
        public readonly int $newUsersThisMonth,
        public readonly float $averagePostsPerUser
    ) {}
}
</pre>

<div class="codehead">UserRepository.php (with DTOs)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function findUserSummaries(): array
{
    $result = $this->createQueryBuilder('u')
        ->select('u.id, u.name, u.email, u.createdAt, COUNT(p.id) as postCount')
        ->leftJoin('u.posts', 'p')
        ->groupBy('u.id, u.name, u.email, u.createdAt')
        ->orderBy('u.name', 'ASC')
        ->getQuery()
        ->getArrayResult();
    
    return array_map(function ($row) {
        return new UserSummaryDTO(
            $row['id'],
            $row['name'],
            $row['email'],
            $row['createdAt'],
            (int) $row['postCount']
        );
    }, $result);
}

public function getSystemStats(): UserStatsDTO
{
    $stats = $this->createQueryBuilder('u')
        ->select('
            COUNT(u.id) as totalUsers,
            COUNT(CASE WHEN u.status = :active THEN 1 END) as activeUsers,
            COUNT(CASE WHEN u.createdAt >= :monthStart THEN 1 END) as newUsers,
            AVG(u.postCount) as avgPosts
        ')
        ->setParameters([
            'active' => 'active',
            'monthStart' => new \DateTimeImmutable('first day of this month')
        ])
        ->getQuery()
        ->getSingleResult();
        
    return new UserStatsDTO(
        (int) $stats['totalUsers'],
        (int) $stats['activeUsers'],
        (int) $stats['newUsers'],
        (float) $stats['avgPosts']
    );
}
</pre>

<p>
DTOs provide a clean separation between the database layer and  
application layer, allowing for optimized queries while maintaining  
a stable interface for consuming code.  
</p>

<h2>Repository with Aggregations</h2>

<p>
Aggregation queries perform calculations on groups of data, providing  
insights and summaries that would be expensive to calculate in PHP.  
</p>

<div class="codehead">UserRepository.php (aggregation methods)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function getUserRegistrationTrends(): array
{
    return $this->createQueryBuilder('u')
        ->select('
            DATE(u.createdAt) as date,
            COUNT(u.id) as registrations,
            MONTH(u.createdAt) as month,
            YEAR(u.createdAt) as year
        ')
        ->where('u.createdAt >= :startDate')
        ->setParameter('startDate', new \DateTimeImmutable('-1 year'))
        ->groupBy('DATE(u.createdAt)')
        ->orderBy('date', 'ASC')
        ->getQuery()
        ->getArrayResult();
}

public function getTopUsersByActivity(): array
{
    return $this->createQueryBuilder('u')
        ->select('u.name, u.email, COUNT(p.id) as postCount, AVG(p.viewCount) as avgViews')
        ->innerJoin('u.posts', 'p')
        ->groupBy('u.id, u.name, u.email')
        ->having('COUNT(p.id) > :minPosts')
        ->setParameter('minPosts', 5)
        ->orderBy('postCount', 'DESC')
        ->addOrderBy('avgViews', 'DESC')
        ->setMaxResults(20)
        ->getQuery()
        ->getArrayResult();
}

public function getUserActivitySummary(int $userId): ?array
{
    return $this->createQueryBuilder('u')
        ->select('
            u.name,
            COUNT(p.id) as totalPosts,
            SUM(p.viewCount) as totalViews,
            MAX(p.createdAt) as lastPostDate,
            AVG(p.viewCount) as avgViewsPerPost
        ')
        ->leftJoin('u.posts', 'p')
        ->where('u.id = :userId')
        ->setParameter('userId', $userId)
        ->groupBy('u.id, u.name')
        ->getQuery()
        ->getSingleResult();
}
</pre>

<p>
Aggregation queries are essential for reporting, analytics, and  
dashboard features. They leverage database capabilities for efficient  
calculation of metrics across large datasets.  
</p>

<h2>Repository with Subqueries</h2>

<p>
Subqueries allow complex filtering and selection logic that references  
other tables or performs calculations on related data.  
</p>

<div class="codehead">UserRepository.php (subquery examples)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function findUsersWithMostPosts(): array
{
    $subQuery = $this->getEntityManager()
        ->createQueryBuilder()
        ->select('COUNT(p2.id)')
        ->from('App\Entity\Post', 'p2')
        ->where('p2.author = u.id');
        
    return $this->createQueryBuilder('u')
        ->where('(' . $subQuery->getDQL() . ') > :minPosts')
        ->setParameter('minPosts', 10)
        ->orderBy('u.name', 'ASC')
        ->getQuery()
        ->getResult();
}

public function findUsersWithNoRecentPosts(int $days = 30): array
{
    $date = new \DateTimeImmutable("-{$days} days");
    
    return $this->createQueryBuilder('u')
        ->where('u.id NOT IN (
            SELECT DISTINCT p.author 
            FROM App\Entity\Post p 
            WHERE p.createdAt >= :recentDate
        )')
        ->setParameter('recentDate', $date)
        ->getQuery()
        ->getResult();
}

public function findUsersAboveAveragePostCount(): array
{
    $avgSubquery = $this->getEntityManager()
        ->createQueryBuilder()
        ->select('AVG(
            SELECT COUNT(p3.id) 
            FROM App\Entity\Post p3 
            WHERE p3.author = u2.id
        )')
        ->from('App\Entity\User', 'u2');
    
    return $this->createQueryBuilder('u')
        ->where('(
            SELECT COUNT(p.id) 
            FROM App\Entity\Post p 
            WHERE p.author = u.id
        ) > (' . $avgSubquery->getDQL() . ')')
        ->getQuery()
        ->getResult();
}
</pre>

<p>
Subqueries enable sophisticated filtering logic and can often replace  
multiple database round trips with a single, more efficient query.  
</p>

<h2>Repository with Native Queries</h2>

<p>
Native SQL queries provide access to database-specific features and  
can be more efficient for complex operations not well-suited to ORM.  
</p>

<div class="codehead">UserRepository.php (native queries)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function findSimilarUsers(int $userId, int $limit = 5): array
{
    $sql = '
        WITH user_interests AS (
            SELECT interest_id, COUNT(*) as interest_strength
            FROM user_interests 
            WHERE user_id = :userId
            GROUP BY interest_id
        ),
        similar_users AS (
            SELECT 
                ui2.user_id,
                SUM(ui.interest_strength) as similarity_score
            FROM user_interests ui
            JOIN user_interests ui2 ON ui.interest_id = ui2.interest_id
            WHERE ui2.user_id != :userId
            GROUP BY ui2.user_id
            ORDER BY similarity_score DESC
            LIMIT :limit
        )
        SELECT u.*, su.similarity_score
        FROM users u
        JOIN similar_users su ON u.id = su.user_id
        ORDER BY su.similarity_score DESC
    ';
    
    return $this->getEntityManager()
        ->getConnection()
        ->executeQuery($sql, [
            'userId' => $userId,
            'limit' => $limit
        ])
        ->fetchAllAssociative();
}

public function getAdvancedUserStatistics(): array
{
    $sql = '
        SELECT 
            u.name,
            u.email,
            COUNT(p.id) as post_count,
            AVG(p.view_count) as avg_views,
            RANK() OVER (ORDER BY COUNT(p.id) DESC) as post_rank,
            PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY p.view_count) as median_views,
            array_agg(DISTINCT c.name ORDER BY c.name) as categories
        FROM users u
        LEFT JOIN posts p ON u.id = p.author_id
        LEFT JOIN post_categories pc ON p.id = pc.post_id  
        LEFT JOIN categories c ON pc.category_id = c.id
        WHERE u.created_at >= NOW() - INTERVAL \'1 year\'
        GROUP BY u.id, u.name, u.email
        HAVING COUNT(p.id) > 0
        ORDER BY post_count DESC
        LIMIT 50
    ';
    
    return $this->getEntityManager()
        ->getConnection()
        ->executeQuery($sql)
        ->fetchAllAssociative();
}
</pre>

<p>
Native queries are ideal for advanced analytics, window functions,  
common table expressions (CTEs), and database-specific optimizations  
that aren't available through Doctrine's ORM layer.  
</p>

<h2>Repository Performance Optimization</h2>

<p>
Optimizing repository queries is crucial for application performance,  
especially as data volume grows and query complexity increases.  
</p>

<div class="codehead">UserRepository.php (optimized methods)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
public function findUsersOptimized(array $criteria = []): array
{
    $qb = $this->createQueryBuilder('u')
        ->select('partial u.{id, name, email}'); // Partial objects for memory efficiency
    
    if (!empty($criteria['name'])) {
        $qb->andWhere('u.name = :name')
           ->setParameter('name', $criteria['name']);
    }
    
    if (!empty($criteria['email_domain'])) {
        $qb->andWhere('u.email LIKE :domain')
           ->setParameter('domain', '%@' . $criteria['email_domain']);
    }
    
    // Use query hint for read-only results
    return $qb->getQuery()
        ->setHint(\Doctrine\ORM\Query::HINT_READ_ONLY, true)
        ->getResult();
}

public function streamLargeDataset(\Closure $processor): void
{
    $batchSize = 1000;
    $offset = 0;
    
    do {
        $query = $this->createQueryBuilder('u')
            ->setFirstResult($offset)
            ->setMaxResults($batchSize)
            ->getQuery();
            
        $results = $query->getResult();
        
        if (empty($results)) {
            break;
        }
        
        $processor($results);
        
        // Clear the entity manager to free memory
        $this->getEntityManager()->clear();
        
        $offset += $batchSize;
        
    } while (count($results) === $batchSize);
}

public function findWithEagerLoading(array $associations = []): array
{
    $qb = $this->createQueryBuilder('u');
    
    foreach ($associations as $association) {
        $qb->leftJoin("u.{$association}", $association)
           ->addSelect($association);
    }
    
    return $qb->getQuery()
        ->setHint(\Doctrine\ORM\Query::HINT_FORCE_PARTIAL_LOAD, true)
        ->getResult();
}
</pre>

<p>
Performance optimization includes using partial objects, query hints,  
batch processing, and strategic eager loading to reduce memory usage  
and query count while maintaining functionality.  
</p>

<h2>Repository Best Practices</h2>

<p>
Following best practices ensures maintainable, testable, and efficient  
repository implementations that scale with your application needs.  
</p>

<div class="codehead">UserRepository.php (best practices example)
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;

/**
 * Repository for User entity following best practices:
 * - Method names are descriptive and consistent
 * - Complex queries are broken into smaller methods
 * - Query logic is testable and reusable
 * - Performance considerations are implemented
 * - Type hints and return types are used throughout
 */
class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    /**
     * Create base query builder with common joins and filters
     */
    private function createUserQueryBuilder(): QueryBuilder
    {
        return $this->createQueryBuilder('u')
            ->where('u.status != :deleted')
            ->setParameter('deleted', 'deleted');
    }

    /**
     * Find active users with optional filtering
     */
    public function findActiveUsers(string $nameFilter = null): array
    {
        $qb = $this->createUserQueryBuilder()
            ->andWhere('u.status = :active')
            ->setParameter('active', 'active');

        if ($nameFilter) {
            $qb->andWhere('u.name LIKE :name')
               ->setParameter('name', '%' . $nameFilter . '%');
        }

        return $qb->orderBy('u.name', 'ASC')
                  ->getQuery()
                  ->getResult();
    }

    /**
     * Find users by multiple criteria with proper parameter binding
     */
    public function findByCriteria(array $criteria): array
    {
        $qb = $this->createUserQueryBuilder();
        $paramCounter = 0;

        foreach ($criteria as $field => $value) {
            $paramName = 'param' . (++$paramCounter);
            
            if (is_array($value)) {
                $qb->andWhere("u.{$field} IN (:{$paramName})")
                   ->setParameter($paramName, $value);
            } else {
                $qb->andWhere("u.{$field} = :{$paramName}")
                   ->setParameter($paramName, $value);
            }
        }

        return $qb->getQuery()->getResult();
    }

    /**
     * Validate and sanitize input for repository methods
     */
    private function validatePaginationParams(int $page, int $limit): array
    {
        $page = max(1, $page);
        $limit = max(1, min(100, $limit)); // Cap at 100 items per page
        
        return [$page, $limit];
    }

    /**
     * Example of a well-documented, type-safe repository method
     */
    public function findUsersPaginated(
        int $page = 1, 
        int $limit = 20,
        array $orderBy = ['name' => 'ASC']
    ): array {
        [$page, $limit] = $this->validatePaginationParams($page, $limit);
        
        $qb = $this->createUserQueryBuilder();
        
        foreach ($orderBy as $field => $direction) {
            $qb->addOrderBy("u.{$field}", $direction);
        }

        return $qb->setFirstResult(($page - 1) * $limit)
                  ->setMaxResults($limit)
                  ->getQuery()
                  ->getResult();
    }
}
</pre>

<div class="codehead">Repository Best Practices Summary
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="explanation">
Key repository best practices:

1. Use descriptive method names that clearly indicate their purpose
2. Always use parameter binding to prevent SQL injection
3. Implement proper error handling and validation
4. Use type hints and return types for better IDE support
5. Break complex queries into smaller, reusable methods
6. Implement pagination limits to prevent memory issues
7. Use query builders for dynamic queries, DQL for static ones
8. Document complex query logic with comments
9. Consider performance implications of each query
10. Write tests for complex repository methods
11. Use partial objects for large datasets
12. Implement proper caching strategies where appropriate
13. Use database indexes for frequently queried columns
14. Monitor query performance with profiling tools
15. Follow consistent naming conventions across repositories
</pre>

<p>
These best practices help create maintainable, efficient, and secure  
repository implementations that serve as a solid foundation for your  
Symfony applications. Regular code reviews and performance monitoring  
help ensure these practices are followed consistently across your  
codebase.  
</p>

<p>
In this comprehensive tutorial, we covered 25 practical examples of  
working with Symfony repositories, from basic CRUD operations to  
advanced optimization techniques. These patterns will help you build  
robust data access layers that scale with your application requirements.  
</p>

<p>
List <a href="/php/">all PHP</a> tutorials.
</p>


</div> <!-- content -->

</div> <!-- container -->

<footer>

<nav>
<a title="Home page" href="/">Home</a> 
<a title="Follow on Twitter" href="https://twitter.com/janbodnar">Twitter</a>
<a title="Visit Github" href="https://github.com/janbodnar">Github</a>
<a title="Subscribe to ZetCode news" href="http://zetcode.us13.list-manage.com/subscribe?u=9def9ccd4c70dbbaf691f90fc&id=6556210f80">Subscribe</a>
<a title="Privacy policy" href="/privacy">Privacy</a> 
<a title="About" href="/about/">About</a>
</nav>

<div>
<span>&copy; 2007 - 2025 Jan Bodnar</span>
<span>admin(at)zetcode.com</span>
</div>

</footer>


<script src="/cfg/utils.js"></script>
</body>
</html>