# Symfony Repositories

This comprehensive tutorial covers Symfony repositories with 25 practical  
examples, progressing from basic concepts to advanced query optimization  
techniques.  

Symfony repositories are part of Doctrine ORM and provide a centralized way  
to encapsulate database query logic. They act as collections of entities and  
offer methods to retrieve entities from the database in a clean and  
maintainable way.  

## Basic Repository Usage

Getting an entity repository and using built-in methods.  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    #[Route('/users', name: 'user_list')]
    public function list(EntityManagerInterface $entityManager): Response
    {
        $userRepository = $entityManager->getRepository(User::class);
        
        $users = $userRepository->findAll();
        
        return $this->json([
            'total' => count($users),
            'users' => array_map(fn($user) => [
                'id' => $user->getId(),
                'name' => $user->getName(),
                'email' => $user->getEmail()
            ], $users)
        ]);
    }
}
```

The `findAll()` method retrieves all entities from the database. Repository  
methods return arrays of entity objects that can be serialized or processed  
as needed.  

## Finding by Primary Key

Using the `find()` method to retrieve entities by their primary key.  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    #[Route('/user/{id}', name: 'user_show')]
    public function show(int $id, EntityManagerInterface $entityManager): Response
    {
        $userRepository = $entityManager->getRepository(User::class);
        
        $user = $userRepository->find($id);
        
        if (!$user) {
            return $this->json(['error' => 'User not found'], 404);
        }
        
        return $this->json([
            'id' => $user->getId(),
            'name' => $user->getName(),
            'email' => $user->getEmail(),
            'createdAt' => $user->getCreatedAt()->format('Y-m-d H:i:s')
        ]);
    }
}
```

The `find()` method returns the entity if found, or null if no entity with  
the given primary key exists. Always check for null to handle missing  
entities gracefully.  

## Finding by Criteria

Using `findBy()` and `findOneBy()` for more complex searches.  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    #[Route('/users/search', name: 'user_search')]
    public function search(Request $request, EntityManagerInterface $entityManager): Response
    {
        $userRepository = $entityManager->getRepository(User::class);
        
        $email = $request->query->get('email');
        $status = $request->query->get('status', 'active');
        
        if ($email) {
            // Find single user by email
            $user = $userRepository->findOneBy(['email' => $email]);
            
            if (!$user) {
                return $this->json(['error' => 'User not found'], 404);
            }
            
            return $this->json([
                'id' => $user->getId(),
                'name' => $user->getName(),
                'email' => $user->getEmail()
            ]);
        }
        
        // Find multiple users by status
        $users = $userRepository->findBy(
            ['status' => $status], 
            ['name' => 'ASC'], 
            10
        );
        
        return $this->json([
            'status' => $status,
            'users' => array_map(fn($user) => [
                'id' => $user->getId(),
                'name' => $user->getName(),
                'status' => $user->getStatus()
            ], $users)
        ]);
    }
}
```

The `findBy()` method accepts criteria, order, limit and offset parameters.  
Use `findOneBy()` when you expect only one result. Both methods return null  
or empty arrays when no results are found.  

## Repository Constructor Injection

Injecting repositories directly into controller constructors for cleaner code.  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    public function __construct(
        private UserRepository $userRepository
    ) {
    }
    
    #[Route('/users/active', name: 'active_users')]
    public function getActiveUsers(): Response
    {
        $users = $this->userRepository->findBy(['status' => 'active']);
        
        return $this->json([
            'count' => count($users),
            'users' => array_map(fn($user) => [
                'id' => $user->getId(),
                'name' => $user->getName(),
                'email' => $user->getEmail()
            ], $users)
        ]);
    }
    
    #[Route('/users/count', name: 'user_count')]
    public function countUsers(): Response
    {
        $total = $this->userRepository->count([]);
        $active = $this->userRepository->count(['status' => 'active']);
        $inactive = $this->userRepository->count(['status' => 'inactive']);
        
        return $this->json([
            'total' => $total,
            'active' => $active,
            'inactive' => $inactive
        ]);
    }
}
```

Constructor injection provides cleaner code and better testability. The  
`count()` method efficiently returns the number of entities matching the  
given criteria without loading them into memory.  

## Custom Repository Class

Creating custom repository classes to encapsulate domain-specific queries.  

**src/Repository/UserRepository.php**

```php
<?php

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

    public function findActiveUsers(): array
    {
        return $this->findBy(['status' => 'active'], ['name' => 'ASC']);
    }

    public function findByEmail(string $email): ?User
    {
        return $this->findOneBy(['email' => $email]);
    }

    public function findRecentUsers(int $days = 30): array
    {
        $date = new \DateTime();
        $date->modify("-{$days} days");
        
        return $this->createQueryBuilder('u')
            ->where('u.createdAt >= :date')
            ->setParameter('date', $date)
            ->orderBy('u.createdAt', 'DESC')
            ->getQuery()
            ->getResult();
    }
}
```

**src/Entity/User.php**

```php
<?php

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'users')]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private int $id;

    #[ORM\Column(length: 180, unique: true)]
    private string $email;

    #[ORM\Column(length: 100)]
    private string $name;

    #[ORM\Column(length: 20)]
    private string $status = 'active';

    #[ORM\Column]
    private \DateTimeImmutable $createdAt;

    public function __construct()
    {
        $this->createdAt = new \DateTimeImmutable();
    }

    // Getters and setters
    public function getId(): int
    {
        return $this->id;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): void
    {
        $this->email = $email;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function setStatus(string $status): void
    {
        $this->status = $status;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }
}
```

Custom repository classes extend `ServiceEntityRepository` and are  
automatically registered as services. They provide a centralized location  
for all queries related to a specific entity.  

## Query Builder Basics

Using the QueryBuilder for more complex queries with conditions.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findUsersByNamePattern(string $pattern): array
    {
        return $this->createQueryBuilder('u')
            ->where('u.name LIKE :pattern')
            ->setParameter('pattern', '%' . $pattern . '%')
            ->orderBy('u.name', 'ASC')
            ->getQuery()
            ->getResult();
    }

    public function findUsersWithComplexCriteria(
        ?string $status = null,
        ?\DateTime $createdAfter = null,
        int $limit = 20
    ): array {
        $qb = $this->createQueryBuilder('u');
        
        if ($status) {
            $qb->andWhere('u.status = :status')
               ->setParameter('status', $status);
        }
        
        if ($createdAfter) {
            $qb->andWhere('u.createdAt > :createdAfter')
               ->setParameter('createdAfter', $createdAfter);
        }
        
        return $qb->orderBy('u.createdAt', 'DESC')
                  ->setMaxResults($limit)
                  ->getQuery()
                  ->getResult();
    }

    public function getQueryBuilderForActiveUsers(): QueryBuilder
    {
        return $this->createQueryBuilder('u')
            ->where('u.status = :status')
            ->setParameter('status', 'active');
    }
}
```

QueryBuilder provides a fluent interface for building complex queries  
programmatically. Use parameter binding to prevent SQL injection attacks.  
The QueryBuilder can be reused and extended by calling methods.  

## Advanced Query Builder Methods

Exploring joins, aggregations, and subqueries with QueryBuilder.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use App\Entity\Post;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findUsersWithPostCount(): array
    {
        return $this->createQueryBuilder('u')
            ->select('u', 'COUNT(p.id) as postCount')
            ->leftJoin('u.posts', 'p')
            ->groupBy('u.id')
            ->having('COUNT(p.id) > 0')
            ->orderBy('postCount', 'DESC')
            ->getQuery()
            ->getResult();
    }

    public function findActiveUsersWithRecentPosts(int $days = 30): array
    {
        $date = new \DateTime();
        $date->modify("-{$days} days");
        
        return $this->createQueryBuilder('u')
            ->select('u')
            ->innerJoin('u.posts', 'p')
            ->where('u.status = :status')
            ->andWhere('p.createdAt >= :recentDate')
            ->setParameter('status', 'active')
            ->setParameter('recentDate', $date)
            ->groupBy('u.id')
            ->orderBy('u.name', 'ASC')
            ->getQuery()
            ->getResult();
    }

    public function findUsersWithoutPosts(): array
    {
        return $this->createQueryBuilder('u')
            ->leftJoin('u.posts', 'p')
            ->where('p.id IS NULL')
            ->getQuery()
            ->getResult();
    }

    public function getUserStatistics(): array
    {
        $result = $this->createQueryBuilder('u')
            ->select([
                'COUNT(u.id) as totalUsers',
                'COUNT(CASE WHEN u.status = \'active\' THEN 1 END) as activeUsers',
                'COUNT(CASE WHEN u.status = \'inactive\' THEN 1 END) as inactiveUsers'
            ])
            ->getQuery()
            ->getSingleResult();
        
        return [
            'total' => (int) $result['totalUsers'],
            'active' => (int) $result['activeUsers'],
            'inactive' => (int) $result['inactiveUsers']
        ];
    }
}
```

Advanced QueryBuilder features include joins, aggregations, and conditional  
expressions. Use LEFT JOIN for optional relationships and INNER JOIN for  
required ones. GROUP BY and HAVING clauses enable aggregated queries.  

## Using DQL (Doctrine Query Language)

Writing raw DQL queries for complex database operations.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\Query;
use Doctrine\Persistence\ManagerRegistry;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findUsersWithDQL(string $emailDomain): array
    {
        $dql = 'SELECT u FROM App\Entity\User u 
                WHERE u.email LIKE :domain 
                ORDER BY u.name ASC';
        
        return $this->getEntityManager()
            ->createQuery($dql)
            ->setParameter('domain', '%@' . $emailDomain)
            ->getResult();
    }

    public function getUserCountByStatus(): array
    {
        $dql = 'SELECT u.status, COUNT(u.id) as userCount 
                FROM App\Entity\User u 
                GROUP BY u.status 
                ORDER BY userCount DESC';
        
        return $this->getEntityManager()
            ->createQuery($dql)
            ->getResult();
    }

    public function findUsersByComplexDQL(
        array $statuses,
        int $minAge = 18
    ): array {
        $dql = 'SELECT u FROM App\Entity\User u 
                WHERE u.status IN (:statuses) 
                AND YEAR(CURRENT_DATE()) - YEAR(u.birthDate) >= :minAge
                ORDER BY u.createdAt DESC';
        
        return $this->getEntityManager()
            ->createQuery($dql)
            ->setParameter('statuses', $statuses)
            ->setParameter('minAge', $minAge)
            ->setMaxResults(50)
            ->getResult();
    }

    public function executeCustomDQLQuery(string $dql, array $parameters = []): mixed
    {
        $query = $this->getEntityManager()->createQuery($dql);
        
        foreach ($parameters as $key => $value) {
            $query->setParameter($key, $value);
        }
        
        return $query->getResult();
    }
}
```

DQL (Doctrine Query Language) is similar to SQL but works with entities  
instead of tables. It provides more flexibility than QueryBuilder for  
complex queries and allows direct control over the generated SQL.  

## Repository with Pagination

Implementing efficient pagination using Doctrine's Paginator.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\Tools\Pagination\Paginator;
use Doctrine\Persistence\ManagerRegistry;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findPaginatedUsers(
        int $page = 1,
        int $limit = 10,
        ?string $status = null
    ): Paginator {
        $qb = $this->createQueryBuilder('u');
        
        if ($status) {
            $qb->where('u.status = :status')
               ->setParameter('status', $status);
        }
        
        $qb->orderBy('u.createdAt', 'DESC')
           ->setFirstResult(($page - 1) * $limit)
           ->setMaxResults($limit);
        
        return new Paginator($qb->getQuery());
    }

    public function getPaginatedUserData(int $page = 1, int $limit = 10): array
    {
        $paginator = $this->findPaginatedUsers($page, $limit);
        
        $totalItems = count($paginator);
        $totalPages = (int) ceil($totalItems / $limit);
        
        return [
            'users' => iterator_to_array($paginator),
            'pagination' => [
                'currentPage' => $page,
                'totalPages' => $totalPages,
                'totalItems' => $totalItems,
                'itemsPerPage' => $limit,
                'hasNextPage' => $page < $totalPages,
                'hasPreviousPage' => $page > 1
            ]
        ];
    }

    public function searchWithPagination(
        string $searchTerm,
        int $page = 1,
        int $limit = 10
    ): array {
        $qb = $this->createQueryBuilder('u')
            ->where('u.name LIKE :search OR u.email LIKE :search')
            ->setParameter('search', '%' . $searchTerm . '%')
            ->orderBy('u.name', 'ASC')
            ->setFirstResult(($page - 1) * $limit)
            ->setMaxResults($limit);
        
        $paginator = new Paginator($qb->getQuery());
        
        return [
            'results' => iterator_to_array($paginator),
            'total' => count($paginator),
            'page' => $page,
            'limit' => $limit
        ];
    }
}
```

**Controller usage example:**

```php
<?php

namespace App\Controller;

use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    #[Route('/users/paginated', name: 'users_paginated')]
    public function paginatedUsers(
        Request $request,
        UserRepository $userRepository
    ): Response {
        $page = $request->query->getInt('page', 1);
        $limit = $request->query->getInt('limit', 10);
        
        $data = $userRepository->getPaginatedUserData($page, $limit);
        
        return $this->json($data);
    }
}
```

Doctrine's Paginator efficiently handles large datasets by calculating  
totals without loading all records into memory. Always validate page and  
limit parameters to prevent abuse.  

## Repository with Caching

Implementing query result caching for better performance.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\Query;
use Doctrine\Persistence\ManagerRegistry;
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

    public function findActiveUsersCached(int $ttl = 3600): array
    {
        return $this->cache->get('active_users', function (ItemInterface $item) use ($ttl) {
            $item->expiresAfter($ttl);
            
            return $this->createQueryBuilder('u')
                ->where('u.status = :status')
                ->setParameter('status', 'active')
                ->orderBy('u.name', 'ASC')
                ->getQuery()
                ->enableResultCache(3600, 'active_users_result')
                ->getResult();
        });
    }

    public function getUserStatisticsCached(): array
    {
        return $this->cache->get('user_statistics', function (ItemInterface $item) {
            $item->expiresAfter(1800); // 30 minutes
            
            $result = $this->createQueryBuilder('u')
                ->select([
                    'COUNT(u.id) as total',
                    'COUNT(CASE WHEN u.status = \'active\' THEN 1 END) as active',
                    'AVG(YEAR(CURRENT_DATE()) - YEAR(u.createdAt)) as avgAge'
                ])
                ->getQuery()
                ->enableResultCache(1800, 'user_stats_result')
                ->getSingleResult();
                
            return [
                'total' => (int) $result['total'],
                'active' => (int) $result['active'],
                'averageAge' => round((float) $result['avgAge'], 1)
            ];
        });
    }

    public function findUserByEmailCached(string $email): ?User
    {
        $cacheKey = 'user_email_' . md5($email);
        
        return $this->cache->get($cacheKey, function (ItemInterface $item) use ($email) {
            $item->expiresAfter(3600);
            
            return $this->createQueryBuilder('u')
                ->where('u.email = :email')
                ->setParameter('email', $email)
                ->getQuery()
                ->enableResultCache(3600, $item->getKey())
                ->getOneOrNullResult();
        });
    }

    public function invalidateUserCaches(): void
    {
        $this->cache->delete('active_users');
        $this->cache->delete('user_statistics');
        
        // Clear Doctrine result cache
        $this->getEntityManager()
             ->getConfiguration()
             ->getResultCache()
             ->clear();
    }
}
```

Result caching improves performance by storing query results temporarily.  
Use appropriate TTL (time-to-live) values based on data freshness  
requirements. Remember to invalidate caches when data changes.  

## Repository Event Integration

Using Symfony events with repository operations for loose coupling.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use App\Event\UserCreatedEvent;
use App\Event\UserUpdatedEvent;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(
        ManagerRegistry $registry,
        private EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($registry, User::class);
    }

    public function saveUser(User $user, bool $isNew = false): User
    {
        $this->getEntityManager()->persist($user);
        $this->getEntityManager()->flush();
        
        if ($isNew) {
            $this->eventDispatcher->dispatch(
                new UserCreatedEvent($user),
                UserCreatedEvent::NAME
            );
        } else {
            $this->eventDispatcher->dispatch(
                new UserUpdatedEvent($user),
                UserUpdatedEvent::NAME
            );
        }
        
        return $user;
    }

    public function findOrCreateUser(string $email, string $name): User
    {
        $user = $this->findOneBy(['email' => $email]);
        
        if (!$user) {
            $user = new User();
            $user->setEmail($email);
            $user->setName($name);
            
            return $this->saveUser($user, true);
        }
        
        return $user;
    }

    public function bulkUpdateStatus(array $userIds, string $status): int
    {
        $updated = $this->createQueryBuilder('u')
            ->update()
            ->set('u.status', ':status')
            ->where('u.id IN (:ids)')
            ->setParameter('status', $status)
            ->setParameter('ids', $userIds)
            ->getQuery()
            ->execute();
        
        // Dispatch event for bulk update
        $this->eventDispatcher->dispatch(
            new UserUpdatedEvent(null, $userIds, $status),
            UserUpdatedEvent::BULK_NAME
        );
        
        return $updated;
    }
}
```

**Event classes:**

```php
<?php

namespace App\Event;

use App\Entity\User;
use Symfony\Contracts\EventDispatcher\Event;

class UserCreatedEvent extends Event
{
    public const NAME = 'user.created';
    
    public function __construct(private User $user)
    {
    }
    
    public function getUser(): User
    {
        return $this->user;
    }
}

class UserUpdatedEvent extends Event
{
    public const NAME = 'user.updated';
    public const BULK_NAME = 'user.bulk_updated';
    
    public function __construct(
        private ?User $user = null,
        private ?array $userIds = null,
        private ?string $status = null
    ) {
    }
    
    public function getUser(): ?User
    {
        return $this->user;
    }
    
    public function getUserIds(): ?array
    {
        return $this->userIds;
    }
    
    public function getStatus(): ?string
    {
        return $this->status;
    }
}
```

Event integration allows decoupling of business logic from repository  
operations. Other parts of the application can listen to these events  
without modifying the repository code directly.  

## Repository with Validation

Adding data validation and business rules within repository methods.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use App\Exception\UserValidationException;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(
        ManagerRegistry $registry,
        private ValidatorInterface $validator
    ) {
        parent::__construct($registry, User::class);
    }

    public function createValidatedUser(array $userData): User
    {
        $user = new User();
        $user->setEmail($userData['email'] ?? '');
        $user->setName($userData['name'] ?? '');
        
        if (isset($userData['status'])) {
            $user->setStatus($userData['status']);
        }
        
        // Validate entity
        $violations = $this->validator->validate($user);
        
        if (count($violations) > 0) {
            $errors = [];
            foreach ($violations as $violation) {
                $errors[] = $violation->getMessage();
            }
            throw new UserValidationException('Validation failed: ' . implode(', ', $errors));
        }
        
        // Business rule validation
        $this->validateBusinessRules($user);
        
        $this->getEntityManager()->persist($user);
        $this->getEntityManager()->flush();
        
        return $user;
    }

    public function updateUserSafely(int $userId, array $updateData): User
    {
        $user = $this->find($userId);
        
        if (!$user) {
            throw new UserValidationException('User not found');
        }
        
        // Store original values for rollback
        $originalName = $user->getName();
        $originalStatus = $user->getStatus();
        
        try {
            if (isset($updateData['name'])) {
                $user->setName($updateData['name']);
            }
            
            if (isset($updateData['status'])) {
                $user->setStatus($updateData['status']);
            }
            
            // Validate updated entity
            $violations = $this->validator->validate($user);
            
            if (count($violations) > 0) {
                throw new UserValidationException('Update validation failed');
            }
            
            $this->validateBusinessRules($user);
            
            $this->getEntityManager()->flush();
            
            return $user;
            
        } catch (\Exception $e) {
            // Rollback changes
            $user->setName($originalName);
            $user->setStatus($originalStatus);
            throw $e;
        }
    }

    private function validateBusinessRules(User $user): void
    {
        // Check for duplicate email
        if ($this->isDuplicateEmail($user)) {
            throw new UserValidationException('Email already exists');
        }
        
        // Validate status transitions
        if (!$this->isValidStatusTransition($user)) {
            throw new UserValidationException('Invalid status transition');
        }
    }

    private function isDuplicateEmail(User $user): bool
    {
        $qb = $this->createQueryBuilder('u')
            ->where('u.email = :email')
            ->setParameter('email', $user->getEmail());
        
        if ($user->getId()) {
            $qb->andWhere('u.id != :id')
               ->setParameter('id', $user->getId());
        }
        
        return $qb->getQuery()->getOneOrNullResult() !== null;
    }

    private function isValidStatusTransition(User $user): bool
    {
        $allowedTransitions = [
            'active' => ['inactive', 'suspended'],
            'inactive' => ['active'],
            'suspended' => ['active', 'inactive']
        ];
        
        $currentStatus = $user->getStatus();
        
        return isset($allowedTransitions[$currentStatus]);
    }
}
```

Repository validation ensures data integrity at the persistence layer.  
Combine Symfony's validator with custom business rules for comprehensive  
data validation. Always handle validation exceptions gracefully.  

## Repository Testing

Writing comprehensive tests for repository methods and queries.  

```php
<?php

namespace App\Tests\Repository;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class UserRepositoryTest extends KernelTestCase
{
    private EntityManagerInterface $entityManager;
    private UserRepository $userRepository;

    protected function setUp(): void
    {
        $kernel = self::bootKernel();
        
        $this->entityManager = $kernel->getContainer()
            ->get('doctrine')
            ->getManager();
            
        $this->userRepository = $this->entityManager
            ->getRepository(User::class);
    }

    public function testFindActiveUsers(): void
    {
        // Create test data
        $activeUser = new User();
        $activeUser->setEmail('active@example.com');
        $activeUser->setName('Active User');
        $activeUser->setStatus('active');
        
        $inactiveUser = new User();
        $inactiveUser->setEmail('inactive@example.com');
        $inactiveUser->setName('Inactive User');
        $inactiveUser->setStatus('inactive');
        
        $this->entityManager->persist($activeUser);
        $this->entityManager->persist($inactiveUser);
        $this->entityManager->flush();
        
        // Test the repository method
        $activeUsers = $this->userRepository->findActiveUsers();
        
        $this->assertCount(1, $activeUsers);
        $this->assertEquals('active', $activeUsers[0]->getStatus());
        $this->assertEquals('Active User', $activeUsers[0]->getName());
    }

    public function testFindRecentUsers(): void
    {
        // Create users with different creation dates
        $recentUser = new User();
        $recentUser->setEmail('recent@example.com');
        $recentUser->setName('Recent User');
        $recentUser->setCreatedAt(new \DateTimeImmutable('-5 days'));
        
        $oldUser = new User();
        $oldUser->setEmail('old@example.com');
        $oldUser->setName('Old User');
        $oldUser->setCreatedAt(new \DateTimeImmutable('-40 days'));
        
        $this->entityManager->persist($recentUser);
        $this->entityManager->persist($oldUser);
        $this->entityManager->flush();
        
        // Test with default 30 days
        $recentUsers = $this->userRepository->findRecentUsers(30);
        
        $this->assertCount(1, $recentUsers);
        $this->assertEquals('Recent User', $recentUsers[0]->getName());
    }

    public function testCountUsersByStatus(): void
    {
        $this->createTestUsers();
        
        $totalCount = $this->userRepository->count([]);
        $activeCount = $this->userRepository->count(['status' => 'active']);
        $inactiveCount = $this->userRepository->count(['status' => 'inactive']);
        
        $this->assertGreaterThan(0, $totalCount);
        $this->assertGreaterThan(0, $activeCount);
        $this->assertEquals($totalCount, $activeCount + $inactiveCount);
    }

    public function testCustomQueryBuilderMethods(): void
    {
        $this->createTestUsers();
        
        // Test pattern search
        $users = $this->userRepository->findUsersByNamePattern('Test');
        $this->assertNotEmpty($users);
        
        // Test complex criteria
        $users = $this->userRepository->findUsersWithComplexCriteria(
            'active',
            new \DateTime('-1 year'),
            5
        );
        
        $this->assertLessThanOrEqual(5, count($users));
    }

    private function createTestUsers(): void
    {
        for ($i = 1; $i <= 10; $i++) {
            $user = new User();
            $user->setEmail("test{$i}@example.com");
            $user->setName("Test User {$i}");
            $user->setStatus($i % 2 === 0 ? 'active' : 'inactive');
            
            $this->entityManager->persist($user);
        }
        
        $this->entityManager->flush();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        
        // Clean up database
        $this->entityManager->close();
        $this->entityManager = null;
    }
}
```

Repository testing ensures query correctness and business logic validation.  
Use KernelTestCase for integration tests with real database connections.  
Always clean up test data to maintain test isolation.  

## Repository Performance Optimization

Implementing performance best practices and query optimization techniques.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use App\Entity\Post;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\Query;
use Doctrine\Persistence\ManagerRegistry;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    // Avoid N+1 queries with eager loading
    public function findUsersWithPostsOptimized(): array
    {
        return $this->createQueryBuilder('u')
            ->select('u', 'p') // Select both user and posts
            ->leftJoin('u.posts', 'p')
            ->where('u.status = :status')
            ->setParameter('status', 'active')
            ->getQuery()
            ->getResult();
    }

    // Use partial objects for large datasets
    public function findUsersPartialData(): array
    {
        return $this->createQueryBuilder('u')
            ->select('partial u.{id, name, email}') // Only select needed fields
            ->where('u.status = :status')
            ->setParameter('status', 'active')
            ->getQuery()
            ->getResult();
    }

    // Batch processing for large operations
    public function batchUpdateUserStatus(array $userIds, string $status): void
    {
        $batchSize = 100;
        $batches = array_chunk($userIds, $batchSize);
        
        foreach ($batches as $batch) {
            $this->createQueryBuilder('u')
                ->update()
                ->set('u.status', ':status')
                ->where('u.id IN (:ids)')
                ->setParameter('status', $status)
                ->setParameter('ids', $batch)
                ->getQuery()
                ->execute();
        }
    }

    // Efficient counting without loading entities
    public function getAdvancedStatistics(): array
    {
        $result = $this->createQueryBuilder('u')
            ->select([
                'COUNT(u.id) as totalUsers',
                'COUNT(CASE WHEN u.status = \'active\' THEN 1 END) as activeUsers',
                'COUNT(CASE WHEN u.createdAt >= :thisMonth THEN 1 END) as newThisMonth',
                'AVG(CASE WHEN u.status = \'active\' THEN 
                    DATEDIFF(CURRENT_DATE(), u.createdAt) END) as avgActiveDays'
            ])
            ->setParameter('thisMonth', new \DateTime('first day of this month'))
            ->getQuery()
            ->getSingleResult();
        
        return [
            'total' => (int) $result['totalUsers'],
            'active' => (int) $result['activeUsers'],
            'newThisMonth' => (int) $result['newThisMonth'],
            'averageActiveDays' => round((float) $result['avgActiveDays'], 1)
        ];
    }

    // Index hints for complex queries
    public function findUsersWithIndexHint(string $emailPattern): array
    {
        $rsm = new \Doctrine\ORM\Query\ResultSetMapping();
        $rsm->addEntityResult(User::class, 'u');
        $rsm->addFieldResult('u', 'id', 'id');
        $rsm->addFieldResult('u', 'email', 'email');
        $rsm->addFieldResult('u', 'name', 'name');
        $rsm->addFieldResult('u', 'status', 'status');
        
        $sql = 'SELECT u.id, u.email, u.name, u.status 
                FROM users u USE INDEX (idx_email) 
                WHERE u.email LIKE ? 
                ORDER BY u.email';
        
        return $this->getEntityManager()
            ->createNativeQuery($sql, $rsm)
            ->setParameter(1, $emailPattern . '%')
            ->getResult();
    }

    // Memory-efficient iteration for large datasets
    public function iterateAllUsers(): \Iterator
    {
        $query = $this->createQueryBuilder('u')
            ->getQuery();
        
        return $query->toIterable();
    }

    // Optimized search with full-text capabilities
    public function searchUsersOptimized(
        string $searchTerm,
        int $limit = 50
    ): array {
        return $this->createQueryBuilder('u')
            ->select('u')
            ->where('MATCH(u.name, u.email) AGAINST (:searchTerm IN BOOLEAN MODE) > 0')
            ->orWhere('u.name LIKE :likeTerm')
            ->orWhere('u.email LIKE :likeTerm')
            ->setParameter('searchTerm', $searchTerm)
            ->setParameter('likeTerm', '%' . $searchTerm . '%')
            ->orderBy('u.name', 'ASC')
            ->setMaxResults($limit)
            ->getQuery()
            ->getResult();
    }

    // Connection-level optimization
    public function executeOptimizedQuery(string $sql, array $params = []): array
    {
        $connection = $this->getEntityManager()->getConnection();
        
        // Use prepared statements for repeated queries
        $stmt = $connection->prepare($sql);
        
        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value);
        }
        
        return $stmt->executeQuery()->fetchAllAssociative();
    }
}
```

Performance optimization in repositories focuses on minimizing database  
calls, reducing memory usage, and leveraging database-specific features.  
Always profile queries and monitor performance in production environments.  

## Repository with Soft Deletes

Implementing soft delete functionality with repository methods.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    // Override findAll to exclude soft-deleted records
    public function findAll(): array
    {
        return $this->findBy(['deletedAt' => null]);
    }

    // Override find to exclude soft-deleted records
    public function find($id, $lockMode = null, $lockVersion = null): ?User
    {
        return $this->findOneBy(['id' => $id, 'deletedAt' => null]);
    }

    // Custom method to find all including soft-deleted
    public function findAllWithDeleted(): array
    {
        return parent::findAll();
    }

    // Find only soft-deleted records
    public function findDeleted(): array
    {
        return $this->createQueryBuilder('u')
            ->where('u.deletedAt IS NOT NULL')
            ->orderBy('u.deletedAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    // Soft delete a user
    public function softDelete(User $user): void
    {
        $user->setDeletedAt(new \DateTimeImmutable());
        $this->getEntityManager()->flush();
    }

    // Restore a soft-deleted user
    public function restore(User $user): void
    {
        $user->setDeletedAt(null);
        $this->getEntityManager()->flush();
    }

    // Hard delete (permanently remove)
    public function hardDelete(User $user): void
    {
        $this->getEntityManager()->remove($user);
        $this->getEntityManager()->flush();
    }

    // Bulk soft delete
    public function bulkSoftDelete(array $userIds): int
    {
        return $this->createQueryBuilder('u')
            ->update()
            ->set('u.deletedAt', ':deletedAt')
            ->where('u.id IN (:ids)')
            ->andWhere('u.deletedAt IS NULL')
            ->setParameter('deletedAt', new \DateTimeImmutable())
            ->setParameter('ids', $userIds)
            ->getQuery()
            ->execute();
    }

    // Clean up old soft-deleted records
    public function cleanupOldDeleted(int $daysOld = 30): int
    {
        $cutoffDate = new \DateTimeImmutable("-{$daysOld} days");
        
        return $this->createQueryBuilder('u')
            ->delete()
            ->where('u.deletedAt IS NOT NULL')
            ->andWhere('u.deletedAt < :cutoffDate')
            ->setParameter('cutoffDate', $cutoffDate)
            ->getQuery()
            ->execute();
    }

    // Override createQueryBuilder to automatically exclude soft-deleted
    public function createQueryBuilder($alias, $indexBy = null): QueryBuilder
    {
        $qb = parent::createQueryBuilder($alias, $indexBy);
        $qb->andWhere($alias . '.deletedAt IS NULL');
        
        return $qb;
    }

    // Create query builder that includes soft-deleted records
    public function createQueryBuilderWithDeleted($alias, $indexBy = null): QueryBuilder
    {
        return parent::createQueryBuilder($alias, $indexBy);
    }

    // Statistics including soft-deleted records
    public function getDeletedStatistics(): array
    {
        $result = $this->createQueryBuilderWithDeleted('u')
            ->select([
                'COUNT(u.id) as totalUsers',
                'COUNT(CASE WHEN u.deletedAt IS NULL THEN 1 END) as activeUsers',
                'COUNT(CASE WHEN u.deletedAt IS NOT NULL THEN 1 END) as deletedUsers'
            ])
            ->getQuery()
            ->getSingleResult();
        
        return [
            'total' => (int) $result['totalUsers'],
            'active' => (int) $result['activeUsers'],
            'deleted' => (int) $result['deletedUsers']
        ];
    }
}
```

**Updated User entity with soft delete support:**

```php
<?php

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'users')]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private int $id;

    #[ORM\Column(length: 180, unique: true)]
    private string $email;

    #[ORM\Column(length: 100)]
    private string $name;

    #[ORM\Column(length: 20)]
    private string $status = 'active';

    #[ORM\Column]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(nullable: true)]
    private ?\DateTimeImmutable $deletedAt = null;

    public function __construct()
    {
        $this->createdAt = new \DateTimeImmutable();
    }

    // ... existing getters and setters

    public function getDeletedAt(): ?\DateTimeImmutable
    {
        return $this->deletedAt;
    }

    public function setDeletedAt(?\DateTimeImmutable $deletedAt): void
    {
        $this->deletedAt = $deletedAt;
    }

    public function isDeleted(): bool
    {
        return $this->deletedAt !== null;
    }
}
```

Soft deletes preserve data while hiding deleted records from normal queries.  
This approach maintains referential integrity and allows for data recovery.  
Remember to handle soft deletes consistently across all repository methods.  

## Repository with Multiple Databases

Managing repositories across multiple database connections.  

```php
<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class UserRepository extends ServiceEntityRepository
{
    private $readOnlyEntityManager;
    
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
        
        // Get read-only connection for queries
        $this->readOnlyEntityManager = $registry->getManager('readonly');
    }

    // Read operations from read-only database
    public function findForReporting(): array
    {
        return $this->readOnlyEntityManager
            ->getRepository(User::class)
            ->createQueryBuilder('u')
            ->select('u.id, u.name, u.email, u.createdAt')
            ->where('u.status = :status')
            ->setParameter('status', 'active')
            ->orderBy('u.createdAt', 'DESC')
            ->getQuery()
            ->getArrayResult();
    }

    // Heavy analytics queries on read replica
    public function getAnalyticsData(\DateTime $startDate, \DateTime $endDate): array
    {
        return $this->readOnlyEntityManager
            ->getRepository(User::class)
            ->createQueryBuilder('u')
            ->select([
                'COUNT(u.id) as totalUsers',
                'COUNT(CASE WHEN u.status = \'active\' THEN 1 END) as activeUsers',
                'DATE(u.createdAt) as registrationDate',
                'COUNT(CASE WHEN DATE(u.createdAt) = CURRENT_DATE() THEN 1 END) as todayRegistrations'
            ])
            ->where('u.createdAt BETWEEN :start AND :end')
            ->setParameter('start', $startDate)
            ->setParameter('end', $endDate)
            ->groupBy('registrationDate')
            ->orderBy('registrationDate', 'ASC')
            ->getQuery()
            ->getArrayResult();
    }

    // Write operations on primary database
    public function createUser(array $userData): User
    {
        $user = new User();
        $user->setEmail($userData['email']);
        $user->setName($userData['name']);
        
        // Use primary entity manager for writes
        $this->getEntityManager()->persist($user);
        $this->getEntityManager()->flush();
        
        return $user;
    }

    // Archive old users to separate database
    public function archiveOldUsers(int $monthsOld = 24): int
    {
        $cutoffDate = new \DateTime("-{$monthsOld} months");
        
        // Get users to archive
        $usersToArchive = $this->createQueryBuilder('u')
            ->where('u.createdAt < :cutoffDate')
            ->andWhere('u.status = :status')
            ->setParameter('cutoffDate', $cutoffDate)
            ->setParameter('status', 'inactive')
            ->getQuery()
            ->getResult();
        
        $archivedCount = 0;
        $archiveEntityManager = $this->getManagerRegistry()
            ->getManager('archive');
        
        foreach ($usersToArchive as $user) {
            // Clone to archive database
            $archiveUser = clone $user;
            $archiveEntityManager->persist($archiveUser);
            
            // Remove from primary database
            $this->getEntityManager()->remove($user);
            $archivedCount++;
        }
        
        $archiveEntityManager->flush();
        $this->getEntityManager()->flush();
        
        return $archivedCount;
    }

    // Cross-database synchronization
    public function synchronizeWithExternal(): array
    {
        $externalEntityManager = $this->getManagerRegistry()
            ->getManager('external');
        
        $externalUsers = $externalEntityManager
            ->getRepository(User::class)
            ->createQueryBuilder('u')
            ->where('u.syncStatus = :status')
            ->setParameter('status', 'pending')
            ->getQuery()
            ->getResult();
        
        $synchronized = [];
        
        foreach ($externalUsers as $externalUser) {
            $localUser = $this->findOneBy(['email' => $externalUser->getEmail()]);
            
            if (!$localUser) {
                // Create new user in local database
                $localUser = new User();
                $localUser->setEmail($externalUser->getEmail());
                $localUser->setName($externalUser->getName());
                
                $this->getEntityManager()->persist($localUser);
                $synchronized[] = $localUser;
            }
        }
        
        $this->getEntityManager()->flush();
        
        return $synchronized;
    }

    // Database health check
    public function checkDatabaseHealth(): array
    {
        $health = [];
        
        try {
            // Check primary database
            $this->getEntityManager()->getConnection()->connect();
            $health['primary'] = 'connected';
        } catch (\Exception $e) {
            $health['primary'] = 'failed: ' . $e->getMessage();
        }
        
        try {
            // Check read-only database
            $this->readOnlyEntityManager->getConnection()->connect();
            $health['readonly'] = 'connected';
        } catch (\Exception $e) {
            $health['readonly'] = 'failed: ' . $e->getMessage();
        }
        
        return $health;
    }
    
    private function getManagerRegistry(): ManagerRegistry
    {
        return $this->getEntityManager()->getConfiguration()->getManagerRegistry();
    }
}
```

**Database configuration example (config/packages/doctrine.yaml):**

```yaml
doctrine:
    dbal:
        default_connection: primary
        connections:
            primary:
                url: '%env(DATABASE_URL)%'
                driver: 'pdo_mysql'
            readonly:
                url: '%env(READONLY_DATABASE_URL)%'
                driver: 'pdo_mysql'
            archive:
                url: '%env(ARCHIVE_DATABASE_URL)%'
                driver: 'pdo_mysql'
    orm:
        default_entity_manager: primary
        entity_managers:
            primary:
                connection: primary
                mappings:
                    App:
                        is_bundle: false
                        dir: '%kernel.project_dir%/src/Entity'
                        prefix: 'App\Entity'
            readonly:
                connection: readonly
                mappings:
                    App:
                        is_bundle: false
                        dir: '%kernel.project_dir%/src/Entity'
                        prefix: 'App\Entity'
            archive:
                connection: archive
                mappings:
                    App:
                        is_bundle: false
                        dir: '%kernel.project_dir%/src/Entity'
                        prefix: 'App\Entity'
```

Multiple database support enables read/write splitting, data archiving,  
and integration with external systems. Each entity manager should be used  
for its specific purpose to maintain data consistency.  

## Conclusion

This tutorial covered 25 comprehensive examples of Symfony repositories,  
from basic usage to advanced optimization techniques.  

Key takeaways:  
- Use repository injection for cleaner, testable code  
- Leverage QueryBuilder for complex queries with better maintainability  
- Implement caching strategies for frequently accessed data  
- Add proper validation and error handling to repository methods  
- Optimize queries to prevent N+1 problems and reduce memory usage  
- Use events for loose coupling between repository operations and business logic  
- Test repository methods thoroughly with realistic data scenarios  
- Consider soft deletes for data preservation and audit trails  
- Implement multiple database strategies for scaling and data management  

Symfony repositories provide a powerful abstraction layer that makes  
database operations both efficient and maintainable when implemented with  
these best practices and patterns.  