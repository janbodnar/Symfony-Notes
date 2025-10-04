
# Symfony bin/console Command Guide

This comprehensive guide covers Symfony's bin/console command-line tool,  
from foundational concepts to advanced usage patterns. Learn how to leverage  
the Console component for development, debugging, and maintenance tasks.  

## What is bin/console?

The `bin/console` command is Symfony's command-line interface (CLI) that  
provides access to hundreds of built-in commands for managing, debugging,  
and developing Symfony applications. It serves as the primary tool for  
interacting with your application outside of web requests.  

Located in the `bin/` directory of every Symfony project, this executable  
PHP script acts as the entry point for all console operations. It leverages  
Symfony's Console component to provide a consistent, user-friendly interface  
for executing tasks that would be cumbersome or impossible through a web  
browser.  

### Core Functionality

**Application Management**: The console provides commands for clearing  
caches, warming up services, checking application status, and managing  
application lifecycle. These operations are essential for deployment and  
maintenance workflows.  

**Database Operations**: Through Doctrine integration, bin/console offers  
comprehensive database management capabilities including schema creation,  
migrations, query execution, and fixture loading. Developers can manage  
entire database lifecycles without leaving the terminal.  

**Code Generation**: MakerBundle commands accessible through bin/console  
automate boilerplate code creation for controllers, entities, forms, and  
more. This accelerates development and ensures consistency across the  
codebase.  

**Debugging Tools**: Debug commands expose internal application state,  
configuration values, service definitions, routing information, and event  
listeners. These tools are invaluable for troubleshooting and understanding  
application behavior.  

**Asset Management**: Commands for managing JavaScript dependencies,  
compiling assets, and optimizing frontend resources integrate seamlessly  
with Symfony's AssetMapper component.  

### Role in Symfony Development

**Development Workflow**: During development, bin/console commands are used  
constantly for creating entities, generating migrations, clearing caches,  
and debugging configuration. These commands streamline repetitive tasks and  
reduce context switching.  

**Testing Environment**: Console commands prepare test databases, load  
fixtures, and run validation checks. They enable automated testing workflows  
and continuous integration pipelines.  

**Production Deployment**: Deployment scripts leverage console commands for  
cache warming, asset compilation, database migrations, and application  
health checks. These commands ensure smooth, repeatable deployments.  

**Maintenance Operations**: Scheduled console commands handle background  
tasks like cleaning up old data, sending notifications, processing queues,  
and generating reports. They extend application functionality beyond web  
requests.  

### Console Component Integration

The Console component provides the foundation for bin/console functionality.  
It offers a robust framework for creating custom commands with features like:  

**Input Handling**: The component parses command-line arguments and options  
using InputInterface, providing type-safe access to user input. It supports  
required arguments, optional arguments, flags, and options with values.  

**Output Formatting**: OutputInterface and SymfonyStyle classes enable rich  
console output with colors, tables, progress bars, and formatted messages.  
This creates professional, user-friendly command-line experiences.  

**Command Registration**: Commands are automatically discovered and  
registered through Symfony's service container. The AsCommand attribute  
marks classes as console commands, making them available instantly.  

**Lifecycle Hooks**: Commands support initialization, interaction, and  
execution phases, allowing validation, user prompts, and complex workflows.  
Error handling and exit codes integrate with shell environments.  

**Dependency Injection**: Console commands are services, enabling full  
access to application dependencies. Commands can inject repositories,  
managers, mailers, and any other service needed for their operations.  

### Architecture and Design

bin/console follows a simple but powerful architecture. The executable  
script bootstraps the Symfony kernel, creates a Console Application instance,  
and registers all available commands. When executed, it parses the command  
name and arguments, locates the corresponding Command class, and executes  
its logic.  

This architecture separates concerns effectively. The Console component  
handles input/output and command lifecycle. The Kernel provides dependency  
injection and service access. Individual Command classes contain business  
logic. This separation enables testing, reusability, and maintainability.  

### Extending bin/console

Developers can create custom commands to automate project-specific tasks.  
Whether importing data from external APIs, generating reports, or performing  
cleanup operations, custom commands integrate seamlessly with bin/console.  

Third-party bundles extend functionality by registering their own commands.  
This plugin architecture makes bin/console infinitely extensible while  
maintaining a consistent user interface.  

## Built-in Console Commands Reference

The following table categorizes Symfony's most commonly used built-in  
commands. These commands are available in standard Symfony installations  
with commonly used bundles.  

### Cache Commands

| Command | Description |
|---------|-------------|
| `cache:clear` | Clears and warms up the application cache |
| `cache:warmup` | Warms up an empty cache |
| `cache:pool:clear` | Clears cache pools |
| `cache:pool:prune` | Prunes cache pools |
| `cache:pool:delete` | Deletes an item from a cache pool |
| `cache:pool:list` | Lists available cache pools |

### Configuration Commands

| Command | Description |
|---------|-------------|
| `config:dump-reference` | Dumps the default configuration for an extension |
| `debug:config` | Dumps the current configuration for an extension |
| `debug:container` | Displays configured services for the application |
| `debug:autowiring` | Lists classes/interfaces for autowiring |
| `debug:dotenv` | Lists all dotenv files with variables and values |

### Debug Commands

| Command | Description |
|---------|-------------|
| `debug:router` | Displays current routes for the application |
| `debug:event-dispatcher` | Displays configured listeners for the application |
| `debug:firewall` | Displays security firewall information |
| `debug:form` | Displays form type information |
| `debug:twig` | Shows a list of twig functions, filters, globals and tests |
| `debug:messenger` | Lists messages you can dispatch using messenger |
| `debug:validator` | Displays validation constraints for classes |

### Doctrine Commands

| Command | Description |
|---------|-------------|
| `doctrine:database:create` | Creates the configured database |
| `doctrine:database:drop` | Drops the configured database |
| `doctrine:schema:create` | Creates database schema based on entities |
| `doctrine:schema:update` | Updates database schema based on entity changes |
| `doctrine:schema:validate` | Validates the mapping files and database schema |
| `doctrine:migrations:migrate` | Executes migration files to update schema |
| `doctrine:migrations:diff` | Generates migration by comparing schemas |
| `doctrine:query:sql` | Executes arbitrary SQL from command line |
| `doctrine:fixtures:load` | Loads data fixtures to database |
| `doctrine:mapping:info` | Shows all mapped entities and their classes |

### Maker Commands

| Command | Description |
|---------|-------------|
| `make:command` | Creates a new console command class |
| `make:controller` | Creates a new controller class |
| `make:entity` | Creates or updates a Doctrine entity class |
| `make:form` | Creates a new form class |
| `make:migration` | Creates a new migration based on database changes |
| `make:crud` | Creates CRUD operations for a Doctrine entity |
| `make:auth` | Creates a Guard authenticator of various types |
| `make:registration-form` | Creates a registration form and controller |
| `make:fixtures` | Creates a new class to load Doctrine fixtures |
| `make:voter` | Creates a new security voter class |

### Router Commands

| Command | Description |
|---------|-------------|
| `router:match` | Helps debug routes by simulating a path info match |
| `debug:router` | Displays current routes for the application |

### Security Commands

| Command | Description |
|---------|-------------|
| `security:hash-password` | Hashes a user password |
| `debug:firewall` | Displays information about security firewalls |

### Server Commands

| Command | Description |
|---------|-------------|
| `server:dump` | Starts a dump server for collecting debug information |
| `server:log` | Starts a log server for viewing logs in real-time |

### Asset Commands

| Command | Description |
|---------|-------------|
| `asset:install` | Installs bundle public resources |
| `assets:install` | Installs bundle assets under public directory |
| `importmap:require` | Adds JavaScript packages to import map |
| `importmap:update` | Updates JavaScript package versions |
| `debug:asset-map` | Displays all assets in the asset mapper |

### Messenger Commands

| Command | Description |
|---------|-------------|
| `messenger:consume` | Consumes messages from message queues |
| `messenger:failed:retry` | Retries failed messages |
| `messenger:failed:show` | Shows failed messages |
| `messenger:failed:remove` | Removes failed messages |
| `messenger:stats` | Shows messenger statistics |

## Cache Commands

### Clearing Application Cache

Removing cached data to reflect configuration and code changes.  

```bash
# Clear cache for current environment
php bin/console cache:clear

# Clear cache for production environment
php bin/console cache:clear --env=prod

# Clear cache without warming up
php bin/console cache:clear --no-warmup

# Clear cache and show what's being deleted
php bin/console cache:clear -v
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\HttpKernel\CacheClearer\CacheClearerInterface;

#[AsCommand(
    name: 'app:cache:custom-clear',
    description: 'Clears custom application caches'
)]
class CustomCacheClearCommand extends Command
{
    public function __construct(
        private CacheClearerInterface $cacheClearer
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Custom Cache Clear');
        
        try {
            $this->cacheClearer->clear('var/cache');
            $io->success('Cache cleared successfully');
            
            return Command::SUCCESS;
        } catch (\Exception $e) {
            $io->error('Failed to clear cache: ' . $e->getMessage());
            
            return Command::FAILURE;
        }
    }
}
```

The cache:clear command removes all cached files and optionally warms up  
the cache with fresh data. In development, caches are automatically  
invalidated when code changes. In production, cache clearing is essential  
after deployments to ensure new code takes effect.  

### Warming Up Cache

Populating cache before handling requests for better performance.  

```bash
# Warm up cache for current environment
php bin/console cache:warmup

# Warm up cache for production
php bin/console cache:warmup --env=prod

# Show detailed output during warmup
php bin/console cache:warmup -v
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\HttpKernel\CacheWarmer\CacheWarmerInterface;

#[AsCommand(
    name: 'app:cache:warmup-custom',
    description: 'Warms up custom application caches'
)]
class CustomCacheWarmupCommand extends Command
{
    public function __construct(
        private CacheWarmerInterface $cacheWarmer
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Cache Warmup');
        $io->text('Warming up application caches...');
        
        $cacheDir = 'var/cache/prod';
        $this->cacheWarmer->warmUp($cacheDir);
        
        $io->success('Cache warmed up successfully');
        
        return Command::SUCCESS;
    }
}
```

Cache warmup preloads frequently used data into cache storage, reducing  
response times for initial requests after deployment. Services, routes,  
translations, and templates are typically warmed up.  

### Managing Cache Pools

Working with specific cache pools for granular cache control.  

```bash
# List all available cache pools
php bin/console cache:pool:list

# Clear a specific cache pool
php bin/console cache:pool:clear cache.app

# Clear multiple cache pools
php bin/console cache:pool:clear cache.app cache.system

# Prune expired items from pools
php bin/console cache:pool:prune

# Delete specific item from cache pool
php bin/console cache:pool:delete cache.app my_cache_key
```

```php
<?php

namespace App\Service;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class ProductService
{
    public function __construct(
        private CacheInterface $cache
    ) {
    }

    public function getFeaturedProducts(): array
    {
        return $this->cache->get('featured_products', function (ItemInterface $item) {
            $item->expiresAfter(3600);
            
            // Expensive operation here
            return [
                ['id' => 1, 'name' => 'Laptop', 'price' => 999.99],
                ['id' => 2, 'name' => 'Smartphone', 'price' => 699.99],
                ['id' => 3, 'name' => 'Tablet', 'price' => 449.99],
            ];
        });
    }
    
    public function clearProductCache(): void
    {
        $this->cache->delete('featured_products');
    }
}
```

Cache pools organize cached data into logical groups. Different pools can  
have different storage backends (Redis, Filesystem, APCu) and expiration  
policies. This granular control enables efficient cache management.  

## Configuration Commands

### Dumping Default Configuration

Viewing available configuration options for bundles.  

```bash
# Dump default configuration for framework bundle
php bin/console config:dump-reference framework

# Dump configuration for doctrine bundle
php bin/console config:dump-reference doctrine

# Dump configuration for security bundle
php bin/console config:dump-reference security

# Show configuration as tree structure
php bin/console config:dump-reference twig --format=tree
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\ContainerInterface;

#[AsCommand(
    name: 'app:config:show',
    description: 'Shows current application configuration'
)]
class ShowConfigCommand extends Command
{
    public function __construct(
        private ContainerInterface $container
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Application Configuration');
        
        $config = [
            'Environment' => $this->container->getParameter('kernel.environment'),
            'Debug Mode' => $this->container->getParameter('kernel.debug') ? 'Enabled' : 'Disabled',
            'Project Dir' => $this->container->getParameter('kernel.project_dir'),
            'Cache Dir' => $this->container->getParameter('kernel.cache_dir'),
            'Log Dir' => $this->container->getParameter('kernel.logs_dir'),
        ];
        
        $io->table(['Setting', 'Value'], array_map(
            fn($k, $v) => [$k, $v],
            array_keys($config),
            array_values($config)
        ));
        
        return Command::SUCCESS;
    }
}
```

The config:dump-reference command displays all available configuration  
options with their default values and descriptions. This documentation is  
invaluable when configuring bundles or troubleshooting configuration issues.  

### Debugging Current Configuration

Inspecting active configuration values.  

```bash
# Show current framework configuration
php bin/console debug:config framework

# Show current doctrine configuration
php bin/console debug:config doctrine

# Show specific configuration path
php bin/console debug:config framework session

# Show configuration in YAML format
php bin/console debug:config security --format=yaml
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

#[AsCommand(
    name: 'app:config:parameters',
    description: 'Lists all configuration parameters'
)]
class ListParametersCommand extends Command
{
    public function __construct(
        private ParameterBagInterface $params
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Configuration Parameters');
        
        $parameters = $this->params->all();
        ksort($parameters);
        
        $rows = [];
        foreach ($parameters as $key => $value) {
            if (is_scalar($value) || is_null($value)) {
                $rows[] = [$key, $value ?? 'null'];
            } else {
                $rows[] = [$key, '<complex value>'];
            }
        }
        
        $io->table(['Parameter', 'Value'], $rows);
        
        return Command::SUCCESS;
    }
}
```

The debug:config command shows the actual configuration being used by the  
application after all configuration files are merged. This helps verify  
environment-specific overrides are working correctly.  

### Inspecting Service Container

Exploring registered services and their configuration.  

```bash
# List all services
php bin/console debug:container

# Search for specific services
php bin/console debug:container cache

# Show service details
php bin/console debug:container cache.app

# Show only public services
php bin/console debug:container --show-public

# Display services with tag
php bin/console debug:container --tag=kernel.event_listener
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\ContainerInterface;

#[AsCommand(
    name: 'app:services:list',
    description: 'Lists custom application services'
)]
class ListServicesCommand extends Command
{
    public function __construct(
        private ContainerInterface $container
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Application Services');
        
        $serviceIds = $this->container->getServiceIds();
        $appServices = array_filter($serviceIds, 
            fn($id) => str_starts_with($id, 'App\\')
        );
        
        sort($appServices);
        
        $io->listing($appServices);
        $io->success(sprintf('Found %d custom services', count($appServices)));
        
        return Command::SUCCESS;
    }
}
```

The debug:container command reveals all services registered in the  
dependency injection container. It shows service IDs, classes, and whether  
services are public or private. Essential for understanding autowiring.  

## Debug Commands

### Debugging Routes

Inspecting application routing configuration.  

```bash
# List all routes
php bin/console debug:router

# Search for specific route
php bin/console debug:router app_product_show

# Show routes matching pattern
php bin/console debug:router | grep product

# Display route in specific format
php bin/console debug:router --format=json

# Test route matching
php bin/console router:match /products/123
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Routing\RouterInterface;

#[AsCommand(
    name: 'app:route:test',
    description: 'Tests route generation'
)]
class RouteTestCommand extends Command
{
    public function __construct(
        private RouterInterface $router
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('route-name', InputArgument::REQUIRED, 'Route name');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $routeName = $input->getArgument('route-name');
        
        try {
            $route = $this->router->getRouteCollection()->get($routeName);
            
            if (!$route) {
                $io->error("Route '$routeName' not found");
                return Command::FAILURE;
            }
            
            $io->success("Route '$routeName' found");
            $io->table(
                ['Property', 'Value'],
                [
                    ['Path', $route->getPath()],
                    ['Methods', implode(', ', $route->getMethods())],
                    ['Controller', $route->getDefault('_controller')],
                ]
            );
            
            return Command::SUCCESS;
        } catch (\Exception $e) {
            $io->error($e->getMessage());
            return Command::FAILURE;
        }
    }
}
```

The debug:router command displays all registered routes with their paths,  
methods, and controllers. The router:match command simulates requests to  
test routing logic without running a web server.  

### Debugging Event Dispatcher

Viewing registered event listeners and subscribers.  

```bash
# List all event listeners
php bin/console debug:event-dispatcher

# Show listeners for specific event
php bin/console debug:event-dispatcher kernel.request

# Display in different format
php bin/console debug:event-dispatcher --format=json

# Show listener priorities
php bin/console debug:event-dispatcher kernel.response
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

#[AsCommand(
    name: 'app:events:dispatch',
    description: 'Dispatches a custom event for testing'
)]
class DispatchEventCommand extends Command
{
    public function __construct(
        private EventDispatcherInterface $dispatcher
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Event Dispatch Test');
        
        $event = new CustomEvent('Test data');
        $this->dispatcher->dispatch($event, 'app.custom_event');
        
        $io->success('Event dispatched successfully');
        $io->text('Event data: ' . $event->getData());
        
        return Command::SUCCESS;
    }
}

class CustomEvent
{
    public function __construct(
        private string $data
    ) {
    }
    
    public function getData(): string
    {
        return $this->data;
    }
}
```

The debug:event-dispatcher command shows all event listeners and their  
priorities. This is crucial for understanding event flow and debugging  
listener execution order.  

### Debugging Twig Templates

Exploring available Twig functions and filters.  

```bash
# List all Twig extensions
php bin/console debug:twig

# Show specific function details
php bin/console debug:twig --filter=asset

# List only filters
php bin/console debug:twig --format=json | grep filter

# Show template loader paths
php bin/console debug:twig --show-paths
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Twig\Environment;

#[AsCommand(
    name: 'app:twig:render',
    description: 'Renders a Twig template from console'
)]
class RenderTwigCommand extends Command
{
    public function __construct(
        private Environment $twig
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $template = $this->twig->createTemplate('Hello {{ name }}!');
        $rendered = $template->render(['name' => 'there']);
        
        $io->success('Template rendered:');
        $io->text($rendered);
        
        return Command::SUCCESS;
    }
}
```

The debug:twig command lists all available Twig functions, filters, tests,  
and global variables. It helps discover template capabilities and verify  
custom Twig extensions are loaded correctly.  

## Doctrine Commands

### Creating and Dropping Databases

Managing database creation and removal.  

```bash
# Create database
php bin/console doctrine:database:create

# Create database for test environment
php bin/console doctrine:database:create --env=test

# Drop database
php bin/console doctrine:database:drop --force

# Drop and recreate database
php bin/console doctrine:database:drop --force && php bin/console doctrine:database:create
```

```php
<?php

namespace App\Command;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:database:reset',
    description: 'Drops and recreates database with schema'
)]
class DatabaseResetCommand extends Command
{
    public function __construct(
        private EntityManagerInterface $em
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Database Reset');
        
        $connection = $this->em->getConnection();
        
        try {
            $io->text('Dropping database...');
            $connection->executeStatement('DROP DATABASE IF EXISTS test_db');
            
            $io->text('Creating database...');
            $connection->executeStatement('CREATE DATABASE test_db');
            
            $io->success('Database reset successfully');
            
            return Command::SUCCESS;
        } catch (\Exception $e) {
            $io->error('Failed: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }
}
```

Database creation commands read configuration from DATABASE_URL environment  
variable and create the database on the configured server. These commands  
are essential for initial setup and testing environments.  

### Managing Database Schema

Creating and updating database structure based on entities.  

```bash
# Create schema from entities
php bin/console doctrine:schema:create

# Update schema to match entities
php bin/console doctrine:schema:update --force

# Show SQL for schema updates
php bin/console doctrine:schema:update --dump-sql

# Validate current schema
php bin/console doctrine:schema:validate

# Drop entire schema
php bin/console doctrine:schema:drop --force
```

```php
<?php

namespace App\Command;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:schema:sync',
    description: 'Synchronizes database schema with entities'
)]
class SchemaSyncCommand extends Command
{
    public function __construct(
        private EntityManagerInterface $em
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Schema Synchronization');
        
        $metadata = $this->em->getMetadataFactory()->getAllMetadata();
        $schemaTool = new SchemaTool($this->em);
        
        $sqls = $schemaTool->getUpdateSchemaSql($metadata);
        
        if (empty($sqls)) {
            $io->success('Schema is already up to date');
            return Command::SUCCESS;
        }
        
        $io->listing($sqls);
        
        if ($io->confirm('Execute these queries?', false)) {
            $schemaTool->updateSchema($metadata);
            $io->success('Schema updated successfully');
        }
        
        return Command::SUCCESS;
    }
}
```

Schema commands compare entity definitions with database structure and  
generate SQL to synchronize them. In production, use migrations instead  
of schema:update for better control and version history.  

### Working with Migrations

Managing database version control through migrations.  

```bash
# Generate migration from schema changes
php bin/console make:migration

# Execute all pending migrations
php bin/console doctrine:migrations:migrate

# Migrate without confirmation
php bin/console doctrine:migrations:migrate --no-interaction

# Show migration status
php bin/console doctrine:migrations:status

# Execute specific migration
php bin/console doctrine:migrations:execute Version20240101120000 --up

# Rollback migration
php bin/console doctrine:migrations:execute Version20240101120000 --down

# Generate diff migration
php bin/console doctrine:migrations:diff
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

#[AsCommand(
    name: 'app:migrations:pending',
    description: 'Shows pending migrations'
)]
class PendingMigrationsCommand extends Command
{
    public function __construct(
        private DependencyFactory $dependencyFactory
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Pending Migrations');
        
        $planCalculator = $this->dependencyFactory->getMigrationPlanCalculator();
        $plan = $planCalculator->getPlanForVersions(
            $this->dependencyFactory->getMetadataStorage()->getExecutedMigrations()
        );
        
        $pending = $plan->getItems();
        
        if (empty($pending)) {
            $io->success('No pending migrations');
            return Command::SUCCESS;
        }
        
        $rows = [];
        foreach ($pending as $item) {
            $rows[] = [$item->getVersion()];
        }
        
        $io->table(['Migration'], $rows);
        $io->note(sprintf('%d migration(s) pending', count($pending)));
        
        return Command::SUCCESS;
    }
}
```

Migrations provide version control for database schemas. Each migration  
represents a single database change with up and down methods. This enables  
reliable, repeatable deployments across environments.  

### Loading Data Fixtures

Populating database with test or initial data.  

```bash
# Load all fixtures
php bin/console doctrine:fixtures:load

# Load without confirmation
php bin/console doctrine:fixtures:load --no-interaction

# Append fixtures without purging
php bin/console doctrine:fixtures:load --append

# Load specific fixture group
php bin/console doctrine:fixtures:load --group=dev
```

```php
<?php

namespace App\DataFixtures;

use App\Entity\Product;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;

class ProductFixtures extends Fixture
{
    public function load(ObjectManager $manager): void
    {
        $products = [
            ['Laptop', 999.99, 10],
            ['Smartphone', 699.99, 25],
            ['Headphones', 149.99, 50],
            ['Tablet', 449.99, 15],
            ['Smartwatch', 299.99, 30],
        ];

        foreach ($products as [$name, $price, $stock]) {
            $product = new Product();
            $product->setName($name);
            $product->setPrice($price);
            $product->setStock($stock);
            $product->setCreatedAt(new \DateTime());
            
            $manager->persist($product);
        }

        $manager->flush();
    }
}
```

Fixtures load predefined data into the database for development and testing.  
They ensure consistent test environments and provide sample data for  
development. Fixtures can reference each other for complex data setups.  

## Maker Commands

### Creating Controllers

Generating controller classes with MakerBundle.  

```bash
# Create basic controller
php bin/console make:controller ProductController

# Create API controller
php bin/console make:controller Api/ProductController
```

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ProductController extends AbstractController
{
    #[Route('/product', name: 'app_product')]
    public function index(): Response
    {
        return $this->render('product/index.html.twig', [
            'controller_name' => 'ProductController',
        ]);
    }
}
```

The make:controller command generates a controller class with a sample  
action and template. Controllers are created in src/Controller directory  
with proper namespacing and boilerplate code.  

### Creating Entities

Generating Doctrine entity classes interactively.  

```bash
# Create new entity
php bin/console make:entity Product

# The command will prompt for fields interactively:
# Field name: name
# Field type: string
# Field length: 255
# Can this field be null: no
# (press return to stop adding fields)
```

```php
<?php

namespace App\Entity;

use App\Repository\ProductRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: ProductRepository::class)]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $name = null;

    #[ORM\Column]
    private ?float $price = null;

    #[ORM\Column]
    private ?int $stock = null;

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

    public function getPrice(): ?float
    {
        return $this->price;
    }

    public function setPrice(float $price): static
    {
        $this->price = $price;
        return $this;
    }

    public function getStock(): ?int
    {
        return $this->stock;
    }

    public function setStock(int $stock): static
    {
        $this->stock = $stock;
        return $this;
    }
}
```

The make:entity command creates or updates entity classes with proper  
Doctrine annotations and getters/setters. It also generates repository  
classes for custom queries.  

### Creating Forms

Generating form type classes for entity handling.  

```bash
# Create form for entity
php bin/console make:form ProductType Product

# Create standalone form
php bin/console make:form ContactType
```

```php
<?php

namespace App\Form;

use App\Entity\Product;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\MoneyType;
use Symfony\Component\Form\Extension\Core\Type\NumberType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class ProductType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('name', TextType::class, [
                'label' => 'Product Name',
            ])
            ->add('price', MoneyType::class, [
                'label' => 'Price',
            ])
            ->add('stock', NumberType::class, [
                'label' => 'Stock Quantity',
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

The make:form command generates form type classes bound to entities or  
standalone forms. Generated forms include field types based on entity  
property types with proper form options.  

### Creating Console Commands

Generating custom command classes.  

```bash
# Create command
php bin/console make:command app:send-reports
```

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

#[AsCommand(
    name: 'app:send-reports',
    description: 'Sends periodic reports to users'
)]
class SendReportsCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument('recipient', InputArgument::REQUIRED, 'Report recipient email')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Report format', 'pdf');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $recipient = $input->getArgument('recipient');
        $format = $input->getOption('format');

        $io->title('Send Reports');
        $io->text(sprintf('Sending %s report to %s', $format, $recipient));
        
        // Report generation and sending logic here
        
        $io->success('Reports sent successfully');

        return Command::SUCCESS;
    }
}
```

The make:command creates a command class with configuration and execution  
methods. Commands support arguments, options, and interactive prompts for  
flexible CLI tools.  

## Router Commands

### Testing Route Matching

Simulating requests to test routing configuration.  

```bash
# Test route matching
php bin/console router:match /products/123

# Test with specific method
php bin/console router:match /products/123 --method=POST

# Test with request headers
php bin/console router:match /api/products --header="Accept: application/json"
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Matcher\UrlMatcherInterface;

#[AsCommand(
    name: 'app:route:validate',
    description: 'Validates route paths'
)]
class ValidateRouteCommand extends Command
{
    public function __construct(
        private UrlMatcherInterface $matcher
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('path', InputArgument::REQUIRED, 'URL path to validate');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $path = $input->getArgument('path');
        
        try {
            $parameters = $this->matcher->match($path);
            
            $io->success("Route matched: " . $parameters['_route']);
            $io->table(
                ['Parameter', 'Value'],
                array_map(fn($k, $v) => [$k, $v], array_keys($parameters), $parameters)
            );
            
            return Command::SUCCESS;
        } catch (\Exception $e) {
            $io->error('Route not found: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }
}
```

The router:match command simulates HTTP requests to test route matching  
without running a web server. It shows which route matches and what  
parameters are extracted from the URL.  

### Listing Application Routes

Displaying all registered routes.  

```bash
# List all routes
php bin/console debug:router

# Search for specific route
php bin/console debug:router app_product

# Filter routes by name pattern
php bin/console debug:router --show-controllers

# Export routes as JSON
php bin/console debug:router --format=json
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Routing\RouterInterface;

#[AsCommand(
    name: 'app:route:count',
    description: 'Counts application routes'
)]
class CountRoutesCommand extends Command
{
    public function __construct(
        private RouterInterface $router
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $routes = $this->router->getRouteCollection();
        $total = $routes->count();
        
        $byMethod = [];
        foreach ($routes as $route) {
            $methods = $route->getMethods() ?: ['ANY'];
            foreach ($methods as $method) {
                $byMethod[$method] = ($byMethod[$method] ?? 0) + 1;
            }
        }
        
        $io->title('Route Statistics');
        $io->text("Total routes: $total");
        
        $rows = array_map(
            fn($method, $count) => [$method, $count],
            array_keys($byMethod),
            array_values($byMethod)
        );
        
        $io->table(['HTTP Method', 'Route Count'], $rows);
        
        return Command::SUCCESS;
    }
}
```

The debug:router command lists all application routes with their names,  
paths, methods, and controllers. It helps verify routing configuration and  
discover available endpoints.  

## Security Commands

### Hashing Passwords

Generating password hashes for users.  

```bash
# Hash a password
php bin/console security:hash-password

# Hash with specific encoder
php bin/console security:hash-password MySecretPassword

# Hash for specific user class
php bin/console security:hash-password --user-class=App\\Entity\\User
```

```php
<?php

namespace App\Command;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

#[AsCommand(
    name: 'app:user:create',
    description: 'Creates a new user with hashed password'
)]
class CreateUserCommand extends Command
{
    public function __construct(
        private UserPasswordHasherInterface $passwordHasher,
        private EntityManagerInterface $em
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('email', InputArgument::REQUIRED, 'User email')
            ->addArgument('password', InputArgument::REQUIRED, 'User password');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $email = $input->getArgument('email');
        $plainPassword = $input->getArgument('password');
        
        $user = new User();
        $user->setEmail($email);
        
        $hashedPassword = $this->passwordHasher->hashPassword($user, $plainPassword);
        $user->setPassword($hashedPassword);
        
        $this->em->persist($user);
        $this->em->flush();
        
        $io->success("User created: $email");
        
        return Command::SUCCESS;
    }
}
```

The security:hash-password command generates password hashes using  
configured password hashers. This is useful for creating initial user  
accounts or testing authentication.  

### Debugging Firewall Configuration

Inspecting security firewall settings.  

```bash
# Show firewall information
php bin/console debug:firewall

# Show specific firewall
php bin/console debug:firewall main

# List all security contexts
php bin/console debug:firewall --list
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

#[AsCommand(
    name: 'app:security:check',
    description: 'Checks security configuration'
)]
class SecurityCheckCommand extends Command
{
    public function __construct(
        private AuthorizationCheckerInterface $authChecker
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Security Configuration Check');
        
        $checks = [
            'Authorization Checker' => $this->authChecker !== null,
        ];
        
        foreach ($checks as $check => $passed) {
            $io->text(sprintf(
                '%s: %s',
                $check,
                $passed ? '<info>✓</info>' : '<error>✗</error>'
            ));
        }
        
        $io->success('Security check complete');
        
        return Command::SUCCESS;
    }
}
```

The debug:firewall command displays security firewall configuration  
including authentication mechanisms, access control rules, and security  
contexts. Essential for troubleshooting authentication issues.  

## Asset Commands

### Installing Bundle Assets

Copying public assets from bundles to web directory.  

```bash
# Install assets
php bin/console assets:install

# Install as symlinks (for development)
php bin/console assets:install --symlink

# Install relative symlinks
php bin/console assets:install --relative

# Force reinstall
php bin/console assets:install --force
```

```php
<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Filesystem;

#[AsCommand(
    name: 'app:assets:copy',
    description: 'Copies custom assets to public directory'
)]
class CopyAssetsCommand extends Command
{
    public function __construct(
        private Filesystem $filesystem,
        private string $projectDir
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('Asset Copy');
        
        $source = $this->projectDir . '/assets/images';
        $target = $this->projectDir . '/public/images';
        
        if (!is_dir($source)) {
            $io->error("Source directory not found: $source");
            return Command::FAILURE;
        }
        
        $this->filesystem->mirror($source, $target);
        
        $io->success('Assets copied successfully');
        
        return Command::SUCCESS;
    }
}
```

The assets:install command copies or symlinks public resources from bundles  
to the public directory where they can be served by the web server. This  
is necessary after installing bundles with CSS, JavaScript, or image files.  

### Managing ImportMap Packages

Adding and updating JavaScript dependencies with AssetMapper.  

```bash
# Add package to importmap
php bin/console importmap:require bootstrap

# Add multiple packages
php bin/console importmap:require stimulus @hotwired/turbo

# Update packages
php bin/console importmap:update

# Remove package
php bin/console importmap:remove bootstrap

# Audit importmap
php bin/console importmap:audit
```

```php
<?php

namespace App\Command;

use Symfony\Component\AssetMapper\ImportMap\ImportMapManager;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'app:importmap:list',
    description: 'Lists all importmap entries'
)]
class ListImportMapCommand extends Command
{
    public function __construct(
        private ImportMapManager $importMapManager
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->title('ImportMap Entries');
        
        $entries = $this->importMapManager->getEntries();
        
        $rows = [];
        foreach ($entries as $entry) {
            $rows[] = [
                $entry->importName,
                $entry->path ?? 'N/A',
                $entry->isRemotePackage() ? 'Remote' : 'Local',
            ];
        }
        
        $io->table(['Import Name', 'Path', 'Type'], $rows);
        
        return Command::SUCCESS;
    }
}
```

ImportMap commands manage JavaScript dependencies without Node.js. The  
importmap:require command downloads packages from CDNs and adds them to  
the import map for use in templates.  

## Conclusion

The bin/console command is an indispensable tool in Symfony development,  
providing command-line access to framework functionality. From cache  
management to database operations, from debugging to code generation,  
console commands streamline workflows and automate repetitive tasks.  

Understanding how to effectively use built-in commands and create custom  
commands enables developers to build robust CLI tools for their  
applications. The Console component's flexibility and Symfony's dependency  
injection make it possible to create sophisticated command-line interfaces  
with minimal code.  

Whether clearing caches during development, running migrations in  
production, or executing scheduled maintenance tasks, bin/console provides  
a consistent, powerful interface for managing Symfony applications across  
all environments.  
