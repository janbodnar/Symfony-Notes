# Symfony Configuration and Environment Management

This comprehensive guide explains how Symfony manages configuration and  
environments through various files and mechanisms. Configuration in  
Symfony is flexible, environment-aware, and designed to separate code  
from settings.  

## Understanding Symfony Configuration

Symfony uses a multi-layered configuration system that separates concerns  
and allows different settings for development, testing, and production  
environments. The configuration system consists of environment variables,  
YAML files, and PHP configuration files that work together to provide  
flexibility and security.  

### Configuration File Structure

Symfony organizes configuration files in a specific directory structure:  

```
config/
├── packages/           # Bundle-specific configuration
│   ├── doctrine.yaml
│   ├── framework.yaml
│   ├── security.yaml
│   └── dev/           # Development environment overrides
│       └── monolog.yaml
│   └── prod/          # Production environment overrides
│       └── monolog.yaml
│   └── test/          # Testing environment overrides
│       └── validator.yaml
├── routes.yaml        # Application routes
├── services.yaml      # Service container configuration
└── bundles.php        # Registered bundles
```

The configuration is loaded in order: base files first, then  
environment-specific overrides. This allows you to define common settings  
once and override only what's different in each environment.  

## Environment Files

### The .env File

The .env file contains environment variables for local development. This  
file is typically committed to version control and contains safe default  
values.  

```bash
# .env

# Environment (dev, prod, test)
APP_ENV=dev
APP_DEBUG=1
APP_SECRET=change-this-secret-in-production

# Database configuration
DATABASE_URL="mysql://db_user:db_password@127.0.0.1:3306/db_name?serverVersion=8.0"

# Mailer configuration
MAILER_DSN=smtp://localhost:1025

# External API endpoints
API_BASE_URL=https://api.example.com
REDIS_URL=redis://localhost:6379
```

This file provides a template for required environment variables. Actual  
values should never contain real credentials or sensitive data. It serves  
as documentation for what variables your application needs.  

### The .env.local File

The .env.local file overrides values from .env for local development.  
This file should never be committed to version control.  

```bash
# .env.local

# Override with real database credentials
DATABASE_URL="mysql://root:secret@127.0.0.1:3306/myapp_dev"

# Local mail catcher
MAILER_DSN=smtp://localhost:1025

# Development API key
API_KEY=dev-api-key-12345
PAYMENT_API_KEY=sk_test_local_development_key
```

Add .env.local to your .gitignore file to prevent accidental commits of  
sensitive data. Each developer can have different local settings without  
affecting others.  

### Environment-Specific Files

Symfony supports environment-specific .env files that are loaded based on  
the APP_ENV variable:  

```bash
# .env.dev - Development defaults
APP_DEBUG=1
LOG_LEVEL=debug
ENABLE_PROFILER=1

# .env.prod - Production defaults  
APP_DEBUG=0
LOG_LEVEL=error
ENABLE_PROFILER=0

# .env.test - Testing defaults
APP_DEBUG=0
DATABASE_URL="sqlite:///%kernel.project_dir%/var/test.db"
```

The loading order is: .env → .env.local → .env.$APP_ENV →  
.env.$APP_ENV.local. Later files override earlier ones.  

### .env File Best Practices

```bash
# .env - Safe defaults and documentation

###> symfony/framework-bundle ###
APP_ENV=dev
APP_SECRET=default-secret-change-in-production
###< symfony/framework-bundle ###

###> doctrine/doctrine-bundle ###
# MySQL example
# DATABASE_URL="mysql://user:pass@localhost:3306/db_name"
# PostgreSQL example
# DATABASE_URL="postgresql://user:pass@localhost:5432/db_name?serverVersion=15"
DATABASE_URL="mysql://app:!ChangeMe!@127.0.0.1:3306/app"
###< doctrine/doctrine-bundle ###

###> symfony/mailer ###
MAILER_DSN=null://null
###< symfony/mailer ###
```

Use comments to provide examples and documentation. Bundle installation  
automatically adds configuration blocks with markers (###>). Keep the  
file organized and document required variables.  

## Configuration Files

### The config/services.yaml File

This file defines service container configuration and parameters:  

```yaml
# config/services.yaml

parameters:
    app.supported_locales: ['en', 'fr', 'de', 'es']
    app.items_per_page: 20
    app.upload_directory: '%kernel.project_dir%/public/uploads'
    app.max_upload_size: 5242880  # 5 MB in bytes

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

    # Explicit service configuration with environment variables
    App\Service\EmailService:
        arguments:
            $fromAddress: '%env(MAIL_FROM_ADDRESS)%'
            $smtpHost: '%env(SMTP_HOST)%'

    App\Service\PaymentProcessor:
        arguments:
            $apiKey: '%env(PAYMENT_API_KEY)%'
            $webhookSecret: '%env(PAYMENT_WEBHOOK_SECRET)%'
            $environment: '%kernel.environment%'
```

Parameters are static values defined at container compile time.  
Environment variables are resolved at runtime. Use %env(VAR_NAME)% to  
inject environment variables into services.  

### Bundle Configuration Files

Each bundle has its own configuration file in config/packages/:  

```yaml
# config/packages/framework.yaml
framework:
    secret: '%env(APP_SECRET)%'
    csrf_protection: true
    http_method_override: false
    handle_all_throwables: true
    
    session:
        handler_id: null
        cookie_secure: auto
        cookie_samesite: lax
        
    php_errors:
        log: true
        
    cache:
        app: cache.adapter.filesystem
        system: cache.adapter.system
        pools:
            cache.app_data:
                adapter: cache.adapter.redis
                provider: '%env(REDIS_URL)%'
```

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

Bundle configuration is merged from all environment-specific files. The  
%kernel.debug% and %kernel.environment% parameters provide context about  
the current environment.  

### Routes Configuration

Routes can be configured in YAML, XML, PHP, or annotations/attributes:  

```yaml
# config/routes.yaml

# Import all controller routes
controllers:
    resource:
        path: ../src/Controller/
        namespace: App\Controller
    type: attribute

# API routes with prefix
api:
    resource: ../src/Controller/Api/
    type: attribute
    prefix: /api
    name_prefix: api_

# Admin routes with requirements
admin:
    resource: ../src/Controller/Admin/
    type: attribute
    prefix: /admin
    requirements:
        _locale: en|fr|de
```

Routes can be environment-specific by placing them in  
config/routes/{environment}/.  

## Environment-Specific Configuration

### Development Configuration

Development environment focuses on debugging and development experience:  

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

```yaml
# config/packages/dev/web_profiler.yaml
web_profiler:
    toolbar: true
    intercept_redirects: false

framework:
    profiler:
        only_exceptions: false
        collect_serializer_data: true
```

The web profiler and detailed logging help developers debug issues. The  
toolbar provides instant feedback about requests, queries, and  
performance.  

### Production Configuration

Production environment prioritizes performance and security:  

```yaml
# config/packages/prod/monolog.yaml
monolog:
    handlers:
        main:
            type: fingers_crossed
            action_level: error
            handler: nested
            excluded_http_codes: [404, 405]
            buffer_size: 50
            
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
# config/packages/prod/doctrine.yaml
doctrine:
    orm:
        auto_generate_proxy_classes: false
        proxy_dir: '%kernel.build_dir%/doctrine/orm/Proxies'
        query_cache_driver:
            type: pool
            pool: doctrine.system_cache_pool
        result_cache_driver:
            type: pool
            pool: doctrine.result_cache_pool

framework:
    cache:
        pools:
            doctrine.result_cache_pool:
                adapter: cache.app
            doctrine.system_cache_pool:
                adapter: cache.system
```

Production disables proxy auto-generation, uses aggressive caching, and  
only logs errors. The fingers_crossed handler reduces I/O by buffering  
logs until an error occurs.  

### Test Configuration

Test environment ensures consistent, isolated testing:  

```yaml
# config/packages/test/framework.yaml
framework:
    test: true
    session:
        storage_factory_id: session.storage.factory.mock_file
    profiler:
        collect: false

# config/packages/test/validator.yaml
framework:
    validation:
        not_compromised_password: false
```

```yaml
# config/packages/test/doctrine.yaml
doctrine:
    dbal:
        # Use in-memory database for faster tests
        url: 'sqlite:///:memory:'
```

Test environment disables external services, uses mock implementations,  
and ensures tests run in isolation. Database uses SQLite in memory for  
speed.  

## Environment Variable Processors

Symfony provides processors to transform environment variables:  

```yaml
# config/services.yaml
parameters:
    # env(VAR) - Get raw value
    database.host: '%env(DATABASE_HOST)%'
    
    # env(resolve:VAR) - Resolve nested variables
    database.url: '%env(resolve:DATABASE_URL)%'
    
    # env(bool:VAR) - Convert to boolean
    app.debug: '%env(bool:APP_DEBUG)%'
    
    # env(int:VAR) - Convert to integer
    app.timeout: '%env(int:API_TIMEOUT)%'
    
    # env(float:VAR) - Convert to float
    app.tax_rate: '%env(float:TAX_RATE)%'
    
    # env(json:VAR) - Parse JSON
    app.feature_flags: '%env(json:FEATURE_FLAGS)%'
    
    # env(base64:VAR) - Decode base64
    app.certificate: '%env(base64:SSL_CERTIFICATE)%'
    
    # env(file:VAR) - Read file contents
    app.secret_key: '%env(file:SECRET_KEY_FILE)%'
    
    # env(default:fallback:VAR) - Provide default value
    app.cache_ttl: '%env(default:cache_default_ttl:int:CACHE_TTL)%'
    cache_default_ttl: 3600
    
    # Chain processors
    app.redis_config: '%env(json:file:REDIS_CONFIG_FILE)%'
```

Processors transform values at runtime. Use them to convert types, decode  
formats, or provide fallback values. Multiple processors can be chained  
from right to left.  

### Custom Environment Variable Processor

Create custom processors for complex transformations:  

```php
<?php

namespace App\DependencyInjection;

use Symfony\Component\DependencyInjection\EnvVarProcessorInterface;

class CustomEnvVarProcessor implements EnvVarProcessorInterface
{
    public function getEnv(string $prefix, string $name, \Closure $getEnv): mixed
    {
        $env = $getEnv($name);
        
        return match ($prefix) {
            'csv' => array_map('trim', explode(',', $env)),
            'uppercase' => strtoupper($env),
            'hash' => hash('sha256', $env),
            default => throw new \RuntimeException("Unsupported prefix: $prefix"),
        };
    }

    public static function getProvidedTypes(): array
    {
        return [
            'csv' => 'array',
            'uppercase' => 'string',
            'hash' => 'string',
        ];
    }
}
```

```yaml
# config/services.yaml
services:
    App\DependencyInjection\CustomEnvVarProcessor:
        tags: ['container.env_var_processor']

parameters:
    # Usage: env(csv:ALLOWED_HOSTS)
    allowed_hosts: '%env(csv:ALLOWED_HOSTS)%'
```

Custom processors extend functionality for application-specific needs.  
Register them with the container.env_var_processor tag.  

## Managing Sensitive Data

### Using Symfony Secrets

Symfony provides a secrets management system for production credentials:  

```bash
# Generate encryption keys
php bin/console secrets:generate-keys

# Set a secret for production
php bin/console secrets:set DATABASE_PASSWORD --env=prod

# Set a secret for development (optional)
php bin/console secrets:set API_KEY --env=dev

# List all secrets
php bin/console secrets:list --env=prod

# Reveal a secret value (for debugging)
php bin/console secrets:reveal DATABASE_PASSWORD --env=prod

# Remove a secret
php bin/console secrets:remove OLD_API_KEY --env=prod
```

Secrets are encrypted and stored in config/secrets/{env}/:  

```
config/secrets/
├── dev/
│   ├── dev.decrypt.private.php  # Private key (gitignored)
│   ├── dev.encrypt.public.php   # Public key (committed)
│   └── DATABASE_PASSWORD.txt    # Encrypted secret (committed)
└── prod/
    ├── prod.decrypt.private.php # Private key (gitignored)
    ├── prod.encrypt.public.php  # Public key (committed)
    └── DATABASE_PASSWORD.txt    # Encrypted secret (committed)
```

The private key must be deployed to production servers separately. Only  
the public key and encrypted secrets are committed to version control.  

### Using Secrets in Configuration

Secrets override environment variables automatically:  

```yaml
# config/packages/doctrine.yaml
doctrine:
    dbal:
        # Will use DATABASE_URL from secrets if available,
        # otherwise from environment variables
        url: '%env(resolve:DATABASE_URL)%'
        password: '%env(DATABASE_PASSWORD)%'
```

```php
<?php

namespace App\Service;

class ApiClient
{
    public function __construct(
        // Symfony automatically resolves from secrets
        private string $apiKey
    ) {
    }
}
```

```yaml
# config/services.yaml
services:
    App\Service\ApiClient:
        arguments:
            $apiKey: '%env(API_KEY)%'
```

Secrets take precedence over .env files. In production, use secrets for  
all sensitive data. In development, .env.local is sufficient.  

### Secrets Best Practices

```php
<?php

namespace App\Service;

class SecretManager
{
    /**
     * Example of accessing secrets in services
     */
    public function __construct(
        private string $databasePassword,
        private string $apiKey,
        private string $webhookSecret
    ) {
    }

    /**
     * Validate secrets are properly configured
     */
    public function validateSecrets(): array
    {
        $issues = [];
        
        if (strlen($this->databasePassword) < 16) {
            $issues[] = 'Database password is too short';
        }
        
        if (!str_starts_with($this->apiKey, 'sk_')) {
            $issues[] = 'API key format is invalid';
        }
        
        if (empty($this->webhookSecret)) {
            $issues[] = 'Webhook secret is not configured';
        }
        
        return $issues;
    }
}
```

Always validate secrets at application startup. Use strong, unique values  
for each environment. Rotate secrets regularly and never log or expose  
them in error messages.  

## Version Control Considerations

### .gitignore Configuration

Configure .gitignore to exclude sensitive files:  

```gitignore
# .gitignore

###> symfony/framework-bundle ###
/.env.local
/.env.local.php
/.env.*.local
/config/secrets/prod/prod.decrypt.private.php
/config/secrets/dev/dev.decrypt.private.php
/public/bundles/
/var/
/vendor/
###< symfony/framework-bundle ###

###> phpunit/phpunit ###
/phpunit.xml
.phpunit.result.cache
###< phpunit/phpunit ###

# Additional local configuration
/config/packages/dev/*.local.yaml
/config/packages/test/*.local.yaml
```

Never commit .env.local, .env.*.local, or secret private keys. These  
files contain environment-specific and sensitive data.  

### What to Commit

Commit these configuration files:  

```
✓ .env                          # Default values and documentation
✓ .env.test                     # Test environment defaults
✓ config/packages/*.yaml        # Bundle configuration
✓ config/packages/{env}/*.yaml  # Environment overrides
✓ config/services.yaml          # Service configuration
✓ config/routes.yaml            # Routes
✓ config/secrets/*/encrypt.public.php  # Public encryption keys
✓ config/secrets/*/*.txt        # Encrypted secrets

✗ .env.local                    # Local overrides
✗ .env.*.local                  # Environment-specific local overrides
✗ config/secrets/*/decrypt.private.php  # Private keys
```

### Environment Template

Provide a .env.example or .env.dist for new developers:  

```bash
# .env.example - Copy to .env.local and fill in values

# Database
DATABASE_URL="mysql://username:password@localhost:3306/database_name"

# Mailer
MAILER_DSN=smtp://username:password@smtp.example.com:587

# External Services
API_KEY=your-api-key-here
PAYMENT_API_KEY=your-payment-key-here
REDIS_URL=redis://localhost:6379

# Feature Flags
ENABLE_FEATURE_X=0
ENABLE_BETA_FEATURES=0
```

Document all required variables and provide examples of valid values.  
This helps new team members set up their environment quickly.  

## Configuration Best Practices

### Organizing Configuration

Keep configuration organized and maintainable:  

```yaml
# config/services.yaml - Well-organized

parameters:
    # Application settings
    app.version: '1.0.0'
    app.name: 'My Application'
    
    # Pagination
    app.items_per_page: 20
    app.max_items_per_page: 100
    
    # File uploads
    app.upload_directory: '%kernel.project_dir%/public/uploads'
    app.allowed_extensions: ['jpg', 'png', 'pdf']
    app.max_file_size: 5242880
    
    # API configuration
    app.api_timeout: 30
    app.api_retry_attempts: 3

services:
    _defaults:
        autowire: true
        autoconfigure: true
        bind:
            # Bind common parameters
            $projectDir: '%kernel.project_dir%'
            $environment: '%kernel.environment%'
            $debug: '%kernel.debug%'

    # Auto-register services
    App\:
        resource: '../src/'
        exclude:
            - '../src/DependencyInjection/'
            - '../src/Entity/'
            - '../src/Kernel.php'

    # Service-specific configuration
    App\Service\FileUploader:
        arguments:
            $uploadDirectory: '%app.upload_directory%'
            $allowedExtensions: '%app.allowed_extensions%'
            $maxFileSize: '%app.max_file_size%'
```

Group related parameters together. Use consistent naming conventions.  
Document complex configurations with comments.  

### Environment-Specific Values

Use environment variables for values that change between environments:  

```php
<?php

namespace App\Service;

class CacheService
{
    public function __construct(
        private string $environment,
        private int $defaultTtl,
        private bool $debug
    ) {
    }

    public function getTtl(string $key): int
    {
        // Shorter TTL in development for easier testing
        if ($this->environment === 'dev') {
            return 60;  // 1 minute
        }
        
        // Longer TTL in production for performance
        if ($this->environment === 'prod') {
            return $this->defaultTtl;
        }
        
        // No caching in tests
        return 0;
    }

    public function shouldCache(): bool
    {
        // Disable caching in debug mode
        return !$this->debug && $this->environment !== 'test';
    }
}
```

```yaml
# config/services.yaml
services:
    App\Service\CacheService:
        arguments:
            $environment: '%kernel.environment%'
            $defaultTtl: '%env(int:CACHE_TTL)%'
            $debug: '%kernel.debug%'
```

Adapt behavior based on environment. Use debug flags for development  
features. Configure production for performance.  

### Configuration Validation

Validate configuration at startup to catch errors early:  

```php
<?php

namespace App\Service;

use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class ConfigValidator
{
    public function __construct(
        private ParameterBagInterface $params
    ) {
    }

    public function validate(): array
    {
        $errors = [];
        
        // Validate required parameters exist
        $required = ['app.upload_directory', 'app.max_file_size'];
        foreach ($required as $param) {
            if (!$this->params->has($param)) {
                $errors[] = "Missing required parameter: $param";
            }
        }
        
        // Validate parameter values
        $uploadDir = $this->params->get('app.upload_directory');
        if (!is_dir($uploadDir)) {
            $errors[] = "Upload directory does not exist: $uploadDir";
        }
        
        $maxSize = $this->params->get('app.max_file_size');
        if ($maxSize < 1024) {
            $errors[] = "Max file size is too small: $maxSize bytes";
        }
        
        return $errors;
    }
}
```

Run validation in development to catch configuration issues. Use console  
commands or kernel events to execute validation checks.  

### Documentation and Comments

Document configuration thoroughly:  

```yaml
# config/packages/custom.yaml

# Custom application configuration
app_custom:
    # Enable or disable feature flags
    features:
        # New dashboard UI (beta)
        new_dashboard: false
        
        # Advanced search with Elasticsearch
        # Requires ELASTICSEARCH_URL to be configured
        advanced_search: false
        
        # Real-time notifications via WebSocket
        # Requires Mercure hub to be running
        realtime_notifications: true
    
    # Performance tuning
    performance:
        # Number of items to load per page (10-100)
        items_per_page: 20
        
        # Cache TTL in seconds (300-3600)
        cache_ttl: 600
        
        # Maximum concurrent API requests (1-10)
        max_concurrent_requests: 5
```

Comments explain what each setting does, acceptable values, and any  
dependencies or requirements. This helps future maintainers understand  
the configuration.  

## Advanced Configuration Patterns

### Configuration Inheritance

Create reusable configuration templates:  

```yaml
# config/packages/cache_config.yaml

# Base cache configuration
framework:
    cache:
        default_redis_provider: '%env(REDIS_URL)%'
        
        pools:
            # Template for Redis-backed cache pools
            cache.template.redis:
                adapter: cache.adapter.redis
                provider: '%env(REDIS_URL)%'
                default_lifetime: 3600
            
            # Application cache (inherits from template)
            cache.app:
                adapter: cache.adapter.redis
                provider: '%env(REDIS_URL)%'
                default_lifetime: 3600
            
            # Session cache (shorter lifetime)
            cache.session:
                adapter: cache.adapter.redis
                provider: '%env(REDIS_URL)%'
                default_lifetime: 1800
```

Templates reduce duplication and ensure consistency across similar  
configurations.  

### Dynamic Configuration

Load configuration based on runtime conditions:  

```php
<?php

namespace App\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;

class AppExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);
        
        // Set parameters based on configuration
        $container->setParameter('app.features', $config['features']);
        
        // Conditionally register services
        if ($config['features']['advanced_search']) {
            $container->register(
                'app.search.elasticsearch',
                'App\Service\ElasticsearchService'
            );
        } else {
            $container->register(
                'app.search.basic',
                'App\Service\BasicSearchService'
            );
        }
    }
}
```

Extensions provide programmatic configuration. Use them for complex  
conditional logic that's difficult to express in YAML.  

### Multi-Tenant Configuration

Support multiple tenants with different configurations:  

```yaml
# config/packages/tenant.yaml
parameters:
    tenants:
        tenant_a:
            database_url: '%env(TENANT_A_DATABASE_URL)%'
            api_key: '%env(TENANT_A_API_KEY)%'
            theme: 'blue'
        tenant_b:
            database_url: '%env(TENANT_B_DATABASE_URL)%'
            api_key: '%env(TENANT_B_API_KEY)%'
            theme: 'green'
```

```php
<?php

namespace App\Service;

class TenantConfigProvider
{
    public function __construct(
        private array $tenants
    ) {
    }

    public function getConfig(string $tenantId): array
    {
        if (!isset($this->tenants[$tenantId])) {
            throw new \InvalidArgumentException("Unknown tenant: $tenantId");
        }
        
        return $this->tenants[$tenantId];
    }

    public function getDatabaseUrl(string $tenantId): string
    {
        return $this->getConfig($tenantId)['database_url'];
    }
}
```

Multi-tenant applications can use parameters and services to isolate  
tenant-specific configuration.  

## Debugging Configuration

### Viewing Configuration

Use console commands to inspect configuration:  

```bash
# List all parameters
php bin/console debug:container --parameters

# Show specific parameter value
php bin/console debug:container --parameter=kernel.project_dir

# List all services
php bin/console debug:container

# Show service definition
php bin/console debug:container App\Service\EmailService

# Show autowiring candidates
php bin/console debug:autowiring

# Dump configuration for a bundle
php bin/console config:dump framework

# Dump current configuration
php bin/console debug:config framework
```

These commands help understand how configuration is resolved and what  
services are available.  

### Configuration Dumping

Export configuration for inspection:  

```bash
# Dump all configuration
php bin/console debug:config

# Dump specific bundle configuration
php bin/console debug:config framework
php bin/console debug:config doctrine
php bin/console debug:config security

# Show configuration tree
php bin/console config:dump-reference framework
```

Configuration dumping reveals actual values after merging and processing.  
Use it to verify environment-specific overrides are applied correctly.  

### Environment Variables Debug

Check environment variable resolution:  

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
    name: 'app:debug:config',
    description: 'Debug application configuration'
)]
class DebugConfigCommand extends Command
{
    public function __construct(
        private ParameterBagInterface $params
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $io->section('Environment');
        $io->listing([
            'Environment: ' . $this->params->get('kernel.environment'),
            'Debug: ' . ($this->params->get('kernel.debug') ? 'Yes' : 'No'),
            'Project Dir: ' . $this->params->get('kernel.project_dir'),
        ]);
        
        $io->section('Key Parameters');
        $keys = [
            'app.items_per_page',
            'app.upload_directory',
            'app.max_file_size',
        ];
        
        foreach ($keys as $key) {
            if ($this->params->has($key)) {
                $io->writeln(sprintf('%s: %s', $key, $this->params->get($key)));
            }
        }
        
        return Command::SUCCESS;
    }
}
```

Custom debug commands help verify configuration in production where debug  
tools may be disabled.  

## Common Configuration Patterns

### Database Configuration

```yaml
# config/packages/doctrine.yaml
doctrine:
    dbal:
        url: '%env(resolve:DATABASE_URL)%'
        
        # Connection pooling
        options:
            1002: 'SET NAMES utf8mb4'  # PDO::MYSQL_ATTR_INIT_COMMAND
        
        # Replica configuration
        replica:
            url: '%env(DATABASE_REPLICA_URL)%'
        
        # Master-slave setup
        connections:
            default:
                url: '%env(DATABASE_URL)%'
                driver: 'pdo_mysql'
                server_version: '8.0'
                charset: utf8mb4
            
            replica:
                url: '%env(DATABASE_REPLICA_URL)%'
                driver: 'pdo_mysql'
                server_version: '8.0'
                charset: utf8mb4
```

### Cache Configuration

```yaml
# config/packages/cache.yaml
framework:
    cache:
        app: cache.adapter.filesystem
        system: cache.adapter.system
        
        pools:
            cache.app_data:
                adapter: cache.adapter.redis
                provider: '%env(REDIS_URL)%'
                default_lifetime: 3600
            
            cache.session_data:
                adapter: cache.adapter.redis
                provider: '%env(REDIS_URL)%'
                default_lifetime: 1800
            
            cache.api_responses:
                adapter: cache.adapter.apcu
                default_lifetime: 600
```

### Email Configuration

```yaml
# config/packages/mailer.yaml
framework:
    mailer:
        dsn: '%env(MAILER_DSN)%'
        envelope:
            sender: '%env(MAIL_FROM_ADDRESS)%'
        headers:
            X-Mailer: 'MyApp Mailer'
```

```bash
# .env
MAILER_DSN=smtp://user:pass@smtp.example.com:587
MAIL_FROM_ADDRESS=noreply@example.com
```

### Logging Configuration

```yaml
# config/packages/monolog.yaml
monolog:
    channels:
        - deprecation  # Deprecations logged to dedicated channel
        - security     # Security events
        - payment      # Payment processing
    
    handlers:
        main:
            type: stream
            path: '%kernel.logs_dir%/%kernel.environment%.log'
            level: debug
            channels: ["!event"]
        
        security:
            type: stream
            path: '%kernel.logs_dir%/security.log'
            level: info
            channels: ["security"]
        
        payment:
            type: stream
            path: '%kernel.logs_dir%/payment.log'
            level: info
            channels: ["payment"]
```

These patterns provide starting points for common configuration needs.  
Adapt them to your specific requirements while maintaining clear  
separation between environments.  

## Summary

Symfony's configuration system provides powerful tools for managing  
application settings across different environments:  

- **Environment files** (.env, .env.local) separate configuration from code
- **YAML configuration** (config/packages/*.yaml) organizes bundle settings
- **Environment-specific overrides** (config/packages/{env}/) customize behavior
- **Parameters** store static values, while **environment variables** provide runtime values
- **Secrets management** secures sensitive data in production
- **Version control practices** protect credentials while sharing configuration
- **Environment variable processors** transform and validate values
- **Debug tools** help troubleshoot configuration issues

Following these practices ensures secure, maintainable, and flexible  
application configuration that adapts to different deployment  
environments.
