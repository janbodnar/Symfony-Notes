# Symfony AssetMapper

AssetMapper is Symfony's modern approach to managing frontend assets without  
requiring Node.js or a build step. It maps and serves JavaScript and CSS files  
directly to the browser while handling imports, versioning, and optimization.  

## Basic Configuration

Setting up AssetMapper in a Symfony application.  

```php
<?php

// config/packages/asset_mapper.yaml
framework:
    asset_mapper:
        paths:
            - assets/
        excluded_patterns:
            - '*/tests/*'
            - '*.spec.js'
```

AssetMapper configuration defines which directories contain assets and which  
patterns to exclude from mapping. The default assets/ directory contains all  
frontend files including JavaScript, CSS, and images.  

## Installing AssetMapper

Installing the AssetMapper component in a Symfony project.  

```bash
composer require symfony/asset-mapper symfony/asset symfony/twig-pack
```

```php
<?php

// After installation, enable it in config/bundles.php (auto-configured)
return [
    // ...
    Symfony\Bundle\FrameworkBundle\FrameworkBundle::class => ['all' => true],
];
```

The asset-mapper bundle provides the infrastructure for mapping assets. The  
asset component handles URL generation and versioning. Installation is quick  
and requires no Node.js dependencies.  

## Mapping JavaScript Files

Creating and mapping a basic JavaScript module.  

```javascript
// assets/app.js
console.log('Application initialized');

document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM ready');
});

export function initApp() {
    console.log('App initialization complete');
}
```

```php
<?php

// templates/base.html.twig
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>{% block title %}Welcome{% endblock %}</title>
        {% block stylesheets %}{% endblock %}
        {% block importmap %}
            {{ importmap('app') }}
        {% endblock %}
    </head>
    <body>
        {% block body %}{% endblock %}
    </body>
</html>
```

The importmap() Twig function generates the necessary import map and module  
script tags. JavaScript files are automatically mapped and can use ES6 module  
syntax without transpilation.  

## Mapping CSS Files

Adding and importing CSS stylesheets.  

```css
/* assets/styles/app.css */
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0;
    padding: 20px;
    background-color: #f5f5f5;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    padding: 2rem;
    border-radius: 8px;
}
```

```php
<?php

// templates/base.html.twig
{% block stylesheets %}
    <link rel="stylesheet" href="{{ asset('styles/app.css') }}">
{% endblock %}
```

CSS files are served directly through the asset() Twig function. AssetMapper  
handles versioning and caching headers automatically for optimal performance.  

## Importing JavaScript Modules

Using ES6 import statements to load JavaScript modules.  

```javascript
// assets/controllers/hello_controller.js
export default class {
    connect() {
        this.element.textContent = 'Hello there from Stimulus!';
        this.element.classList.add('connected');
    }
}
```

```javascript
// assets/app.js
import HelloController from './controllers/hello_controller.js';

console.log('Imported:', HelloController);
```

AssetMapper automatically resolves relative imports without requiring a build  
step. All JavaScript follows standard ES6 module syntax and runs natively in  
modern browsers.  

## Using importmap.php

Configuring third-party packages via importmap.  

```php
<?php

// importmap.php
return [
    'app' => [
        'path' => './assets/app.js',
        'entrypoint' => true,
    ],
    '@hotwired/stimulus' => [
        'version' => '3.2.2',
    ],
    '@hotwired/turbo' => [
        'version' => '7.3.0',
    ],
    'bootstrap' => [
        'version' => '5.3.2',
    ],
    'bootstrap/dist/css/bootstrap.min.css' => [
        'version' => '5.3.2',
        'type' => 'css',
    ],
];
```

The importmap.php file defines entry points and external package dependencies.  
Packages are downloaded from CDNs and cached locally. The entrypoint flag marks  
files that should be loaded on page load.  

## Installing Packages

Adding JavaScript packages using the importmap:require command.  

```bash
php bin/console importmap:require @hotwired/stimulus
php bin/console importmap:require @hotwired/turbo
php bin/console importmap:require bootstrap
```

```php
<?php

// This command updates importmap.php and downloads packages
// Output: Added "@hotwired/stimulus" to importmap.php
```

The importmap:require command fetches packages from jsDelivr CDN and adds them  
to the import map. Downloaded files are cached in assets/vendor/ directory for  
offline development.  

## Asset Versioning

Enabling automatic versioning for cache busting.  

```php
<?php

// config/packages/framework.yaml
framework:
    assets:
        version_strategy: 'Symfony\Component\Asset\VersionStrategy\JsonManifestVersionStrategy'
        json_manifest_path: '%kernel.project_dir%/public/assets/manifest.json'
```

```php
<?php

// Usage in Twig templates
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class AssetController extends AbstractController
{
    #[Route('/demo', name: 'demo')]
    public function demo(): Response
    {
        return $this->render('demo.html.twig');
    }
}
```

AssetMapper automatically generates versioned URLs with content hashes. This  
ensures browsers always load the latest version when files change while  
maximizing cache effectiveness.  

## Using asset:install Command

Installing assets from bundles to the public directory.  

```bash
php bin/console assets:install
php bin/console assets:install --symlink
php bin/console assets:install --relative
```

```php
<?php

// Configuration for custom asset installation
// config/packages/framework.yaml
framework:
    assets:
        packages:
            admin:
                base_path: '/admin-assets'
```

The assets:install command copies or symlinks bundle assets to public/bundles/.  
The --symlink option creates symbolic links instead of copying files, useful  
for development. The --relative option creates relative symbolic links.  

## Preloading Assets

Optimizing performance with resource preloading.  

```php
<?php

// templates/base.html.twig
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <link rel="preload" href="{{ asset('styles/app.css') }}" as="style">
        <link rel="preload" href="{{ preload(asset('images/logo.png')) }}" as="image">
        {% block stylesheets %}
            <link rel="stylesheet" href="{{ asset('styles/app.css') }}">
        {% endblock %}
        {{ importmap('app') }}
    </head>
    <body>
        {% block body %}{% endblock %}
    </body>
</html>
```

The preload() function generates Link headers for HTTP/2 push. This tells  
browsers to fetch critical resources early, improving page load performance.  
Preloading works best for above-the-fold assets like fonts and CSS.  

## Stimulus Controller Integration

Integrating Stimulus controllers with AssetMapper.  

```javascript
// assets/bootstrap.js
import { Application } from '@hotwired/stimulus';

const application = Application.start();
application.debug = false;
window.Stimulus = application;

export { application };
```

```javascript
// assets/controllers/dropdown_controller.js
import { Controller } from '@hotwired/stimulus';

export default class extends Controller {
    static targets = ['menu'];
    
    connect() {
        console.log('Dropdown controller connected');
    }
    
    toggle() {
        this.menuTarget.classList.toggle('hidden');
    }
}
```

```javascript
// assets/app.js
import './bootstrap.js';
import DropdownController from './controllers/dropdown_controller.js';

Stimulus.register('dropdown', DropdownController);
```

Stimulus controllers work seamlessly with AssetMapper. Controllers are  
registered manually and loaded as standard ES6 modules without requiring  
webpack or other bundlers.  

## Page-Specific Assets

Loading assets only on specific pages.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class DashboardController extends AbstractController
{
    #[Route('/dashboard', name: 'dashboard')]
    public function index(): Response
    {
        return $this->render('dashboard/index.html.twig');
    }
}
```

```twig
{# templates/dashboard/index.html.twig #}
{% extends 'base.html.twig' %}

{% block stylesheets %}
    {{ parent() }}
    <link rel="stylesheet" href="{{ asset('styles/dashboard.css') }}">
{% endblock %}

{% block importmap %}
    {{ importmap(['app', 'dashboard']) }}
{% endblock %}

{% block body %}
    <div class="dashboard">
        <h1>Dashboard</h1>
    </div>
{% endblock %}
```

Multiple entry points can be specified in importmap() to load page-specific  
JavaScript. This reduces initial page load by only including necessary code  
for each route.  

## Lazy Loading Modules

Implementing dynamic imports for code splitting.  

```javascript
// assets/app.js
document.getElementById('load-chart').addEventListener('click', async () => {
    const { default: Chart } = await import('./modules/chart.js');
    
    const chart = new Chart(document.getElementById('chart-container'));
    chart.render();
});
```

```javascript
// assets/modules/chart.js
export default class Chart {
    constructor(element) {
        this.element = element;
    }
    
    render() {
        this.element.innerHTML = '<div class="chart">Chart rendered</div>';
    }
}
```

Dynamic imports allow lazy loading of modules only when needed. This reduces  
initial bundle size and improves performance for features not immediately  
visible or used by all users.  

## Asset Mapper with Turbo

Combining AssetMapper with Hotwired Turbo for SPA-like navigation.  

```php
<?php

// importmap.php
return [
    'app' => [
        'path' => './assets/app.js',
        'entrypoint' => true,
    ],
    '@hotwired/turbo' => [
        'version' => '7.3.0',
    ],
];
```

```javascript
// assets/app.js
import '@hotwired/turbo';

document.addEventListener('turbo:load', () => {
    console.log('Page loaded via Turbo');
});

document.addEventListener('turbo:before-cache', () => {
    // Clean up before caching the page
});
```

Turbo Drive intercepts link clicks and form submissions to perform AJAX  
requests. AssetMapper serves Turbo as a standard ES6 module without any  
build configuration.  

## Custom Asset Paths

Configuring multiple asset directories.  

```php
<?php

// config/packages/asset_mapper.yaml
framework:
    asset_mapper:
        paths:
            - assets/
            - vendor/acme/bundle/Resources/public
            - '%kernel.project_dir%/custom-assets'
        excluded_patterns:
            - '*/node_modules/*'
            - '*.test.js'
```

Multiple asset paths allow organizing files across different directories.  
Bundle assets, third-party libraries, and custom assets can all be mapped  
and served through AssetMapper.  

## TypeScript Support

Using TypeScript files with AssetMapper.  

```typescript
// assets/app.ts
interface User {
    id: number;
    name: string;
    email: string;
}

const users: User[] = [
    { id: 1, name: 'John Doe', email: 'john@example.com' },
    { id: 2, name: 'Jane Smith', email: 'jane@example.com' }
];

function displayUsers(userList: User[]): void {
    userList.forEach(user => {
        console.log(`${user.name} - ${user.email}`);
    });
}

displayUsers(users);
```

```bash
# Compile TypeScript to JavaScript
tsc assets/app.ts --outDir assets/compiled --module es2020
```

AssetMapper can serve compiled TypeScript files. Use the TypeScript compiler  
to generate ES6 modules, then map the output directory in AssetMapper  
configuration for serving.  

## CSS Imports in JavaScript

Importing CSS files from JavaScript modules.  

```javascript
// assets/components/modal.js
import '../styles/modal.css';

export default class Modal {
    constructor(element) {
        this.element = element;
    }
    
    open() {
        this.element.classList.add('modal-open');
        document.body.classList.add('modal-backdrop');
    }
    
    close() {
        this.element.classList.remove('modal-open');
        document.body.classList.remove('modal-backdrop');
    }
}
```

```css
/* assets/styles/modal.css */
.modal-open {
    display: block;
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.modal-backdrop {
    overflow: hidden;
}
```

CSS imports in JavaScript ensure styles are loaded when the component is used.  
AssetMapper handles CSS imports and automatically injects link tags into the  
document head.  

## Image Assets

Managing and optimizing image assets.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class GalleryController extends AbstractController
{
    #[Route('/gallery', name: 'gallery')]
    public function index(): Response
    {
        $images = [
            'logo.png',
            'banner.jpg',
            'thumbnail.webp',
        ];
        
        return $this->render('gallery/index.html.twig', [
            'images' => $images,
        ]);
    }
}
```

```twig
{# templates/gallery/index.html.twig #}
{% for image in images %}
    <img src="{{ asset('images/' ~ image) }}" 
         alt="Gallery image"
         loading="lazy">
{% endfor %}
```

Images in the assets/ directory are automatically mapped and versioned.  
AssetMapper generates URLs with content hashes for effective browser caching.  
Use loading="lazy" for images below the fold.  

## Font Assets

Loading custom web fonts efficiently.  

```css
/* assets/styles/fonts.css */
@font-face {
    font-family: 'CustomFont';
    src: url('../fonts/customfont.woff2') format('woff2'),
         url('../fonts/customfont.woff') format('woff');
    font-weight: normal;
    font-style: normal;
    font-display: swap;
}

body {
    font-family: 'CustomFont', sans-serif;
}
```

```php
<?php

// templates/base.html.twig
{% block stylesheets %}
    <link rel="preload" 
          href="{{ asset('fonts/customfont.woff2') }}" 
          as="font" 
          type="font/woff2" 
          crossorigin>
    <link rel="stylesheet" href="{{ asset('styles/fonts.css') }}">
{% endblock %}
```

Font files should be preloaded to prevent layout shifts. AssetMapper serves  
font files with proper MIME types and cache headers. Use font-display: swap  
to show fallback fonts while custom fonts load.  

## Environment-Specific Assets

Configuring assets differently for dev and production.  

```php
<?php

// config/packages/dev/asset_mapper.yaml
framework:
    asset_mapper:
        paths:
            - assets/
        server:
            enabled: true
            port: 8080

// config/packages/prod/asset_mapper.yaml
framework:
    asset_mapper:
        paths:
            - assets/
        server:
            enabled: false
```

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
        return $this->render('home/index.html.twig', [
            'environment' => $this->getParameter('kernel.environment'),
        ]);
    }
}
```

Development mode serves unminified assets with source maps for debugging.  
Production mode serves optimized assets with aggressive caching headers.  
Environment-specific configuration allows tailoring asset delivery.  

## Asset Dumping

Generating optimized assets for production deployment.  

```bash
php bin/console asset-map:compile

# Output structure:
# public/assets/app-abc123.js
# public/assets/styles/app-def456.css
# public/assets/manifest.json
```

```php
<?php

// After compilation, the manifest maps logical paths to versioned files
// public/assets/manifest.json
{
    "app.js": "assets/app-abc123.js",
    "styles/app.css": "assets/styles/app-def456.css"
}
```

The asset-map:compile command generates production-ready assets with content  
hashes in filenames. The manifest.json file maps original filenames to  
versioned URLs for the asset() function.  

## Removing Assets

Removing packages from the import map.  

```bash
php bin/console importmap:remove @hotwired/stimulus
php bin/console importmap:remove bootstrap

# Removes entries from importmap.php and deletes cached vendor files
```

```php
<?php

// importmap.php after removal
return [
    'app' => [
        'path' => './assets/app.js',
        'entrypoint' => true,
    ],
    '@hotwired/turbo' => [
        'version' => '7.3.0',
    ],
];
```

The importmap:remove command cleans up both the importmap.php configuration  
and the downloaded vendor files. This keeps the project lean by removing  
unused dependencies.  

## Updating Dependencies

Updating JavaScript package versions.  

```bash
php bin/console importmap:update
php bin/console importmap:update @hotwired/stimulus
php bin/console importmap:update --dry-run

# Check for available updates
php bin/console importmap:outdated
```

```php
<?php

// importmap:update fetches the latest compatible versions
// and updates importmap.php accordingly
return [
    '@hotwired/stimulus' => [
        'version' => '3.2.2', // Updated from 3.2.1
    ],
];
```

The importmap:update command checks for newer versions of packages and updates  
them. Use --dry-run to preview changes before applying. The importmap:outdated  
command lists packages with available updates.  

## Auditing Import Map

Inspecting the current import map configuration.  

```bash
php bin/console importmap:audit

# Output shows:
# - All mapped packages and their versions
# - Entry points
# - Local paths
# - External dependencies
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
    name: 'app:check-assets',
    description: 'Check asset configuration'
)]
class CheckAssetsCommand extends Command
{
    public function __construct(
        private ImportMapManager $importMapManager
    ) {
        parent::__construct();
    }
    
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        
        $entries = $this->importMapManager->getEntries();
        
        $io->title('Import Map Entries');
        $io->table(
            ['Package', 'Version', 'Type'],
            array_map(fn($entry) => [
                $entry->importName,
                $entry->version ?? 'local',
                $entry->isEntrypoint ? 'entrypoint' : 'dependency'
            ], $entries)
        );
        
        return Command::SUCCESS;
    }
}
```

The importmap:audit command provides visibility into the asset configuration.  
Custom commands can programmatically inspect and validate the import map  
using the ImportMapManager service.  

## Building Custom Importers

Creating custom importers for specialized asset types.  

```php
<?php

namespace App\AssetMapper;

use Symfony\Component\AssetMapper\AssetMapperInterface;
use Symfony\Component\AssetMapper\MappedAsset;

class SvgSpriteImporter
{
    public function __construct(
        private AssetMapperInterface $assetMapper
    ) {
    }
    
    public function generateSprite(): string
    {
        $assets = $this->assetMapper->allAssets();
        $svgContent = '<svg xmlns="http://www.w3.org/2000/svg">';
        
        foreach ($assets as $asset) {
            if ($this->isSvgIcon($asset)) {
                $content = file_get_contents($asset->sourcePath);
                $id = pathinfo($asset->logicalPath, PATHINFO_FILENAME);
                $svgContent .= sprintf(
                    '<symbol id="%s">%s</symbol>',
                    $id,
                    $this->extractSvgContent($content)
                );
            }
        }
        
        $svgContent .= '</svg>';
        return $svgContent;
    }
    
    private function isSvgIcon(MappedAsset $asset): bool
    {
        return str_starts_with($asset->logicalPath, 'icons/')
            && str_ends_with($asset->logicalPath, '.svg');
    }
    
    private function extractSvgContent(string $svg): string
    {
        preg_match('/<svg[^>]*>(.*?)<\/svg>/s', $svg, $matches);
        return $matches[1] ?? '';
    }
}
```

Custom importers can process and transform assets during the mapping phase.  
This example creates SVG sprites from individual icon files for optimized  
icon delivery.  

## Asset Map Compiler Events

Hooking into the asset compilation process.  

```php
<?php

namespace App\EventListener;

use Symfony\Component\AssetMapper\Event\PreAssetsCompileEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Psr\Log\LoggerInterface;

class AssetCompileListener implements EventSubscriberInterface
{
    public function __construct(
        private LoggerInterface $logger
    ) {
    }
    
    public static function getSubscribedEvents(): array
    {
        return [
            PreAssetsCompileEvent::class => 'onPreCompile',
        ];
    }
    
    public function onPreCompile(PreAssetsCompileEvent $event): void
    {
        $this->logger->info('Starting asset compilation');
        
        // Perform pre-compilation tasks
        // - Validate assets
        // - Generate additional files
        // - Clean up temporary files
        
        $manifest = $event->getManifest();
        $this->logger->info('Compiling assets', [
            'count' => count($manifest),
        ]);
    }
}
```

Asset compilation events allow running custom logic before and after assets  
are compiled. This is useful for validation, generating derived assets, or  
integrating with external tools.  

## Debugging Assets

Troubleshooting asset mapping issues.  

```bash
php bin/console debug:asset-map
php bin/console debug:asset-map app.js
php bin/console debug:asset-map --full

# Shows mapped paths, versions, and configuration
```

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\AssetMapper\AssetMapperInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class DebugController extends AbstractController
{
    #[Route('/debug/assets', name: 'debug_assets')]
    public function debugAssets(AssetMapperInterface $assetMapper): Response
    {
        $assets = [];
        foreach ($assetMapper->allAssets() as $asset) {
            $assets[] = [
                'logical_path' => $asset->logicalPath,
                'public_path' => $asset->publicPath,
                'source_path' => $asset->sourcePath,
            ];
        }
        
        return $this->render('debug/assets.html.twig', [
            'assets' => $assets,
        ]);
    }
}
```

The debug:asset-map command lists all mapped assets and their configuration.  
In development, create debug routes to inspect the asset mapper state and  
troubleshoot path resolution issues.  

## Performance Optimization

Optimizing AssetMapper for production performance.  

```php
<?php

// config/packages/prod/asset_mapper.yaml
framework:
    asset_mapper:
        paths:
            - assets/
        # Enable asset compilation
        compile: true
        
    assets:
        # Use JSON manifest for versioning
        version_strategy: 'Symfony\Component\Asset\VersionStrategy\JsonManifestVersionStrategy'
        json_manifest_path: '%kernel.project_dir%/public/assets/manifest.json'
        
    # Enable HTTP cache
    http_cache:
        enabled: true
        default_ttl: 31536000
```

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class PerformanceController extends AbstractController
{
    #[Route('/optimized', name: 'optimized')]
    public function index(): Response
    {
        $response = $this->render('optimized/index.html.twig');
        
        // Set aggressive caching for static assets
        $response->setPublic();
        $response->setMaxAge(31536000);
        $response->setSharedMaxAge(31536000);
        
        return $response;
    }
}
```

Production optimization includes asset compilation, versioned URLs, and  
aggressive HTTP caching. AssetMapper generates content-hashed filenames  
allowing year-long cache durations for immutable assets.  

## Integration with Sass

Compiling Sass to CSS for use with AssetMapper.  

```bash
# Install Sass compiler
npm install -g sass

# Compile Sass files
sass assets/styles/app.scss:assets/styles/app.css --watch
```

```scss
// assets/styles/app.scss
$primary-color: #3490dc;
$font-stack: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;

body {
    font-family: $font-stack;
    color: #333;
}

.button {
    background-color: $primary-color;
    color: white;
    padding: 0.75rem 1.5rem;
    border-radius: 0.375rem;
    
    &:hover {
        background-color: darken($primary-color, 10%);
    }
}
```

```php
<?php

// templates/base.html.twig
{% block stylesheets %}
    <link rel="stylesheet" href="{{ asset('styles/app.css') }}">
{% endblock %}
```

AssetMapper can serve compiled Sass/SCSS files. Use the Sass compiler to  
generate CSS files, then map the output directory. For development, use  
--watch mode to automatically recompile on changes.  

## Working with SVG Icons

Managing SVG icons as assets.  

```php
<?php

namespace App\Twig;

use Symfony\Component\AssetMapper\AssetMapperInterface;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class IconExtension extends AbstractExtension
{
    public function __construct(
        private AssetMapperInterface $assetMapper
    ) {
    }
    
    public function getFunctions(): array
    {
        return [
            new TwigFunction('icon', [$this, 'renderIcon'], ['is_safe' => ['html']]),
        ];
    }
    
    public function renderIcon(string $name, array $attributes = []): string
    {
        $asset = $this->assetMapper->getAsset("icons/{$name}.svg");
        
        if (!$asset) {
            return '';
        }
        
        $svg = file_get_contents($asset->sourcePath);
        
        // Add custom attributes
        if (!empty($attributes)) {
            $attrString = '';
            foreach ($attributes as $key => $value) {
                $attrString .= sprintf(' %s="%s"', $key, htmlspecialchars($value));
            }
            $svg = preg_replace('/<svg/', '<svg' . $attrString, $svg, 1);
        }
        
        return $svg;
    }
}
```

```twig
{# Usage in templates #}
<button>
    {{ icon('user', {class: 'icon-small'}) }}
    Profile
</button>

<a href="#">
    {{ icon('home') }}
    Home
</a>
```

Custom Twig extensions can inline SVG icons from mapped assets. This approach  
allows styling SVG icons with CSS and eliminates additional HTTP requests for  
icon files.  
