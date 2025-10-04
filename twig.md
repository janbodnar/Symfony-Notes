# Twig Templating

Twig is the default templating engine for Symfony applications. It provides  
a clean, powerful syntax for rendering HTML with dynamic data, while  
maintaining security through automatic output escaping. Twig templates are  
compiled to optimized PHP code for excellent performance.  

## Introduction to Twig

Twig separates presentation logic from business logic, making templates  
easy to read and maintain. The syntax uses curly braces for output `{{ }}`,  
curly braces with percent for control structures `{% %}`, and curly braces  
with hash for comments `{# #}`. All output is automatically escaped to  
prevent XSS attacks.  

### Why Twig?

**Security**: Automatic output escaping protects against cross-site  
scripting (XSS) vulnerabilities. Variables are HTML-escaped by default,  
preventing malicious code injection.  

**Performance**: Twig templates compile to optimized PHP code and are  
cached. After the initial compilation, templates execute as fast as native  
PHP code.  

**Flexibility**: Template inheritance, macros, filters, and functions  
provide powerful tools for building complex layouts. Create reusable  
components and organize templates efficiently.  

**Designer-Friendly**: Clean syntax is easier for frontend developers to  
read and write compared to mixing PHP and HTML. Twig's limited logic scope  
encourages proper separation of concerns.  

**Extensibility**: Create custom filters, functions, and tests tailored to  
your application's needs. Symfony provides many built-in extensions for  
common tasks.  

## Directory Structure

Templates are organized in the `templates/` directory following a  
conventional structure that mirrors your application's organization.  

```
templates/
├── base.html.twig              # Main base template
├── _partials/                  # Reusable template fragments
│   ├── header.html.twig
│   ├── footer.html.twig
│   └── alert.html.twig
├── product/                    # Product-related templates
│   ├── index.html.twig        # Product list
│   ├── show.html.twig         # Product detail
│   ├── edit.html.twig         # Product edit form
│   └── _form.html.twig        # Form partial
├── user/                       # User-related templates
│   ├── profile.html.twig
│   ├── settings.html.twig
│   └── list.html.twig
└── email/                      # Email templates
    ├── welcome.html.twig
    └── notification.txt.twig
```

Templates should be organized by feature or controller. Use subdirectories  
for related templates. Prefix partial templates with underscore to indicate  
they're meant for inclusion, not direct rendering.  

## Basic Syntax

### Variable Output

Displaying variables and object properties in templates.  

```twig
{# templates/product/show.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    {# Simple variable output #}
    <h1>{{ product.name }}</h1>
    
    {# Object property access #}
    <p>Price: ${{ product.price }}</p>
    <p>SKU: {{ product.sku }}</p>
    
    {# Array access #}
    <p>Category: {{ categories[0] }}</p>
    
    {# Method calls #}
    <p>Total: ${{ product.getTotal() }}</p>
    
    {# Concatenation #}
    <p>Full name: {{ user.firstName ~ ' ' ~ user.lastName }}</p>
    
    {# Mathematical operations #}
    <p>Tax: ${{ product.price * 0.2 }}</p>
    <p>Subtotal: ${{ product.price + shipping }}</p>
{% endblock %}
```

Double curly braces `{{ }}` output variable values. Twig automatically  
escapes HTML to prevent XSS attacks. Use dot notation to access object  
properties, array elements, or call methods. The tilde `~` operator  
concatenates strings.  

### Comments

Adding documentation to templates without rendering output.  

```twig
{# This is a single-line comment #}

{#
    Multi-line comment
    spanning multiple lines
    for longer explanations
#}

{# TODO: Add product image gallery #}

<div class="product">
    {{ product.name }} {# Display product name #}
</div>
```

Comments use `{# #}` syntax and are not included in rendered output. Use  
them to document template logic, leave notes for developers, or temporarily  
disable code during debugging.  

## Control Structures

### Conditionals

Making decisions in templates based on data.  

```twig
{# templates/product/card.html.twig #}
{% if product.inStock %}
    <span class="badge badge-success">Available</span>
{% elseif product.backorder %}
    <span class="badge badge-warning">Backorder</span>
{% else %}
    <span class="badge badge-danger">Out of Stock</span>
{% endif %}

{# Multiple conditions #}
{% if user.isActive and user.isVerified %}
    <p>Welcome back, {{ user.name }}!</p>
{% endif %}

{% if product.onSale or product.featured %}
    <div class="highlight">Special Offer!</div>
{% endif %}

{# Negation #}
{% if not user.isPremium %}
    <a href="{{ path('upgrade') }}">Upgrade to Premium</a>
{% endif %}

{# Complex conditions #}
{% if product.price > 100 and (product.category == 'Electronics' or product.brand == 'Premium') %}
    <span>Free Shipping</span>
{% endif %}
```

Use `if`, `elseif`, and `else` for conditional rendering. Combine  
conditions with `and`, `or`, and `not` operators. Comparison operators  
include `==`, `!=`, `<`, `>`, `<=`, `>=`. Parentheses group complex  
conditions.  

### Loops

Iterating over collections and arrays.  

```twig
{# templates/product/list.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    <h1>Products</h1>
    
    {% for product in products %}
        <div class="product-card">
            <h2>{{ loop.index }}. {{ product.name }}</h2>
            <p>${{ product.price }}</p>
            
            {% if loop.first %}
                <span class="badge">Featured</span>
            {% endif %}
            
            {% if loop.last %}
                <hr>
            {% endif %}
        </div>
    {% else %}
        <p>No products available.</p>
    {% endfor %}
    
    {# Loop with custom keys #}
    {% for key, value in attributes %}
        <dt>{{ key }}</dt>
        <dd>{{ value }}</dd>
    {% endfor %}
    
    {# Accessing loop metadata #}
    {% for item in items %}
        <tr class="{{ cycle(['odd', 'even'], loop.index0) }}">
            <td>Item {{ loop.index }} of {{ loop.length }}</td>
            <td>{{ loop.revindex }} remaining</td>
        </tr>
    {% endfor %}
{% endblock %}
```

The `for` loop iterates over arrays and collections. The special `loop`  
variable provides metadata: `loop.index` (1-based), `loop.index0`  
(0-based), `loop.first`, `loop.last`, `loop.length`, and `loop.revindex`.  
Use `{% else %}` to handle empty collections.  

## Filters

### Common Filters

Transforming and formatting data in templates.  

```twig
{# templates/article/show.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    {# String manipulation #}
    <h1>{{ article.title|upper }}</h1>
    <h2>{{ article.subtitle|lower }}</h2>
    <p>{{ article.slug|title }}</p>
    
    {# String truncation #}
    <p>{{ article.content|slice(0, 200) }}...</p>
    <p>{{ article.description|truncate(100) }}</p>
    
    {# Date formatting #}
    <time>{{ article.publishedAt|date('F j, Y') }}</time>
    <small>{{ article.updatedAt|date('Y-m-d H:i:s') }}</small>
    <span>{{ article.createdAt|date('relative') }}</span>
    
    {# Number formatting #}
    <p>Price: ${{ product.price|number_format(2) }}</p>
    <p>Views: {{ article.views|number_format(0, '.', ',') }}</p>
    
    {# Array operations #}
    <p>Tags: {{ article.tags|join(', ') }}</p>
    <p>Word count: {{ article.content|split(' ')|length }}</p>
    <p>First tag: {{ article.tags|first }}</p>
    <p>Last tag: {{ article.tags|last }}</p>
    
    {# Default values #}
    <p>Author: {{ article.author|default('Anonymous') }}</p>
    
    {# HTML escaping #}
    <div>{{ article.htmlContent|raw }}</div>
    <script>{{ article.data|json_encode|raw }}</script>
{% endblock %}
```

Filters transform values using the pipe operator `|`. Chain multiple  
filters together. Common filters include `upper`, `lower`, `title`,  
`length`, `date`, `number_format`, `join`, `default`, and `raw`. The `raw`  
filter bypasses auto-escaping for trusted HTML content.  

### Advanced Filters

More complex data transformations.  

```twig
{# templates/user/profile.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    {# Array filtering #}
    {% set activeUsers = users|filter(u => u.isActive) %}
    {% set premiumUsers = users|filter(u => u.plan == 'premium') %}
    
    {# Array mapping #}
    {% set userNames = users|map(u => u.name) %}
    
    {# Sorting #}
    {% set sortedProducts = products|sort((a, b) => a.price <=> b.price) %}
    
    {# Reversing #}
    {% for item in items|reverse %}
        <li>{{ item.name }}</li>
    {% endfor %}
    
    {# URL encoding #}
    <a href="?search={{ query|url_encode }}">Search</a>
    
    {# String replacement #}
    <p>{{ text|replace({'old': 'new', 'foo': 'bar'}) }}</p>
    
    {# Format strings #}
    <p>{{ "Hello there, %s!"|format(user.name) }}</p>
    
    {# Markdown to HTML #}
    <div>{{ content|markdown_to_html }}</div>
    
    {# Absolute URLs #}
    <link rel="canonical" href="{{ path('product_show', {id: product.id})|url }}">
{% endblock %}
```

Advanced filters enable complex transformations. Use `filter` and `map` for  
array operations. The `sort` filter accepts comparison functions. Combine  
filters with Twig's arrow function syntax for powerful data manipulation.  

## Functions

### Built-in Functions

Twig provides functions for common template operations.  

```twig
{# templates/layout/navigation.html.twig #}
<nav>
    {# Route generation #}
    <a href="{{ path('home') }}">Home</a>
    <a href="{{ path('product_list') }}">Products</a>
    <a href="{{ path('product_show', {id: 42}) }}">Product #42</a>
    
    {# Absolute URLs #}
    <a href="{{ url('contact') }}">Contact Us</a>
    
    {# Asset management #}
    <link rel="stylesheet" href="{{ asset('css/style.css') }}">
    <script src="{{ asset('js/app.js') }}"></script>
    <img src="{{ asset('images/logo.png') }}" alt="Logo">
    
    {# Absolute asset URLs #}
    <link rel="canonical" href="{{ absolute_url(asset('images/product.jpg')) }}">
    
    {# Random values #}
    <div class="bg-{{ random(['red', 'blue', 'green']) }}">
        Random background
    </div>
    
    {# Range generation #}
    {% for i in range(1, 10) %}
        <span>{{ i }}</span>
    {% endfor %}
    
    {% for letter in range('a', 'z') %}
        <li>{{ letter }}</li>
    {% endfor %}
    
    {# Date functions #}
    <p>Current year: {{ 'now'|date('Y') }}</p>
    <p>Tomorrow: {{ date('+1 day')|date('Y-m-d') }}</p>
</nav>
```

The `path()` function generates relative URLs from route names. The `url()`  
function creates absolute URLs. The `asset()` function resolves asset  
paths. Use `random()` for random selection and `range()` to generate  
numeric or alphabetic sequences.  

### Testing Values

Checking value types and states.  

```twig
{# templates/product/show.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    {# Type checking #}
    {% if product.tags is defined %}
        <p>Tags: {{ product.tags|join(', ') }}</p>
    {% endif %}
    
    {% if description is null %}
        <p>No description available</p>
    {% endif %}
    
    {# Collection tests #}
    {% if products is empty %}
        <p>No products found</p>
    {% else %}
        <p>Found {{ products|length }} products</p>
    {% endif %}
    
    {# Numeric tests #}
    {% if product.stock is even %}
        <span>Even stock count</span>
    {% endif %}
    
    {% if quantity is odd %}
        <span>Odd quantity</span>
    {% endif %}
    
    {# String tests #}
    {% if user.role is same as('ROLE_ADMIN') %}
        <a href="{{ path('admin_panel') }}">Admin Panel</a>
    {% endif %}
    
    {# Divisibility #}
    {% if loop.index is divisible by(3) %}
        <div class="clearfix"></div>
    {% endif %}
    
    {# Custom tests #}
    {% if product is instanceof('App\\\\Entity\\\\DigitalProduct') %}
        <span>Digital Download</span>
    {% endif %}
{% endblock %}
```

Use the `is` operator to test values. Common tests include `defined`,  
`null`, `empty`, `even`, `odd`, `same as`, and `divisible by`. Tests are  
useful for conditional logic without complex expressions.  

## Template Inheritance

### Base Templates

Creating reusable layout templates.  

```twig
{# templates/base.html.twig #}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}My Application{% endblock %}</title>
    
    {% block meta %}
        <meta name="description" content="{% block description %}Default description{% endblock %}">
    {% endblock %}
    
    {% block stylesheets %}
        <link rel="stylesheet" href="{{ asset('css/bootstrap.min.css') }}">
        <link rel="stylesheet" href="{{ asset('css/app.css') }}">
    {% endblock %}
</head>
<body>
    <header>
        {% block header %}
            <nav class="navbar">
                <a href="{{ path('home') }}" class="navbar-brand">MyApp</a>
                <ul class="navbar-nav">
                    <li><a href="{{ path('products') }}">Products</a></li>
                    <li><a href="{{ path('about') }}">About</a></li>
                </ul>
            </nav>
        {% endblock %}
    </header>
    
    <main class="container">
        {% block flash_messages %}
            {% for label, messages in app.flashes %}
                {% for message in messages %}
                    <div class="alert alert-{{ label }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endfor %}
        {% endblock %}
        
        {% block body %}{% endblock %}
    </main>
    
    <footer>
        {% block footer %}
            <p>&copy; {{ 'now'|date('Y') }} MyApp. All rights reserved.</p>
        {% endblock %}
    </footer>
    
    {% block javascripts %}
        <script src="{{ asset('js/jquery.min.js') }}"></script>
        <script src="{{ asset('js/app.js') }}"></script>
    {% endblock %}
</body>
</html>
```

Base templates define the overall page structure using blocks. Child  
templates can override these blocks to customize specific sections. Blocks  
can have default content that displays if not overridden. Use descriptive  
block names that indicate their purpose.  

### Extending Templates

Child templates inherit and customize base layouts.  

```twig
{# templates/product/show.html.twig #}
{% extends 'base.html.twig' %}

{% block title %}{{ product.name }} - Products{% endblock %}

{% block description %}{{ product.description|slice(0, 160) }}{% endblock %}

{% block stylesheets %}
    {{ parent() }}
    <link rel="stylesheet" href="{{ asset('css/product.css') }}">
{% endblock %}

{% block body %}
    <div class="product-detail">
        <div class="row">
            <div class="col-md-6">
                <img src="{{ asset('images/products/' ~ product.image) }}" 
                     alt="{{ product.name }}"
                     class="img-fluid">
            </div>
            
            <div class="col-md-6">
                <h1>{{ product.name }}</h1>
                
                <div class="price">
                    {% if product.onSale %}
                        <span class="original">${{ product.originalPrice }}</span>
                        <span class="sale">${{ product.price }}</span>
                        <span class="badge">{{ product.discount }}% OFF</span>
                    {% else %}
                        <span>${{ product.price }}</span>
                    {% endif %}
                </div>
                
                <p>{{ product.description }}</p>
                
                {% if product.inStock %}
                    <form method="post" action="{{ path('cart_add', {id: product.id}) }}">
                        <input type="hidden" name="_token" value="{{ csrf_token('add-to-cart') }}">
                        <button type="submit" class="btn btn-primary">Add to Cart</button>
                    </form>
                {% else %}
                    <p class="text-danger">Out of Stock</p>
                {% endif %}
            </div>
        </div>
    </div>
{% endblock %}

{% block javascripts %}
    {{ parent() }}
    <script src="{{ asset('js/product-gallery.js') }}"></script>
{% endblock %}
```

Use `{% extends %}` to inherit from a base template. Override blocks by  
redefining them in the child template. Call `{{ parent() }}` to include the  
parent block's content before or after your additions. This is useful for  
adding extra stylesheets or scripts while keeping the base template's  
assets.  

### Multi-Level Inheritance

Creating intermediate layout templates.  

```twig
{# templates/layout/admin.html.twig #}
{% extends 'base.html.twig' %}

{% block stylesheets %}
    {{ parent() }}
    <link rel="stylesheet" href="{{ asset('css/admin.css') }}">
{% endblock %}

{% block header %}
    <nav class="admin-nav">
        <a href="{{ path('admin_dashboard') }}">Dashboard</a>
        <a href="{{ path('admin_users') }}">Users</a>
        <a href="{{ path('admin_products') }}">Products</a>
        <a href="{{ path('admin_orders') }}">Orders</a>
    </nav>
{% endblock %}

{% block body %}
    <div class="admin-layout">
        <aside class="sidebar">
            {% block sidebar %}
                <ul class="nav">
                    <li><a href="{{ path('admin_dashboard') }}">Overview</a></li>
                    <li><a href="{{ path('admin_settings') }}">Settings</a></li>
                </ul>
            {% endblock %}
        </aside>
        
        <main class="admin-content">
            {% block admin_content %}{% endblock %}
        </main>
    </div>
{% endblock %}
```

```twig
{# templates/admin/users/list.html.twig #}
{% extends 'layout/admin.html.twig' %}

{% block title %}User Management - Admin{% endblock %}

{% block admin_content %}
    <h1>Users</h1>
    
    <table class="table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Email</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for user in users %}
                <tr>
                    <td>{{ user.id }}</td>
                    <td>{{ user.name }}</td>
                    <td>{{ user.email }}</td>
                    <td>
                        <a href="{{ path('admin_user_edit', {id: user.id}) }}">Edit</a>
                    </td>
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% endblock %}
```

Create intermediate templates for section-specific layouts like admin  
panels or user dashboards. These templates extend the base template and are  
themselves extended by feature templates. This creates a three-level  
hierarchy: base → section → feature.  

## Template Includes

### Including Partials

Reusing template fragments across multiple templates.  

```twig
{# templates/_partials/alert.html.twig #}
<div class="alert alert-{{ type|default('info') }} {{ class|default('') }}" role="alert">
    {% if icon|default(false) %}
        <i class="icon-{{ icon }}"></i>
    {% endif %}
    {{ message }}
    {% if dismissible|default(false) %}
        <button type="button" class="close" data-dismiss="alert">×</button>
    {% endif %}
</div>
```

```twig
{# templates/product/show.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    {# Include with variables #}
    {% include '_partials/alert.html.twig' with {
        'type': 'success',
        'message': 'Product loaded successfully!',
        'dismissible': true
    } %}
    
    {# Include with only specified variables #}
    {% include '_partials/alert.html.twig' with {
        'type': 'warning',
        'message': 'Limited stock available'
    } only %}
    
    {# Include without additional variables #}
    {% include '_partials/breadcrumb.html.twig' %}
    
    <h1>{{ product.name }}</h1>
{% endblock %}
```

Use `{% include %}` to embed template fragments. Pass variables using the  
`with` keyword. Add `only` to limit the included template to specified  
variables, preventing access to the parent template's context. Prefix  
partial templates with underscore to distinguish them from full templates.  

### Dynamic Includes

Including templates based on runtime conditions.  

```twig
{# templates/product/show.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    {# Include based on product type #}
    {% include 'product/_type/' ~ product.type ~ '.html.twig' %}
    
    {# Include with fallback #}
    {% include ['product/_custom/' ~ product.id ~ '.html.twig',
                'product/_type/' ~ product.type ~ '.html.twig',
                'product/_default.html.twig'] %}
    
    {# Conditional include #}
    {% if product.hasReviews %}
        {% include 'product/_reviews.html.twig' %}
    {% endif %}
    
    {# Include with ignore missing #}
    {% include 'product/_custom_message.html.twig' ignore missing %}
{% endblock %}
```

Construct template names dynamically using string concatenation. Provide  
fallback templates in an array. Use `ignore missing` to silently skip  
non-existent templates. This pattern enables flexible, content-driven  
template selection.  

### Template Embedding

Including templates with block overrides.  

```twig
{# templates/_partials/card.html.twig #}
<div class="card {{ class|default('') }}">
    {% block card_header %}
        <div class="card-header">
            <h3>{% block card_title %}Default Title{% endblock %}</h3>
        </div>
    {% endblock %}
    
    {% block card_body %}
        <div class="card-body">
            {% block card_content %}
                Default content
            {% endblock %}
        </div>
    {% endblock %}
    
    {% block card_footer %}{% endblock %}
</div>
```

```twig
{# templates/product/show.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    {# Embed allows overriding blocks #}
    {% embed '_partials/card.html.twig' with {
        'class': 'product-card'
    } %}
        {% block card_title %}{{ product.name }}{% endblock %}
        
        {% block card_content %}
            <p class="price">${{ product.price }}</p>
            <p>{{ product.description }}</p>
        {% endblock %}
        
        {% block card_footer %}
            <div class="card-footer">
                <a href="{{ path('cart_add', {id: product.id}) }}" class="btn">
                    Add to Cart
                </a>
            </div>
        {% endblock %}
    {% endembed %}
{% endblock %}
```

Embedding combines `include` and `extends` functionality. The embedded  
template defines blocks that can be overridden. Use `{% embed %}` when you  
need to customize parts of a reusable component while keeping its  
structure. This is perfect for card layouts, modals, and other UI  
components.  

## Macros

### Defining Macros

Creating reusable template functions.  

```twig
{# templates/_macros/forms.html.twig #}
{% macro input(name, value, type, label, attributes) %}
    <div class="form-group">
        {% if label %}
            <label for="{{ name }}">{{ label }}</label>
        {% endif %}
        <input type="{{ type|default('text') }}" 
               id="{{ name }}" 
               name="{{ name }}" 
               value="{{ value|default('') }}"
               class="form-control {{ attributes.class|default('') }}"
               {% for attr, val in attributes|default({}) if attr != 'class' %}
                   {{ attr }}="{{ val }}"
               {% endfor %}>
    </div>
{% endmacro %}

{% macro button(text, type, class) %}
    <button type="{{ type|default('button') }}" 
            class="btn {{ class|default('btn-primary') }}">
        {{ text }}
    </button>
{% endmacro %}

{% macro select(name, options, selected, label) %}
    <div class="form-group">
        {% if label %}
            <label for="{{ name }}">{{ label }}</label>
        {% endif %}
        <select id="{{ name }}" name="{{ name }}" class="form-control">
            {% for value, text in options %}
                <option value="{{ value }}" 
                        {% if value == selected %}selected{% endif %}>
                    {{ text }}
                </option>
            {% endfor %}
        </select>
    </div>
{% endmacro %}
```

Macros are reusable template functions defined with `{% macro %}`. They  
accept parameters and return rendered HTML. Store macros in dedicated  
template files for organization. Use macros for repetitive HTML patterns  
like form fields, buttons, or UI components.  

### Using Macros

Importing and calling macros in templates.  

```twig
{# templates/user/register.html.twig #}
{% extends 'base.html.twig' %}

{% import '_macros/forms.html.twig' as forms %}

{% block body %}
    <h1>Register</h1>
    
    <form method="post" action="{{ path('user_register') }}">
        {{ forms.input('username', '', 'text', 'Username', {
            'required': 'required',
            'placeholder': 'Enter username',
            'class': 'input-lg'
        }) }}
        
        {{ forms.input('email', '', 'email', 'Email Address', {
            'required': 'required',
            'placeholder': 'your@email.com'
        }) }}
        
        {{ forms.input('password', '', 'password', 'Password', {
            'required': 'required',
            'minlength': '8'
        }) }}
        
        {{ forms.select('country', countries, selectedCountry, 'Country') }}
        
        {{ forms.button('Create Account', 'submit', 'btn-primary btn-lg') }}
    </form>
{% endblock %}
```

Import macros using `{% import %}` with an alias. Call macros like  
functions using the alias and macro name. Pass arguments in the order  
defined in the macro. Macros help maintain consistency and reduce code  
duplication across forms and UI components.  

## Global Variables

### App Variable

Accessing application context in templates.  

```twig
{# templates/base.html.twig #}
<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}My App{% endblock %}</title>
</head>
<body>
    {# Current user #}
    {% if app.user %}
        <div class="user-info">
            Welcome, {{ app.user.username }}!
            <a href="{{ path('app_logout') }}">Logout</a>
        </div>
    {% else %}
        <a href="{{ path('app_login') }}">Login</a>
    {% endif %}
    
    {# Current request #}
    <p>Current route: {{ app.request.attributes.get('_route') }}</p>
    <p>Method: {{ app.request.method }}</p>
    <p>Locale: {{ app.request.locale }}</p>
    
    {# Session access #}
    {% if app.session.get('last_visit') %}
        <p>Last visit: {{ app.session.get('last_visit')|date('Y-m-d H:i') }}</p>
    {% endif %}
    
    {# Environment #}
    {% if app.environment == 'dev' %}
        <div class="dev-toolbar">Development Mode</div>
    {% endif %}
    
    {# Flash messages #}
    {% for label, messages in app.flashes %}
        {% for message in messages %}
            <div class="alert alert-{{ label }}">{{ message }}</div>
        {% endfor %}
    {% endfor %}
    
    {% block body %}{% endblock %}
</body>
</html>
```

The global `app` variable provides access to the current user, request,  
session, environment, and flash messages. Use `app.user` for  
authentication checks. Access request data through `app.request`. Check the  
environment with `app.environment`.  

## Custom Twig Extensions

### Creating Filters

Extending Twig with custom filters.  

```php
<?php

namespace App\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFilter;

class AppExtension extends AbstractExtension
{
    public function getFilters(): array
    {
        return [
            new TwigFilter('price', [$this, 'formatPrice']),
            new TwigFilter('excerpt', [$this, 'createExcerpt']),
            new TwigFilter('slugify', [$this, 'slugify']),
        ];
    }

    public function formatPrice(float $price, string $currency = 'USD'): string
    {
        $symbols = [
            'USD' => '$',
            'EUR' => '€',
            'GBP' => '£',
        ];

        $symbol = $symbols[$currency] ?? $currency;
        return $symbol . number_format($price, 2);
    }

    public function createExcerpt(string $text, int $length = 100): string
    {
        if (strlen($text) <= $length) {
            return $text;
        }

        $excerpt = substr($text, 0, $length);
        $lastSpace = strrpos($excerpt, ' ');

        if ($lastSpace !== false) {
            $excerpt = substr($excerpt, 0, $lastSpace);
        }

        return $excerpt . '...';
    }

    public function slugify(string $text): string
    {
        $text = strtolower($text);
        $text = preg_replace('/[^a-z0-9]+/', '-', $text);
        return trim($text, '-');
    }
}
```

Create custom filters by extending `AbstractExtension`. Define filter  
methods and register them in `getFilters()`. Filters receive the value as  
the first parameter followed by any additional arguments. The extension is  
automatically registered if autoconfiguration is enabled.  

### Creating Functions

Adding custom Twig functions.  

```php
<?php

namespace App\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class UtilityExtension extends AbstractExtension
{
    public function getFunctions(): array
    {
        return [
            new TwigFunction('icon', [$this, 'renderIcon'], [
                'is_safe' => ['html']
            ]),
            new TwigFunction('format_bytes', [$this, 'formatBytes']),
            new TwigFunction('random_color', [$this, 'randomColor']),
        ];
    }

    public function renderIcon(string $name, string $class = ''): string
    {
        return sprintf(
            '<i class="icon icon-%s %s"></i>',
            htmlspecialchars($name),
            htmlspecialchars($class)
        );
    }

    public function formatBytes(int $bytes, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);

        $bytes /= pow(1024, $pow);

        return round($bytes, $precision) . ' ' . $units[$pow];
    }

    public function randomColor(): string
    {
        return sprintf('#%06X', mt_rand(0, 0xFFFFFF));
    }
}
```

Custom functions are created similarly to filters. Mark functions that  
return HTML with `is_safe => ['html']` to prevent double escaping. Use  
functions for operations that don't transform input values but generate new  
content.  

### Using Custom Extensions

Applying custom filters and functions in templates.  

```twig
{# templates/product/list.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    <h1>Products</h1>
    
    {% for product in products %}
        <div class="product-card" style="border-color: {{ random_color() }}">
            <h2>
                {{ icon('star', 'featured') }}
                {{ product.name }}
            </h2>
            
            <p class="price">{{ product.price|price('USD') }}</p>
            <p class="excerpt">{{ product.description|excerpt(150) }}</p>
            
            <a href="{{ path('product_show', {
                slug: product.name|slugify
            }) }}">
                View Details
            </a>
            
            {% if product.fileSize %}
                <small>Size: {{ format_bytes(product.fileSize) }}</small>
            {% endif %}
        </div>
    {% endfor %}
{% endblock %}
```

Use custom filters and functions like built-in ones. Combine them with  
other Twig features for powerful templating. Custom extensions help  
encapsulate application-specific formatting and logic in reusable  
components.  

## Best Practices

### Template Organization

Structure templates for maintainability and reusability.  

**Use Template Inheritance**: Create base templates for common layouts.  
Extend them in feature-specific templates. This reduces duplication and  
ensures consistent styling across pages.  

**Organize by Feature**: Group related templates in subdirectories by  
controller or feature area. Keep templates close to the code that renders  
them for easier navigation.  

**Prefix Partials**: Name reusable fragments with an underscore prefix  
(`_header.html.twig`, `_form.html.twig`). This convention indicates they're  
meant for inclusion, not direct rendering.  

**Keep Logic Minimal**: Templates should focus on presentation. Move  
complex logic to controllers, services, or Twig extensions. Use filters and  
functions for simple transformations only.  

**Use Descriptive Names**: Name templates and blocks clearly to indicate  
their purpose. Use `product/show.html.twig` instead of  
`product/detail.html.twig` to match controller action names.  

### Performance Optimization

Optimize template rendering for better performance.  

**Enable Template Caching**: Twig automatically caches compiled templates  
in production. Never disable caching in production environments.  

**Minimize Database Queries**: Fetch all required data in controllers.  
Avoid lazy-loading relationships in templates. Use eager loading with  
Doctrine for better performance.  

**Use Asset Versioning**: Version static assets to enable long-term  
caching. Symfony's asset component handles this automatically with  
versioning strategies.  

**Optimize Includes**: Excessive template includes add overhead. Combine  
small fragments or use template inheritance instead of many separate  
includes.  

**Lazy Load Images**: Use loading attributes and placeholders for images  
below the fold. This improves initial page load times.  

### Security Considerations

Ensure template security and prevent vulnerabilities.  

**Trust Auto-Escaping**: Twig escapes output by default. Don't disable  
auto-escaping globally. Use the `raw` filter only for trusted content.  

**Validate User Input**: Never trust user data in templates. Validate and  
sanitize in controllers before passing to templates.  

**Use CSRF Tokens**: Include CSRF tokens in forms for state-changing  
operations. Symfony's form component handles this automatically.  

**Sanitize URLs**: Use `path()` and `url()` functions for route generation  
instead of building URLs manually. This prevents injection attacks.  

**Be Careful with Raw**: Only use the `raw` filter for content from  
trusted sources. Applying `raw` to user input creates XSS vulnerabilities.  

### Code Reusability

Create maintainable and DRY templates.  

**Use Macros for Repetition**: Extract repeated patterns into macros. Form  
fields, buttons, and UI components are good candidates for macros.  

**Create Base Templates**: Build base templates for different sections  
(public site, admin panel, email templates). Extend these bases for  
consistent layouts.  

**Leverage Template Inheritance**: Use three-level inheritance (base →  
section → feature) for complex applications. This provides flexibility  
while maintaining consistency.  

**Include Partials Wisely**: Use includes for truly reusable fragments.  
For variations, consider using parameters or macros instead of creating  
multiple similar partials.  

**Document Complex Templates**: Add comments to explain non-obvious logic,  
especially in base templates or complex macros. Future developers will  
appreciate the context.  

## Advanced Techniques

### Horizontal Reuse

Sharing functionality across templates without inheritance.  

```twig
{# templates/_traits/pagination.html.twig #}
{% block pagination %}
    {% if pages > 1 %}
        <nav class="pagination">
            {% for i in range(1, pages) %}
                <a href="{{ path(route, {page: i}) }}" 
                   class="{{ i == currentPage ? 'active' : '' }}">
                    {{ i }}
                </a>
            {% endfor %}
        </nav>
    {% endif %}
{% endblock %}
```

```twig
{# templates/product/list.html.twig #}
{% extends 'base.html.twig' %}
{% use '_traits/pagination.html.twig' %}

{% block body %}
    <h1>Products</h1>
    
    {% for product in products %}
        <div class="product">{{ product.name }}</div>
    {% endfor %}
    
    {{ block('pagination') }}
{% endblock %}
```

Use `{% use %}` to import blocks from other templates without extending  
them. This enables horizontal reuse of template fragments across different  
template hierarchies. Useful for shared functionality like pagination,  
filtering, or sorting controls.  

### Template Composition

Composing complex templates from smaller parts.  

```twig
{# templates/product/show.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    <article class="product-detail">
        {% include 'product/_header.html.twig' %}
        
        <div class="product-content">
            {% include 'product/_gallery.html.twig' %}
            {% include 'product/_info.html.twig' %}
        </div>
        
        {% include 'product/_related.html.twig' %}
        {% include 'product/_reviews.html.twig' %}
    </article>
{% endblock %}
```

Break complex templates into logical sections. Each section can be  
developed and tested independently. This composition approach makes  
templates easier to understand and maintain.  

### Template Debugging

Debugging techniques for template development.  

```twig
{# templates/debug/variables.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    {# Dump single variable #}
    {{ dump(product) }}
    
    {# Dump multiple variables #}
    {{ dump(product, user, cart) }}
    
    {# Dump all variables #}
    {{ dump() }}
    
    {# Check variable type #}
    <p>Type: {{ attribute(product, '__class__')|default('unknown') }}</p>
    
    {# Conditional debugging #}
    {% if app.environment == 'dev' %}
        <div class="debug-info">
            <h3>Debug Information</h3>
            {{ dump(product) }}
        </div>
    {% endif %}
{% endblock %}
```

Use the `dump()` function in development to inspect variables. It requires  
the debug mode and DebugBundle. Wrap debug output in environment checks to  
prevent exposure in production. The Symfony Profiler provides detailed  
template information in the web debug toolbar.  

Twig provides a powerful, secure, and flexible templating system for  
Symfony applications. Master template inheritance, includes, and custom  
extensions to build maintainable and efficient templates. Follow best  
practices for organization, performance, and security to create  
professional-grade applications.  
