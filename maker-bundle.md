# Symfony MakerBundle

The Symfony MakerBundle is a powerful code generation tool that  
accelerates development by automating the creation of boilerplate code  
for common Symfony components. Rather than manually writing repetitive  
code structures, developers can use simple console commands to generate  
controllers, entities, forms, tests, and much more with proper structure  
and best practices built in.  

## What is MakerBundle?

MakerBundle is a development-only bundle that provides a collection of  
`make:*` commands through Symfony's console component. Each command  
scaffolds different parts of a Symfony application, from simple value  
objects to complex CRUD operations with forms and controllers.  

The bundle intelligently generates code that follows Symfony's  
conventions and best practices. It understands your application's  
structure, existing entities, and configuration, allowing it to create  
code that integrates seamlessly with your project. Generated code uses  
modern PHP features like attributes, type declarations, and constructor  
property promotion.  

## Purpose and Benefits

**Rapid Development**: MakerBundle dramatically reduces the time spent  
writing boilerplate code. What might take 15-30 minutes to write manually  
can be generated in seconds with the right command.  

**Consistency**: All generated code follows consistent patterns and  
Symfony best practices. This is especially valuable in team environments  
where maintaining code standards across developers can be challenging.  

**Learning Tool**: For developers new to Symfony, MakerBundle serves as  
an excellent learning resource. By examining generated code, developers  
can understand proper structure, naming conventions, and architectural  
patterns.  

**Reduces Errors**: Manual typing introduces typos and structural  
mistakes. Generated code is syntactically correct and follows proper  
conventions, eliminating common beginner mistakes.  

**Customizable Templates**: While MakerBundle provides sensible defaults,  
the generated code can be customized by overriding the bundle's templates  
to match your team's specific needs.  

**Time Savings**: The bundle handles tedious tasks like creating  
repositories, adding doctrine annotations, implementing interfaces, and  
setting up test structures, allowing developers to focus on business  
logic.  

## How It Enhances Symfony Development

MakerBundle integrates deeply with Symfony's ecosystem. When generating  
an entity, it understands Doctrine relationships. When creating a form,  
it knows about form types and validation. When scaffolding authentication,  
it configures security properly.  

The commands are interactive, guiding developers through the generation  
process with helpful prompts and validation. This interactive approach  
educates while it generates, explaining options and their implications.  

Generated code serves as a starting point, not a final solution.  
Developers can immediately modify and extend the generated classes to  
meet specific requirements. This flexibility makes MakerBundle suitable  
for projects of any size and complexity.  

By handling repetitive tasks, MakerBundle allows developers to maintain  
flow state and focus on solving actual business problems rather than  
fighting with boilerplate. It's an essential tool in any Symfony  
developer's toolkit.  

## Installation

MakerBundle should only be installed in the development environment:  

```bash
composer require --dev symfony/maker-bundle
```

The bundle is automatically enabled in the `dev` environment and should  
never be deployed to production.  

## Available Make Commands

Below is a comprehensive table of all available `make:*` commands:  

| Command | Description |
|---------|-------------|
| `make:auth` | Creates a Guard authenticator for login functionality |
| `make:command` | Creates a new console command class |
| `make:controller` | Creates a new controller class |
| `make:crud` | Creates CRUD operations for a Doctrine entity |
| `make:docker:database` | Adds a database container to docker-compose.yaml |
| `make:entity` | Creates or updates a Doctrine entity class |
| `make:fixtures` | Creates a new class to load Doctrine fixtures |
| `make:form` | Creates a new form class |
| `make:message` | Creates a new message and handler for messenger |
| `make:messenger-middleware` | Creates a new messenger middleware |
| `make:migration` | Creates a new migration based on database changes |
| `make:registration-form` | Creates a registration form and controller |
| `make:reset-password` | Creates password reset functionality |
| `make:serializer:encoder` | Creates a new serializer encoder class |
| `make:serializer:normalizer` | Creates a new serializer normalizer class |
| `make:subscriber` | Creates a new event subscriber class |
| `make:test` | Creates a new test class |
| `make:twig-extension` | Creates a new Twig extension class |
| `make:user` | Creates a user class for security |
| `make:validator` | Creates a new custom validator constraint |
| `make:voter` | Creates a new security voter class |

## Practical Examples

### make:controller

Creating a new controller class.  

```bash
php bin/console make:controller ProductController
```

This generates a controller with a default route and action:  

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

The command creates both the controller and its corresponding Twig  
template. The controller extends AbstractController, providing access  
to common methods like render(), redirectToRoute(), and json(). The  
Route attribute defines the URL path and route name. Developers can  
immediately add more methods and customize the logic.  

### make:entity

Creating or updating a Doctrine entity.  

```bash
php bin/console make:entity Product
```

The command interactively asks for field names, types, and constraints:  

```php
<?php

namespace App\Entity;

use App\Repository\ProductRepository;
use Doctrine\DBAL\Types\Types;
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

    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $description = null;

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

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function setDescription(?string $description): static
    {
        $this->description = $description;

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

The entity includes proper Doctrine attributes, nullable fields where  
appropriate, and fluent setters that return static for method chaining.  
Running the command again on an existing entity allows adding new fields.  
The command also generates a repository class for database queries.  

### make:form

Creating a form type class.  

```bash
php bin/console make:form ProductType
```

When prompted, specify the entity class to bind the form to:  

```php
<?php

namespace App\Form;

use App\Entity\Product;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\MoneyType;
use Symfony\Component\Form\Extension\Core\Type\NumberType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
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
                'attr' => ['class' => 'form-control'],
            ])
            ->add('description', TextareaType::class, [
                'label' => 'Description',
                'required' => false,
                'attr' => ['class' => 'form-control', 'rows' => 5],
            ])
            ->add('price', MoneyType::class, [
                'label' => 'Price',
                'currency' => 'USD',
                'attr' => ['class' => 'form-control'],
            ])
            ->add('stock', NumberType::class, [
                'label' => 'Stock Quantity',
                'attr' => ['class' => 'form-control'],
            ])
        ;
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Product::class,
        ]);
    }
}
```

The form type maps to the entity's properties. Each field uses an  
appropriate form type with sensible defaults. Developers can customize  
field types, labels, and HTML attributes. The form can be rendered in  
controllers and used for both creating and updating entities.  

### make:crud

Generating complete CRUD operations.  

```bash
php bin/console make:crud Product
```

This creates a controller with index, new, show, edit, and delete actions:  

```php
<?php

namespace App\Controller;

use App\Entity\Product;
use App\Form\ProductType;
use App\Repository\ProductRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/product')]
class ProductController extends AbstractController
{
    #[Route('/', name: 'app_product_index', methods: ['GET'])]
    public function index(ProductRepository $repository): Response
    {
        return $this->render('product/index.html.twig', [
            'products' => $repository->findAll(),
        ]);
    }

    #[Route('/new', name: 'app_product_new', methods: ['GET', 'POST'])]
    public function new(Request $request, EntityManagerInterface $entityManager): Response
    {
        $product = new Product();
        $form = $this->createForm(ProductType::class, $product);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $entityManager->persist($product);
            $entityManager->flush();

            return $this->redirectToRoute('app_product_index', [], Response::HTTP_SEE_OTHER);
        }

        return $this->render('product/new.html.twig', [
            'product' => $product,
            'form' => $form,
        ]);
    }

    #[Route('/{id}', name: 'app_product_show', methods: ['GET'])]
    public function show(Product $product): Response
    {
        return $this->render('product/show.html.twig', [
            'product' => $product,
        ]);
    }

    #[Route('/{id}/edit', name: 'app_product_edit', methods: ['GET', 'POST'])]
    public function edit(Request $request, Product $product, EntityManagerInterface $entityManager): Response
    {
        $form = $this->createForm(ProductType::class, $product);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $entityManager->flush();

            return $this->redirectToRoute('app_product_index', [], Response::HTTP_SEE_OTHER);
        }

        return $this->render('product/edit.html.twig', [
            'product' => $product,
            'form' => $form,
        ]);
    }

    #[Route('/{id}', name: 'app_product_delete', methods: ['POST'])]
    public function delete(Request $request, Product $product, EntityManagerInterface $entityManager): Response
    {
        if ($this->isCsrfTokenValid('delete'.$product->getId(), $request->request->get('_token'))) {
            $entityManager->remove($product);
            $entityManager->flush();
        }

        return $this->redirectToRoute('app_product_index', [], Response::HTTP_SEE_OTHER);
    }
}
```

The CRUD controller provides complete functionality for managing entities.  
It includes proper HTTP method restrictions, CSRF protection for deletes,  
and parameter conversion for entity loading. Corresponding Twig templates  
are also generated for each action, providing a complete admin interface.  

### make:command

Creating a console command.  

```bash
php bin/console make:command app:process-orders
```

This generates a command class:  

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
    name: 'app:process-orders',
    description: 'Process pending orders',
)]
class ProcessOrdersCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument('batch-size', InputArgument::OPTIONAL, 'Number of orders to process')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Simulate processing without changes')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $batchSize = $input->getArgument('batch-size') ?? 100;
        $dryRun = $input->getOption('dry-run');

        $io->title('Order Processing');
        
        if ($dryRun) {
            $io->note('Running in dry-run mode');
        }

        $io->success(sprintf('Processed %d orders', $batchSize));

        return Command::SUCCESS;
    }
}
```

Commands extend the Command class and use AsCommand attribute for  
configuration. The configure() method defines arguments and options.  
The execute() method contains the command logic. SymfonyStyle provides  
formatted output methods. Commands automatically appear in the console  
command list and can be run with php bin/console.  

### make:test

Creating test classes.  

```bash
php bin/console make:test TestCase ProductServiceTest
```

Choose the test type (TestCase, KernelTestCase, WebTestCase, etc.):  

```php
<?php

namespace App\Tests\Service;

use PHPUnit\Framework\TestCase;

class ProductServiceTest extends TestCase
{
    public function testSomething(): void
    {
        $this->assertTrue(true);
    }
}
```

For functional tests with database access:  

```bash
php bin/console make:test WebTestCase ProductControllerTest
```

This generates:  

```php
<?php

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class ProductControllerTest extends WebTestCase
{
    public function testIndex(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/product');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorTextContains('h1', 'Products');
    }
}
```

Test generation creates properly namespaced classes in the tests  
directory. WebTestCase provides methods for simulating HTTP requests  
and analyzing responses. KernelTestCase boots the Symfony kernel for  
testing services. TestCase is for unit tests without framework features.  

### make:subscriber

Creating an event subscriber.  

```bash
php bin/console make:subscriber RequestSubscriber
```

Select the events to subscribe to:  

```php
<?php

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class RequestSubscriber implements EventSubscriberInterface
{
    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        
        // Custom logic here
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        $response = $event->getResponse();
        
        // Modify response headers or content
        $response->headers->set('X-Custom-Header', 'value');
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => 'onKernelRequest',
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }
}
```

Event subscribers implement EventSubscriberInterface and define which  
events to listen to in getSubscribedEvents(). The subscriber is  
automatically registered with the event dispatcher. Each subscribed  
event gets a corresponding handler method. Subscribers are perfect for  
cross-cutting concerns like logging, security checks, or header injection.  

### make:voter

Creating a security voter.  

```bash
php bin/console make:voter ProductVoter
```

Specify the entity class:  

```php
<?php

namespace App\Security\Voter;

use App\Entity\Product;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\User\UserInterface;

class ProductVoter extends Voter
{
    public const EDIT = 'PRODUCT_EDIT';
    public const DELETE = 'PRODUCT_DELETE';
    public const VIEW = 'PRODUCT_VIEW';

    protected function supports(string $attribute, mixed $subject): bool
    {
        return in_array($attribute, [self::EDIT, self::DELETE, self::VIEW])
            && $subject instanceof Product;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();

        if (!$user instanceof UserInterface) {
            return false;
        }

        /** @var Product $product */
        $product = $subject;

        return match($attribute) {
            self::VIEW => true,
            self::EDIT => $this->canEdit($product, $user),
            self::DELETE => $this->canDelete($product, $user),
            default => false,
        };
    }

    private function canEdit(Product $product, UserInterface $user): bool
    {
        // Implement your own logic
        return in_array('ROLE_ADMIN', $user->getRoles());
    }

    private function canDelete(Product $product, UserInterface $user): bool
    {
        // Implement your own logic
        return in_array('ROLE_ADMIN', $user->getRoles());
    }
}
```

Voters handle complex authorization logic. The supports() method  
determines if the voter should handle the permission check. The  
voteOnAttribute() method contains the actual authorization logic.  
Voters are used with $this->denyAccessUnlessGranted() in controllers  
or the is_granted() function in templates.  

### make:validator

Creating a custom validation constraint.  

```bash
php bin/console make:validator IsValidProductCode
```

This creates both the constraint and validator:  

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;

#[\Attribute]
class IsValidProductCode extends Constraint
{
    public string $message = 'The product code "{{ value }}" is not valid.';
    public string $mode = 'strict';
}
```

```php
<?php

namespace App\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

class IsValidProductCodeValidator extends ConstraintValidator
{
    public function validate(mixed $value, Constraint $constraint): void
    {
        if (!$constraint instanceof IsValidProductCode) {
            throw new UnexpectedTypeException($constraint, IsValidProductCode::class);
        }

        if (null === $value || '' === $value) {
            return;
        }

        if (!is_string($value)) {
            throw new UnexpectedTypeException($value, 'string');
        }

        // Custom validation logic
        if (!preg_match('/^PRD-[A-Z0-9]{6}$/', $value)) {
            $this->context->buildViolation($constraint->message)
                ->setParameter('{{ value }}', $value)
                ->addViolation();
        }
    }
}
```

Custom validators extend ConstraintValidator and implement validation  
logic in the validate() method. The constraint class defines the error  
message and any configuration options. Use the attribute on entity  
properties to apply the validation.  

### make:migration

Creating database migrations.  

```bash
php bin/console make:migration
```

This generates a migration based on entity changes:  

```php
<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20240101120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Add price and stock columns to product table';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('ALTER TABLE product ADD price DOUBLE PRECISION NOT NULL');
        $this->addSql('ALTER TABLE product ADD stock INT NOT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('ALTER TABLE product DROP price');
        $this->addSql('ALTER TABLE product DROP stock');
    }
}
```

Migrations are automatically generated by comparing your entity mappings  
to the database schema. The up() method applies changes, while down()  
reverts them. Run migrations with php bin/console doctrine:migrations:migrate.  
Always review generated SQL before executing in production.  

### make:fixtures

Creating data fixtures for testing.  

```bash
php bin/console make:fixtures ProductFixtures
```

This creates a fixture class:  

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
        for ($i = 1; $i <= 10; $i++) {
            $product = new Product();
            $product->setName('Product ' . $i);
            $product->setDescription('Description for product ' . $i);
            $product->setPrice(rand(10, 100) + rand(0, 99) / 100);
            $product->setStock(rand(0, 100));
            
            $manager->persist($product);
        }

        $manager->flush();
    }
}
```

Fixtures populate the database with test data. They're essential for  
development and testing environments. Load fixtures with  
php bin/console doctrine:fixtures:load. Fixtures can reference other  
fixtures and create complex object graphs for realistic test scenarios.  

### make:user

Creating a user entity for authentication.  

```bash
php bin/console make:user
```

Answer prompts about user properties and password storage:  

```php
<?php

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: '`user`')]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 180, unique: true)]
    private ?string $email = null;

    #[ORM\Column]
    private array $roles = [];

    #[ORM\Column]
    private ?string $password = null;

    public function getId(): ?int
    {
        return $this->id;
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

    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    public function getRoles(): array
    {
        $roles = $this->roles;
        $roles[] = 'ROLE_USER';

        return array_unique($roles);
    }

    public function setRoles(array $roles): static
    {
        $this->roles = $roles;

        return $this;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): static
    {
        $this->password = $password;

        return $this;
    }

    public function eraseCredentials(): void
    {
        // Clear temporary sensitive data
    }
}
```

The user entity implements UserInterface and  
PasswordAuthenticatedUserInterface for Symfony security integration.  
It includes email-based authentication, role management, and password  
hashing support. The security.yaml configuration is automatically  
updated to use this user class.  

### make:auth

Creating authentication system.  

```bash
php bin/console make:auth
```

Choose authenticator type and answer configuration questions:  

```php
<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class LoginFormAuthenticator extends AbstractLoginFormAuthenticator
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'app_login';

    public function __construct(private UrlGeneratorInterface $urlGenerator)
    {
    }

    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('email', '');

        $request->getSession()->set(SecurityRequestAttributes::LAST_USERNAME, $email);

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($request->request->get('password', '')),
            [
                new CsrfTokenBadge('authenticate', $request->request->get('_csrf_token')),
                new RememberMeBadge(),
            ]
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('app_dashboard'));
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}
```

The authenticator handles the complete login process including CSRF  
protection, remember me functionality, and post-login redirects. A  
login controller and template are also generated. The security.yaml  
file is updated with the authenticator configuration.  

### make:registration-form

Creating user registration system.  

```bash
php bin/console make:registration-form
```

This generates a complete registration flow:  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\RegistrationFormType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

class RegistrationController extends AbstractController
{
    #[Route('/register', name: 'app_register')]
    public function register(
        Request $request,
        UserPasswordHasherInterface $userPasswordHasher,
        EntityManagerInterface $entityManager
    ): Response {
        $user = new User();
        $form = $this->createForm(RegistrationFormType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $user->setPassword(
                $userPasswordHasher->hashPassword(
                    $user,
                    $form->get('plainPassword')->getData()
                )
            );

            $entityManager->persist($user);
            $entityManager->flush();

            return $this->redirectToRoute('app_login');
        }

        return $this->render('registration/register.html.twig', [
            'registrationForm' => $form,
        ]);
    }
}
```

The registration controller handles form submission, password hashing,  
and user persistence. A corresponding form type and template are  
generated. Optional email verification can be added during generation.  

### make:reset-password

Creating password reset functionality.  

```bash
php bin/console make:reset-password
```

This creates a complete password reset flow with token generation:  

```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\ChangePasswordFormType;
use App\Form\ResetPasswordRequestFormType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use SymfonyCasts\Bundle\ResetPassword\Controller\ResetPasswordControllerTrait;
use SymfonyCasts\Bundle\ResetPassword\ResetPasswordHelperInterface;

#[Route('/reset-password')]
class ResetPasswordController extends AbstractController
{
    use ResetPasswordControllerTrait;

    public function __construct(
        private ResetPasswordHelperInterface $resetPasswordHelper,
        private EntityManagerInterface $entityManager
    ) {
    }

    #[Route('', name: 'app_forgot_password_request')]
    public function request(Request $request, MailerInterface $mailer): Response
    {
        $form = $this->createForm(ResetPasswordRequestFormType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            return $this->processSendingPasswordResetEmail(
                $form->get('email')->getData(),
                $mailer
            );
        }

        return $this->render('reset_password/request.html.twig', [
            'requestForm' => $form,
        ]);
    }

    // Additional methods for handling reset token and changing password...
}
```

The reset password system includes token generation, email sending,  
token validation, and password update functionality. Multiple  
controllers, forms, and email templates are generated to provide a  
complete, secure password reset flow.  

### make:message

Creating messenger messages and handlers.  

```bash
php bin/console make:message SendNotificationMessage
```

This generates a message class and handler:  

```php
<?php

namespace App\Message;

class SendNotificationMessage
{
    private string $userId;
    private string $message;

    public function __construct(string $userId, string $message)
    {
        $this->userId = $userId;
        $this->message = $message;
    }

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function getMessage(): string
    {
        return $this->message;
    }
}
```

```php
<?php

namespace App\MessageHandler;

use App\Message\SendNotificationMessage;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
class SendNotificationMessageHandler
{
    public function __invoke(SendNotificationMessage $message): void
    {
        // Process the message
        $userId = $message->getUserId();
        $text = $message->getMessage();
        
        // Send notification logic here
    }
}
```

Messages represent units of work to be processed asynchronously.  
Handlers process the messages. Dispatch messages with the MessageBus  
service. Configure transports in messenger.yaml for queue backends  
like RabbitMQ, Redis, or Doctrine.  

### make:twig-extension

Creating custom Twig extensions.  

```bash
php bin/console make:twig-extension PriceExtension
```

This creates an extension class:  

```php
<?php

namespace App\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFilter;
use Twig\TwigFunction;

class PriceExtension extends AbstractExtension
{
    public function getFilters(): array
    {
        return [
            new TwigFilter('format_price', [$this, 'formatPrice']),
        ];
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('calculate_tax', [$this, 'calculateTax']),
        ];
    }

    public function formatPrice(float $price, string $currency = 'USD'): string
    {
        return match($currency) {
            'USD' => '$' . number_format($price, 2),
            'EUR' => '€' . number_format($price, 2),
            'GBP' => '£' . number_format($price, 2),
            default => number_format($price, 2) . ' ' . $currency,
        };
    }

    public function calculateTax(float $amount, float $rate = 0.20): float
    {
        return round($amount * $rate, 2);
    }
}
```

Twig extensions add custom filters, functions, and tests to templates.  
The extension is automatically registered. Use filters with the pipe  
syntax: {{ price|format_price('EUR') }}. Functions are called directly:  
{{ calculate_tax(100, 0.15) }}.  

### make:serializer:normalizer

Creating custom serializer normalizers.  

```bash
php bin/console make:serializer:normalizer ProductNormalizer
```

This generates a normalizer class:  

```php
<?php

namespace App\Serializer;

use App\Entity\Product;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

class ProductNormalizer implements NormalizerInterface
{
    public function normalize(mixed $object, ?string $format = null, array $context = []): array
    {
        /** @var Product $object */
        return [
            'id' => $object->getId(),
            'name' => $object->getName(),
            'description' => $object->getDescription(),
            'price' => [
                'amount' => $object->getPrice(),
                'currency' => 'USD',
                'formatted' => '$' . number_format($object->getPrice(), 2),
            ],
            'stock' => $object->getStock(),
            'available' => $object->getStock() > 0,
        ];
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof Product;
    }

    public function getSupportedTypes(?string $format): array
    {
        return [
            Product::class => true,
        ];
    }
}
```

Normalizers control how objects are converted to arrays for  
serialization. They enable custom output formats, computed properties,  
and fine-grained control over API responses. The normalizer is  
automatically registered with the serializer service.  

### make:docker:database

Adding database container to Docker configuration.  

```bash
php bin/console make:docker:database
```

Select database type (PostgreSQL, MySQL, MariaDB, etc.):  

```yaml
# docker-compose.yaml
services:
  database:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-secret}
      POSTGRES_USER: ${POSTGRES_USER:-symfony}
      POSTGRES_DB: ${POSTGRES_DB:-symfony}
    ports:
      - "5432:5432"
    volumes:
      - database_data:/var/lib/postgresql/data

volumes:
  database_data:
```

The command adds a properly configured database service to your  
docker-compose.yaml file. Environment variables are parameterized for  
flexibility. Data volumes ensure persistence across container restarts.  

## Best Practices

**Review Generated Code**: Always examine generated code before using it.  
MakerBundle provides excellent starting points but may need customization  
for specific requirements.  

**Keep It Updated**: Update MakerBundle regularly to get new features and  
improved code generation. Newer versions generate code using the latest  
PHP and Symfony features.  

**Use Interactive Mode**: Let the interactive prompts guide you. They  
provide context and prevent common mistakes. The questions help you  
understand configuration options.  

**Combine Commands**: Use make:entity, then make:migration, then  
make:crud for rapid CRUD development. Commands work together to create  
complete features quickly.  

**Don't Overwrite Blindly**: When regenerating existing files, carefully  
review what will be overwritten. MakerBundle warns about overwrites but  
won't preserve custom modifications.  

**Learn from Generated Code**: Study the patterns and practices in  
generated code. They demonstrate proper Symfony architecture and can  
improve your coding style.  

**Version Control**: Commit generated code to version control. This  
allows tracking changes and reverting if needed. Generated code is part  
of your application, not a build artifact.  

**Customize Templates**: For teams with specific coding standards,  
override MakerBundle templates. This ensures all generated code follows  
your conventions automatically.  

## Conclusion

Symfony MakerBundle is an indispensable tool that dramatically improves  
developer productivity and code quality. By automating boilerplate  
generation, it allows developers to focus on business logic rather than  
structural code. The bundle's deep integration with Symfony's ecosystem  
ensures generated code follows best practices and works seamlessly with  
existing components.  

Whether you're building a simple blog or a complex enterprise application,  
MakerBundle accelerates development while maintaining code quality. Its  
interactive commands educate while they generate, making it valuable for  
both beginners learning Symfony and experienced developers building  
production applications.  

Mastering MakerBundle commands is essential for modern Symfony  
development. The time invested in learning these commands pays dividends  
in reduced development time, fewer errors, and more consistent code  
across projects.  
