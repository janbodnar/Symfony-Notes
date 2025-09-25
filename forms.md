# Symfony Forms

Forms in Symfony provide a robust way to create, process, and validate HTML  
forms. The Form component handles form rendering, data binding, validation,  
and security features like CSRF protection automatically.  

## Basic Form Creation

Creating a simple form using Symfony's form builder.  

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class BasicFormController extends AbstractController
{
    #[Route('/basic-form', name: 'basic_form')]
    public function basicForm(Request $request): Response
    {
        $form = $this->createFormBuilder()
            ->add('name', TextType::class, [
                'label' => 'Full Name',
                'required' => true,
            ])
            ->add('email', TextType::class, [
                'label' => 'Email Address',
            ])
            ->add('submit', SubmitType::class, [
                'label' => 'Send Message'
            ])
            ->getForm();

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $data = $form->getData();
            
            $this->addFlash('success', 
                'Hello there ' . $data['name'] . '! Form submitted successfully.');
            
            return $this->redirectToRoute('basic_form');
        }

        return $this->render('form/basic.html.twig', [
            'form' => $form->createView(),
        ]);
    }
}
```

This example creates a basic form with text fields using the form builder.  
The handleRequest() method processes the submitted data and validates it  
according to the configured constraints.  

## Entity-Based Form

Creating forms bound to entity objects for automatic data mapping.  

```php
<?php

namespace App\Form;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class UserType extends AbstractType
{
    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('firstName', TextType::class, [
                'label' => 'First Name',
                'required' => true,
            ])
            ->add('lastName', TextType::class, [
                'label' => 'Last Name',
                'required' => true,
            ])
            ->add('email', EmailType::class, [
                'label' => 'Email Address',
            ])
            ->add('password', PasswordType::class, [
                'label' => 'Password',
            ])
            ->add('save', SubmitType::class, [
                'label' => 'Create User'
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => User::class,
        ]);
    }
}
```

Entity-based forms automatically map form fields to entity properties.  
The data_class option links the form to a specific entity class for  
seamless data binding and persistence.  

## Form Field Types

Exploring different form field types available in Symfony.  

```php
<?php

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\BirthdayType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\DateType;
use Symfony\Component\Form\Extension\Core\Type\IntegerType;
use Symfony\Component\Form\Extension\Core\Type\NumberType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;

class FieldTypesForm extends AbstractType
{
    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('name', TextType::class, [
                'label' => 'Full Name',
            ])
            ->add('description', TextareaType::class, [
                'label' => 'Description',
                'attr' => ['rows' => 4],
            ])
            ->add('age', IntegerType::class, [
                'label' => 'Age',
            ])
            ->add('salary', NumberType::class, [
                'label' => 'Salary',
                'scale' => 2,
            ])
            ->add('birthdate', BirthdayType::class, [
                'label' => 'Birth Date',
            ])
            ->add('startDate', DateType::class, [
                'label' => 'Start Date',
                'widget' => 'single_text',
            ])
            ->add('isActive', CheckboxType::class, [
                'label' => 'Active User',
                'required' => false,
            ])
            ->add('country', ChoiceType::class, [
                'label' => 'Country',
                'choices' => [
                    'United States' => 'us',
                    'Canada' => 'ca',
                    'United Kingdom' => 'uk',
                    'Germany' => 'de',
                ],
            ])
            ->add('submit', SubmitType::class, [
                'label' => 'Submit Form'
            ]);
    }
}
```

Symfony provides many built-in field types for different data types.  
Each field type has specific options for customization, validation,  
and rendering behavior.  

## Form Validation

Adding validation constraints to form fields.  

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;

#[ORM\Entity]
#[UniqueEntity(fields: ['email'], message: 'Email already exists.')]
class Contact
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 100)]
    #[Assert\NotBlank(message: 'Name cannot be empty.')]
    #[Assert\Length(
        min: 2,
        max: 100,
        minMessage: 'Name must be at least {{ limit }} characters.',
        maxMessage: 'Name cannot exceed {{ limit }} characters.'
    )]
    private ?string $name = null;

    #[ORM\Column(length: 180)]
    #[Assert\NotBlank(message: 'Email is required.')]
    #[Assert\Email(message: 'Please provide a valid email address.')]
    private ?string $email = null;

    #[ORM\Column(type: 'text')]
    #[Assert\NotBlank(message: 'Message cannot be empty.')]
    #[Assert\Length(
        min: 10,
        minMessage: 'Message must be at least {{ limit }} characters.'
    )]
    private ?string $message = null;

    #[ORM\Column]
    #[Assert\Range(
        min: 18,
        max: 120,
        notInRangeMessage: 'Age must be between {{ min }} and {{ max }}.'
    )]
    private ?int $age = null;

    // Getters and setters...
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

    public function getMessage(): ?string
    {
        return $this->message;
    }

    public function setMessage(string $message): static
    {
        $this->message = $message;
        return $this;
    }

    public function getAge(): ?int
    {
        return $this->age;
    }

    public function setAge(int $age): static
    {
        $this->age = $age;
        return $this;
    }
}
```

Validation constraints ensure data integrity and provide user feedback.  
Constraints can be applied at the entity level or directly in form fields  
for specific validation requirements.  

## Custom Form Field Type

Creating a reusable custom form field type.  

```php
<?php

namespace App\Form\Type;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;
use Symfony\Component\OptionsResolver\OptionsResolver;

class PhoneNumberType extends AbstractType
{
    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('countryCode', TextType::class, [
                'attr' => [
                    'placeholder' => '+1',
                    'class' => 'form-control country-code',
                    'maxlength' => 4,
                ],
            ])
            ->add('areaCode', TextType::class, [
                'attr' => [
                    'placeholder' => '555',
                    'class' => 'form-control area-code',
                    'maxlength' => 3,
                ],
            ])
            ->add('number', TextType::class, [
                'attr' => [
                    'placeholder' => '0123456',
                    'class' => 'form-control phone-number',
                    'maxlength' => 10,
                ],
            ]);
    }

    public function buildView(
        FormView $view, 
        FormInterface $form, 
        array $options
    ): void {
        $view->vars['display_format'] = $options['display_format'];
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'display_format' => 'international',
            'data_class' => null,
            'compound' => true,
        ]);

        $resolver->setAllowedValues('display_format', [
            'international', 'national', 'compact'
        ]);
    }

    public function getBlockPrefix(): string
    {
        return 'phone_number';
    }
}
```

Custom form types allow you to create reusable form components with  
specific behavior and rendering. They can be compound types that contain  
multiple child fields or extend existing field types.  

## File Upload Form

Handling file uploads with validation and processing.  

```php
<?php

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\FileType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Validator\Constraints\File;
use Symfony\Component\Validator\Constraints\NotBlank;

class DocumentUploadType extends AbstractType
{
    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('title', TextType::class, [
                'label' => 'Document Title',
                'constraints' => [
                    new NotBlank([
                        'message' => 'Please enter a document title.',
                    ]),
                ],
            ])
            ->add('document', FileType::class, [
                'label' => 'Document File (PDF, DOC, DOCX)',
                'mapped' => false,
                'required' => true,
                'constraints' => [
                    new File([
                        'maxSize' => '10M',
                        'mimeTypes' => [
                            'application/pdf',
                            'application/msword',
                            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        ],
                        'mimeTypesMessage' => 'Please upload a valid document (PDF, DOC, DOCX)',
                        'maxSizeMessage' => 'File size cannot exceed 10MB',
                    ])
                ],
            ])
            ->add('image', FileType::class, [
                'label' => 'Thumbnail Image (optional)',
                'mapped' => false,
                'required' => false,
                'constraints' => [
                    new File([
                        'maxSize' => '5M',
                        'mimeTypes' => [
                            'image/jpeg',
                            'image/png',
                            'image/gif',
                        ],
                        'mimeTypesMessage' => 'Please upload a valid image (JPEG, PNG, GIF)',
                    ])
                ],
            ])
            ->add('upload', SubmitType::class, [
                'label' => 'Upload Document'
            ]);
    }
}
```

File upload forms require specific validation constraints and processing.  
The mapped => false option prevents automatic entity binding for file fields  
that need custom handling.  

## Dynamic Form Fields

Creating forms with dynamic fields based on user selections.  

```php
<?php

namespace App\Form;

use App\Entity\Category;
use App\Entity\Product;
use Doctrine\ORM\EntityRepository;
use Symfony\Bridge\Doctrine\Form\Type\EntityType;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\MoneyType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormEvent;
use Symfony\Component\Form\FormEvents;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class DynamicProductType extends AbstractType
{
    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('name', TextType::class, [
                'label' => 'Product Name',
            ])
            ->add('category', EntityType::class, [
                'class' => Category::class,
                'choice_label' => 'name',
                'placeholder' => 'Select a category...',
                'label' => 'Category',
            ])
            ->add('price', MoneyType::class, [
                'label' => 'Price',
                'currency' => 'USD',
            ]);

        $builder->addEventListener(
            FormEvents::PRE_SET_DATA,
            [$this, 'onPreSetData']
        );

        $builder->addEventListener(
            FormEvents::PRE_SUBMIT,
            [$this, 'onPreSubmit']
        );

        $builder->add('submit', SubmitType::class, [
            'label' => 'Save Product'
        ]);
    }

    public function onPreSetData(FormEvent $event): void
    {
        $product = $event->getData();
        $form = $event->getForm();

        if ($product && $product->getCategory()) {
            $this->addSubcategoryField($form, $product->getCategory());
        }
    }

    public function onPreSubmit(FormEvent $event): void
    {
        $data = $event->getData();
        $form = $event->getForm();

        if (isset($data['category']) && $data['category']) {
            $category = $form->get('category')
                ->getConfig()
                ->getOption('em')
                ->getRepository(Category::class)
                ->find($data['category']);

            if ($category) {
                $this->addSubcategoryField($form, $category);
            }
        }
    }

    private function addSubcategoryField(
        FormInterface $form, 
        Category $category
    ): void {
        $form->add('subcategory', EntityType::class, [
            'class' => Category::class,
            'choice_label' => 'name',
            'placeholder' => 'Select a subcategory...',
            'query_builder' => function (EntityRepository $er) use ($category) {
                return $er->createQueryBuilder('c')
                    ->where('c.parent = :category')
                    ->setParameter('category', $category);
            },
            'required' => false,
            'label' => 'Subcategory',
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

Dynamic forms adjust their fields based on user input using form events.  
This allows for cascading dropdowns and conditional field display based  
on the selected values.  

## Form Collections

Managing collections of embedded forms for one-to-many relationships.  

```php
<?php

namespace App\Form;

use App\Entity\Order;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CollectionType;
use Symfony\Component\Form\Extension\Core\Type\DateType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class OrderType extends AbstractType
{
    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('orderNumber', TextType::class, [
                'label' => 'Order Number',
            ])
            ->add('orderDate', DateType::class, [
                'label' => 'Order Date',
                'widget' => 'single_text',
            ])
            ->add('items', CollectionType::class, [
                'entry_type' => OrderItemType::class,
                'entry_options' => ['label' => false],
                'allow_add' => true,
                'allow_delete' => true,
                'by_reference' => false,
                'label' => 'Order Items',
            ])
            ->add('submit', SubmitType::class, [
                'label' => 'Save Order'
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Order::class,
        ]);
    }
}
```

```php
<?php

namespace App\Form;

use App\Entity\OrderItem;
use App\Entity\Product;
use Symfony\Bridge\Doctrine\Form\Type\EntityType;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\IntegerType;
use Symfony\Component\Form\Extension\Core\Type\MoneyType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class OrderItemType extends AbstractType
{
    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('product', EntityType::class, [
                'class' => Product::class,
                'choice_label' => 'name',
                'label' => 'Product',
            ])
            ->add('quantity', IntegerType::class, [
                'label' => 'Quantity',
                'attr' => ['min' => 1],
            ])
            ->add('unitPrice', MoneyType::class, [
                'label' => 'Unit Price',
                'currency' => 'USD',
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => OrderItem::class,
        ]);
    }
}
```

Collection forms handle one-to-many relationships by embedding multiple  
sub-forms. The allow_add and allow_delete options enable dynamic  
addition and removal of collection items.  

## Form Themes and Customization

Customizing form rendering with themes and templates.  

```php
<?php

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;

class CustomStyledForm extends AbstractType
{
    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('name', TextType::class, [
                'label' => 'Full Name',
                'attr' => [
                    'class' => 'form-control form-control-lg',
                    'placeholder' => 'Enter your full name',
                ],
                'row_attr' => [
                    'class' => 'form-group mb-4',
                ],
            ])
            ->add('email', EmailType::class, [
                'label' => 'Email Address',
                'attr' => [
                    'class' => 'form-control',
                    'placeholder' => 'you@example.com',
                ],
                'help' => 'We will never share your email with anyone.',
                'row_attr' => [
                    'class' => 'form-group mb-3',
                ],
            ])
            ->add('message', TextareaType::class, [
                'label' => 'Message',
                'attr' => [
                    'class' => 'form-control',
                    'rows' => 5,
                    'placeholder' => 'Your message here...',
                ],
                'help' => 'Please provide as much detail as possible.',
            ])
            ->add('submit', SubmitType::class, [
                'label' => 'Send Message',
                'attr' => [
                    'class' => 'btn btn-primary btn-lg',
                ],
            ]);
    }
}
```

Form customization can be done through HTML attributes, CSS classes,  
and help text. For advanced customization, you can create custom form  
themes using Twig templates.  

## Ajax Form Submission

Creating forms that submit via Ajax for better user experience.  

```php
<?php

namespace App\Controller;

use App\Entity\Comment;
use App\Form\CommentType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class AjaxFormController extends AbstractController
{
    #[Route('/ajax/comment', name: 'ajax_comment')]
    public function ajaxComment(
        Request $request,
        EntityManagerInterface $em
    ): Response {
        $comment = new Comment();
        $form = $this->createForm(CommentType::class, $comment);

        if ($request->isMethod('POST')) {
            $form->handleRequest($request);

            if ($form->isSubmitted() && $form->isValid()) {
                $em->persist($comment);
                $em->flush();

                if ($request->isXmlHttpRequest()) {
                    return new JsonResponse([
                        'success' => true,
                        'message' => 'Comment posted successfully!',
                        'comment' => [
                            'id' => $comment->getId(),
                            'author' => $comment->getAuthor(),
                            'content' => $comment->getContent(),
                            'createdAt' => $comment->getCreatedAt()->format('Y-m-d H:i'),
                        ],
                    ]);
                }

                $this->addFlash('success', 'Comment posted successfully!');
                return $this->redirectToRoute('ajax_comment');
            }

            if ($request->isXmlHttpRequest()) {
                $errors = [];
                foreach ($form->getErrors(true) as $error) {
                    $errors[] = $error->getMessage();
                }

                return new JsonResponse([
                    'success' => false,
                    'errors' => $errors,
                ], 422);
            }
        }

        return $this->render('form/ajax_comment.html.twig', [
            'form' => $form->createView(),
        ]);
    }

    #[Route('/api/validate-email', name: 'api_validate_email')]
    public function validateEmail(Request $request): JsonResponse
    {
        $email = $request->query->get('email');
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return new JsonResponse([
                'valid' => false,
                'message' => 'Invalid email format',
            ]);
        }

        // Check if email exists in database
        // $exists = $userRepository->findOneBy(['email' => $email]);
        
        return new JsonResponse([
            'valid' => true,
            'message' => 'Email is valid',
        ]);
    }
}
```

Ajax forms provide real-time validation and submission without page  
refreshes. Use isXmlHttpRequest() to detect Ajax requests and return  
appropriate JSON responses.  

## Multi-Step Forms

Creating wizard-style forms with multiple steps.  

```php
<?php

namespace App\Controller;

use App\Entity\UserRegistration;
use App\Form\Step1Type;
use App\Form\Step2Type;
use App\Form\Step3Type;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Annotation\Route;

class MultiStepFormController extends AbstractController
{
    #[Route('/registration/step/{step}', name: 'registration_step', 
           requirements: ['step' => '\d+'], defaults: ['step' => 1])]
    public function registrationStep(
        int $step,
        Request $request,
        SessionInterface $session,
        EntityManagerInterface $em
    ): Response {
        // Get or create registration data from session
        $registrationData = $session->get('registration_data', []);
        $registration = new UserRegistration();
        
        // Populate registration with existing data
        if (!empty($registrationData)) {
            $registration->fromArray($registrationData);
        }

        switch ($step) {
            case 1:
                $form = $this->createForm(Step1Type::class, $registration);
                $template = 'registration/step1.html.twig';
                break;
            case 2:
                if (empty($registrationData['step1_completed'])) {
                    return $this->redirectToRoute('registration_step', ['step' => 1]);
                }
                $form = $this->createForm(Step2Type::class, $registration);
                $template = 'registration/step2.html.twig';
                break;
            case 3:
                if (empty($registrationData['step2_completed'])) {
                    return $this->redirectToRoute('registration_step', ['step' => 2]);
                }
                $form = $this->createForm(Step3Type::class, $registration);
                $template = 'registration/step3.html.twig';
                break;
            default:
                throw $this->createNotFoundException('Invalid step');
        }

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // Store form data in session
            $registrationData = array_merge(
                $registrationData, 
                $registration->toArray()
            );
            $registrationData["step{$step}_completed"] = true;
            $session->set('registration_data', $registrationData);

            if ($step < 3) {
                return $this->redirectToRoute('registration_step', [
                    'step' => $step + 1
                ]);
            } else {
                // Final step - persist to database
                $finalRegistration = new UserRegistration();
                $finalRegistration->fromArray($registrationData);
                
                $em->persist($finalRegistration);
                $em->flush();

                // Clear session data
                $session->remove('registration_data');

                $this->addFlash('success', 
                    'Registration completed successfully!');
                
                return $this->redirectToRoute('registration_complete');
            }
        }

        return $this->render($template, [
            'form' => $form->createView(),
            'step' => $step,
            'totalSteps' => 3,
        ]);
    }

    #[Route('/registration/complete', name: 'registration_complete')]
    public function registrationComplete(): Response
    {
        return $this->render('registration/complete.html.twig');
    }
}
```

Multi-step forms use session storage to maintain data across steps.  
Each step validates its portion of the data before proceeding to the  
next step in the workflow.  

## Form Security

Implementing security measures like CSRF protection and field encryption.  

```php
<?php

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Regex;

class SecureRegistrationForm extends AbstractType
{
    public function __construct(
        private CsrfTokenManagerInterface $csrfTokenManager
    ) {
    }

    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('username', TextType::class, [
                'label' => 'Username',
                'constraints' => [
                    new NotBlank(),
                    new Length(['min' => 3, 'max' => 25]),
                    new Regex([
                        'pattern' => '/^[a-zA-Z0-9_]+$/',
                        'message' => 'Username can only contain letters, numbers, and underscores.',
                    ]),
                ],
            ])
            ->add('email', EmailType::class, [
                'label' => 'Email',
            ])
            ->add('password', RepeatedType::class, [
                'type' => PasswordType::class,
                'first_options' => [
                    'label' => 'Password',
                    'attr' => ['autocomplete' => 'new-password'],
                ],
                'second_options' => [
                    'label' => 'Confirm Password',
                    'attr' => ['autocomplete' => 'new-password'],
                ],
                'invalid_message' => 'The password fields must match.',
                'constraints' => [
                    new NotBlank(),
                    new Length([
                        'min' => 8,
                        'minMessage' => 'Password must be at least {{ limit }} characters.',
                    ]),
                    new Regex([
                        'pattern' => '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/',
                        'message' => 'Password must contain uppercase, lowercase, number and special character.',
                    ]),
                ],
            ])
            ->add('honeypot', HiddenType::class, [
                'mapped' => false,
                'attr' => [
                    'style' => 'display: none;',
                    'tabindex' => '-1',
                    'autocomplete' => 'off',
                ],
            ])
            ->add('timestamp', HiddenType::class, [
                'data' => time(),
                'mapped' => false,
            ])
            ->add('register', SubmitType::class, [
                'label' => 'Create Account'
            ]);
    }
}
```

Security measures include CSRF tokens (enabled by default), honeypot  
fields for bot detection, form submission timing validation, and strong  
password requirements with proper constraints.  

## API Form Integration

Creating forms that interact with external APIs for data validation.  

```php
<?php

namespace App\Form;

use App\Service\AddressValidationService;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CountryType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormError;
use Symfony\Component\Form\FormEvent;
use Symfony\Component\Form\FormEvents;

class AddressFormWithApiValidation extends AbstractType
{
    public function __construct(
        private AddressValidationService $addressValidator
    ) {
    }

    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('street', TextType::class, [
                'label' => 'Street Address',
            ])
            ->add('city', TextType::class, [
                'label' => 'City',
            ])
            ->add('state', TextType::class, [
                'label' => 'State/Province',
            ])
            ->add('postalCode', TextType::class, [
                'label' => 'Postal Code',
            ])
            ->add('country', CountryType::class, [
                'label' => 'Country',
                'preferred_choices' => ['US', 'CA', 'GB'],
            ])
            ->add('submit', SubmitType::class, [
                'label' => 'Validate Address'
            ]);

        // Add custom validation using external API
        $builder->addEventListener(
            FormEvents::POST_SUBMIT,
            [$this, 'validateAddressWithApi']
        );
    }

    public function validateAddressWithApi(FormEvent $event): void
    {
        $form = $event->getForm();
        $data = $form->getData();

        if (!$data || !$form->isValid()) {
            return;
        }

        try {
            $addressData = [
                'street' => $data['street'],
                'city' => $data['city'],
                'state' => $data['state'],
                'postalCode' => $data['postalCode'],
                'country' => $data['country'],
            ];

            $validationResult = $this->addressValidator
                ->validateAddress($addressData);

            if (!$validationResult['valid']) {
                $form->addError(new FormError(
                    'Address validation failed: ' . $validationResult['message']
                ));
            }

            if (isset($validationResult['suggestions'])) {
                $form->get('street')->addError(new FormError(
                    'Did you mean: ' . $validationResult['suggestions']['street']
                ));
            }

        } catch (\Exception $e) {
            $form->addError(new FormError(
                'Unable to validate address at this time. Please try again.'
            ));
        }
    }
}
```

```php
<?php

namespace App\Service;

use Symfony\Contracts\HttpClient\HttpClientInterface;

class AddressValidationService
{
    public function __construct(
        private HttpClientInterface $httpClient,
        private string $apiKey
    ) {
    }

    public function validateAddress(array $address): array
    {
        try {
            $response = $this->httpClient->request('POST', 
                'https://api.addressvalidation.com/validate', [
                'json' => $address,
                'headers' => [
                    'Authorization' => 'Bearer ' . $this->apiKey,
                    'Content-Type' => 'application/json',
                ],
                'timeout' => 10,
            ]);

            return $response->toArray();

        } catch (\Exception $e) {
            return [
                'valid' => false,
                'message' => 'API validation service unavailable',
            ];
        }
    }
}
```

API integration allows forms to validate data against external services.  
Use form events to call APIs after form submission and add validation  
errors based on the API response.  

## Advanced Form Events

Using form events for complex form behavior and data transformation.  

```php
<?php

namespace App\Form;

use App\Entity\Invoice;
use App\Entity\Tax;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CollectionType;
use Symfony\Component\Form\Extension\Core\Type\DateType;
use Symfony\Component\Form\Extension\Core\Type\MoneyType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormEvent;
use Symfony\Component\Form\FormEvents;
use Symfony\Component\OptionsResolver\OptionsResolver;

class InvoiceFormWithEvents extends AbstractType
{
    public function __construct(
        private EntityManagerInterface $entityManager
    ) {
    }

    public function buildForm(
        FormBuilderInterface $builder, 
        array $options
    ): void {
        $builder
            ->add('invoiceNumber', TextType::class, [
                'label' => 'Invoice Number',
            ])
            ->add('invoiceDate', DateType::class, [
                'label' => 'Invoice Date',
                'widget' => 'single_text',
            ])
            ->add('subtotal', MoneyType::class, [
                'label' => 'Subtotal',
                'currency' => 'USD',
            ])
            ->add('items', CollectionType::class, [
                'entry_type' => InvoiceItemType::class,
                'allow_add' => true,
                'allow_delete' => true,
                'by_reference' => false,
                'label' => 'Invoice Items',
            ]);

        // Event listeners for complex form behavior
        $builder->addEventListener(
            FormEvents::PRE_SET_DATA,
            [$this, 'onPreSetData']
        );

        $builder->addEventListener(
            FormEvents::PRE_SUBMIT,
            [$this, 'onPreSubmit']
        );

        $builder->addEventListener(
            FormEvents::POST_SUBMIT,
            [$this, 'onPostSubmit']
        );

        $builder->add('submit', SubmitType::class, [
            'label' => 'Save Invoice'
        ]);
    }

    public function onPreSetData(FormEvent $event): void
    {
        $invoice = $event->getData();
        $form = $event->getForm();

        // Auto-generate invoice number if new invoice
        if ($invoice && !$invoice->getId()) {
            $lastInvoice = $this->entityManager
                ->getRepository(Invoice::class)
                ->findOneBy([], ['id' => 'DESC']);

            $nextNumber = $lastInvoice 
                ? 'INV-' . str_pad($lastInvoice->getId() + 1, 6, '0', STR_PAD_LEFT)
                : 'INV-000001';

            $invoice->setInvoiceNumber($nextNumber);
        }

        // Add tax fields based on invoice configuration
        if ($invoice && $invoice->getCustomer() && $invoice->getCustomer()->getTaxRegion()) {
            $taxRegion = $invoice->getCustomer()->getTaxRegion();
            $this->addTaxFields($form, $taxRegion);
        }
    }

    public function onPreSubmit(FormEvent $event): void
    {
        $data = $event->getData();

        // Calculate totals before validation
        if (isset($data['items']) && is_array($data['items'])) {
            $subtotal = 0;
            
            foreach ($data['items'] as $item) {
                if (isset($item['quantity'], $item['unitPrice'])) {
                    $subtotal += (float) $item['quantity'] * (float) $item['unitPrice'];
                }
            }
            
            $data['subtotal'] = $subtotal;
            $event->setData($data);
        }
    }

    public function onPostSubmit(FormEvent $event): void
    {
        $invoice = $event->getData();
        $form = $event->getForm();

        if (!$invoice || !$form->isValid()) {
            return;
        }

        // Auto-calculate taxes after form submission
        $taxAmount = $this->calculateTax($invoice);
        $invoice->setTaxAmount($taxAmount);
        $invoice->setTotal($invoice->getSubtotal() + $taxAmount);

        // Set invoice status based on total
        if ($invoice->getTotal() > 0) {
            $invoice->setStatus('pending');
        } else {
            $invoice->setStatus('void');
        }
    }

    private function addTaxFields(FormInterface $form, string $taxRegion): void
    {
        $taxes = $this->entityManager
            ->getRepository(Tax::class)
            ->findByRegion($taxRegion);

        foreach ($taxes as $tax) {
            $form->add('tax_' . $tax->getId(), MoneyType::class, [
                'label' => $tax->getName() . ' (' . $tax->getRate() . '%)',
                'required' => false,
                'mapped' => false,
                'currency' => 'USD',
            ]);
        }
    }

    private function calculateTax(Invoice $invoice): float
    {
        // Tax calculation logic based on customer location and items
        $taxRate = 0.08; // Example tax rate
        return $invoice->getSubtotal() * $taxRate;
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Invoice::class,
        ]);
    }
}
```

Form events provide hooks for complex business logic, data transformation,  
and dynamic field manipulation. They execute at different stages of form  
processing for maximum flexibility and control.  

## Form Testing

Writing comprehensive tests for Symfony forms and form types.  

```php
<?php

namespace App\Tests\Form;

use App\Entity\User;
use App\Form\UserRegistrationType;
use Symfony\Component\Form\Test\TypeTestCase;
use Symfony\Component\Form\Extension\Validator\ValidatorExtension;
use Symfony\Component\Validator\Validation;

class UserRegistrationTypeTest extends TypeTestCase
{
    protected function getExtensions(): array
    {
        $validator = Validation::createValidator();

        return [
            new ValidatorExtension($validator),
        ];
    }

    public function testSubmitValidData(): void
    {
        $formData = [
            'firstName' => 'John',
            'lastName' => 'Doe',
            'email' => 'john.doe@example.com',
            'password' => [
                'first' => 'SecurePass123!',
                'second' => 'SecurePass123!',
            ],
            'agreeToTerms' => true,
        ];

        $user = new User();
        $form = $this->factory->create(UserRegistrationType::class, $user);

        $form->submit($formData);

        $this->assertTrue($form->isSynchronized());
        $this->assertTrue($form->isValid());

        $this->assertEquals('John', $user->getFirstName());
        $this->assertEquals('Doe', $user->getLastName());
        $this->assertEquals('john.doe@example.com', $user->getEmail());
        $this->assertTrue($user->isAgreeToTerms());

        $view = $form->createView();
        $children = $view->children;

        foreach (array_keys($formData) as $key) {
            $this->assertArrayHasKey($key, $children);
        }
    }

    public function testFormValidation(): void
    {
        $formData = [
            'firstName' => '',  // Should fail validation
            'lastName' => 'Doe',
            'email' => 'invalid-email',  // Should fail validation
            'password' => [
                'first' => '123',  // Too short
                'second' => '456',  // Doesn't match first
            ],
            'agreeToTerms' => false,  // Should fail validation
        ];

        $user = new User();
        $form = $this->factory->create(UserRegistrationType::class, $user);
        $form->submit($formData);

        $this->assertTrue($form->isSynchronized());
        $this->assertFalse($form->isValid());

        // Check specific field errors
        $this->assertGreaterThan(0, count($form->get('firstName')->getErrors()));
        $this->assertGreaterThan(0, count($form->get('email')->getErrors()));
        $this->assertGreaterThan(0, count($form->get('password')->getErrors()));
        $this->assertGreaterThan(0, count($form->get('agreeToTerms')->getErrors()));
    }

    public function testFormView(): void
    {
        $user = new User();
        $user->setFirstName('Jane');
        $user->setLastName('Smith');
        
        $form = $this->factory->create(UserRegistrationType::class, $user);
        $view = $form->createView();

        $this->assertEquals('Jane', $view->children['firstName']->vars['value']);
        $this->assertEquals('Smith', $view->children['lastName']->vars['value']);
        $this->assertArrayHasKey('email', $view->children);
        $this->assertArrayHasKey('password', $view->children);
    }
}
```

```php
<?php

namespace App\Tests\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

class RegistrationControllerTest extends WebTestCase
{
    public function testRegistrationFormRender(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/register');

        $this->assertResponseIsSuccessful();
        $this->assertSelectorTextContains('h1', 'Create Account');
        
        // Check form fields are present
        $this->assertCount(1, $crawler->filter('input[name="user_registration[firstName]"]'));
        $this->assertCount(1, $crawler->filter('input[name="user_registration[email]"]'));
        $this->assertCount(1, $crawler->filter('input[name="user_registration[password][first]"]'));
    }

    public function testSuccessfulRegistration(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/register');

        $form = $crawler->selectButton('Create Account')->form([
            'user_registration[firstName]' => 'Test',
            'user_registration[lastName]' => 'User',
            'user_registration[email]' => 'test@example.com',
            'user_registration[password][first]' => 'SecurePassword123!',
            'user_registration[password][second]' => 'SecurePassword123!',
            'user_registration[agreeToTerms]' => true,
        ]);

        $client->submit($form);

        $this->assertResponseRedirects('/registration/success');

        // Follow the redirect
        $client->followRedirect();
        $this->assertResponseIsSuccessful();
        $this->assertSelectorTextContains('.alert-success', 'Registration successful');

        // Verify user was created in database
        $container = static::getContainer();
        $userRepository = $container->get('doctrine')->getRepository(User::class);
        $user = $userRepository->findOneBy(['email' => 'test@example.com']);
        
        $this->assertNotNull($user);
        $this->assertEquals('Test', $user->getFirstName());
        $this->assertEquals('User', $user->getLastName());
    }

    public function testRegistrationValidationErrors(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/register');

        $form = $crawler->selectButton('Create Account')->form([
            'user_registration[firstName]' => '',  // Empty required field
            'user_registration[lastName]' => 'User',
            'user_registration[email]' => 'invalid-email',  // Invalid email
            'user_registration[password][first]' => '123',  // Too short
            'user_registration[password][second]' => '456',  // Doesn't match
            'user_registration[agreeToTerms]' => false,  // Not agreed
        ]);

        $client->submit($form);

        $this->assertResponseIsSuccessful();  // Form redisplays with errors
        $this->assertSelectorExists('.form-error');
        $this->assertSelectorTextContains('.form-error', 'This value should not be blank');
    }

    public function testCsrfProtection(): void
    {
        $client = static::createClient();
        
        // Submit form with invalid CSRF token
        $client->request('POST', '/register', [
            'user_registration' => [
                'firstName' => 'Test',
                'lastName' => 'User',
                'email' => 'test@example.com',
                'password' => [
                    'first' => 'SecurePassword123!',
                    'second' => 'SecurePassword123!',
                ],
                'agreeToTerms' => true,
                '_token' => 'invalid-token',
            ],
        ]);

        $this->assertResponseStatusCodeSame(Response::HTTP_UNPROCESSABLE_ENTITY);
    }
}
```

Comprehensive form testing includes unit tests for form types, integration  
tests for controllers, validation testing, and security testing. Use  
TypeTestCase for isolated form testing and WebTestCase for full  
integration testing.  