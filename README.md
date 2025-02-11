# Symfony-Notes


## Custom service in a test

```php
class HelloServiceTest extends KernelTestCase
{
    public function testHello(): void
    {
        self::bootKernel();
        $helloService = self::getContainer()->get(HelloService::class);

        $this->assertSame('hello there', $helloService->hello());
    }
}
```

If we want to get our service from a container, we either have to make it public in  
the `services.yaml` or use it somewhere.  

```yaml
services:

    App\Service\HelloService:
        public: true
```
