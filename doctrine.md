
<!DOCTYPE html>
<html lang="en">
<head>
<title>Doctrine one-to-many relationship tutorial</title>
<link rel="stylesheet" href="/cfg/style.css" type="text/css">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="keywords" content="Doctrine, PHP, one-to-many, databases, PostgreSQL, programming">
<meta name="description" content="Doctrine one-to-many relationship tutorial shows how to
create a one-to-many relationship in PHP with Doctrime ORM.">
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
<li><a href="/ebooks/mysqljava/">MySQL Java ebook</a></li>
</ul>

</div>

</div>



<div class="content">



<h1>Doctrine one-to-many relationship tutorial</h1>

<p class="last_mod">
last modified July 10, 2020 
</p>

<p>
Doctrine one-to-many relationship tutorial shows how to create a one-to-many
relationship in PHP with Doctrime ORM.
</p>

<h2>Doctrine</h2>

<p>
<dfn>Doctrine</dfn> is a set of PHP libraries primarily focused on providing
persistence services in PHP. Its main projects are an object-relational mapper
(ORM) and the database abstraction layer (DBAL).
Doctrine is an open source project made available for free under the MIT license.
</p>


<h2>Doctrine entity relationships</h2>

<p>
<dfn>Entity</dfn> is a PHP object that is going to be persisted. Entity classes
are decorated with annotations such as <code>@Id</code>, <code>@Table</code>,
or <code>@Column</code>. There are relationships between entities (also called
associations.) The basic associations are one-to-one, one-to-many, and many-to-many.
</p>

<p>
Relationships may be unidirectional or bidirectional. In a unidirectional
relationship we have a navigational access in one direction, in a bidirectional
relationship, we have access in both directions. Suppose we have two entities:
User and Post. There is a one-to-many relationship between the entities; one
user may have multiple posts. In a unidirectional relationship, we can get posts
from a user. In a bidirectional, we can get the user from the posts as well.
</p>



<h2>One-to-many relationship</h2>


<p>
In a one-to-many relationship, one record in a table can be associated with
one or more records in another table. For example, one customer can have
many orders.
</p>

<p>
The bidirectional one-to-many mapping requires the <code>mappedBy</code> attribute
to be on the one side and the <code>inversedBy</code> attribute on the many side.
There is no difference between a bidirectional one-to-many and a bidirectional
many-to-one relationship.
</p>

<p>
The <code>@ManyToOne</code> represents the owning side of a bidirectional assocation.
The <code>@OneToMany</code> represents the inverse side of a bidirectional assocation.
The owning side of a bidirectional relationship is the side that contains the foreign key.
</p>

<p>
The <code>targetEntity</code> property defines the entity to which we are creating 
the relationship.
</p>

<p>
The <code>mappedBy</code> attribute hints the name of the variable that maps the child 
entity in the parent entity. The <code>inversedBy</code> attribute hints the name of 
the variable that maps the parent entity in the child entity. 
Both attributes help Doctrine optimize the queries.
</p>

<p>
The <code>@JoinColumn</code> defines the name of the column that contains the foreign 
key. The foreign key is created on the table which has the annotation.
The annotation is no required; if not used, the necessary attributes are inferred.
If specified, the <code>name</code> and <code>referencedColumnName</code> attributes 
are required. The <code>name</code> specifies the column name that holds the foreign key 
identifier for the relation. The <code>referencedColumnName</code> specified the name of 
the primary key identifier that is used for joining of the relation.
</p>


<h2>Doctrine installation</h2>

<p>
We install Doctrine and some helper tools.
</p>

<pre class="compact">
$ composer req doctrine/dbal
</pre>

<p>
We install Doctrine. Note that the DBAL layer is included in the <code>doctrine/dbal</code>
package.
</p>

<pre class="compact">
$ composer req symfony/var-dumper
$ composer req tightenco/collect
</pre>

<p>
We install Symfony's dumper and Laravel collections. We will be using
them in our examples.
</p>

<pre class="compact">
$ composer dumpautoload
</pre>

<p>
We generate a list of all classes that need to be included in the project.
The <code>composer</code> re-reads the <code>composer.json</code> file to build
up the list of files to autoload.
</p>


<h2>Bootstrapping Doctrine CLI examples</h2>

<p>
We create a bootstrap file that will be included in all examples.
</p>

<div class="codehead">bootstrap.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

require_once "vendor/autoload.php";

$isDevMode = true;
$config = Setup::createAnnotationMetadataConfiguration([__DIR__ . "/src"], $isDevMode);
$config->addEntityNamespace('', 'App\Entity');

$conn = ['driver' => 'pdo_pgsql', 'host' => 'localhost', 'dbname' => 'testdb',
    'port' => 5432, 'user' => 'postgres', 'password' => 's$cret'];

$em = EntityManager::create($conn, $config);
</pre>

<p>
In the bootstrap file, we include the autoloading file and set up the
connection to the PostgreSQL database.
</p>

<pre class="explanation">
$isDevMode = true;
$config = Setup::createAnnotationMetadataConfiguration([__DIR__ . "/src"], $isDevMode);
$config->addEntityNamespace('', 'App\Entity');
</pre>

<p>
We create a Doctrine ORM configuration for annotations.
</p>

<pre class="explanation">
$conn = ['driver' => 'pdo_pgsql', 'host' => 'localhost', 'dbname' => 'testdb',
  'port' => 5432, 'user' => 'postgres', 'password' => 's$cret'];
</pre>

<p>
We specify the database configuration parameters.
</p>

<pre class="explanation">
$em = EntityManager::create($conn, $config);
</pre>

<p>
We obtain the entity manager.
</p>

<div class="codehead">composer.json
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
{
    "require": {
        "doctrine/orm": "^2.6"
    },
    "autoload": {
        "psr-4": {
            "App\\": "src"
        }
    },
    "require-dev": {
        "symfony/var-dumper": "^4.2"
    }
}
</pre>

<p>
This is the <code>composer.json</code> file.
</p>


<h2>Doctrine one-to-many bidirectional example</h2>

<p>

</p>

<div class="codehead">src/Entity/Task.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Entity;

use App\Entity\User;

/**
 * @Entity
 * @Table(name="tasks")
 **/
class Task
{
    /**
     * @Id
     * @Column(type="integer")
     * @GeneratedValue(strategy="IDENTITY")
     */
    protected $id;

    /**
     *  @Column(type="string")
     */
    protected $name;

    /**
     * @ManyToOne(targetEntity="User", inversedBy="tasks", cascade={"persist", "remove"})
     * @JoinColumn(name="user_id", referencedColumnName="id")
     */
    protected $user;

    public function getId() : int
    {
        return $this-&gt;id;
    }

    public function getName() : string
    {
        return $this-&gt;name;
    }

    public function setName($name) : void
    {
        $this-&gt;name = $name;
    }

    public function addUser(User $user): void
    {
        $this-&gt;user = $user;
    }

    public function getUser() : User
    {
        return $this-&gt;user;
    }
}
</pre>

<p>

</p>


<div class="codehead">src/Entity/User.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

namespace App\Entity;

use App\Entity\Task;
use Doctrine\Common\Collections\Collection;
use Doctrine\Common\Collections\ArrayCollection;

/**
 * @Entity
 * @Table(name="users")
 **/
class User
{
    /**
     * @Id
     * @Column(type="integer")
     * @GeneratedValue(strategy="IDENTITY")
     */
    protected $id;

    /**
     * @Column(type="string")
     */
    protected $name;

    /**
     * @OneToMany(targetEntity="Task", mappedBy="user", cascade={"persist", "remove"})
     */
    protected $tasks;

    public function __construct()
    {
        $this-&gt;tasks = new ArrayCollection();
    }

    public function getId() : int
    {
        return $this-&gt;id;
    }

    public function getName() : string
    {
        return $this-&gt;name;
    }

    public function setName($name) : void
    {
        $this-&gt;name = $name;
    }

    public function getTasks() : Collection
    {
        return $this-&gt;tasks;
    }

    public function addTask(Task $task): void
    {
        $task-&gt;addUser($this);
        $this-&gt;tasks[] = $task;
    }
}
</pre>

<p>

</p>

<pre class="compact">
$ vendor\bin\doctrine orm:schema-tool:create
</pre>

<p>
With the above command, we  create tables from the entities. 
</p>


<div class="codehead">create_users_tasks.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

require_once 'bootstrap.php';

use App\Entity\User;
use App\Entity\Task;

$task1 = new Task();
$task1-&gt;setName('Task A');

$task2 = new Task();
$task2-&gt;setName('Task B');

$task3 = new Task();
$task3-&gt;setName('Task C');

$task4 = new Task();
$task4-&gt;setName('Task D');

$task5 = new Task();
$task5-&gt;setName('Task E');

$user1 = new User();
$user1-&gt;setName('John Doe');
$user1-&gt;addTask($task1);
$user1-&gt;addTask($task2);
$user1-&gt;addTask($task3);

$user2 = new User();
$user2-&gt;setName('Lucia Brenner');
$user2-&gt;addTask($task4);
$user2-&gt;addTask($task5);

$em-&gt;persist($task1);
$em-&gt;persist($task2);
$em-&gt;persist($task3);
$em-&gt;persist($task4);
$em-&gt;persist($task5);

$em-&gt;persist($user1);
$em-&gt;persist($user2);

$em-&gt;flush();
</pre>

<p>
In the program, we create two users who have five tasks.
</p>


<div class="codehead">show_user_tasks.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

require_once "bootstrap.php";

use App\Entity\User;

$userId = 2;

$repository = $em-&gt;getRepository(User::class);
$user = $repository-&gt;find($userId);

echo "User: " . $user-&gt;getName() . "\n";
dump($user-&gt;getTasks());

$tasks = $user-&gt;getTasks();

foreach ($tasks as $task)
{
   echo $task-&gt;getName() . "\n";
}
</pre>

<p>

</p>


<div class="codehead">show_task_user.php
  <i class="fas fa-copy copy-icon" onclick="copyCode(this)"></i>
</div>
<pre class="code">
&lt;?php

require_once "bootstrap.php";

use App\Entity\Task;

$taskId = 5;

$repository = $em-&gt;getRepository(Task::class);
$task = $repository-&gt;find($taskId);

if ($task !== null)
{
    echo "Task: " . $task-&gt;getName() . "\n";
    echo "User: " . $task-&gt;getUser()-&gt;getName() . "\n";
}
</pre>

<p>
In the example, we get a task and find out its user.
</p>

<p>
In this tutorial, we have
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
