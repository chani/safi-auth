# Safi Auth Extension (`safi-auth`)

Authentication, session management, and brute-force protection extension for the Safi Microframework.

---

## 1. Quickstart

### Installation

```bash
composer require chani/safi-auth
```

### Service Provider Registration

Register `AuthServiceProvider` during application bootstrapping (`init.inc.php`):

```php
$assembler->registerProvider(new \Safi\Extensions\Auth\AuthServiceProvider());
```

### Database Initialization

Execute the CLI command to create schema tables and default admin record:

```bash
php bin/safi auth:init
```

---

## 2. How-To Guides

### Protecting Controller Routes

Routes are secure by default. Set `public: true` in the `#[Route]` attribute to grant unauthenticated access.

```php
declare(strict_types=1);

namespace Components\Example\Controllers;

use Safi\Core\AbstractController;
use Safi\Core\Attributes\Route;
use Safi\Core\Http\Response;

final class ExampleController extends AbstractController
{
    #[Route('/public-page', method: 'GET', name: 'example.public', public: true)]
    public function publicPage(): Response
    {
        return $this->render('@Example/public');
    }

    #[Route('/protected-page', method: 'GET', name: 'example.protected')]
    public function protectedPage(): Response
    {
        return $this->render('@Example/protected');
    }
}
```

---

## 3. Reference

### CLI Commands

- `auth:init`: Creates database tables and initial admin record.

### Endpoints

| URI                           | Method | Public | Name                         | Function                       |
| ----------------------------- | ------ | ------ | ---------------------------- | ------------------------------ |
| `/login`                      | `GET`  | Yes    | `auth.login.show`            | Displays login form            |
| `/login`                      | `POST` | Yes    | `auth.login`                 | Authenticates credentials      |
| `/logout`                     | `POST` | No     | `auth.logout`                | Terminates session             |
| `/admin/users`                | `GET`  | No     | `admin.users.index`          | User directory list            |
| `/admin/users/save`           | `POST` | No     | `admin.users.save`           | Creates user                   |
| `/admin/users/delete`         | `POST` | No     | `admin.users.delete`         | Deletes user                   |
| `/admin/sessions`             | `GET`  | No     | `admin.sessions.index`       | Active sessions and locked IPs |
| `/admin/sessions/unlock`      | `POST` | No     | `admin.sessions.unlock`      | Unlocks single IP              |
| `/admin/sessions/unlock-bulk` | `POST` | No     | `admin.sessions.unlock_bulk` | Unlocks multiple IPs           |
| `/admin/sessions/kill`        | `POST` | No     | `admin.sessions.kill`        | Terminates active user session |

---

## 4. Architecture & Concepts

- **ORM & Database Agnostic:** `safi-auth` depends solely on `safi-core` contracts (`DatabaseDriverInterface` and `ModelInterface`). It does not hardcode any ORM dependency (such as RedBeanPHP or Eloquent) and works seamlessly with any database driver registered in the Safi container.
- **Inverted Access Control:** Unflagged routes are blocked by `AuthMiddleware`. Access requires explicit `public: true` route metadata.
- **XHR & HTMX Behavior:** Unauthenticated XHR requests receive HTTP 401 with an `HX-Redirect: /login` header instead of standard 302 HTML redirects.
- **Brute-Force Shield:** `BruteForceShield` limits failed login attempts using a PSR-16 cache backend or in-memory array storage.

---

## License

MIT License. Author: Jean Bruenn
