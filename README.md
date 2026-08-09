# Safi Auth Extension (`safi-auth`)

Authentication, session management, and brute-force protection extension for the Safi Microframework.

---

## 1. Quickstart

### Installation

```bash
composer require chani/safi-auth
```

### Service Provider Registration

Register `AuthServiceProvider` into the `Assembler` during application bootstrapping (`init.inc.php`):

```php
use Safi\Extensions\Auth\AuthServiceProvider;

$provider = new AuthServiceProvider();
$provider->register($assembler);
```

### Attach Authentication Middleware

Attach `AuthMiddleware` to your `Kernel` middleware pipeline:

```php
use Safi\Extensions\Auth\AuthMiddleware;

$kernel = new Kernel(
    router: $router,
    logger: $logger,
    view: $viewEngine,
    middlewares: [
        $assembler->get(AuthMiddleware::class),
    ],
);
```

### Database Initialization

Execute the CLI command to create schema tables and the default admin record:

```bash
# Initialize with default credentials (admin / admin):
php bin/safi auth:init

# Or set a custom admin password directly:
php bin/safi auth:init YourSecurePassword123
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

### Handling Two-Factor Authentication (2FA / TOTP)

When a user with 2FA enabled attempts to log in, `loginWithCredentials()` returns `false` and dispatches a `TwoFactorChallengeRequestedEvent`.

To complete authentication or generate a setup QR code in your application/UI:

```php
// 1. Verify TOTP Challenge Code
if ($authService->isTwoFactorPending()) {
    $success = $authService->verifyTwoFactorCode($userInputCode);
}

// 2. Generate Provisioning URI for QR Codes (e.g. Authenticator Apps)
$provisioningUri = $totpService->getProvisioningUri($user->email, $secret);
```

---

## 3. Reference

### CLI Commands

- `auth:init`: Creates database tables and initial admin record.
- `auth:permissions-scan`: Scans codebase for `#[Permission]` attributes and registers them in the database.

### Endpoints

| URI       | Method | Public | Name              | Function                  |
| --------- | ------ | ------ | ----------------- | ------------------------- |
| `/login`  | `GET`  | Yes    | `auth.login.show` | Displays login form       |
| `/login`  | `POST` | Yes    | `auth.login`      | Authenticates credentials |
| `/logout` | `POST` | No     | `auth.logout`     | Terminates active session |

---

## 4. Architecture & Concepts

- **ORM & Database Agnostic:** `safi-auth` depends solely on `safi-core` contracts (`DatabaseDriverInterface` and `ModelInterface`). It does not hardcode any ORM dependency and works seamlessly with any registered database driver.
- **Inverted Access Control:** Unflagged routes are blocked by `AuthMiddleware`. Access requires explicit `public: true` route metadata.
- **XHR & HTMX Behavior:** Unauthenticated XHR/HTMX requests receive HTTP 401 with an `HX-Redirect: /login` header instead of standard HTML redirects.
- **Brute-Force Shield:** `BruteForceShield` limits failed login attempts per IP/account using a PSR-16 cache backend or in-memory storage.

---

## License

MIT License. Author: Jean Bruenn
