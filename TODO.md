# safi-auth — TODO

## Ecosystem Portability & Framework Bridges

- [ ] Extract persistence layer behind `UserRepositoryInterface` and `UserSessionRepositoryInterface` to remove hard lock-in on `safi-db-redbean`.
- [ ] Implement PSR-15 compliant `PsrAuthMiddleware` (`Psr\Http\Server\MiddlewareInterface`) alongside native Safi `Context` middleware.
- [ ] Define `AuthServiceInterface` contract to allow standalone usage of `AuthService` and `BruteForceShield` in PSR-11 compatible frameworks

## Permissions & Delegation System (RBAC)

- [ ] Implement `#[Permission(key, label, category)]` attribute scanner for auto-registering permissions from external components/extensions.
- [ ] Design lightweight group hierarchy and permission mapping model (`groups`, `user_groups`, `group_permissions`).
- [ ] Implement `AuthService::can(User $user, string $permission)` capability evaluation.
- [ ] Build Admin Panel UI hooks for assigning permissions to roles (lean and transparent, avoiding legacy CMS bloat).
