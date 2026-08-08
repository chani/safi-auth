# safi-auth — TODO

## 1. Permissions & Delegation System (RBAC)

- [ ] Implement `#[Permission(key, label, category)]` attribute scanner for auto-registering permissions from external components/extensions.
- [ ] Design lightweight group hierarchy and permission mapping model (`groups`, `user_groups`, `group_permissions`).
- [ ] Implement `AuthService::can(User $user, string $permission)` capability evaluation.
- [ ] Build Admin Panel UI hooks for assigning permissions to roles (lean and transparent, avoiding legacy CMS bloat).

## 2. Event Lifecycle & CLI Support

- [ ] Dispatch domain events (`UserLoggedInEvent`, `FailedLoginAttemptEvent`, etc.) via `EventDispatcher`.
- [ ] Add `auth:reset-password` CLI command for emergency credential recovery.
