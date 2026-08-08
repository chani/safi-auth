# safi-auth — TODO

## Permissions & Delegation System (RBAC)

- [ ] Implement `#[Permission(key, label, category)]` attribute scanner for auto-registering permissions from external components/extensions.
- [ ] Design lightweight group hierarchy and permission mapping model (`groups`, `user_groups`, `group_permissions`).
- [ ] Implement `AuthService::can(User $user, string $permission)` capability evaluation.
- [ ] Build Admin Panel UI hooks for assigning permissions to roles (lean and transparent, avoiding legacy CMS bloat).
