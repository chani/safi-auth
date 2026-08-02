# safi-auth — TODO

## Core Refactorings
- [ ] Convert manual route array registrations in controllers to native PHP 8.5 `#[Route]` attributes.
- [ ] Handle HTMX requests in `AuthController` using `HX-Redirect` response headers.

## Permissions & Delegation System
- [ ] Implement `#[Permission(key, label, category)]` attribute and reflection scanner.
- [ ] Implement group hierarchy and delegation model (`groups`, `user_groups`, `group_permissions` tables).
- [ ] Resolve parent group permission inheritance in `AuthService::can()`.
- [ ] Enforce `is_visible` logic: Admins can only view and delegate permissions they currently hold.

## GDPR Compliance Engine
- [ ] Implement `#[PersonalData]` attribute for marking model properties.
- [ ] Implement `DsgvoExportService` for generating user data exports (JSON) and handling data erasure.

## Endpoints
- [ ] Add session termination endpoint (`POST /admin/sessions/kill`) in `AdminController`.
