# µADR-036: Database Driver Abstraction in Auth Extension
-----
tags: #auth #database #dip #abstraction #architecture
status: accepted
context: The authentication module requires database persistence for users, login attempts, and IP locks, but must remain uncoupled from specific ORM implementations (e.g., RedBeanPHP or LynaDB).
decisions:
  - Depend strictly on `Safi\Core\Contracts\DatabaseDriverInterface`.
  - Use `dispenseModel(User::class)` and `storeModel()` for user entity management.
  - Keep `User` model bean wrapping transparent to ensure portability across different ORMs.
consequences:
  - Allows swapping the database driver without modifying authentication logic or models.
