# µADR-037: Pragmatic ORM Abstraction and Model Query Strategy
-----
tags: #orm #redbean #lynadb #architecture #models
status: accepted
context: RedBeanPHP was chosen to eliminate database schema boilerplate and mapping configuration. Falling back to raw SQL SELECT queries in controllers invalidates the purpose of having an ORM.
decisions:
  - Utilize ORM model abstractions (`findModels`, `findOneModel`, `loadModel`, `storeModel`, `trashModel`) for all application-level database operations.
  - Eliminate raw SQL `SELECT`, `DELETE`, and `INSERT` statements in domain logic and controllers.
  - Keep model implementations (e.g., `User`, `LockedIp`) strictly lightweight with zero schema annotations.
  - Guarantee full compatibility with future LynaDB driver replacements by routing all model retrieval through `DatabaseDriverInterface`.
consequences:
  - Maximizes ORM capabilities without introducing complex mapping configuration.
  - Keeps application and controller code 100% object-oriented and free of SQL string coupling.
