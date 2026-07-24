# Safi Auth Extension (`safi-auth`)

Authentication, session management, and brute-force shielding extension for the Safi Microframework.

---

## Features

* **Session Security:** Session ID regeneration and User-Agent fingerprinting (`µADR-035`).
* **Brute-Force Shield:** Sliding window rate limiting for authentication attempts.
* **Database Agnostic:** Interacts exclusively through `DatabaseDriverInterface` (`µADR-036`).

---

## License

Distributed under the **MIT License**. Author: **Jean Bruenn**
