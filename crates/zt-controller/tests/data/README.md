# Test key material

These are throwaway RSA keys, used only by `tests/auth.rs`. They sign
nothing but the test tokens, and they are committed on purpose so the tests
are reproducible without a key generation step.

They are not, and must not be, used for anything else. A production key
belongs in the controller's identity store, which is created on first run
and written with owner-only permissions.
