# Deliberately insecure teaching fixtures

Files in this directory demonstrate scanner findings. Do not apply them to a
cluster or cloud account, or reuse their credential-like literals. They are
excluded from the normal production configuration scan and can be scanned
explicitly with `make scan-insecure`.

The historical password-pattern findings in `bad-main.tf` remain under provenance
review. Their location in teaching material is not proof that they were never
real credentials. No values are reproduced here and no exception is approved.
See `docs/production-readiness.md` for the required owner verification.
