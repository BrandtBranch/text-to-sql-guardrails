# The same fuzz variations with every layer switched off

Same seeds, same generator and same definition of harm as the main fuzz run, but no parser, no read-only connection, no authorizer and no time or row limits (only a 0.6 second hard cap so a test cannot hang).

| Seed | Variations | Caused harm | Of variations from attacks | Of variations from normal questions |
|---|---|---|---|---|
| 1 | 20,000 | 5,979 | 5,778 of 12,593 | 201 of 7,407 |
| 2 | 20,000 | 6,064 | 5,868 of 12,754 | 196 of 7,246 |

**Total: 12,043 of 40,000 variations caused harm with no protection.** With the full guardrails the same variations caused harm 0 times.
