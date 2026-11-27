# What happens when a layer fails

Attacks that work with no protection in this run: 51 of 53. With all four layers on, 0 get through.

| Layer that fails (the other three stay on) | Attacks that get through |
|---|---|
| query checker | 0 |
| read-only mode | 0 |
| permission check | 0 |
| time and row limit | 3 |

| Two layers fail together | Attacks that get through |
|---|---|
| query checker + read-only mode | 0 |
| query checker + permission check | 37 |
| query checker + time and row limit | 6 |
| read-only mode + permission check | 0 |
| read-only mode + time and row limit | 3 |
| permission check + time and row limit | 3 |

| Only this layer is on | Attacks that get through |
|---|---|
| query checker | 3 |
| read-only mode | 44 |
| permission check | 6 |
| time and row limit | 44 |
