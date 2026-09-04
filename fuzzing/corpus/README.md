# Fuzzing seed corpus

The checked-in corpus contains only reviewed, non-weaponized semantic inputs.
Generated and minimized cases are written below `output/fuzzing/` and are not
committed by default. Every retained case records its source hash, deterministic
seed, mutation trace, target manifest, oracle evidence, and artifact hashes.

Ground-truth labels are evaluator-only data and must never be passed to a fuzz
target.
