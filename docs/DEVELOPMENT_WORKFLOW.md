# Development Workflow

From Phase2 onward, `D:/work_git/cybermatch-framework` is the canonical working repository.

Do not continue feature development in:

`D:/source/repos/profilecore/PoC_Projects/cybermatch`

unless explicitly syncing back to the Git repository.

## Recommended Workflow

1. Work inside `D:/work_git/cybermatch-framework`
2. Run tests before commit

```powershell
python -m compileall cybermatch.py run_scenarios.py
python -m pytest
```

3. Review changes

```powershell
git status --short
git diff
```

4. Commit with a clear message
5. Push to GitHub

## Generated Files

Do not commit:

* output/
* __pycache__/
* .pytest_cache/
* *.npz
* smoke_fix*.py

Representative figures and reports may be copied manually into `docs/`.
