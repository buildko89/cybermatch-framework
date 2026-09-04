# External command allowlists

Real external SUT execution is disabled unless all of the following are true:

1. the campaign selects `transport: command`;
2. `allow_external_execution` is exactly `true`;
3. `command_allowlist` resolves to a repository file;
4. `command_id` selects an exact entry with an absolute existing executable;
5. `CYBERMATCH_ALLOW_EXTERNAL_SUT=1` is present in the runner environment.

Commands are executed with `shell=False`. Arguments must contain both `{input}` and
`{output}` placeholders. Do not add production endpoints or credentials to an allowlist.
