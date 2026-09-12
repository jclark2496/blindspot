## Summary

- 

## Verification

- [ ] `python3 scripts/generate_rules.py --check`
- [ ] `python3 test_engine.py`
- [ ] `node tests/check_rule_parity.js`
- [ ] `python3 -m unittest tests/test_cli_features.py`
- [ ] Extension syntax checks, if browser code changed

## Rule/catalog changes

- [ ] I changed `rules/catalog.json` instead of generated rule files.
- [ ] I regenerated rules with `python3 scripts/generate_rules.py` if needed.
- [ ] I updated `corpus/corpus_index.json` if expected detections changed.
- [ ] Not applicable.

## Security notes

- [ ] No secrets, private keys, credentials, real customer data, or confidential prompts are included.
- [ ] Intentional malicious samples are isolated under corpus/demo fixtures and documented.
