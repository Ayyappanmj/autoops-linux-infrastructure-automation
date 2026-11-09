# Linux / WSL / Git-Bash convenience targets. On plain Windows use scripts/windows_validate.ps1.
PY ?= python3
.PHONY: validate test demo lint syntax check
validate:
	$(PY) -m autoops validate
	$(PY) -m autoops inventory-check
test:
	$(PY) -m pytest
demo:
	$(PY) -m autoops report --demo
	-$(PY) -m autoops drift --previous examples/sample_previous_state.json
	-$(PY) -m autoops compliance
lint:
	yamllint -c .yamllint .
	cd ansible && ansible-lint
syntax:
	cd ansible && for p in playbooks/*.yml; do ANSIBLE_CONFIG=$$PWD/ansible.cfg ansible-playbook -i inventory/localhost.yml --syntax-check $$p || exit 1; done
check:
	bash scripts/run_checks.sh
