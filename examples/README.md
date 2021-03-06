This directory contains examples of using Arbiter to detect previously known vulnerabilities.

The vulnerable binaries are present inside `cve-binaries` directory and the corresponding templates used to detect the bugs can be found inside `cve-vuln_templates`.

The `cve-logs` directory contains the output generated by Arbiter when running the VD against the target binary.

Please refer to the README file inside `cve-logs` for an explanation on how to interpret the output.


# Running the examples
Use the `run_arbiter` script using the `-f` flag to specify a VD inside `cve-vuln_templates` and the `-t` flag to specify a binary inside `cve-binaries`.

Optionally, set the `-l` and `-j` flags to a directory in order to view the output from Arbiter.

For example, in order to run the CVE-XXXX-YYYY example, the command used would look like

```
cd <path/to/arbiter>
mkdir <some_log_dir>
mkdir <some_json_dir>
./vuln_templates/run_arbiter.py -f examples/cve-vuln_templates/vd_cve-xxxx-yyyy.py -t examples/cve-binaries/cve-xxxx-yyyy -l <some_log_dir> -j <some_json_dir>
```