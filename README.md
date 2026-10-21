# MithP-FALL2026-SQA

COMP 5710/6710 Software Quality Assurance, Fall 2026. Project: add fuzzing, forensics logging and continuous integration to SLI-KUBE (KubeSec), a Python static analysis tool for Kubernetes manifests.

## Team

- Team name: Mith P
- Members:
  1. Mith Patel, mithpatel01@gmail.com

## SQA deliverables

| Activity | Where |
|---|---|
| Fuzzing of 10 methods | `fuzz.py`, results in `fuzz_results/` |
| Forensics in 10 methods | `forensics.py`, changes in `scanner.py`, demo in `run_forensics_demo.py`, tests in `TEST_FORENSICS.py` |
| Continuous integration | `.github/workflows/python.build.yml` |
| Report and lessons learned | `SQA-REPO.md` |
| Execution evidence | `evidence/` |

Quick start:

```bash
pip install pytest pandas numpy PyYAML ruamel.yaml sarif-om jschema-to-python typer
python fuzz.py                      # fuzz 10 methods, writes fuzz_results/
python -m pytest -q TEST_PARSING.py TEST_FORENSICS.py
python run_forensics_demo.py        # writes forensics.log
```

`yq` (mikefarah, v4) must be on the PATH for the scanner methods that report line numbers.

---

# Original project README

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 

[![forthebadge made-with-python](http://ForTheBadge.com/images/badges/made-with-python.svg)](https://www.python.org/)

[![Actions Status](https://github.com/paser-group/KubeSec/workflows/Build%20KubeTaint/badge.svg)](https://github.com/Build%20TaintPupp/actions)


# Taintube: Taint Tracking for Security Analysis of Kubernetes Manifests 

## Development Environment
We use Conda to manage the virtual environment for KubeSec. To see the content of the environment, see [environment.yml](./environment.yml).

To use the environment, use the following commands.

```bash
# Create
conda env create -f environment.yml

# Activate
conda activate KUBESEC

# Deactivate
conda deactivate

# Export (if you modify the environment)
conda env export --from-history > environment.yml
```

## Running the tool

The tool is available as a Docker image: https://hub.docker.com/repository/docker/akondrahman/sli-kube 

### Instruction to run the tool from Docker Hub:

- docker rm $(docker ps -a -f status=exited -f status=created -q)
- docker rmi -f $(docker images -a -q)
- docker pull akondrahman/sli-kube
- docker images -a
- docker run --rm -it akondrahman/sli-kube bash
- cd SLI-KUBE-WORK/KubeSec-master/
- python3 main.py

### Build and run locally
You can also build the docker container locally.

After running the tool, you will find a CSV file called 'slikube_results.csv' in the scanned directory.

```bash
# Build the image
docker build -t slikube .

# Run the container 
# Replace '/Users/phu/Desktop/tf-open-source/aws-eks-base' with your local path
docker run --rm -v /Users/phu/Desktop/tf-open-source/aws-eks-base:/iac --name slikube slikube /iac
```

## Collaborators 

Akond Rahman (Lead), Rahul Pandita, and Shazibul Islam Shamim 


