#!/bin/bash
set -e -u -o pipefail -x
trap "kill 0" SIGINT SIGTERM

mkdir -p /var/tmp/openjml{,-build}

# Install OpenJML
pushd /var/tmp/openjml-build
git clone https://github.com/OpenJML/OpenJML.git
cd OpenJML && git checkout e4dc6371e2cf45d1a08b5c91990e2a875f33dd27
cp OpenJML/releaseBuilds-CI/openjml.jar /var/tmp/openjml/openjml.jar
popd

# Install Z3
pushd /var/tmp/openjml-build
git clone https://github.com/OpenJML/Solvers.git
cd Solvers && git checkout 023d9682b6fa2e5d70e7587e2e293bdeae4e0885
cp -r Solvers-linux /var/tmp/openjml
popd

# Run the OpenJML proof.  Currently we only check the annotations on the files
# in FILES.  We will continue adding files to this list as we add annotations.
cd src/main/java

declare -a FILES=(
  com/amazonaws/encryptionsdk/model/KeyBlob.java
)

for file in ${FILES[@]}; do
  java -Xmx4g -jar /var/tmp/openjml/openjml.jar -- -Werror -progress -timeout 600 -esc -spec-math=bigint -code-math=safe -minQuant -no-staticInitWarning -prover z3_4_3 -sourcepath . ${file}
done
