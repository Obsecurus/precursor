#!/usr/bin/env bash
set -euo pipefail

out_dir="${1:-dist/cli-assets}"
bin_path="${2:-./target/release/precursor}"

mkdir -p "${out_dir}/complete" "${out_dir}/doc"

common_options="-f --input-folder -z --input-blob -p --pattern-file -t --tlsh -a --tlsh-algorithm -d --tlsh-diff -y --tlsh-sim-only -x --tlsh-distance -l --tlsh-length --similarity-mode --protocol-hints --protocol-hints-limit -P --single-packet -A --abstain-threshold -k --protocol-top-k -m --input-mode -j --input-json-key -s --stats -h --help"

cat > "${out_dir}/complete/precursor.bash" <<EOF
_precursor() {
  local cur
  COMPREPLY=()
  cur="\${COMP_WORDS[COMP_CWORD]}"
  if [[ "\${cur}" == -* ]]; then
    COMPREPLY=( \$(compgen -W "${common_options}" -- "\${cur}") )
    return 0
  fi
}
complete -F _precursor precursor
EOF

cat > "${out_dir}/complete/precursor.fish" <<'EOF'
complete -c precursor -f
complete -c precursor -s f -l input-folder -d "Specify the path to the input folder."
complete -c precursor -s z -l input-blob -d "Process each input source as a single blob."
complete -c precursor -s p -l pattern-file -d "Pattern file path."
complete -c precursor -s t -l tlsh -d "Calculate TLSH hash."
complete -c precursor -s a -l tlsh-algorithm -d "TLSH algorithm." -a "48_1 128_1 128_3 256_1 256_3"
complete -c precursor -s d -l tlsh-diff -d "Perform TLSH distance calculations."
complete -c precursor -s y -l tlsh-sim-only -d "Only output similar payloads."
complete -c precursor -s x -l tlsh-distance -d "TLSH distance threshold."
complete -c precursor -s l -l tlsh-length -d "Include length in TLSH diff."
complete -c precursor -l similarity-mode -d "Similarity backend." -a "tlsh mrshv2 fbhash"
complete -c precursor -l protocol-hints -d "Emit protocol hint JSON to STDERR."
complete -c precursor -l protocol-hints-limit -d "Limit protocol hint candidates."
complete -c precursor -s P -l single-packet -d "Enable single-packet protocol inference."
complete -c precursor -s A -l abstain-threshold -d "Protocol inference abstain threshold."
complete -c precursor -s k -l protocol-top-k -d "Protocol candidate count."
complete -c precursor -s m -l input-mode -d "Input mode." -a "base64 string hex"
complete -c precursor -s j -l input-json-key -d "JSON extraction key."
complete -c precursor -s s -l stats -d "Emit statistics to STDERR."
complete -c precursor -s h -l help -d "Show help."
EOF

cat > "${out_dir}/complete/_precursor.ps1" <<EOF
Register-ArgumentCompleter -CommandName precursor -ScriptBlock {
  param(\$wordToComplete)
  ${common_options}
    .Split(" ")
    | Where-Object { \$_ -like "\$wordToComplete*" }
    | ForEach-Object { [System.Management.Automation.CompletionResult]::new(\$_, \$_, 'ParameterName', \$_) }
}
EOF

cat > "${out_dir}/complete/_precursor" <<EOF
#compdef precursor

local -a opts
opts=(
  '-f[Specify the path to the input folder]:input-folder:_files'
  '--input-folder[Specify the path to the input folder]:input-folder:_files'
  '-z[Process each input source as a single blob]'
  '--input-blob[Process each input source as a single blob]'
  '-p[Specify pattern file path]:pattern-file:_files'
  '--pattern-file[Specify pattern file path]:pattern-file:_files'
  '-t[Calculate TLSH hash]'
  '--tlsh[Calculate TLSH hash]'
  '-a[Specify TLSH algorithm]:tlsh-algorithm:(48_1 128_1 128_3 256_1 256_3)'
  '--tlsh-algorithm[Specify TLSH algorithm]:tlsh-algorithm:(48_1 128_1 128_3 256_1 256_3)'
  '-d[Perform TLSH distance calculations]'
  '--tlsh-diff[Perform TLSH distance calculations]'
  '-y[Only output payloads with TLSH similarities]'
  '--tlsh-sim-only[Only output payloads with TLSH similarities]'
  '-x[Set TLSH distance threshold]:tlsh-distance:'
  '--tlsh-distance[Set TLSH distance threshold]:tlsh-distance:'
  '-l[Include payload length in TLSH diff]'
  '--tlsh-length[Include payload length in TLSH diff]'
  '--similarity-mode[Select similarity backend]:similarity-mode:(tlsh mrshv2 fbhash)'
  '--protocol-hints[Emit protocol hints to STDERR]'
  '--protocol-hints-limit[Set protocol hint candidate limit]:protocol-hints-limit:'
  '-P[Enable single-packet protocol inference]'
  '--single-packet[Enable single-packet protocol inference]'
  '-A[Set protocol inference abstain threshold]:abstain-threshold:'
  '--abstain-threshold[Set protocol inference abstain threshold]:abstain-threshold:'
  '-k[Set protocol candidate count]:protocol-top-k:'
  '--protocol-top-k[Set protocol candidate count]:protocol-top-k:'
  '-m[Set input mode]:input-mode:(base64 string hex)'
  '--input-mode[Set input mode]:input-mode:(base64 string hex)'
  '-j[Set JSON extraction key]:input-json-key:'
  '--input-json-key[Set JSON extraction key]:input-json-key:'
  '-s[Emit statistics JSON to STDERR]'
  '--stats[Emit statistics JSON to STDERR]'
  '-h[Show help]'
  '--help[Show help]'
)

_arguments -S \$opts '*:pattern: '
EOF

if command -v help2man >/dev/null 2>&1; then
  help2man -N --name "pre-protocol payload tagging and similarity analysis" "${bin_path}" > "${out_dir}/doc/precursor.1"
else
  {
    echo ".TH precursor 1"
    echo ".SH NAME"
    echo "precursor - pre-protocol payload tagging and similarity analysis"
    echo ".SH SYNOPSIS"
    echo "precursor [PATTERN] [OPTIONS]"
    echo ".SH DESCRIPTION"
    "${bin_path}" --help
  } > "${out_dir}/doc/precursor.1"
fi
