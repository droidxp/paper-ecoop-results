./clean.sh
cd scripts
python3 generate_union_of_executions.py
python3 compute_diff_between_benign_and_malign.py
