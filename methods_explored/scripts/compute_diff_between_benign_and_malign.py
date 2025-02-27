from os import listdir
from os.path import isfile, join

src_dir   = "../output"
diffs_dir = f"{src_dir}/diffs"

tools = ['droidbot']

files = [f for f in listdir(src_dir) if isfile(join(src_dir, f)) and f.endswith('csv')]

benign_apps    = {}
malicious_apps = {}

print(f"[Info] Processing files in {src_dir}")
print(f"[Info] Number of files: {len(files)}")  

methods_in_diff = {}

sensitive_methods = []

with open('sensitive_methods.txt', 'r') as fh:
    lines = fh.readlines()

    for line in lines:
        sensitive_methods.append(line.replace('\n', ''))
        
for f in files:
    elements = f.split('-')

    if len(elements) < 4:
        continue
    
    tool = elements[0]
    classification = elements[1]
    apk = elements[2] + "-" + elements[3]

    if tool not in tools:
        continue

    with open(join(src_dir, f)) as fh:
        lines = fh.readlines()

        methods = set()
        
        for line in lines:
            method = line.replace('\n', '')
            if method in sensitive_methods:
                methods.add(f"\042{method}\042")

    if classification == 'benign':
        benign_apps[(tool, apk)] = methods
    elif classification == 'malicious':
        malicious_apps[(tool, apk)] = methods
    else:
        continue

summary = {} 

for (tool, apk), bMethods in benign_apps.items():
    mMethods = malicious_apps.get((tool, apk), set())

    dMethods = mMethods.difference(bMethods)

    summary[(tool, apk)] = len(dMethods)

    file_name = f"{diffs_dir}/{tool}-diff-{apk}.csv"
    
    with open(file_name, 'w') as fh:
        fh.writelines(dMethods)

    for m in dMethods:
        total = methods_in_diff.get(m, 0)
        methods_in_diff[m] = total + 1

summary_file = f"{diffs_dir}/summary.csv"
methods_in_diff_file = f"{diffs_dir}/methods_in_diff.csv"

with open(summary_file, 'w') as fh:
    fh.write("tool,apk,methods_in_diff\n")
    for ((tool, apk), ms) in summary.items():
        fh.write(f"{tool},{apk},{ms}\n")

with open(methods_in_diff_file, 'w') as fh:
    fh.write("method,occurrences\n")
    
    for (m, t) in methods_in_diff.items():
        fh.write(f"{m},{t}\n")

    
            
print(f"[Info] Results exported to {diffs_dir}")
