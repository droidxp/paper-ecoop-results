"""Compute the union of sensitive method calls during DroidXP executions. 

   Description: Given three executions for DroidBot, for instance,
   this script computes the union of the calls to sensitive methods 
   for a given app. 
"""
import os

tools = ['droidbot']
executions = [1,2,3]
non_relevant_categories = [] 

print(f"[Info] Computing the union of executions {executions}")
print(f"[Info] Tools: {tools}")
print(f"[Info] Searching for files named sensitiveMtd.csv")

mapping = {} # a dictionary mapping (tool, apk) into a set of methods. 

for root, dirs, files in os.walk('..'):
    for f in files:
        if f.endswith('sensitiveMtd.csv'):
            relative_path = os.path.join(root, f)

            elements = relative_path.split('/')

            execution = int(elements[2])
            tool = elements[3]
            apk = elements[4]

            print(elements)
            print(f"[Info] {tool} - {execution} - {apk}")
            
            if (tool not in tools) or (execution not in executions):
                continue

            methods = mapping.get((tool, apk), set())

            with open(relative_path) as fh:
                lines = fh.readlines()

                for line in lines:
                    category = line[0:line.find(',')]

                    if category in non_relevant_categories:
                        continue
                    
                    method = line[line.find('<'):]
                    methods.add(method)

            mapping[(tool,apk)] = methods

output_dir = '../output'

os.makedirs(output_dir, exist_ok = True)

for ((tool, apk), methods) in mapping.items():
    with open(f"{output_dir}/{tool}-{apk}.csv", 'w') as fh:
        fh.writelines(methods)

print(f"[Info] done. Results of the union executions are in {output_dir}")

