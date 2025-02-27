"""Compute the union of sensitive method calls during DroidXP executions. 

   Description: Given three executions for DroidBot, for instance,
   this script computes the union of the calls to sensitive methods 
   for a given app. 
"""
import os

tools = ['droidbot']
base_executions = [1]
extended_executions = [2]

non_relevant_categories = [] 

print(f"[Info] Computing the false positive rate")
print(f"[Info] Tools: {tools}")
print(f"[Info] Searching for files named sensitiveMtd.csv")

base_mapping = {} # a dictionary mapping (tool, apk) into a set of methods. 
extended_mapping = {}

sensitive_methods = []

with open('sensitive_methods2.txt', 'r') as fh:
    lines = fh.readlines()

    for line in lines:
        sensitive_methods.append(line.replace('\n', ''))

for root, dirs, files in os.walk('..'):
    for f in files:
        if f.endswith('sensitiveMtd.csv'):
            relative_path = os.path.join(root, f)

            elements = relative_path.split('/')

            execution = int(elements[2])
            tool = elements[3]
            apk = elements[4]

            print(f"[Info] {tool} - {execution} - {apk}")
            
            if (tool in tools):
                methods = set()

                with open(relative_path) as fh:
                    lines = fh.readlines()
                    
                    for line in lines:
                        category = line[0:line.find(',')]

                        method = line[line.find('<'):]
                        method = method.replace('\n', '')

                        #methods.add(method)
                        if method in sensitive_methods:
                            methods.add(method)
                                            
                if (apk.startswith('benign')) and (execution in base_executions):
                    methodsInUnion = base_mapping.get((tool, apk), set())
                    base_mapping[(tool, apk)] = methods.union(methodsInUnion)
                elif (apk.startswith('benign')) and (execution in extended_executions):
                    extended_mapping[(tool, apk, execution)] = methods
                else:
                    continue

output_dir = '../output'

os.makedirs(output_dir, exist_ok = True)

total = 0
with open(f"{output_dir}/fp.csv", 'w') as fh:
    fh.write("Tool, APK, Execution, Diff\n")
    for ((tool, apk), s1) in base_mapping.items():
        for execution in extended_executions:
            s2 = extended_mapping.get((tool, apk, execution), set())
            diff = len(s2.difference(s1))
            if diff > 0:
                print(f"{tool} - {apk}")
                total = total + 1
            fh.write(f"{tool},{apk},{execution},{diff}\n")
                    
                    
        
print(total)
print(f"[Info] done. Results of the union executions are in {output_dir}/fp.csv")

