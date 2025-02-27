## Replication Package


This is the replication package for the paper: Mining Android Sandox for Malware Detection : Replication and Extension Study

### Abstract


The widespread use of smartphones in our daily lives has elevated concerns regarding their security among researchers and practitioners. Particularly, security issues are highly prevalent in Android, the most popular mobile operating system. Previous research has explored various techniques to address these concerns, including the Mining Android Sandbox approach (MAS approach), which aims to identify malicious behavior in repackaged Android applications (apps). However, earlier studies have been limited by small datasets, typically consisting of only 102 pairs of original and repackaged apps. This limitation raises questions about the external validity of their findings and whether the MAS approach can be generalized to larger datasets. To address these concerns, this paper shows a replication study focused on evaluating the accuracy of the MAS approach. Unlike previous studies, our research employs a dataset that is an order of magnitude larger, comprising 4,076 pairs of apps covering a more diverse range of Android malware families. Surprisingly, our findings indicate a significant drop in the accuracy of the MAS approach for identifying malware, with the F1-score decreasing from 0.89 in previous studies to 0.54 in our larger dataset. Upon closer examination, we discovered that the higher representation of certain malware families partially accounts for the increased number of instance where the MAS approach fails to correctly classify a repackaged app as malware. Our findings highlight the limitations of the MAS approach, particularly when scaled, and underscore the importance of complementing it with other techniques to effectively detect a broader range of malware. This opens avenues for further discussion on addressing the blind spots that affect the accuracy of the MAS approach.

### Malware Dataset

We use a curated dataset of 4,076 repackaged apps based on two repositories, RePack (https://github.com/serval-snt-uni-lu/RepackageRepo.git) and AndroMalPack (https://github.com/hasnainrafique/AndroMalPack-Dataset). Both were curated using automatic procedures that extract repackaged apps from the [Androzoo repository] (https://androzoo.uni.lu/gp-metadata), and arrange the samples on the following CSV [file](https://github.com/droidxp/paper-ecoop-results/blob/main/Samples.csv). In this file, the columns are: First - original app hash, Second - repackage app hash. The original dataset from previous research works has 102 repackaged apps, which we also separate and available in the following CSV [file](https://github.com/droidxp/paper-ecoop-results/blob/main/originalSamples.csv). To download both dataset we used this python [script](https://github.com/droidxp/paper-ecoop-results/blob/main/getApps.py)

We queried the VirusTotal repository (https://www.virustotal.com/gui/home/upload) to find out which repackaged apps in our dataset have been indeed labeled as malware, and if positive, find which malware family the sample came from. To collect this information, we use avclass2 tool (https://github.com/malicialab/avclass). The first step for that is to create a hash [list](https://github.com/droidxp/paper-ecoop-results/blob/main/listRepackagedHash.csv) of all repackage app hash which we would like to check at VirusTotal. With this list, we use a python [script](https://github.com/droidxp/paper-ecoop-results/blob/main/urltoFile.py) to download all Json files from VirusTotal, which we use at avclass2 tool to get information about repackage family. After this procedure, we get the following [dataset](https://github.com/droidxp/paper-ecoop-results/blob/main/avClassResultRepackaged.csv). In this dataset, if the sample was flagged by more than 1 AV engine, the column 'family' contains the family name, or 'None' if VirusTotal do not detected the malware family. If the sample was flagged by just 1 or 0 AV engine, the column contains 'None'.

We also characterize our dataset according to the similarity between the original and repackage app versions, using SimiDroid tool (https://github.com/lilicoding/SimiDroid). As a first step, we use SimiDroid tool to get Json files containing information about methods identical, similar, new, deleted, and similarity Score from our sample. As a final result, we have this CSV [file](https://github.com/droidxp/paper-ecoop-results/blob/main/summarySimiDroid.csv) with information about differences between app pairs (original/repackage), and similarity score from our samples.


