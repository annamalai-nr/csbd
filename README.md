What does this repository contain?
    
    This repository contains a python based reimplementation of the Android Malware Detection paper "Allix, Kevin, et al. "Empirical assessment of machine learning-based malware detectors for Android." Empirical Software Engineering 21.1 (2016): 183-211.". The paper used Control Flow Graph (CFG) signatures of methods in Android apps to detect malice apps. Hence this approach is called CFG signature based detection (CSBD), for short.

What package/platform dependencies do I have to run the code?

    The code is developed and tested using python 2.7 on Ubuntu 16.04 PC.
    The following packages need to be installed to run the code:
    1. sklearn (==0.18.1)
    2. pebble
    3. glob
    4. joblib (==0.11)

How do I use it?

    Just clone the repo and follow the following instructions:

    1. Move to the "src" folder.

    2. Run 'python Main.py --help' for the input arguments
    CSBD can be run in 2 modes: (1) Random split classification, (2) Holdout classifiction. In random split mode, the apps in the given dataset are split into training and test sets and are used to train and evaluate the malware detection model, respectively. In the holdout classification mode, separate training and test sets could be provided by the user. 

    The default value of the arguments of CSBD are:

    --randomsplit      1 (split the dataset into training and test set and use the same for training and evaluating the model, respectively)
    --maldir       '../data/small_proto_apks/malware' (malware samples used to train the model)
    --gooddir      '../data/small_proto_apks/goodware' (goodware samples used to train the model)
    --testmaldir   '../data/apks/malware' (malware samples used to test the model. ONLY APPLICABLE IF --randomsplit IS 0.)
    --testgooddir  '../data/apks/goodware' (goodware samples used to test the model. ONLY APPLICABLE IF --randomsplit IS 0.)
    --testsize     0.3 (30% of the samples will be used for testing and the remaining 70% will be used to train the model. ONLY APPLICABLE IF --randomsplit IS 1.)
    --numfeatures  5000 (number of features to be selected)
    --processno    maximum number of CPU cores to be used for multiprocessing (only during the feature extraction phase)
    --timeout      120 (max number of seconds to be spent on extracting CFG signature features from apk files) 
    
    3. Run 'python Main.py --randomsplit 1 --maldir <folder containing malware apks> --gooddir <folder containing goodware apks>' to build and test a CSBD malware detection model. By defatult, 70% and 30% of the samples will be used for training and testing the model, respectively. 

    4. Run 'python Main.py --randomsplit 0 --maldir <folder containing training set malware apks> --gooddir <folder containing training set goodware apks> --testmaldir <folder containing test set malware apks> --testgooddir <folder containing test set goodware apks>'.

    Functionalities:

    User need to specify which mode* of classification to be done from --holdout option;
   
    Random split classification:

    **--randomsplit 1(default)** allows you to do a random split classification for the given malware dataset and benign/goodware dataset. 
    The --maldir and --gooddir arguments should be the directories containing malware Apks and benign-ware Apks. The txt files will be 
    generated automatically before the program does the random split classification.

    Hold-out classification:

    **--randomsplit 0** allows you to specify the testing set. You can do a hold-out classification for the given training set and test set. 
    Beside settling the training set arguments as --holdout 0, You need to specify the testing set arguments in the command line i.e --testmaldir
    and --testgooddir. The txt files will be generated automatically before the program does the hold-out classification.
    
Who do I talk to?

    In case of issues/difficulties in running the code, please contact me at ANNAMALA002@e.ntu.edu.sg
    
    You may also contact Arief Kresnadi Ignatius Kasim at arie0010@e.ntu.edu.sg or Loo Jia Yi at e140112@e.ntu.edu.sg  

When you use this code, please consider citing our paper (as a part of these papers, we provide CSBD open src implementation):

    1. Narayanan, Annamalai, et al. "Context-Aware, Adaptive, and Scalable Android Malware Detection Through Online Learning." IEEE Transactions on Emerging Topics in Computational Intelligence 1.3 (2017): 157-175.

    2. Narayanan, Annamalai, et al. "A Multi-view Context-aware Approach to Android Malware Detection and Malicious Code Localization." arXiv preprint arXiv:1704.01759 (2017).
