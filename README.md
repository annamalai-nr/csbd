How do I get set up?

    Install Anaconda

    Anaconda is a completely free Python distribution (including for commercial use and redistribution). It includes over 195 of the most 
    popular Python packages for science, math, engineering, data analysis. Download from http://continuum.io/downloads.

    Download this repository

    (Optional) Install Visual Studio 2015 with Python Tools

    You may see there are solution files inside the repository. You may want to use Visual Studio 2015 to open it and do some modifications.

    Done. Follow the **How do I use it?** section below to do your experiments.

Who do I talk to?

    You may also contact Annamalai at ANNAMALA002@e.ntu.edu.sg

How do I use it?

    For CSBD, please make the repository folder as the current working directory.

    Run 'python Main.py --help' for the input arguments
 
    The default value of the arguments of CSBD are:

    --holdout      0 (split the dataset into training and test set and use the same for training and evaluating the model, respectively)
    --maldir       '../data/small_proto_apks/malware'
    --gooddir      '../data/small_proto_apks/goodware'
    --testmaldir   '../data/apks/malware'
    --testgooddir  '../data/apks/goodware'
    --testsize     0.3 (30% of the samples will be used for testing and the remaining 70% will be used to train the model)
    --numfeatures  5000
    --processno    maximum number of CPU cores to be used for multiprocessing (only during the feature extraction phase)
    --timeout      120(s)  
    
    
    Functionalities:

    User need to specify which mode* of classification to be done from --holdout option;
   
    Random split classification:

    **--holdout 0(default)** allows you to do a random split classification for the given malware dataset and benign/goodware dataset. 
    The --maldir and --gooddir arguments should be the directories containing malware Apks and benign-ware Apks. The txt files will be 
    generated automatically before the program does the random split classification.

    Hold-out classification:

    **--holdout 1** allows you to specify the testing set. You can do a hold-out classification for the given training set and test set. 
    Beside settling the training set arguments as --holdout 0, You need to specify the testing set arguments in the command line i.e --testmaldir
    and --testgooddir. The txt files will be generated automatically before the program does the hold-out classification.
    
