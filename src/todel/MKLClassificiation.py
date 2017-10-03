import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn import svm
from sklearn.cross_validation import cross_val_score
from sklearn.cross_validation import train_test_split
from sklearn import metrics
from sklearn import grid_search
from sklearn.preprocessing import Normalizer
import os
import sys
from random import randint
import logging
import pylab as plt
from matplotlib import cm
from pprint import pprint
import re
import Hedge

#logging level
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('sys.stdout')

def LineTokenizer (Str):
    return Str.split('\n')

def SpaceTokenizer (Str):
    return Str.split()

def GetFileList(Directory):
    '''
    Get the list of file names (absolute path) in a directory

    :param String Directory: absolute path of a directory
    :return FileList: list of file names
    :rtype: List
    '''
    FileList = [os.path.join(Directory, File) \
                for File in os.listdir(Directory) if os.path.isfile(os.path.join(Directory, File))]

    return FileList

def GetFileListMLDic(RootDir, BaseNameList, WLDirName, ApiDirName, PermDirName, SrcSinkDirName, DirPosfixDic):
    FileDic = {}
    FileDic[WLDirName] = [os.path.join(RootDir, WLDirName, BaseName+DirPosfixDic[WLDirName]) for BaseName in BaseNameList]
    FileDic[ApiDirName] = [os.path.join(RootDir, ApiDirName, BaseName+DirPosfixDic[ApiDirName]) for BaseName in BaseNameList]
    FileDic[PermDirName] = [os.path.join(RootDir, PermDirName, BaseName+DirPosfixDic[PermDirName]) for BaseName in BaseNameList]
    FileDic[SrcSinkDirName] = [os.path.join(RootDir, SrcSinkDirName, BaseName+DirPosfixDic[SrcSinkDirName]) for BaseName in BaseNameList]
    return FileDic

def GetBaseNameList(Directory):
    BaseNameList = [re.sub(r".apk.*", "", File) for File in os.listdir(Directory) if os.path.isfile(os.path.join(Directory, File))]
    return BaseNameList 

def GetSampleNLabel(MalwareCorpus, GoodwareCorpus, WLDirName, ApiDirName, PermDirName, SrcSinkDirName, DirPosfixDic, Split, Randomize):
    '''
    Train a classifier for classifying malwares and goodwares using Support Vector Machine technique
    Compute the prediction accuracy and f1 score of the classifier

    :param String MalwareCorpus: absolute path of the malware corpus
    :param String GoodwareCorpus: absolute path of the goodware corpus
    :param String FeatureOption: tfidf or binary, specify how to construct the feature vector 
    :param Split - test set split (defult is 0.3 for testing and 0.7 for training) 
    :param Randomize - may or may not be True
    '''
    
    logger.debug ("Loading positive and negative sample file basename") 
    AllMalSamplesBase = GetBaseNameList(os.path.join(MalwareCorpus, WLDirName))
    AllGoodSamplesBase = GetBaseNameList(os.path.join(GoodwareCorpus, WLDirName))
    logger.info ("All Samples loaded") 
    logger.debug ("Test set split = %s", Split)

    if Randomize:
        TrainMalSamplesBase, TestMalSamplesBase = train_test_split(AllMalSamplesBase, 
            test_size=Split, 
            random_state=randint(0,99))
        TrainGoodSamplesBase, TestGoodSamplesBase = train_test_split(AllGoodSamplesBase, 
            test_size=Split, 
            random_state=randint(0,99))
        logger.info ("Training and test sets split randomly") 

    else:
        TrainMalSamplesBase, TestMalSamplesBase = train_test_split(AllMalSamplesBase, 
            test_size=Split)
        TrainGoodSamplesBase, TestGoodSamplesBase = train_test_split(AllGoodSamplesBase, 
            test_size=Split)
        logger.info ("Training and test sets split w/o randomization") 

    # label malware as 1 and goodware as -1
    TrainMalLabels = np.ones(len(TrainMalSamplesBase))
    TestMalLabels = np.ones(len(TestMalSamplesBase))
    TrainGoodLabels = np.empty(len(TrainGoodSamplesBase))
    TrainGoodLabels.fill(-1)
    TestGoodLabels = np.empty(len(TestGoodSamplesBase))
    TestGoodLabels.fill(-1)
    logger.debug ("Training and test sets labels generated (+1 and -1)") 
    
    TrainLabels = TrainMalLabels.tolist()
    TrainLabels.extend(TrainGoodLabels.tolist())
    TestLabels = TestMalLabels.tolist()
    TestLabels.extend(TestGoodLabels.tolist())
    
    TrainMalSamplesMLDic = GetFileListMLDic(MalwareCorpus, TrainMalSamplesBase, WLDirName, ApiDirName, PermDirName, SrcSinkDirName, DirPosfixDic)
    TestMalSamplesMLDic = GetFileListMLDic(MalwareCorpus, TestMalSamplesBase, WLDirName, ApiDirName, PermDirName, SrcSinkDirName, DirPosfixDic)
    TrainGoodSamplesMLDic = GetFileListMLDic(GoodwareCorpus, TrainGoodSamplesBase, WLDirName, ApiDirName, PermDirName, SrcSinkDirName, DirPosfixDic)
    TestGoodSamplesMLDic = GetFileListMLDic(GoodwareCorpus, TestGoodSamplesBase, WLDirName, ApiDirName, PermDirName, SrcSinkDirName, DirPosfixDic)
    
    TrainSamplesDic = {}
    TrainSamplesDic[WLDirName] = TrainMalSamplesMLDic[WLDirName] + TrainGoodSamplesMLDic[WLDirName]
    TrainSamplesDic[ApiDirName] = TrainMalSamplesMLDic[ApiDirName] + TrainGoodSamplesMLDic[ApiDirName]
    TrainSamplesDic[PermDirName] = TrainMalSamplesMLDic[PermDirName] + TrainGoodSamplesMLDic[PermDirName]
    TrainSamplesDic[SrcSinkDirName] = TrainMalSamplesMLDic[SrcSinkDirName] + TrainGoodSamplesMLDic[SrcSinkDirName]
    
    TestSamplesDic = {}
    TestSamplesDic[WLDirName] = TestMalSamplesMLDic[WLDirName] + TestGoodSamplesMLDic[WLDirName]
    TestSamplesDic[ApiDirName] = TestMalSamplesMLDic[ApiDirName] + TestGoodSamplesMLDic[ApiDirName]
    TestSamplesDic[PermDirName] = TestMalSamplesMLDic[PermDirName] + TestGoodSamplesMLDic[PermDirName]
    TestSamplesDic[SrcSinkDirName] = TestMalSamplesMLDic[SrcSinkDirName] + TestGoodSamplesMLDic[SrcSinkDirName]
    
    return TrainSamplesDic, TestSamplesDic, TrainLabels, TestLabels


def Classification(FeatureOption, FeatuesToSelect, TrainSamples, TestSamples, TrainLabels, MyTokenizer,  TestLabels):
    logger.debug ("Gonna perform %s feature vector generation", FeatureOption)
    if(FeatureOption == 'tfidf'):
        CVectorizer = CountVectorizer(input=u'filename', lowercase=False, token_pattern=None, tokenizer=MyTokenizer)
        TFIDFTransformer = TfidfTransformer()
        TrainDocsTermsFVs = CVectorizer.fit_transform(TrainSamples) 
        TestDocsTermsFVs = CVectorizer.transform(TestSamples)
        TrainFVs = TFIDFTransformer.fit_transform(TrainDocsTermsFVs)
        TestFVs = TFIDFTransformer.transform(TestDocsTermsFVs)
                
    elif(FeatureOption == 'tf'):
        CVectorizer = CountVectorizer(input=u'filename', lowercase=False, token_pattern=None, tokenizer=MyTokenizer)
        normalizer = Normalizer()
        TrainDocsTermsFVs = CVectorizer.fit_transform(TrainSamples) 
        TestDocsTermsFVs = CVectorizer.transform(TestSamples)
        TrainFVs = TrainDocsTermsFVs
        TestFVs = TestDocsTermsFVs
        
    elif(FeatureOption == 'binary'):
        CVectorizer = CountVectorizer(input=u'filename', lowercase=False, token_pattern=None, tokenizer=MyTokenizer, binary=True, dtype=np.float64)
        normalizer = Normalizer()
        TrainDocsTermsFVs = CVectorizer.fit_transform(TrainSamples) 
        TestDocsTermsFVs = CVectorizer.transform(TestSamples)
        TrainFVs = normalizer.fit_transform(TrainDocsTermsFVs)
        TestFVs = normalizer.transform(TestDocsTermsFVs)

    print "*"*100
    Features = CVectorizer.get_feature_names()
#     pprint (Features)
    print "Total # features ", len(Features)
    print "*"*100
    logger.info ("%s feature vectors generated", FeatureOption)
    
    logger.info ("Gonna perform classification with C-SVM")
    # step 3: model selection through cross validation
    # assuming SVM is the only classifier we are gonna try, we will set the c parameter as follows.
    Clf = grid_search.GridSearchCV(svm.LinearSVC(), {'C':[ 0.01, 0.1, 1, 10, 100, 1000]}, cv=5, scoring = 'f1', n_jobs=10)
    BestModel = Clf.fit (TrainFVs, TrainLabels)
    # best model is chosen thro 5-fold cross validation and stored in the variable: BestModel

    # step 4: Evaluate the best model on test set
    PredictedLabels = BestModel.predict(TestFVs)
    Accuracy = np.mean(PredictedLabels == TestLabels)
    print "Test Set Accuracy = ", Accuracy
    print(metrics.classification_report(TestLabels, 
                PredictedLabels, target_names=['Goodware', 'Malware']))
    
    return BestModel, TestFVs
    
    

def MKLClassification(MalwareCorpus, GoodwareCorpus, WLDirName, ApiDirName, PermDirName, SrcSinkDirName, DirPosfixDic, Split, Randomize, FeatuesToSelect, Beta, Iter, Eps):
    TrainSamplesDic, TestSamplesDic, TrainLabels, TestLabels = GetSampleNLabel(MalwareCorpus, GoodwareCorpus, WLDirName, ApiDirName, PermDirName, SrcSinkDirName, DirPosfixDic, Split, Randomize)
    WLBestModel, WLTestFVs = Classification("tfidf", FeatuesToSelect, TrainSamplesDic[WLDirName], TestSamplesDic[WLDirName], TrainLabels, SpaceTokenizer, TestLabels)
    ApiBestModel, ApiTestFVs = Classification("binary", FeatuesToSelect, TrainSamplesDic[ApiDirName], TestSamplesDic[ApiDirName], TrainLabels, LineTokenizer, TestLabels)
    PermBestModel, PermTestFVs = Classification("binary", FeatuesToSelect, TrainSamplesDic[PermDirName], TestSamplesDic[PermDirName], TrainLabels, LineTokenizer, TestLabels)
    SrcSinkBestModel, SrcSinkTestFVs = Classification("binary", FeatuesToSelect, TrainSamplesDic[SrcSinkDirName], TestSamplesDic[SrcSinkDirName], TrainLabels, LineTokenizer, TestLabels)

    Kernels = [WLBestModel, ApiBestModel, PermBestModel, SrcSinkBestModel]
    TestFVs = [WLTestFVs, ApiTestFVs, PermTestFVs, SrcSinkTestFVs]
#     Kernels = [ApiBestModel, PermBestModel, SrcSinkBestModel]
#     TestFVs = [ApiTestFVs, PermTestFVs, SrcSinkTestFVs]
    KernelWts = Hedge.CombineKernels(Kernels, Beta, Iter, Eps, TestFVs, TestLabels)
    
    WLPredict = WLBestModel.predict(WLTestFVs)
    ApiPredict = ApiBestModel.predict(ApiTestFVs)
    PermPredict = PermBestModel.predict(PermTestFVs)
    SrcSinkPredict = SrcSinkBestModel.predict(SrcSinkTestFVs)
    
#     CombinedPredicts = ApiPredict * KernelWts[0] + PermPredict * KernelWts[1] + SrcSinkPredict * KernelWts[2]
    CombinedPredicts = WLPredict * KernelWts[0] + ApiPredict * KernelWts[1] + PermPredict * KernelWts[2] + SrcSinkPredict * KernelWts[3]
    for i in range(len(CombinedPredicts)):
        if(CombinedPredicts[i] >= 0):
            CombinedPredicts[i] = 1
        else:
            CombinedPredicts[i] = -1
    Accuracy = np.mean(CombinedPredicts == TestLabels)
    print "Test Set Accuracy = ", Accuracy
    print(metrics.classification_report(TestLabels, 
                CombinedPredicts, target_names=['Goodware', 'Malware']))
    

def main(MalwareDirName, GoodwareDirName, ProcessNo, Split, Randomize, NumFeaturesToBeSelected, Beta, Iter, Eps):
    '''
    Main function for malware detection classification

    :param String MalwareDirName: name of the malware directory in ApkDatasetDir
    :param String GoodwareDirName: name of the goodware directory in ApkDatasetDir
    :param int/String ProcessNo: number of processes scheduled for CFG string creation
    :param String FeatureOption: tfidf or tf or binary, specify how to construct the feature vector
    :param Test set split - num in range [0,1] (default is 0.3 for testing and 0.7 for training)
    :param Randomize - True or False
    '''
    
    #currently unused - ProcessNo
    del ProcessNo

    Split = float (Split)
    if str(Randomize).lower() == 'true':
        Randomize = True
    else:
        Randomize = False
    
    # hardcode
    WLDirName = "WLKernelIPFiles"
    ApiDirName = "APIsWODesc"
    PermDirName = "Perms"
    SrcSinkDirName = "ComSrcSink"
    DirPosfixDic = {}
    DirPosfixDic[WLDirName] = ".apk.ReducediCFGWLKernel"
    DirPosfixDic[ApiDirName] = ".apk.ReducediCFGWLKernel.ReducediCFG.APIs.DescStripped"
    DirPosfixDic[PermDirName] = ".apk.ReducediCFGWLKernel.ReducediCFG.Perms"
    DirPosfixDic[SrcSinkDirName] = ".apk.ReducediCFGWLK.ComSrcSink"

    MKLClassification(MalwareDirName, GoodwareDirName, WLDirName, ApiDirName, PermDirName, SrcSinkDirName, DirPosfixDic, Split, Randomize, int(NumFeaturesToBeSelected), Beta, Iter, Eps)

# main("/home/crazyconv/Desktop/Ureca/Malware_Detection/Dataset/Drebin01RedICFG253", "/home/crazyconv/Desktop/Ureca/Malware_Detection/Dataset/MUDFLOWRedICFG274", 1, 0.3, True, 0, 0.9, 20, 0.01)
# main("/home/crazyconv/Conv/mkl/Dataset/Drebin01RedICFG253", "/home/crazyconv/Conv/mkl/Dataset/MUDFLOWRedICFG274", 1, 0.3, True, 0, 0.9, 20, 0.01)
if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8], sys.argv[9])