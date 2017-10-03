import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer as TF
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import accuracy_score
from sklearn.cross_validation import cross_val_score
from sklearn.cross_validation import train_test_split
from sklearn.feature_selection import SelectKBest, chi2
from sklearn import metrics
import os, sys, glob
from random import randint
import logging
from time import time

#logging level
logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger('HoldoutClf.stdout')
Logger.setLevel("INFO")

def MyTokenizer(Str):
    return Str.split()

def HoldoutClassification(TrainMalwareCorpus, TrainGoodwareCorpus, TestMalwareCorpus, TestGoodwareCorpus, NumFeaturesToBeSelected, FeatureOption):
    '''
    Train a classifier for classifying malwares and goodwares using Random Forest technique
    Compute the prediction accuracy and f1 score of the classifier

    :param String TrainMalwareCorpus: absolute path of the malware corpus for training
    :param String TrainGoodwareCorpus: absolute path of the goodware corpus for training
    :param String TestMalwareCorpus: absolute path of the malware corpus for testing
    :param String TestGoodwareCorpus: absolute path of the goodware corpus for testing
    :param integer NumFeaturesToBeSelected: number of top features to select
    :param Boolean FeatureOption: False
    '''

    # Step 1: Getting the malware and goodware txt files for both training and testing
    Logger.debug ("Loading positive and negative samples")
    TrainMalSamples = glob.glob(os.path.join(TrainMalwareCorpus,'*txt'))
    TrainGoodSamples = glob.glob(os.path.join(TrainGoodwareCorpus,'*txt'))
    TestMalSamples = glob.glob(os.path.join(TestMalwareCorpus,'*txt'))
    TestGoodSamples = glob.glob(os.path.join(TestGoodwareCorpus,'*txt'))
    Logger.info ("All Samples loaded")

    # Step 2: Creating feature vectors
    FeatureVectorizer = TF(input='filename', lowercase=False, token_pattern=None,
                           tokenizer=MyTokenizer, binary=FeatureOption, dtype=np.float64)
    XTrain = FeatureVectorizer.fit_transform(TrainMalSamples + TrainGoodSamples)
    XTest = FeatureVectorizer.transform(TestMalSamples + TestGoodSamples)

    # Label training sets malware as 1 and goodware as -1
    TrainMalLabels = np.ones(len(TrainMalSamples))
    TrainGoodLabels = np.empty(len(TrainGoodSamples))
    TrainGoodLabels.fill(-1)
    YTrain = np.concatenate((TrainMalLabels, TrainGoodLabels), axis=0)
    Logger.info("Training Label array - generated")

    # Label testing sets malware as 1 and goodware as -1
    TestMalLabels = np.ones(len(TestMalSamples))
    TestGoodLabels = np.empty(len(TestGoodSamples))
    TestGoodLabels.fill(-1)
    YTest = np.concatenate((TestMalLabels, TestGoodLabels), axis=0)
    Logger.info("Testing Label array - generated")

    # Step 3: Doing feature selection
    Features = FeatureVectorizer.get_feature_names()
    Logger.info("Total number of features: {} ".format(len(Features)))

    if len(Features) > NumFeaturesToBeSelected:
        # with feature selection
        Logger.info("Gonna select %s features", NumFeaturesToBeSelected)
        FSAlgo = SelectKBest(chi2, k=NumFeaturesToBeSelected)

        XTrain = FSAlgo.fit_transform(XTrain, YTrain)
        XTest = FSAlgo.transform(XTest)

    # Step 4: Model selection through cross validation
    # Assuming RandomForest is the only classifier we are gonna try, we will set the n_estimators parameter as follows.
    Parameters = {'n_estimators': [10, 50, 100, 200, 500, 1000],
                  'bootstrap': [True, False],
                  'criterion': ['gini', 'entropy']}
    Clf = GridSearchCV(RandomForestClassifier(), Parameters, cv=5, scoring='f1', n_jobs=-1)
    RFmodels = Clf.fit(XTrain, YTrain)
    BestModel = RFmodels.best_estimator_
    Logger.info('CV done - Best model selected: {}'.format(BestModel))
    # Best model is chosen through 5-fold cross validation and stored in the variable: RFmodels

    Logger.info("Gonna perform classification with C-RandomForest")

    # Step 5: Evaluate the best model on test set
    YPred = RFmodels.predict(XTest)
    Accuracy = accuracy_score(YTest, YPred)
    print "Test Set Accuracy = ", Accuracy
    print(metrics.classification_report(YTest, YPred, labels=[1, -1], target_names=['Malware', 'Goodware']))