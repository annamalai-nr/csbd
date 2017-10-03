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
Logger = logging.getLogger('RandomClf.stdout')
Logger.setLevel("INFO")

def MyTokenizer(Str):
    return Str.split()

def RandomClassification(MalwareCorpus, GoodwareCorpus, TestSize, NumFeaturesToBeSelected, FeatureOption):
    '''
    Train a classifier for classifying malwares and goodwares using Random Forest technique
    Compute the prediction accuracy and f1 score of the classifier

    :param String MalwareCorpus: absolute path of the malware corpus
    :param String GoodwareCorpus: absolute path of the goodware corpus
    :param Float TestSize: test set split (default is 0.3 for testing and 0.7 for training)
    :param integer NumFeaturesToBeSelected: number of top features to select
    :param Boolean FeatureOption: False
    '''

    # Step 1: Getting the malware and goodware txt files
    Logger.debug ("Loading positive and negative samples")
    AllMalSamples = glob.glob(os.path.join(MalwareCorpus,'*txt'))
    AllGoodSamples = glob.glob(os.path.join(GoodwareCorpus,'*txt'))
    Logger.info ("All Samples loaded")

    # Step 2: Creating feature vector
    FeatureVectorizer = TF(input='filename', lowercase=False, token_pattern=None,
                           tokenizer=MyTokenizer, binary=FeatureOption, dtype=np.float64)
    X = FeatureVectorizer.fit_transform(AllMalSamples + AllGoodSamples)

    # Label malware as 1 and goodware as -1
    MalLabels = np.ones(len(AllMalSamples))
    GoodLabels = np.empty(len(AllGoodSamples))
    GoodLabels.fill(-1)
    Y = np.concatenate((MalLabels, GoodLabels), axis=0)
    Logger.info("Label array - generated")

    # Step 3: Split all samples into training and test set
    XTrain, XTest, YTrain, YTest = train_test_split(X, Y,
                                                        test_size=TestSize, random_state=randint(0,100))
    Logger.debug ("Test set split = %s", TestSize)

    Features = FeatureVectorizer.get_feature_names()
    Logger.info ("Total number of features: {} ".format(len(Features)))

    if len(Features) > NumFeaturesToBeSelected:
        #with feature selection
        Logger.info ("Gonna select %s features", NumFeaturesToBeSelected)
        FSAlgo = SelectKBest(chi2, k = NumFeaturesToBeSelected)

        XTrain = FSAlgo.fit_transform(XTrain, YTrain)
        XTest = FSAlgo.transform(XTest)
        

    Logger.info ("Gonna perform classification with C-RandomForest")


    # Step 4: model selection through cross validation
    # Assuming RandomForest is the only classifier we are gonna try, we will set the n_estimators parameter as follows.
    Parameters = {'n_estimators': [10,50,100,200,500,1000],
                  'bootstrap': [True, False],
                  'criterion': ['gini', 'entropy']}
    Clf = GridSearchCV(RandomForestClassifier(), Parameters,  cv=5, scoring = 'f1', n_jobs=-1)
    RFmodels = Clf.fit(XTrain, YTrain)
    BestModel = RFmodels.best_estimator_
    Logger.info('CV done - Best model selected: {}'.format(BestModel))
    # Best model is chosen through 5-fold cross validation and stored in the variable: RFmodels

    # Step 5: Evaluate the best model on test set
    YPred = RFmodels.predict(XTest)
    Accuracy = accuracy_score(YTest, YPred)
    print "Test Set Accuracy = ", Accuracy
    print(metrics.classification_report(YTest, YPred,  labels=[1, -1], target_names=['Malware', 'Goodware']))


