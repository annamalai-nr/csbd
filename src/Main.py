import os, argparse, psutil, logging
from GetCorpus import GetDataSet
from RandomClassification import RandomClassification
from HoldoutClassification import HoldoutClassification

#logging level
logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger('main.stdout')

def main(Args, FeatureOption):
    '''
    Main function for malware and goodware classification
    :param args: arguments acquired from command lines(refer to ParseArgs() for list of args)
    :param FeatureOption: False
    '''
    MalDir = Args.maldir
    GoodDir = Args.gooddir
    ProcessNo = Args.processno
    TimeOut = Args.timeout
    GetDataSet(MalDir, ProcessNo, TimeOut)
    GetDataSet(GoodDir, ProcessNo, TimeOut)
    NumFeaturesToBeSelected = Args.numfeatures

    if Args.randomsplit == 1:
        # Random Classification to be performed
        TestSize = Args.testsize
        Logger.debug("MalDir: {}, GoodDir: {}, ProcessNo: {}, TestSize: {}, " \
          "NumFeaturesToBeSelected: {}, FeatureOption: {}, TimeOut: {}".format(MalDir, GoodDir,
                                                                  ProcessNo,
                                                                  TestSize,
                                                                  NumFeaturesToBeSelected,
                                                                  FeatureOption,
                                                                  TimeOut))
        RandomClassification(MalDir, GoodDir, TestSize, NumFeaturesToBeSelected, FeatureOption)
    else:
        # Holdout Classification to be performed
        TestMalDir = Args.testmaldir
        TestGoodDir = Args.testgooddir
        GetDataSet(TestMalDir, ProcessNo, TimeOut)
        GetDataSet(TestGoodDir, ProcessNo, TimeOut)
        Logger.debug("TrainMalDir: {}, TrainGoodDir: {}, TestMalDir: {}, TestGoodDir:{} ProcessNo: {}," \
                     "NumFeaturesToBeSelected: {}, FeatureOption: {}, TimeOut: {}".format(MalDir, GoodDir,
                                                                                          TestMalDir, TestGoodDir,
                                                                                          ProcessNo,
                                                                                          NumFeaturesToBeSelected,
                                                                                          FeatureOption,
                                                                                          TimeOut))
        HoldoutClassification(MalDir, GoodDir, TestMalDir, TestGoodDir, NumFeaturesToBeSelected, FeatureOption)

def ParseArgs():
    Args = argparse.ArgumentParser("UserInput")
    Args.add_argument("--randomsplit", default= 1, type=int,
                      help="Type of classification to be performed(1 for Random split classification and 0 for Holdout classification")
    Args.add_argument("--maldir", default="../data/small_proto_apks/malware",
                      help="Absolute path to directory containing malware apks")
    Args.add_argument("--gooddir", default="../data/small_proto_apks/goodware",
                      help="Absolute path to directory containing benign/goodware apks")
    Args.add_argument("--testmaldir", default="../data/apks/malware",
                      help="Absolute path to directory containing malware apks for testing(for Holdout Classification)")
    Args.add_argument("--testgooddir", default="../data/apks/goodware",
                      help="Absolute path to directory containing benign/goodware apks for testing(for Holdout Classification)")
    Args.add_argument("--testsize", default=0.3, type=float,
                      help="Size of test set split from whole dataset(must be in the range (0.0, 1.0)")
    Args.add_argument("--numfeatures", default=5000, type=int,
                      help="Number of top features to select")
    Args.add_argument("--processno", default=psutil.cpu_count(), type=int,
                      help="Number of processes scheduled")
    Args.add_argument("--timeout", default=120, type=int,
                      help="Max number of seconds that can be used for extracting CFG signature features from an apk")

    return Args.parse_args()
if __name__ == "__main__":
    main(ParseArgs(), False)
