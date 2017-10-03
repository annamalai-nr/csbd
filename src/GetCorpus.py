import sys
sys.path.append("Androguard")
import androlyze
import zipfile
import string
import re
import os
import glob
from time import time
from pebble import ProcessPool


def GetCFGString(ApkFName, OutputFName):
    '''
	Get the CFG string of an apk and write to a txt file

	:param String ApkFName: absolute path of the apk file
	:param String OutputFName: absolute path of the txt file
	'''
    if os.path.isfile(OutputFName):
        print 'Output file: {} exists, so skipping {}'.format(OutputFName, ApkFName)
        return

    T0 = time()
    try:
        a, d, dx = androlyze.AnalyzeAPK(ApkFName)
    except zipfile.BadZipfile:
        # if file is not an APK, may be a dex object
        try:
            d, dx = androlyze.AnalyzeDex(ApkFName)
        except Exception as e:
            # if file cannot be processed as an apk nor a dex object
            # it may be malformed file, then just return
            return
    except Exception as e:
        return

    OutputFH = open(OutputFName, 'w+')
    try:
        for method in d.get_methods():
            SignatureText = dx.get_method_signature(method, predef_sign=androlyze.analysis.SIGNATURE_L0_0).get_string()
            SignatureText = string.replace(SignatureText, 'B[]', 'B[NULL]')
            ProcessedText = re.sub(r"B\[(.*?)\]", "\g<1> ", SignatureText)
            if ProcessedText:
                print >> OutputFH, ProcessedText

    finally:
        OutputFH.close()
    print 'Done generating CFG signature strings for file: {} in {} sec.'.format(os.path.basename(ApkFName),
                                                                                 round(time() - T0, 2))


def GetDataSet(ApkDir, ProcessNo, TimeOut):
    '''
	Construct a collection of corpuses, containing CFG strings of goodware and malware apks, in txt files

	:param String ApkDir: absolute path of the root directory of goodware and malware apks
	:param int/String ProcessNo: number of processes scheduled
	:param int/String TimeOut: Max number of seconds that can be used for extracting CFG signature features from an apk
	'''

    ProcessNo = int(ProcessNo)
    ApkFilesToProcess = glob.glob(os.path.join(ApkDir, '*.apk'))
    OpFNames = [ApkFile.replace('.apk', '.txt') for ApkFile in ApkFilesToProcess]

    print 'Gonna process {} files with {} cpus'.format(len(ApkFilesToProcess), ProcessNo)

    print "=========== Extracting CFG string ============="
    with ProcessPool(max_workers=ProcessNo) as pool:
        jobs = [pool.schedule(GetCFGString, args=[ApkFile, OpFName], timeout=TimeOut) for ApkFile, OpFName in zip(ApkFilesToProcess, OpFNames)]

    for j in jobs:
        try:
            j.get()
        except:
            pass
    print "=========== CFG string Done ============="


if __name__ == "__main__":
    GetDataSet(sys.argv[1], sys.argv[2])
