import sys
from pprint import pprint
import json
import logging
import collections

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('sys.stdout')


class PScoutMapping (object):
    
    ##################################################
    #                 Constructor                    #
    ##################################################
    def __init__(self):
        with open('PScoutPermApiDict.json', 'rb') as FH:
            #Filename of PScout dict is hard-coded
            #It could be changed if needed
            
            self.PermApiDictFromJson = json.load(FH) 


            
    ##################################################
    #                 Get Routines                   #
    ##################################################
    
    def GetAllPerms (self):
        return list (self.PermApiDictFromJson.keys())



    def GetAllApis (self):
        return list(self.PermApiDictFromJson.values())


    
    def GetApisFromPerm (self, Perm):
        PermAsKey = Perm
        if PermAsKey not in self.PermApiDictFromJson:
            logger.error ("Permission %s not found in the PScout Dict",
                           PermAsKey)
            return -1
        else:
            return self.PermApiDictFromJson[PermAsKey]


        
    def GetPermFromApi (self, ApiClass, ApiMethodName):
        for PermAsKey in self.PermApiDictFromJson.keys():
            Perm = PermAsKey
            logger.debug ("Checking if the permission associated is %s",
                          Perm)
            
            for Api in self.PermApiDictFromJson[Perm]:
                if Api[0].lower() == ApiClass.lower() and \
                Api[1].lower() == ApiMethodName.lower():
                    logger.info("for API %s %s PScout maps permission %s", 
                             ApiClass, ApiMethodName, Perm)
                    return Perm
        #logger.info ("Unable to find any permission\
        #associated to this API %s %s", ApiClass, ApiMethodName)
        return None 



    ##################################################
    #                 Print Routines                 #
    ##################################################
    
    def PrintDict(self):
        pprint (self.PermApiDictFromJson)


        
    def PrintAllPerms (self):        
        for PermAsKey in self.PermApiDictFromJson:
            print PermAsKey


            
    def PrintAllApis(self):
        for Api in self.PermApiDictFromJson.values():
            print Api


    
    def PrintApisForPerm(self, Perm):
        PermAsKey = Perm
        
        if PermAsKey not in self.PermApiDictFromJson:
            logger.error ("Permission %s not found in the PScout Dict", 
                          PermAsKey)
            return -1
            
        for Api in self.PermApiDictFromJson[Perm]:
            pprint (Api)
        return 0
    
    ##################################################
    #                 Sorting the dict               #
    ##################################################
    def SortDictByKeys (self):
        self.PermApiDictFromJson = \
        collections.OrderedDict(sorted(self.PermApiDictFromJson.items()))
        

        

    
def main ():
    '''
    This is a sample showing to init the PScout Mapping dict and query it
    This is how the caller function can create an instance of this 
    'PScoutMapping' class and use it!
    '''
    
    #DictFName = sys.argv[1]
    PMap =  PScoutMapping()
    
    #PMap.PrintDict()
    #PMap.PrintAllPerms()
    #PMap.PrintAllApis()    
    Perms = PMap.GetAllPerms()
    #Apis = PMap.GetAllApis()    
    print Perms[60]
    #raw_input("Enter...")
    #PermsApis = PMap.GetApisFromPerm(Perms[60])
    #pprint (PermsApis)
    
    print PMap.GetPermFromApi(
    'com.android.internal.telephony.sip.SipPhone$SipConnection$1', 
                              'onError')
    
    
    


if __name__ == '__main__':
    main()