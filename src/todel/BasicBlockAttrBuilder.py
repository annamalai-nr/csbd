def GetBasicBlockDalvikCode(BasicBlock):
	'''
	Get the list of dalvik code of the instrcutions contained in the BasicBlock
	
	:param DVMBasicBlock BasicBlock
	:return DalvikCodeList
	:rtype List<String>
	'''

	DalvikCodeList = []
	for Instruction in BasicBlock.get_instructions():
		CodeLine = str(Instruction.get_name() + " " + Instruction.get_output())
		DalvikCodeList.append(CodeLine)
	return DalvikCodeList


def GetInvokedAndroidApis(DalvikCodeList):
	'''
	Get the android APIs invoked by a list of instrcutions
	:param List<String> DalvikCodeList
	:return ApiList
	:rtype List
	'''
	DalvikCodeList = set(DalvikCodeList)
	ApiList = []
	for DalvikCode in DalvikCodeList:
		if "invoke-" in DalvikCode:
			Parts = DalvikCode.split(",")
			for Part in Parts:
				if ";->" in Part:
					Part = Part.strip()
					if Part.startswith('Landroid'):
						FullApi = Part
						ApiParts = FullApi.split(";->")
						ApiClass = ApiParts[0].strip()
						ApiName = ApiParts[1].split("(")[0].strip()
						ApiDetails = {}
						ApiDetails['FullApi'] = FullApi
						ApiDetails['ApiClass'] = ApiClass
						ApiDetails['ApiName'] = ApiName
						ApiList.append(ApiDetails)

	return ApiList

def GetPermissions(ApiList, PMap):
	'''
	Get Android Permissions used by a list of android APIs

	:param List ApiList
	:param PScoutMapping.PScoutMapping PMap
	:return PermissionSet
	:rtype Set<String>
	'''

	PermissionSet = set()
	for Api in ApiList:
		ApiClass = Api['ApiClass'].replace("/", ".").replace("Landroid", "android").strip()
		Permission = PMap.GetPermFromApi(ApiClass, Api['ApiName'])
		if(not Permission == None):
			PermissionSet.add(Permission)

	return PermissionSet

def GetSusiSrcsSinks(ApiList, SusiMap):
	'''
	Get sources and sinks used in a list of android APIs

	:param List ApiList
	:param Susi.SusiDictMaker SusiMap
	:return SourceSet: Set of SUSI src
	:rtype Set<String>
	:return SinkSet: Set of SUSI sink
	:rtype Set<String>
	'''

	SourceSet = set()
	SinkSet = set()

	for Api in ApiList:
		ApiClass = Api['ApiClass'].replace("/", ".").replace("Landroid", "android").strip()
		Source = SusiMap.GetSusiCategoryFromApi(ApiClass, Api['ApiName'], "src")
		if(not Source == -1):
			SourceSet.add(Source)
		Sink = SusiMap.GetSusiCategoryFromApi(ApiClass, Api['ApiName'], "sink")
		if(not Sink == -1):
			SinkSet.add(Sink)

	return SourceSet, SinkSet