def CombineKernels(Kernels, Beta, Iter, Eps, SampleFVs, Labels):
	'''
	Train combined kernels from a list of kernels
	:param List Kernels
	:param float Beta: down-scale parameter
	:param int Iter: maxium number of iterations with stable results to go through
 	:param float Eps: criteria for "stable results"
 					  Please refer to the comment below for implication of Iter and Eps
 	:param List Samples: list of training sample feature vector
 	:param List Labels: list of training sample labels
	'''

	# initialization
	KernelNo = len(Kernels)
	KernelWts = [1.0/KernelNo for x in range(KernelNo)]
	MKPredictInd = [1 for x in range(KernelNo)]
	MKPredictCom = 0
	Loss = [0 for x in range(KernelNo)]

	for SIndex in range(SampleFVs[0].shape[0]):
		print "======== Iteration" + str(SIndex) + "========"
		# Get Combined Prediction
		MKPredictCom = 0
		for KIndex in range(KernelNo):
			MKPredictInd[KIndex] = Kernels[KIndex].predict(SampleFVs[KIndex][SIndex])
			MKPredictCom += MKPredictInd[KIndex] * KernelWts[KIndex]

		if(MKPredictCom >= 0):
			MKPredictCom = 1
		else:
			MKPredictCom = -1
		print "Combined Prediction:" + str(MKPredictCom)
		print "Actual Prediction:" + str(Labels[SIndex])

		Loss = [0 for x in range(KernelNo)]
		# Penalize kernels if predicting wrongly
		if(not MKPredictCom == Labels[SIndex]):
			for KIndex in range(KernelNo):
				if(not MKPredictInd[KIndex] == Labels[SIndex]):
					Loss[KIndex] = 1.0

			TotalLoss = sum(Loss)
			Loss = [LossInv/TotalLoss for LossInv in Loss]

			# Update and normalize weights
			for KIndex in range(KernelNo):
				KernelWts[KIndex] = KernelWts[KIndex] * pow(Beta, Loss[KIndex])
			TotalWt = sum(KernelWts)
			KernelWts = [KernelWt/TotalWt for KernelWt in KernelWts]

		print "Loss:" + str(Loss)
		print "KernelWts:" + str(KernelWts)
		print "Sum of KernelWts:" + str(sum(KernelWts))

	return KernelWts

# def test(Kernels, Beta, Iter, Eps, SampleFVs, Labels):
# 	'''
# 	Train combined kernels from a list of kernels
# 	:param List Kernels
# 	:param float Beta: down-scale parameter
# 	:param int Iter: maxium number of iterations with stable results to go through
# 	:param float Eps: criteria for "stable results"
# 					  Please refer to the comment below for implication of Iter and Eps
# 	:param List Samples: list of training sample feature vector
# 	:param List Labels: list of training sample labels
# 	'''

# 	# initialization
# 	KernelNo = len(Kernels)
# 	KernelWts = [1.0/KernelNo for x in range(KernelNo)]
# 	MKPredictInd = [1 for x in range(KernelNo)]
# 	MKPredictCom = 0
# 	Loss = [0 for x in range(KernelNo)]
# 	PLabels = [[1,1,1,1,1,1,1,1,1,1],[1,-1,1,-1,1,-1,1,-1,1,-1],[1,1,-1,-1,1,-1,1,1,-1,1],[1,-1,1,-1,-1,1,-1,1,-1,1]]

# 	for SIndex in range(len(SampleFVs[0])):
# 		# Get Combined Prediction
# 		MKPredictCom = 0
# 		for KIndex in range(KernelNo):
# 			print "Kernels[" + str(KIndex) + "]: " + Kernels[KIndex]
# 			MKPredictInd[KIndex] = PLabels[KIndex][SIndex] #Kernels[KIndex].predict(SampleFVs[KIndex][SIndex])
# 			MKPredictCom += MKPredictInd[KIndex] * KernelWts[KIndex]

# 		if(MKPredictCom >= 0):
# 			MKPredictCom = 1
# 		else:
# 			MKPredictCom = -1

# 		Loss = [0 for x in range(KernelNo)]
# 		# Penalize kernels if predicting wrongly
# 		if(not MKPredictCom == Labels[SIndex]):
# 			for KIndex in range(KernelNo):
# 				if(not MKPredictInd[KIndex] == Labels[SIndex]):
# 					Loss[KIndex] = 1.0

# 			TotalLoss = sum(Loss)
# 			Loss = [LossInv/TotalLoss for LossInv in Loss]

# 			print Loss

# 			# Update and normalize weights
# 			for KIndex in range(KernelNo):
# 				KernelWts[KIndex] = KernelWts[KIndex] * pow(Beta, Loss[KIndex])
# 			TotalWt = sum(KernelWts)
# 			KernelWts = [KernelWt/TotalWt for KernelWt in KernelWts]

# 			print KernelWts
# 			print "Sum: " + str(sum(KernelWts))
# 	print "Final Result: "
# 	print KernelWts
# 	return KernelWts

# Kernels = ['k1', 'k2', 'k3', 'k4']
# Beta = 0.9
# Iter = 2
# Eps = 0.01
# Samples = [9,8,7,6,5,4,3,2,1,0]
# Labels = [1, -1, 1, -1, 1, -1, 1, -1, 1, -1]
# test(Kernels, Beta, Iter, Eps, Samples, Labels)