import argparse
import os
import shutil


parser = argparse.ArgumentParser()
parser.add_argument("-c", "--certs", dest='certs_dir', help="Input the Top Level Dir Name to store the certs")
parser.add_argument("-m", "--mac", dest='mac', help="MAC Address ie: 0007814300e43e99")
parser.add_argument("-u", "--usage", dest='usage', action='store_true', help="python createCertDir.py --certs  Certs_xxxxxx --mac 0007814300xxxxxx")
parser.add_argument("-V", "--version", dest='version', action='store_true', help="Display current version of this script")
args = parser.parse_args()

VERSION_STRING = "V1.00 11/7/2018"

if args.version :
	print "Version: %s\n" % VERSION_STRING
        exit(0)

if args.usage :
	print "Usage: python createCertDir.py --certs  Certs_e4e24e --mac 0007814300e4e24e\n"
        exit(0)

cwd = os.getcwd()
if not os.path.exists(args.certs_dir):
	os.makedirs(args.certs_dir)
	os.makedirs(args.certs_dir+'/AAA')
        os.makedirs(args.certs_dir+'/CA Certs')
	os.makedirs(args.certs_dir+'/DL')
	os.makedirs(args.certs_dir+'/DLCA')
	os.makedirs(args.certs_dir+'/Meter Security')
	os.makedirs(args.certs_dir+'/NMS')
	os.makedirs(args.certs_dir+'/Operator')
	os.makedirs(args.certs_dir+'/Xroot')
	os.makedirs(args.certs_dir+'/Meter Security/CER')
	os.makedirs(args.certs_dir+'/Meter Security/P12')



shutil.copy("00_"+args.mac+"_ROOT.x509", args.certs_dir+'/CA Certs/'+"00_rootCA.ins.x509")
shutil.copy("00_"+args.mac+"_ROOT.x509", args.certs_dir+'/Xroot/'+"00_"+args.mac+"_ROOT.x509")
shutil.copy("01_"+args.mac+"_MFG.x509", args.certs_dir+'/CA Certs/'+"01_"+args.mac+"_MFG.ins.x509")
shutil.copy("01_"+args.mac+"_OPERATOR.x509", args.certs_dir+'/Operator/'+"01_"+args.mac+"_OPERATOR.x509")
shutil.copy("02_"+args.mac+"_DLCA.x509", args.certs_dir+'/DLCA/'+"02_"+args.mac+"_DLCA.x509")
shutil.copy("02_"+args.mac+".pkcs8", args.certs_dir+'/Meter Security/CER/'+"02_"+args.mac+".pkcs8")
shutil.copy("02_"+args.mac+"_BC.x509", args.certs_dir+'/Meter Security/CER/'+"02_"+args.mac+"_BC.x509")
shutil.copy("03_"+args.mac+"_DL.x509", args.certs_dir+'/DL/'+"03_"+args.mac+"_DL.x509")
shutil.copy(args.mac+".p12", args.certs_dir+'/Meter Security/P12/'+args.mac+".p12")
shutil.copy(args.mac+"-p12pwd.txt", args.certs_dir+'/Meter Security/P12/'+"00_"+args.mac+"-p12pwd.txt")
shutil.copy("Ipv6labAAA.cer", args.certs_dir+'/AAA/'+"Ipv6labAAA.cer")
shutil.copy("FNDCertificate.pem", args.certs_dir+'/NMS/'+"FNDCertificate.pem")
