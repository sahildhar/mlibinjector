#!/usr/bin/env python

__author__ = 'Sahil Dhar (@0x401)'
__description__ = 'A handy script to inject Frida-Gadgets and enable debugging in Android applications'


import os
import argparse
import lief
import re 

from subprocess import Popen,PIPE,call
from termcolor import colored
from xml.etree import ElementTree as ET
from shutil import copyfile
from glob import glob
from time import sleep
from random import randint,sample
from string import lowercase



file_types = {
		'armeabi-v7a':'7f454c4601010100000000000000000003002800010000000000000034000000',
		'arm64-v8a':'7f454c460201010000000000000000000300b700010000000000000000000000',
		'x86':'7f454c4601010100000000000000000003000300010000000000000034000000',
		'x86_64':'7f454c4602010100000000000000000003003e00010000000000000000000000'
		}
		
libdir = {'arm64-v8a':'','armeabi-v7a':'','x86':'','x86_64':''}
android_namespace = 'http://schemas.android.com/apk/res/android'
ET.register_namespace('android',android_namespace)

tools = os.path.join(os.path.dirname(__file__),'tools')
apktool = "java -jar %s " %(os.path.join(tools,'apktool.jar'))
sign = "java -jar %s " %(os.path.join(tools,'sign.jar'))


def verbose(str):
	if _verbose:
		print colored('>>> %s' %str,'yellow')

def exec_cmd(cmd):
	verbose(cmd)
	p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
	r = p.communicate()
	r = '\n'.join(x for x in r)
	return r


def inject_lib(native_lib,gadget_lib):
	"""
	Inject library dependency to pre-existing native lib
	requires android.permission.INTERNET in AndroidManifest.xml
	when using server mode for frida-gadget.
	"""

	native = lief.parse(native_lib)
	native.add_library(gadget_lib)
	native.write(native_lib)

def get_launchable_activity(apk_name):
	"""
	Parses AndroidManifest.xml and returns all launchable activities
	will throw an error for corrupted xml documents
	"""

	manifest_file = apk_name.split('.apk')[0]+'/AndroidManifest.xml'
	name = '{http://schemas.android.com/apk/res/android}name'
	try:
		main_activities = []
		parser = ET.parse(manifest_file)
		root = parser.getroot()
		package_name = root.attrib['package']
		activities = root.findall('application')[0].findall('activity');
		activity_alias = root.findall('application')[0].findall('activity-alias');


		if len(activities) > 0:
			for activity in activities:
				intent_filters = activity.findall('intent-filter')
				if len(intent_filters) > 0:
					for intent in intent_filters:
						categories = intent.findall('category')
						if len(categories) > 0:
							for category in categories:
								for val in category.attrib.values():
									if val == 'android.intent.category.LAUNCHER':
										activity_name = activity.attrib[name]
										if activity_name.startswith('.'):
											main_activities.append(package_name + activity_name)
										elif re.match(r'^[a-zA-Z0-9-_]+$',activity_name):
											main_activities.append(package_name + '.' + activity_name)
										else:
											main_activities.append(activity_name)
		if len(activity_alias) > 0:
			for activity in activity_alias:
				intent_filters = activity.findall('intent-filter')
				if len(intent_filters) > 0:
					for intent in intent_filters:
						categories = intent.findall('category')
						if len(categories) > 0:
							for category in categories:
								for val in category.attrib.values():
									if val == 'android.intent.category.LAUNCHER':
										activity_name = activity.attrib[name]
										if activity_name.startswith('.'):
											main_activities.append(package_name + activity_name)
										elif re.match(r'^[a-zA-Z0-9-_]+$',activity_name):
											main_activities.append(package_name + '.' + activity_name)
										else:
											main_activities.append(activity_name)
		return main_activities
	except Exception,ex:
		# print ex
		pass




def decompile_apk(apkname):
	"""
	Decompile apk file using apktool.jar

	"""
	verbose('Decompiling %s' %(apkname))
	cmd = "%s d -f %s" % (apktool,apkname)
	r = exec_cmd(cmd)
	verbose(r)
	print colored('I: Decompiled %s' %(apkname), color='green')


def sign_apk(apkname):
	"""
	sign apk using default developer certificate via sign.jar  
	
	"""
	r = exec_cmd('%s %s' %(sign,apkname))
	verbose(r)


def build_and_sign(apkname):
	"""
	Build using apktool.jar
	sign again using sign.jar

	"""
	dirname = apkname.split('.apk')[0]
	verbose('Building apk file')
	cmd = '%s b -f %s' %(apktool,dirname)
	r = exec_cmd(cmd)
	verbose(r)
	print colored('I: Build done', color='green')
	apkname = '%s/dist/%s' %(dirname,dirname+'.apk')
	verbose('Signing %s' %apkname)
	sign_apk(apkname)	


def enable_debugging(apkname):
	"""
	Enable debug flag in AndroidManifest.xml
	Uses apktool.jar and sign.jar

	"""
	decompile_apk(apkname)
	dirname = apkname.split('.apk')[0]
	filename = dirname + '/AndroidManifest.xml'
	verbose('Enabling android-debug:true in %s' %filename)
	fp = open(filename,'r')
	parser = ET.parse(fp)
	application = parser.getroot()[0]
	keyname = '{http://schemas.android.com/apk/res/android}debuggable'
	if application.attrib.has_key(keyname):
		application.attrib[keyname] = 'true'
	else:
		application.attrib[keyname] = 'true'
	parser.write(filename,encoding='utf-8',xml_declaration=True)
	print colored('I: Enabled android-debug:true in %s' %filename, color='green')
	build_and_sign(dirname)

def check_permission(filename,filter):
	"""
	Check apk permission specified in filter by parsing AndroidManifest.xml
	Currently used for checking android.permission.INTERNET permission.

	"""


	verbose('Checking permissions in %s' %filename)
	parser = ET.parse(filename)
	manifest = parser.getroot()
	package_name = manifest.attrib['package'].replace('.','/')
	permissions = manifest.findall('uses-permission')
	if len(permissions) > 0:
		for perm in permissions:
			name = '{%s}name' % android_namespace
			verbose('uses-permission: %s' %(perm.attrib[name]))
			if perm.attrib[name]  == filter:
				return True
				break
			else:
				return False
	else:
		verbose('No permissions are defined in %s' %(filename))
		return False

def add_permission(filename,permission_name):
	"""
	Add permissions to apkfile specified in filter by parsing AndroidManifest.xml
	Currently used for adding android.permission.INTERNET permission.

	"""
	verbose('Adding %s permission to %s' %(permission_name,filename))
	parser = ET.parse(filename)
	manifest = parser.getroot()
	perm_element = ET.Element('uses-permission')
	name = '{%s}name' % android_namespace
	perm_element.attrib[name] = permission_name
	manifest.append(perm_element)
	parser.write(filename,encoding='utf-8',xml_declaration=True)
	print colored('I: Added %s permission to %s' %(permission_name,filename), 'green')

def write_config(filename,host=None,port=None,s_file=None,s_dir=None):
	"""
	Generates frida config file based on supplied parameters
	"""

	if (host and port):
		data = '''{
  "interaction": {
    "type": "listen",
    "address": "%s",
    "port": %s,
    "on_load": "wait"
  }
}''' %(host,port)
		verbose(data)
		open(filename,'w').write(data)

	elif port:
		data = '''{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": %s,
    "on_load": "wait"
  }
}''' %(port)
		verbose(data)
		open(filename,'w').write(data)

	elif s_file:
		data = '''{
  "interaction": {
    "type": "script",
    "path": "%s",
    "on_change": "reload"
  }
}''' %(s_file)
		open(filename,'w').write(data)
	elif s_dir:
		data = '''{
  "interaction": {
    "type": "script-directory",
    "path": "%s",
	"on_change":"rescan"
  }
}''' %(s_dir)
		verbose(data)
		open(filename,'w').write(data)
		


def copy_libs(libpath,dirname):
	"""
	copy frida gadgets into /lib/<arch> folders

	"""

	global libdir
	if len(arch) > 0:
		for k in libdir.keys():
			if k not in arch:
				libdir.pop(k)

	for dir in libdir.keys():
		libdir[dir] = os.path.join(dirname,'lib',dir)
		verbose(libdir[dir])
		if not os.path.exists(libdir[dir]):
			os.makedirs(libdir[dir])
		else:
			verbose('Dir %s already exists' %(libdir[dir]))
	if os.path.exists(libpath):
		lib_files = glob(libpath+'/*.so')
		for src in lib_files:
			sig =  open(src,'rb').read(32).encode('hex')
			for key in libdir.keys():
				if sig == file_types[key]:
					dest = os.path.join(libdir[key],gadgetfile)
					_configfile = os.path.join(libdir[key],configfile)
					verbose('%s --> %s' %(src,dest))
					copyfile(src,dest)
					write_config(_configfile,host=host,port=port,s_file=scriptfile,s_dir=scriptdir)

	else:
		print colored('E: Please provide the path to frida-gadget lib(.so) files',color='red')
		os._exit(1)


def inject_smali(filename):
	"""
	Injects smali prologue or smali direct methods in
	launchable activities by parsing smali code  to load frida-gadgets.

	"""
	if nativelib:
		verbose(libdir)
		for key,dir in libdir.iteritems():
			_nativelib = os.path.join(dir,nativelib)
			verbose(_nativelib)
			inject_lib(_nativelib,gadgetfile)
	else:
		_filename = os.path.basename(filename)
		prologue_stmt = """

	const-string v0, "%s"

	invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

""" %(gadgetfile.split('.so')[0][3:])
		direct_method = """

.method static constructor <clinit>()V
	.locals 1

	.prologue
	const-string v0, "%s"

	invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

	return-void
.end method


""" %(gadgetfile.split('.so')[0][3:])
		verbose('Injecting smali code in %s' %(_filename))
		rf= open(filename,'r')
		lines = rf.readlines()
		rf.close()
		cursor = None
		s_constructor = False
		eof = len(lines) - 1
		for index,line in enumerate(lines):
			if '# direct methods' in line:
				cursor = index + 1

			if '.method static constructor <clinit>()V' in line:
				cursor = index + 1
				method_start = cursor
				s_constructor = True

			if (s_constructor):
				if (index == cursor):
					# print "Cursor is at %d" %cursor
					# Found prologue write after it

					if '.prologue' in line:
						lines.insert(cursor+2,prologue_stmt)
						verbose('Smali prologue injected')
						break

					# No .prologue found write after constructor
					elif '.end method' in line:
						lines.insert(method_start + 1, prologue_stmt)
						verbose('Smali prologue injected')
						break
					else:
						cursor += 1

			# Couldn't find the static constructor, injecting static constructor
			elif (s_constructor == False and cursor != None and index == eof):
				# print "Index is at %d" %index
				# print "Cursor is at %d" %cursor
				lines.insert(cursor,direct_method)
				verbose('Static constructor injected')
				break

		wf = open(filename,'w')
		wf.writelines(lines)
		wf.close()
		print colored('I: Smali code written to %s' %(_filename),color='green')


def inject_frida_gadget(apkname,libpath):
	"""
	Handles process of injecting Frida gadgets
	
	"""
	verbose('Injecting frida gagdet in %s' %apkname)
	decompile_apk(apkname)
	dirname = apkname.split('.apk')[0].replace('\\','/')
	androidmanifest = dirname + '/AndroidManifest.xml'
	name = '{%s}name' % android_namespace
	permission_name = 'android.permission.INTERNET'	
	

	activity_names = get_launchable_activity(apkname)

	if not(scriptfile or scriptdir):
		if check_permission(androidmanifest,permission_name) == False:
			add_permission(androidmanifest,permission_name)
			copy_libs(libpath, dirname)

		else:
			copy_libs(libpath,dirname)
	else:
		copy_libs(libpath,dirname)

	for activity_name in activity_names:
		activity_file_path = activity_name.replace('.','/')
		main_activityfile = dirname + '/smali/' + activity_file_path + '.smali'
		inject_smali(main_activityfile)

	build_and_sign(apkname)
	print colored('I: Frida Gadget injected','green')
	print colored('I: Use command frida -U -n Gadget to connect to gadget :)','green')


def main():
	global _verbose, arch, nativelib, host, port
	global scriptfile, scriptdir, gadgetfile, configfile

	port = None
	host = None
	scriptfile = None
	scriptdir = None
	nativelib = None
	_verbose = False
	gadgetfile = 'libfrida-gadget.so'
	configfile = 'libfrida-gadget.config.so'
	arch = []

	desc = '''
[mlibinjector] -  %s - %s
''' %(__description__, __author__)

	parser = argparse.ArgumentParser(description=desc, version='mlibinjector version: 1.0')
	parser.add_argument('apkname', type=str, help='Apk Name')
	parser.add_argument('-s', action='store_true', dest='sign', help='Sign apk')
	parser.add_argument('-d', action='store_true', dest='decompile', help='Decompile using apktool')
	parser.add_argument('-b', action='store_true', dest='build', help='Build & Sign & Zipalign')
	parser.add_argument('-e', action='store_true', dest='enableDebug', help='Enable debug mode for apk')
	parser.add_argument('-i', action='store_true', dest='injectFrida', help='Inject frida-gadget in *listen* mode (requires -p)')
	parser.add_argument('-p', action='store', dest='libPath', help='Absolute path to downloaded frida-gadgets (.so) files')
	parser.add_argument('--port', action='store', type=int, dest='port', help='Listen frida-gadget on port number in *listen mode*')
	parser.add_argument('--host', action='store',  dest='host', help='Listen frida-gadget on specific network interface in *listen mode*')
	parser.add_argument('--script-file', action='store', dest='scriptfile', help='Path to script file on the device')
	parser.add_argument('--script-dir',action='store', dest='scriptdir', help='Path to directory containing frida scripts on the device')
	parser.add_argument('--native-lib',action='store', dest='nativelib', help='Name of exisiting native lib. Example "libnative-lib.so"')
	parser.add_argument('--arch',action='store', dest='arch', help='Add frida gadget for particular arch.(arm64-v8a|armeabi-v7a|x86|x86_64)')
	parser.add_argument('--random', action='store_true', dest='randomize', help='Randomize frida-gadget name')
	parser.add_argument('-V',action='store_true', dest='verbose', help='Verbose')


	v = parser.parse_args()

	if((v.port) and (v.port in range (1,65535))):
		port = v.port

	if v.host:
		host = v.host
		verbose(host)

	if v.scriptfile:
		scriptfile = v.scriptfile

	if v.scriptdir:
		scriptdir = v.scriptdir

	if v.nativelib:
		nativelib = v.nativelib

	if v.randomize:
		name = ''.join(x for x in sample(lowercase,randint(6,15)))
		gadgetfile = 'lib%s.so' %name
		configfile = 'lib%s.config.so' %name

	if v.verbose:
		_verbose = True

	if v.arch:
		archs = v.arch.split(',')
		for a in archs:
			if a not in libdir.keys():
				print colored('%s arch is not supported' %a)
				os._exit(1)

		arch = archs


	if(v.apkname and os.path.isfile(v.apkname) and os.access(v.apkname,os.R_OK)):
		if(v.sign):
			sign_apk(v.apk_name)

		elif(v.decompile):
			decompile_apk(v.apkname)

		elif(v.build):
			build_and_sign(v.apkname)

		elif(v.enableDebug):
			enable_debugging(v.apkname)

		elif(v.injectFrida and v.libPath):
			inject_frida_gadget(v.apkname,v.libPath)
		else:
			parser.print_help()
	else:
		parser.print_help()
		print colored('E: Please Provide a valid apk file',color='red')
		os._exit(1)

