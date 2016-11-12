#!/usr/bin/env python

import argparse
import copy
import json
import os.path
import random
import re
import string
import sys
import boto3
import botocore

REST_API_GET_FETCH_COUNT_LIMIT = 500
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S %z'
JSON_INDENT_SIZE = 4
JSON_INDENT_REGEXP = re.compile(r'^( +)(.*)')

API_GATEWAY_PRINCIPAL_SERVICE = 'apigateway.amazonaws.com'
API_GATEWAY_ID_IDENTIFIER = (10,string.digits + string.ascii_lowercase) # [0-9a-z]
API_GATEWAY_EXPORT_TYPE = 'swagger'
API_GATEWAY_EXPORT_PROPERTY_COLLECTION = { 'extensions': 'integrations' }
API_GATEWAY_EXPORT_CONTENT_TYPE = 'application/json'

# note: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-set-up-simple-proxy.html#api-gateway-proxy-resource
API_GATEWAY_DEFINITION_RESOURCE_PATH_REGEXP = re.compile(
	r'^(?:'
		# root URI followed by optional catch all (greedy path variable)
		r'(?P<root_path_uri>/)(?P<root_catch_all>\{[a-zA-Z0-9._-]+\+\})?|'
		# one or more resource path parts [/PART_NAME] followed by optional catch all
		r'(?P<path_uri>(?:/[a-zA-Z0-9._-]+)+)(?:/(?P<catch_all>\{[a-zA-Z0-9._-]+\+\}))?'
	r')$'
)

API_GATEWAY_DEFINITION_HTTP_ANY_METHOD = 'x-amazon-apigateway-any-method'
API_GATEWAY_DEFINITION_VALID_HTTP_METHOD_SET = {
	'delete','get','head','options','patch','post','put',
	API_GATEWAY_DEFINITION_HTTP_ANY_METHOD
}

API_GATEWAY_DEFINITION_INTEGRATION_PROPERTY = 'x-amazon-apigateway-integration'
API_GATEWAY_DEFINITION_INTEGRATION_TYPE_SET = { 'aws','aws_proxy' }

API_GATEWAY_DEFINITION_PUT_MODE = 'overwrite'
API_GATEWAY_DEFINITION_STRUCT_PATH_IGNORE_LIST = [
	['basePath'],
	['host'],
	['info','version']
]

API_GATEWAY_LAMBDA_URI_ARN_REGEXP = re.compile(
	r'^arn:aws:apigateway:[a-z]{2}-[a-z]{4,}-[0-9]:lambda:'
	r'path/(?P<path_version>[0-9]{4}-[0-9]{2}-[0-9]{2})/'
	r'functions/(?P<arn>arn:aws:lambda:[a-z]{2}-[a-z]{4,}-[0-9]:[0-9]+:'
	r'function:(?P<function_name>[^ /]+))/invocations$'
)

API_GATEWAY_LAMBDA_URI_ARN_GENERIC_REGEXP = re.compile(
	r'^arn:aws:apigateway::lambda:'
	r'path/(?P<path_version>[0-9]{4}-[0-9]{2}-[0-9]{2})/'
	r'functions/arn:aws:lambda:::'
	r'function:(?P<function_name>[^ /]+)/invocations$'
)

LAMBDA_ARN_PROPERTY_REGEXP = re.compile(
	r'^arn:aws:lambda:'
	r'(?P<region>[a-z]{2}-[a-z]{4,}-[0-9]):'
	r'(?P<account_id>[0-9]+):function:[^ /]+$'
)

LAMBDA_POLICY_ACTION_INVOKE = 'lambda:InvokeFunction'
LAMBDA_POLICY_PRINCIPAL_SERVICE = 'apigateway.amazonaws.com'
# note: http://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html#api-gateway-calling-api-permissions
LAMBDA_POLICY_API_GATEWAY_SOURCE_ARN_REGEXP = re.compile(
	r'^arn:aws:execute-api:'
	r'(?P<region>[a-z]{2}-[a-z]{4,}-[0-9]):'
	r'(?P<account_id>[0-9]+):'
	r'(?P<api_id>[a-z0-9]{10})/\*/'
	r'(?P<http_method>[^ /]+)'
	# resource URI character class of [a-zA-Z0-9._-] validated via API Gateway admin console
	# matching either root [/], or one or more resource path parts [/PART_NAME] followed by optional catch all [*]
	r'(?P<path_uri>/\*?|(?:/[a-zA-Z0-9._-]+)+(?:/\*)?)$'
)

LAMBDA_POLICY_APPLY_PERMISSIONS_EXCLUSIVE = 'exclusive'
LAMBDA_POLICY_APPLY_PERMISSIONS_INCLUSIVE = 'inclusive'
LAMBDA_POLICY_STATEMENT_ID_IDENTIFIER = (32,string.hexdigits[:16]) # [0-9a-f]


class Console:
	verbose = False

	def exit_error(self,message):
		sys.stderr.write('Error: {0}\n'.format(message))
		sys.exit(1)

	def write_info(self,message = ''):
		if (Console.verbose):
			print(message)

	def write_notice(self,message):
		self.write_info('Notice: {0}'.format(message))

def json_struct_compare(struct_a,struct_b,path_ignore_list = []):
	def get_type(item):
		# treat unicode type as string
		item_type = type(item)
		return str if (item_type is unicode) else item_type

	def compare(data_a,data_b,struct_path = [],struct_path_part = None):
		def get_updated_struct_path():
			if (struct_path_part is not None):
				# copy and update struct path
				return list(struct_path) + [struct_path_part]

			# no update to path
			return struct_path

		# type: list
		if (type(data_a) is list):
			# [data_b] a list and of same length as [data_a]?
			if (
				(type(data_b) is not list) or
				(len(data_a) != len(data_b))
			):
				return False

			# iterate over list items
			struct_path = get_updated_struct_path()
			for list_index,list_item in enumerate(data_a):
				# compare [data_a] against [data_b] at list index
				if (not compare(list_item,data_b[list_index],struct_path,list_index)):
					return False

			# list identical
			return True

		# type: dictionary
		if (type(data_a) is dict):
			# is [data_b] a dictionary?
			if (type(data_b) is not dict):
				return False

			# iterate over dictionary keys
			struct_path = get_updated_struct_path()
			for dict_key,dict_value in data_a.items():
				dict_key = str(dict_key) # normalize unicode

				# skip check of dictionary key if struct path is in ignore list
				if ((struct_path + [dict_key]) in path_ignore_list):
					continue

				# key exists in [data_b] dictionary, and same value?
				if (
					(dict_key not in data_b) or
					(not compare(dict_value,data_b[dict_key],struct_path,dict_key))
				):
					return False

			# dictionary identical
			return True

		# simple value - compare both value and type for equality
		return (
			(data_a == data_b) and
			(get_type(data_a) is get_type(data_b))
		)

	# compare a to b, then b to a
	return (
		compare(struct_a,struct_b) and
		compare(struct_b,struct_a)
	)

def read_arguments():
	console = Console()

	# create parser
	parser = argparse.ArgumentParser(
		description =
			'Creates or updates an AWS API Gateway instance by API name from a JSON Swagger 2.0 definition. '
			'Can also export an active API Gateway instance back to definition file.'
	)

	parser.add_argument(
		'--region',
		help = 'AWS target region',
		required = True
	)

	parser.add_argument(
		'--api-name',
		help = 'API Gateway name for upsert or export',
		metavar = 'NAME',
		required = True
	)

	parser.add_argument(
		'--api-stage',
		help = 'API stage name for upsert or export',
		metavar = 'NAME',
		required = True
	)

	parser.add_argument(
		'--export-file-json',
		help = 'Export API Gateway definition to the given file',
		metavar = 'FILE'
	)

	parser.add_argument(
		'--generic-lambda-integration-uri',
		action = 'store_true',
		help = 'Exported definition will have Lambda function integration URIs converted to a generic format'
	)

	parser.add_argument(
		'--upsert-file-json',
		help = 'Definition file to create/update an API Gateway instance from',
		metavar = 'FILE'
	)

	parser.add_argument(
		'--apply-lambda-permissions',
		choices = {
			LAMBDA_POLICY_APPLY_PERMISSIONS_EXCLUSIVE,
			LAMBDA_POLICY_APPLY_PERMISSIONS_INCLUSIVE
		},
		help =
			'Update Lambda function policies referenced by API definition to enable invoke actions. '
			'The \'exclusive\' mode removes policies unrelated to gateway instance, \'inclusive\' will preserve such policies.'
	)

	parser.add_argument(
		'--dry-run',
		action = 'store_true',
		help = 'Display what would happen during API definition upsert, without committing changes'
	)

	parser.add_argument(
		'--quiet',
		action = 'store_true',
		help = 'Suppress output during export/upsert progress'
	)

	arg_list = parser.parse_args()

	# validate AWS region
	if (not re.search(r'^[a-z]{2}-[a-z]{4,}-[0-9]$',arg_list.region)):
		console.exit_error('Invalid AWS target region format [{0}]'.format(arg_list.region))

	# validate naming format of API name and stage name
	if (not re.search(r'^[A-Za-z0-9][A-Za-z0-9-_]+[A-Za-z0-9]$',arg_list.api_name)):
		console.exit_error('Invalid API Gateway name [{0}]'.format(arg_list.api_name))

	if (not re.search(r'^[A-Za-z0-9][A-Za-z0-9_]+[A-Za-z0-9]$',arg_list.api_stage)):
		console.exit_error('Invalid API Gateway stage name [{0}]'.format(arg_list.api_stage))

	# confirm one of [--export-file-json] or [--upsert-file-json] is given
	if ((arg_list.export_file_json is None) and (arg_list.upsert_file_json is None)):
		console.exit_error('Specify one of --export-file-json or --upsert-file-json')

	upsert_mode = False
	file_path_json = arg_list.export_file_json
	if (arg_list.upsert_file_json is not None):
		# ensure file exists
		if (not os.path.isfile(arg_list.upsert_file_json)):
			console.exit_error('Unable to open [{0}] for API Gateway upsert'.format(arg_list.upsert_file_json))

		# file exists - get canonical path
		file_path_json = os.path.realpath(arg_list.upsert_file_json)
		upsert_mode = True

	# confirm if [--export-generic-lambda-arn-uri] enabled that we are in export definition mode
	if (arg_list.generic_lambda_integration_uri and upsert_mode):
		console.exit_error('Generic Lambda function integration URI mode only valid during API definition export')

	# confirm if [--apply-lambda-permissions] specified that we are in upsert definition mode
	if ((arg_list.apply_lambda_permissions is not None) and (not upsert_mode)):
		console.exit_error('Apply Lambda permissions option only valid with upsert mode')

	# confirm if [--dry-run] mode that we are in upsert definition mode
	if (arg_list.dry_run and (not upsert_mode)):
		console.exit_error('Dry run option only valid for upsert mode')

	# return arguments
	return (
		arg_list.region,
		arg_list.api_name,arg_list.api_stage,
		upsert_mode,file_path_json,
		arg_list.generic_lambda_integration_uri,
		arg_list.apply_lambda_permissions,
		arg_list.dry_run,
		not arg_list.quiet
	)

class LambdaAccess:
	aws_target_region = None

	_client = None
	_function_collection = None

	def get_client(self):
		# return existing Lambda API client instance, or create new
		if (not LambdaAccess._client):
			LambdaAccess._client = boto3.client(
				'lambda',
				region_name = LambdaAccess.aws_target_region
			)

		return LambdaAccess._client

	def get_function_collection(self):
		# if no function list - build now
		if (LambdaAccess._function_collection is None):
			Console().write_info('Fetching Lambda function list\n')
			LambdaAccess._function_collection = {}

			# fetch all Lambda functions for account/region - handling pagination if required over multiple API calls
			fetch_marker = None
			while (True):
				request_args = {}
				if (fetch_marker):
					request_args['Marker'] = fetch_marker

				list_response = self.get_client().list_functions(**request_args)

				if ('Functions' in list_response):
					# add each function to collection - keyed by ARN
					for function_item in list_response['Functions']:
						# extract Lambda properties from ARN
						function_arn = str(function_item['FunctionArn'])
						arn_match = LAMBDA_ARN_PROPERTY_REGEXP.search(function_arn)

						if (arn_match):
							# add function and extracted ARN details to collection
							LambdaAccess._function_collection[function_arn] = {
								'name': str(function_item['FunctionName']),
								'region': arn_match.group('region'),
								'account_id': arn_match.group('account_id')
							}

				if ('NextMarker' not in list_response):
					break # no more functions

				fetch_marker = list_response['NextMarker']

		return LambdaAccess._function_collection

def get_api_export_from_api_id_stage_name(api_gateway_client,api_id,api_stage_name):
	response_get_export = api_gateway_client.get_export(
		restApiId = api_id,
		stageName = api_stage_name,
		exportType = API_GATEWAY_EXPORT_TYPE,
		parameters = API_GATEWAY_EXPORT_PROPERTY_COLLECTION,
		accepts = API_GATEWAY_EXPORT_CONTENT_TYPE
	)

	# return as Python structure
	return json.loads(
		response_get_export['body'].read()
	)

def get_api_data_from_name_stage(api_gateway_client,api_name,api_stage_name):
	console = Console()

	api_id = None
	api_definition = None

	console.write_info('Retrieving API Gateway [{0}] at stage [{1}]\n'.format(api_name,api_stage_name))

	# fetch API Gateway REST API collection
	rest_api_list = api_gateway_client.get_rest_apis(
		limit = REST_API_GET_FETCH_COUNT_LIMIT
	)

	# find our requested API ID by name
	# note: ensure name is found only once - otherwise can't guarantee working with correct API
	for rest_api_item in rest_api_list['items']:
		if (rest_api_item['name'] != api_name):
			# skip item
			continue

		if (api_id):
			# have already found a REST API with this exact name - can't proceed
			console.exit_error('Unable to safely reference [{0}], as more than one API shares this name'.format(api_name))

		# save API ID
		api_id = str(rest_api_item['id'])

	if (not api_id):
		# no API found for requested name
		console.write_info('Unable to locate active API named [{0}]\n'.format(api_name))

	else:
		# API by name found, continue on
		console.write_info('API with ID [{0}] located'.format(api_id))

		# fetch list of stages defined for API
		stage_list = api_gateway_client.get_stages(
			restApiId = api_id
		)

		# attempt to locate requested stage from list returned
		for stage_item in stage_list['item']:
			if (stage_item['stageName'] != api_stage_name):
				# skip stage
				continue

			# found stage name match for API
			console.write_info('Stage [{0}] found, last updated at [{1}]\n'.format(
				api_stage_name,
				stage_item['lastUpdatedDate'].strftime(DATETIME_FORMAT)
			))

			# fetch definition export from API stage and exit loop
			api_definition = get_api_export_from_api_id_stage_name(
				api_gateway_client,
				api_id,api_stage_name
			)

			break

		if (not api_definition):
			# found the API we seek, but not the stage name
			console.write_info('Unable to locate stage of [{0}]\n'.format(api_stage_name))

	# return API ID and definition data
	return api_id,api_definition

def traverse_api_definition_integration_uri(api_definition,handler):
	def get_resource_path_uri_parts(path_uri):
		path_match = API_GATEWAY_DEFINITION_RESOURCE_PATH_REGEXP.search(str(path_uri))

		if (path_match):
			if (path_match.group('root_path_uri')):
				# root path
				return path_match.group('root_path_uri','root_catch_all')

			# sub-level resource path
			return path_match.group('path_uri','catch_all')

		# unable to parse resource path (this is bad)
		return None

	# definition must have top level [paths] property containing a dictionary - else exit
	if (
		('paths' not in api_definition) or
		(type(api_definition['paths']) is not dict)
	):
		return

	# traverse paths
	for path_uri,path_definition in api_definition['paths'].items():
		# path definitions must be of type dictionary - otherwise skip
		if (type(path_definition) is not dict):
			continue

		# parse resource path URI
		resource_path_uri_parts = get_resource_path_uri_parts(path_uri)
		if (not resource_path_uri_parts):
			# invalid path URI - skip
			continue

		for http_method,method_definition in path_definition.items():
			# lower-case and verify [http_method] is valid
			http_method = str(http_method.strip().lower())
			if (http_method not in API_GATEWAY_DEFINITION_VALID_HTTP_METHOD_SET):
				continue

			# only interested in integration type 'aws'/'aws_proxy' with a 'uri' target
			if (
				(API_GATEWAY_DEFINITION_INTEGRATION_PROPERTY not in method_definition) or
				(type(method_definition[API_GATEWAY_DEFINITION_INTEGRATION_PROPERTY]) is not dict) or
				('uri' not in method_definition[API_GATEWAY_DEFINITION_INTEGRATION_PROPERTY]) or (
					method_definition[API_GATEWAY_DEFINITION_INTEGRATION_PROPERTY].get('type') not in
					API_GATEWAY_DEFINITION_INTEGRATION_TYPE_SET
				)
			):
				continue

			# pass integration data to [handler]
			uri_transform = handler(
				http_method = http_method,
				path_uri = resource_path_uri_parts[0],
				path_uri_catch_all = resource_path_uri_parts[1],
				integration_uri = str(method_definition[API_GATEWAY_DEFINITION_INTEGRATION_PROPERTY]['uri'].strip())
			)

			if (uri_transform):
				# handler returned URI - transform definition
				method_definition[API_GATEWAY_DEFINITION_INTEGRATION_PROPERTY]['uri'] = uri_transform

def build_identifier(identifier_spec):
	target_length,charset = identifier_spec
	charset_length = len(charset) - 1

	char_list = []
	while (len(char_list) < target_length):
		# pick the next random character, add to list
		char_list.append(charset[random.randint(0,charset_length)])

	# join characters and return new identifier
	return ''.join(char_list)

def upsert_api_definition(
	api_gateway_client,api_data,
	api_name,api_stage_name,
	file_source_json_path,
	dry_run_mode
):
	console = Console()

	# unpack API data tuple
	api_id,api_definition = api_data
	file_source_json_name = os.path.basename(file_source_json_path)

	# load JSON definition source from disk to struct
	fp = open(file_source_json_path,'r')
	upsert_definition = json.load(fp)
	fp.close()

	# ensure upsert definition [info -> title] matches that of the desired API name
	if (
		('info' not in upsert_definition) or
		(type(upsert_definition['info']) is not dict)
	):
		# can't find required property within definition
		console.exit_error('Unable to locate [info] property for API definition [{0}]'.format(file_source_json_name))

	# set definition title to desired API name and fully qualify generic formatted Lambda ARN integration targets
	upsert_definition['info']['title'] = api_name
	upsert_api_definition_qualify_generic_lambda_uri(upsert_definition)

	def put_definition_and_deploy(action_type):
		if (not dry_run_mode):
			# update API with definition data import
			api_gateway_client.put_rest_api(
				restApiId = api_id,
				mode = API_GATEWAY_DEFINITION_PUT_MODE,
				failOnWarnings = False,
				body = json.dumps(
					upsert_definition,
					separators = (',',':')
				)
			)

		console.write_info('Imported definition [{0}]'.format(file_source_json_name))

		if (not dry_run_mode):
			# create new/updated stage from imported definition
			api_gateway_client.create_deployment(
				restApiId = api_id,
				stageName = api_stage_name,
				cacheClusterEnabled = False
			)

		# emit message, return deployed definition
		console.write_info('{0} deployment stage [{1}]\n'.format(action_type,api_stage_name))

		if (dry_run_mode):
			# if dry run mode, just return definition source given - is sufficient for dry run checks
			return upsert_definition

		else:
			# return current definition - post deployment
			return get_api_export_from_api_id_stage_name(
				api_gateway_client,
				api_id,api_stage_name
			)

	# existing API Gateway stage definition found?
	if (api_definition):
		# yes - compare current to proposed definition
		if (json_struct_compare(
			api_definition,upsert_definition,
			API_GATEWAY_DEFINITION_STRUCT_PATH_IGNORE_LIST
		)):
			# existing and proposed definitions are functionally equivalent
			console.write_info('API [{0}] at stage [{1}] matches given definition [{2}]\nNo deployment required\n'.format(
				api_name,api_stage_name,
				file_source_json_name
			))

		else:
			# differences between current and proposed definitions
			console.write_info('Differences between API [{0}] at stage [{1}] and definition [{2}]'.format(
				api_name,api_stage_name,
				file_source_json_name
			))

			# import definition and update stage
			api_definition = put_definition_and_deploy('Updated')

	else:
		# no stage defined - does API exist?
		if (not api_id):
			if (dry_run_mode):
				# generate faux API Gateway ID for dry run
				api_id = build_identifier(API_GATEWAY_ID_IDENTIFIER)
				console.write_notice('Mock API ID of [{0}] generated for dry run mode\n'.format(api_id))

			else:
				# create new API Gateway instance
				response_create_api = api_gateway_client.create_rest_api(name = api_name)
				api_id = str(response_create_api['id'])

			console.write_info('Created API Gateway [{0}] with ID [{1}]'.format(api_name,api_id))

		# import definition and create stage
		api_definition = put_definition_and_deploy('Created')

	# return updated API data tuple
	return api_id,api_definition

def upsert_api_definition_qualify_generic_lambda_uri(api_definition):
	console = Console()

	class this:
		function_name_collection = None
		processed = False

	def get_function_name_collection():
		# if no function collection defined - build now
		if (this.function_name_collection is None):
			# transform function list into function name/data tuple pairs
			this.function_name_collection = {
				function_item['name']: (function_arn,function_item['region'])
				for function_arn,function_item in LambdaAccess().get_function_collection().items()
			}

		return this.function_name_collection

	def traverse_handler(http_method,path_uri,path_uri_catch_all,integration_uri):
		# attempt match of generic Lambda ARN function name from integration URI
		lambda_match = API_GATEWAY_LAMBDA_URI_ARN_GENERIC_REGEXP.search(integration_uri)
		if (not lambda_match):
			return

		# fetch collection of Lambda functions - does generic function name exist?
		function_name = lambda_match.group('function_name')
		if (function_name not in get_function_name_collection()):
			# function not found in account/region - no transform possible
			return

		# flag a transform has occurred and fetch function data
		this.processed = True
		function_arn,function_region = get_function_name_collection()[function_name]
		console.write_info('Qualified upsert Lambda integration URI [{0}]'.format(function_arn))

		# return qualified Lambda integration URI, updating API definition
		return 'arn:aws:apigateway:{0}:lambda:path/{1}/functions/{2}/invocations'.format(
			function_region,
			lambda_match.group('path_version'),
			function_arn
		)

	# traverse and where possible, qualify generic Lambda URI paths
	traverse_api_definition_integration_uri(api_definition,traverse_handler)

	# if processing done, emit a blank info line
	if (this.processed):
		console.write_info()

def upsert_api_definition_lambda_apply_permissions(
	api_data,api_exclusive_mode,
	dry_run_mode
):
	console = Console()

	# unpack API data tuple, create Lambda access instance
	api_id,api_definition = api_data
	lambdaAccess = LambdaAccess()

	# extract HTTP method/URI path and associated Lambda ARN from API definition integration URIs
	api_definition_method_path_lambda_set = set()

	def traverse_handler(http_method,path_uri,path_uri_catch_all,integration_uri):
		# attempt extract of Lambda ARN from integration URI
		lambda_match = API_GATEWAY_LAMBDA_URI_ARN_REGEXP.search(integration_uri)

		if (lambda_match):
			if (path_uri_catch_all):
				# resource path contains catch-all (greedy), append URI wildcard [/*] as used by Lambda function policy
				path_uri = '{0}{1}*'.format(path_uri,'' if (path_uri == '/') else '/')

			api_definition_method_path_lambda_set.add((
				http_method,
				path_uri,
				lambda_match.group('arn')
			))

	traverse_api_definition_integration_uri(api_definition,traverse_handler)

	# if no Lambda integrations found - then no work to do
	if (not api_definition_method_path_lambda_set):
		return

	# iterate Lambda functions, removing policies related to API definition not required
	# create set of Lambda ARN's referenced in definition
	api_referenced_function_arn_set = {
		item_function_arn
		for void,void,item_function_arn in api_definition_method_path_lambda_set
	}

	def get_api_gateway_function_invoke_policy_set(function_arn,region,account_id):
		# fetch current policy for Lambda function
		# note: boto will (annoyingly) throw an exception if no policy currently exists - so must catch this
		try:
			policy = lambdaAccess.get_client().get_policy(FunctionName = function_arn)

		except botocore.exceptions.ClientError as e:
			# no policies defined for Lambda
			return set()

		# found a policy - parse JSON and confirm we have a statement structure to work with
		policy = json.loads(policy['Policy'])
		if (
			('Statement' not in policy) or
			(type(policy['Statement']) is not list)
		):
			return set()

		invoke_policy_set = set()
		for statement_item in policy['Statement']:
			# skip policy statements we aren't interested in
			if (
				(statement_item['Action'] != LAMBDA_POLICY_ACTION_INVOKE) or
				('Condition' not in statement_item) or
				('ArnLike' not in statement_item['Condition']) or
				('AWS:SourceArn' not in statement_item['Condition']['ArnLike']) or
				(statement_item['Effect'] != 'Allow') or
				('Service' not in statement_item['Principal']) or
				(statement_item['Principal']['Service'] != LAMBDA_POLICY_PRINCIPAL_SERVICE)
			):
				continue

			# parse source ARN condition - does is match required context?
			arn_match = LAMBDA_POLICY_API_GATEWAY_SOURCE_ARN_REGEXP.search(
				str(statement_item['Condition']['ArnLike']['AWS:SourceArn'])
			)

			if (not arn_match):
				continue

			# transform HTTP method to API Gateway 'any method' if wildcard
			# will be easier for compare against items contained in [api_definition_method_path_lambda_set]
			http_method = arn_match.group('http_method').lower()
			if (http_method == '*'):
				http_method = API_GATEWAY_DEFINITION_HTTP_ANY_METHOD

			if (
				(arn_match.group('region') == region) and
				(arn_match.group('account_id') == account_id)
			):
				invoke_policy_set.add((
					str(statement_item['Sid']),
					arn_match.group('api_id'),
					http_method,
					arn_match.group('path_uri'),
				))

		return invoke_policy_set

	def retain_existing_function_policy(policy_api_id,policy_check):
		if (api_exclusive_mode):
			# retaining policies only related to API definition
			if (policy_api_id != api_id):
				return False

			# is related policy required by API definition?
			if (policy_check not in api_definition_method_path_lambda_set):
				return False

		else:
			# retaining policies related to other API definitions
			# is related policy required by API definition?
			if (
				(policy_api_id == api_id) and
				(policy_check not in api_definition_method_path_lambda_set)
			):
				return False

		# retain policy
		return True

	def get_policy_http_method(definition_http_method):
		if (definition_http_method == API_GATEWAY_DEFINITION_HTTP_ANY_METHOD):
			return '*'

		return definition_http_method.upper()

	function_policy_updated = False
	for function_arn,function_item in lambdaAccess.get_function_collection().items():
		# if function not referenced in API definition - skip it
		if (function_arn not in api_referenced_function_arn_set):
			continue

		# fetch function invoke policies related to region, account ID and API ID
		invoke_policy_set = get_api_gateway_function_invoke_policy_set(
			function_arn,
			function_item['region'],
			function_item['account_id']
		)

		# check each policy to determine if still required by API definition
		for policy_sid,policy_api_id,policy_http_method,policy_path_uri in invoke_policy_set:
			policy_check = (policy_http_method,policy_path_uri,function_arn)

			if (retain_existing_function_policy(policy_api_id,policy_check)):
				# policy to remain against function
				if (
					(policy_api_id == api_id) and
					(policy_check in api_definition_method_path_lambda_set)
				):
					# remove policy from API definition referenced Lambda function set
					# thus won't be processed by the 'add policy' routines below
					api_definition_method_path_lambda_set.remove(policy_check)

			else:
				# remove policy from function
				if (not dry_run_mode):
					lambdaAccess.get_client().remove_permission(
						FunctionName = function_arn,
						StatementId = policy_sid
					)

				console.write_info('Removed Lambda function [{0}] policy [{1}:{2}:{3}]'.format(
					function_item['name'],
					policy_api_id,
					get_policy_http_method(policy_http_method),
					policy_path_uri
				))

				function_policy_updated = True

	# if removals made - emit blank line
	if (function_policy_updated):
		console.write_info()

	# for remaining [api_definition_method_path_lambda_set] items - add function policies
	function_policy_updated = False
	for function_http_method,function_path_uri,function_arn in api_definition_method_path_lambda_set:
		# if function not defined for account/region, skip it
		if (function_arn not in lambdaAccess.get_function_collection()):
			continue

		# add policy allowing invoke from API Gateway instance for specific HTTP method/URI path defined by [SourceArn]
		function_item = lambdaAccess.get_function_collection()[function_arn]
		policy_http_method = get_policy_http_method(function_http_method)

		if (not dry_run_mode):
			lambdaAccess.get_client().add_permission(
				FunctionName = function_arn,
				StatementId = build_identifier(LAMBDA_POLICY_STATEMENT_ID_IDENTIFIER),
				Action = LAMBDA_POLICY_ACTION_INVOKE,
				Principal = LAMBDA_POLICY_PRINCIPAL_SERVICE,
				SourceArn = 'arn:aws:execute-api:{0}:{1}:{2}/*/{3}{4}'.format(
					function_item['region'],
					function_item['account_id'],
					api_id,
					policy_http_method,
					function_path_uri
				)
			)

		console.write_info('Added Lambda function [{0}] policy [{1}:{2}:{3}]'.format(
			function_item['name'],
			api_id,
			policy_http_method,
			function_path_uri
		))

		function_policy_updated = True

	# if policy additions updates made, emit blank line
	if (function_policy_updated):
		console.write_info()

def export_api_definition(api_data,file_target_json_path,generic_lambda_integration_uri):
	console = Console()

	# unpack API data tuple
	api_id,api_definition = api_data

	# do we have an API definition to export/save?
	if (not api_definition):
		console.exit_error('No definition available for export')

	# copy definition structure, if enabled apply generic Lambda function integration URIs
	api_definition_export = copy.deepcopy(api_definition)

	if (generic_lambda_integration_uri):
		def traverse_handler(http_method,path_uri,path_uri_catch_all,integration_uri):
			# if URI matches that of a Lambda function integration, convert to generic form
			lambda_match = API_GATEWAY_LAMBDA_URI_ARN_REGEXP.search(integration_uri)

			if (lambda_match):
				return (
					'arn:aws:apigateway::lambda:path/{0}/functions/'
					'arn:aws:lambda:::function:{1}/invocations'.format(
						lambda_match.group('path_version'),
						lambda_match.group('function_name')
					)
				)

		traverse_api_definition_integration_uri(api_definition_export,traverse_handler)

	# convert API definition struct data back to JSON
	rest_api_json = json.dumps(
		api_definition_export,
		indent = JSON_INDENT_SIZE,
		separators = (',',': '),
		sort_keys = True
	)

	# write definition back to file with tab indents
	def tab_indent_json():
		json_line_list = []
		for json_line in rest_api_json.split('\n'):
			# match JSON line spaced indent
			indent_match = JSON_INDENT_REGEXP.search(json_line)
			if (indent_match):
				# rewrite line with tab indents in place of spaces
				json_line = (
					('\t' * int(len(indent_match.group(1)) / JSON_INDENT_SIZE)) +
					indent_match.group(2)
				)

			json_line_list.append(json_line)

		# join tabbed lines back together
		return '\n'.join(json_line_list)

	fp = open(file_target_json_path,'w')
	fp.write(tab_indent_json() + '\n')
	fp.close()

	# finish up
	console.write_info('Successfully exported API definition to [{0}]\n'.format(file_target_json_path))

def display_api_invoke_uri(api_data):
	# unpack API data tuple
	api_id,api_definition = api_data

	# ensure we have a 'host' property
	if ('host' in api_definition):
		# API Gateway definitions with custom domain names assigned won't have 'basePath' defined
		base_path = '/'
		if ('basePath' in api_definition):
			base_path = api_definition['basePath']

		Console().write_info('API invoke URI: https://{0}{1}'.format(
			api_definition['host'],
			base_path
		))

def main():
	# fetch arguments
	(
		aws_target_region,
		api_name,api_stage_name,
		upsert_mode,file_path_json,
		export_generic_lambda_integration_uri,
		apply_lambda_permission_mode,
		dry_run_mode,
		verbose_mode
	) = read_arguments()

	# set Console verbose mode and target AWS region for Lambda access class
	Console.verbose = verbose_mode
	LambdaAccess.aws_target_region = aws_target_region

	console = Console()

	if (dry_run_mode):
		console.write_notice('Dry run mode enabled, additions/modifications reported but not applied to account/region\n')

	# create API Gateway client
	api_gateway_client = boto3.client(
		'apigateway',
		region_name = aws_target_region
	)

	# fetch requested API data from name/stage combination
	api_data = get_api_data_from_name_stage(
		api_gateway_client,
		api_name,api_stage_name
	)

	if (upsert_mode):
		# upsert API definition from file
		api_data = upsert_api_definition(
			api_gateway_client,api_data,
			api_name,api_stage_name,
			file_path_json,
			dry_run_mode
		)

		# if apply Lambda permission mode enabled:
		# - parse API definition for Lambda references
		# - ensure API Gateway instance can invoke Lambda function(s) found (and update where required)
		if (apply_lambda_permission_mode is not None):
			upsert_api_definition_lambda_apply_permissions(
				api_data,
				apply_lambda_permission_mode == LAMBDA_POLICY_APPLY_PERMISSIONS_EXCLUSIVE,
				dry_run_mode
			)

	else:
		# export API definition to file and display public endpoint
		export_api_definition(
			api_data,file_path_json,
			export_generic_lambda_integration_uri
		)

	# display the API invoke URI and end successfully
	display_api_invoke_uri(api_data)
	if (dry_run_mode):
		console.write_notice('Dry run completed')

	sys.exit(0)


if (__name__ == '__main__'):
	main()
