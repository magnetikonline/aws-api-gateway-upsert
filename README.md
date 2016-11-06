# AWS API Gateway upsert
Command line utility for upserting (create if not exist, otherwise update) [AWS API Gateway](https://aws.amazon.com/api-gateway/) instances from [Swagger 2.0](http://swagger.io/specification/) JSON definitions.

Features:
- Ability to create, update or export API Gateway instances from/to JSON Swagger definition files.
- With API updates, automatically compares current to proposed definition - only deploying when differences are detected. Useful for continuous delivery pipelines and avoiding creation of duplicated API Gateway deployments.
- Lambda functions referenced as integration targets can optionally have permissions [updated during the upsert process](#lambda-function-policy-creation), enabling invoke access from the API Gateway instance. This includes support for [September 2016 feature additions](https://aws.amazon.com/blogs/aws/api-gateway-update-new-features-simplify-api-development/) of:
	- Catch-all path variables.
	- HTTP pseudo `ANY` method.
- Definition referenced Lambda function integration ARNs can be written in a generic format, without specifying AWS region and account ID - improving portability.

In addition all upsert operations can also be executed in a dry run mode, for testing write operations actions that would be applied to the target AWS account/region.

- [Requires](#requires)
- [Usage](#usage)
	- [Lambda function policy creation](#lambda-function-policy-creation)
	- [Lambda function generic format ARNs](#lambda-function-generic-format-arns)
- [Examples](#examples)
- [Definition templates](#definition-templates)

## Requires
- Python 2.7.x.
- [Boto 3](https://boto3.readthedocs.io/en/latest/).

## Usage
```
usage: awsapigatewayupsert.py [-h] --region REGION --api-name NAME --api-stage
                              NAME [--export-file-json FILE]
                              [--generic-lambda-integration-uri]
                              [--upsert-file-json FILE]
                              [--apply-lambda-permissions {exclusive,inclusive}]
                              [--dry-run] [--quiet]

Creates or updates an AWS API Gateway instance by API name from a JSON Swagger
2.0 definition. Can also export an active API Gateway instance back to
definition file.

optional arguments:
  -h, --help            show this help message and exit
  --region REGION       AWS target region
  --api-name NAME       API Gateway name for upsert or export
  --api-stage NAME      API stage name for upsert or export
  --export-file-json FILE
                        Export API Gateway definition to the given file
  --generic-lambda-integration-uri
                        Exported definition will have Lambda function
                        integration URIs converted to a generic format
  --upsert-file-json FILE
                        Definition file to create/update an API Gateway
                        instance from
  --apply-lambda-permissions {exclusive,inclusive}
                        Update Lambda function policies referenced by API
                        definition to enable invoke actions. The 'exclusive'
                        mode removes policies unrelated to gateway instance,
                        'inclusive' will preserve such policies.
  --dry-run             Display what would happen during API definition
                        upsert, without committing changes
  --quiet               Suppress output during export/upsert progress
```

### Lambda function policy creation
For an API Gateway instance to successfully [invoke a Lambda function](http://docs.aws.amazon.com/lambda/latest/dg/with-on-demand-https.html), permissions allowing the gateway are required against the function itself.

During the upsert of a definition, integration Lambda targets within the current account/region can have policies managed via `--apply-lambda-permissions` to complement gateway requirements:
- The `exclusive` mode will **remove all** API Gateway related permissions from Lambda functions that are not associated to the upserted API. Use this mode when referenced Lambda functions are used by a *single* API Gateway instance only.
- Alternatively `inclusive` mode will **retain** all permissions unrelated to the current API Gateway instance - only removing what is not directly required by the current upsert API. Use this mode when Lambda functions have dependency on *multiple* API Gateway endpoints.

Some format examples of generated Lambda function permissions:

HTTP method | URI path | Generated permission
:--- | :--- | :---
`GET` | `/` | `arn:aws:execute-api:REGION:ACCOUNT_ID:API_ID/*/GET/`
`POST` | `/api/path` | `arn:aws:execute-api:REGION:ACCOUNT_ID:API_ID/*/POST/api/path`
`ANY` * | `/api/path` | `arn:aws:execute-api:REGION:ACCOUNT_ID:API_ID/*/*/api/path`
`GET` | `/api/path/{proxy+}` | `arn:aws:execute-api:REGION:ACCOUNT_ID:API_ID/*/GET/api/path/*`
`ANY` * | `/api/path/{proxy+}` | `arn:aws:execute-api:REGION:ACCOUNT_ID:API_ID/*/*/api/path/*`

**Note:**
- The `ANY` pseudo method is represented as `x-amazon-apigateway-any-method` within Swagger definitions.
- Policies assigned to a Lambda function can be view via the AWS CLI [`lambda get-policy`](http://docs.aws.amazon.com/cli/latest/reference/lambda/get-policy.html) command.

### Lambda function generic format ARNs
Lambda function ARN integration points referenced in definitions can be written in a generic format, where the AWS region and account ID are not specified.

For example:
```
arn:aws:apigateway:ap-southeast-2:lambda:path/2015-03-31/functions/arn:aws:lambda:ap-southeast-2:123456789012:function:lambda-function/invocations
```

becomes:
```
arn:aws:apigateway::lambda:path/2015-03-31/functions/arn:aws:lambda:::function:lambda-function/invocations
```

- During upsert operations, generic format ARNs will be detected and expanded on the fly before further API processing continues.
- The export definition mode also supports writing back generic format Lambda function ARNs through use of the `--generic-lambda-integration-uri` argument.

## Examples
Upsert definition JSON file `/path/to/definition.json` to an API named `my-first-api` within AWS region `ap-southeast-2` deployed to stage named `production`:
```sh
$ ./awsapigatewayupsert.py \
	--region ap-southeast-2 \
	--api-name my-first-api \
	--api-stage production \
	--upsert-file-json /path/to/definition.json
```

- Upsert definition `/path/to/definition.json` to an API `my-second-api` deployed at stage `development`.
- Lambda functions referenced within definition will have policy permissions added/removed to complement that of the definition.
- In addition, any Lambda permissions not associated to `my-second-api` will be removed:
```sh
$ ./awsapigatewayupsert.py \
	--region ap-southeast-2 \
	--api-name my-second-api \
	--api-stage development \
	--upsert-file-json /path/to/definition.json \
	--apply-lambda-permissions exclusive
```

- Export API named `my-first-api` deployed at stage `production` to a definition Swagger 2.0 JSON file `/path/to/definition.json`.
- In addition, any Lambda function referenced integration URIs will be converted to generic form ARNs:
```sh
$ ./awsapigatewayupsert.py \
	--region ap-southeast-2 \
	--api-name my-first-api \
	--api-stage production \
	--export-file-json /path/to/definition.json \
	--generic-lambda-integration-uri
```

## Definition templates
Example JSON Swagger 2.0 API Gateway templates for common implementation patterns:
- [`lambda-awsproxy-any-route-cors.json`](definition-template/lambda-awsproxy-any-route-cors.json) implements:
	- Request paths of both `/method` and `/method/*` ([catch-all](http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-set-up-simple-proxy.html#api-gateway-proxy-resource) path) with upstream Lambda function targets via the `aws_proxy` integration type.
	- Accepting any HTTP method verb via the pseduo `ANY` / `x-amazon-apigateway-any-method` method.
	- [CORS policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS) to match, allowing any requesting domain (via `*` wildcard).
- [`lambda-awsproxy-classic-any-cors.json`](definition-template/lambda-awsproxy-classic-any-cors.json) implements:
	- Request paths of `/awsproxy` and `/classic` with Lambda function upstream targets via `aws_proxy` and `aws` (classic) integration systems respectively.
	- Accepting any HTTP method verb via the pseduo `ANY` / `x-amazon-apigateway-any-method` method.
	- [CORS policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS) to match, allowing any requesting domain (via `*` wildcard).
- [`lambda-awsproxy-get-root-catchall.json`](definition-template/lambda-awsproxy-get-root-catchall.json) implements:
	- Request paths of `/` and `/*` ([catch-all](http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-set-up-simple-proxy.html#api-gateway-proxy-resource) path) with upstream target of a single Lambda functions via the `aws_proxy` integration type.
	- Any URI under the root for `GET` HTTP method requests and routed to the target Lambda function.
