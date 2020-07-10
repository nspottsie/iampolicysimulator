import glob, os
import boto3
import json

# the local credential policy to use
iam_credentials_profile = '<Insert Credentials Profile Name>'

# the policy arn to simulate
policy_source_arn = "<Insert IAM Policy ARN>"

# the arn of the permissions boundary
permissions_boundary_arn = '<Insert IAM Permissions Boundary ARN>'

# a list of valud arns to use for testing the permissions boundary
valid_resource_arns = ["<Insert Valid Resource ARNs>"]

# the context keys
context_keys = [{'ContextKeyName': 'aws:RequestedRegion', 'ContextKeyValues':['us-east-1'], 'ContextKeyType':'string'}]

# open a boto session and client with IAM
session = boto3.Session(profile_name=iam_credentials_profile)
iam_svc = session.client('iam')

# data structure to hold actions by service
iam_service_actions = {}

# iterate through all the json files in the actions folder and store them indexed by service prefix
os.chdir("actions")
for file in glob.glob("*.json"):
    with open(file) as json_file:
        for row in json.load(json_file):
            prefix = row['prefix']
            if prefix not in iam_service_actions:
                iam_service_actions[prefix] = []
            name = row['name']
            iam_service_actions[prefix].append(prefix + ':' + name)

os.chdir("../")

# runs an iam policy simulation with the given attributes
def run_iam_policy_simulation(source_arn, actions, context_keys, resource_arns, out_file_name):
    paginator = iam_svc.get_paginator('simulate_principal_policy')
    response_iterator = paginator.paginate(PolicySourceArn=source_arn,ActionNames=actions,ContextEntries=context_keys,ResourceArns=resource_arns)

    output = []
    output.append(f"{'IAM Allow/Deny':<18}{'Action Name':<50}{'Organizations Allow/Deny':<30}{'Missing Context Values'}")

    for response in response_iterator:
        if response is None or 'ResponseMetadata' not in response or response['ResponseMetadata']['HTTPStatusCode'] != 200:
            print("Error retreiving the context keys from the API, duming response and bailing")
            print(response)
            exit(-1)
        
        evaluation_results = response['EvaluationResults']
        for evaluation_result in evaluation_results:
            action_name = evaluation_result['EvalActionName']
            eval_decision = evaluation_result['EvalDecision']
            missing_context_values = evaluation_result['MissingContextValues']
            allowed_by_organizations = evaluation_result['OrganizationsDecisionDetail']['AllowedByOrganizations']

            if eval_decision == 'implicitDeny' or eval_decision == 'explicitDeny':
                eval_decision = "deny"
            
            if allowed_by_organizations is True:
                allowed_by_organizations = "Allowed"
            else:
                allowed_by_organizations = "Deny"

            output.append(f"{eval_decision.title():<18}{action_name:<50}{allowed_by_organizations:<30}{missing_context_values}")
        
    with open(out_file_name, 'w') as out_file:
        out_file.write('\n'.join(output))

# test 1, iam actions with no policy boundary specified
run_iam_policy_simulation(policy_source_arn, iam_service_actions['iam'], context_keys, ["*"], "iam_test_1_with_no_permissions_boundary.txt")

# test 2, iam actions with a valid policy boundary specified
context_keys.append({'ContextKeyName': 'iam:PermissionsBoundary', 'ContextKeyValues':[permissions_boundary_arn], 'ContextKeyType':'string'})
run_iam_policy_simulation(policy_source_arn, iam_service_actions['iam'], context_keys, ["*"], "iam_test_2_with_permissions_boundary.txt")

# test 3, iam actions with policy boundary specified and a valid resource id
run_iam_policy_simulation(policy_source_arn, iam_service_actions['iam'], context_keys, valid_resource_arns, "iam_test_3_with_permissions_boundary_and_matching_resource.txt")
