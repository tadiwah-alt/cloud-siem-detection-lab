
# Python SDK used to interact with AWS
import boto3
from botocore.exceptions import ClientError

#Lambda function that will run when invocked
def lambda_handler(event, context):
    iam_accessKeyId = event["detail"]["resource"]["accessKeyDetails"]["accessKeyId"]
    iam_userName = event["detail"]["resource"]["accessKeyDetails"]["userName"]

    if iam_user_handler(iam_accessKeyId, iam_userName):
        print(f"{iam_userName}'s key has been disabled")

    else:
        print(f"Failed to dsiable {iam_userName}'s key")




# Function to disable compromised IAM user
def iam_user_handler(iam_accessKeyId, iam_userName):
    iam_client = boto3.client('iam')

    try:
        iam_client.update_access_key(
            UserName = iam_userName,
            AccessKeyId = iam_accessKeyId,
            Status ='Inactive'
            )
        
        return True

    except ClientError as e:
        print(e)
        
        return False







