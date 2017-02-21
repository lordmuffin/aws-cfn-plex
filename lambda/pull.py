# Written by: Andrew Jackson
# This is used to pull repo from github and drop to S3
import urllib2
import boto3
import sys
import json
import cfnresponse
s3 = boto3.resource('s3')

def lambda_handler(event, context):
    print "event.dump = " + json.dumps(event)
    responseData = {}
    # If not valid cloudformation custom resource call
    try:
        response = urllib2.urlopen (event["ResourceProperties"]["git_url"].encode('utf-8'))
        zipcontent = response.read()
        s3.Bucket(event["ResourceProperties"]["bucket_name"]).put_object(Key=event["ResourceProperties"]["key"], Body=zipcontent)
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, ".zip pulled to S3 Bucket!")
    except Exception:
        cfnresponse.send(event, context, cfnresponse.FAILED, responseData, "Bucket Name and Key are all required.")
        print "ERROR"
