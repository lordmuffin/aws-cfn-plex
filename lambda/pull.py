# Written by: Andrew Jackson
# This is used to pull repo from github and drop to S3
import urllib2
import boto3
import sys
import json
s3 = boto3.resource('s3')

def lambda_handler(event, context):
    print "event.dump = " + json.dumps(event)
    # If not valid cloudformation custom resource call

    response = urllib2.urlopen (event["ResourceProperties"]["git_url"].encode('utf-8'))
    zipcontent = response.read()
    s3.Bucket(event["ResourceProperties"]["bucket_name"]).put_object(Key=event["ResourceProperties"]["key"], Body=zipcontent)
