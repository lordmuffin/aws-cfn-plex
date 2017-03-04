#!/usr/bin/python
# Written by: Andrew Jackson
# This is used to pull repo from github and drop to S3
import urllib2
import boto3
import sys
import json
import cfnresponse
import git
s3 = boto3.resource('s3')

def lambda_handler(event, context):
    print "event.dump = " + json.dumps(event)
    responseData = {}
    # If not valid cloudformation custom resource call
    try:
        git.Git().clone(event["ResourceProperties"]["git_url"])

# Foreach Object in the cloned folder, upload to s3 cloned folder.

        s3.Bucket(event["ResourceProperties"]["bucket_name"]).put_object(Key=event["ResourceProperties"]["key"], Body=zipcontent)
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, ".zip pulled to S3 Bucket!")
    except Exception:
        cfnresponse.send(event, context, cfnresponse.FAILED, responseData, "Bucket Name and Key are all required.")
        print "ERROR"


import git
git.Git().clone("git://gitorious.org/git-python/mainline.git")
