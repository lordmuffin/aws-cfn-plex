# aws-cfn-plex
## Synopsis

This is for deploying Plex server form CFN.

## Code Example

Show what the library does as concisely as possible, developers should be able to figure out **how** your project solves their problem by looking at the code example. Make sure the API you are showing off is obvious, and that your code is short and concise.

## Goals

I will try and keep a running list of goals here for everyone's reference.  
- Keep all keys secure and as unobtainable by AWS as possible.
  - Use AWS KMS probably - Seems secure enough based on their Policies?
  - Allow adding public key to CFM for auto-injection into SSH?
- Pre-Package AMI with Packer - Include things like:
  - Plex
  - ENCFS - Self Encrypt with autogeneration on startup???
  - ACD_CLI - Service to mount drive after ENCFS Encrypts
  - 

## Installation

Provide code examples and explanations of how to get the project.

## API Reference

Depending on the size of the project, if it is small and simple enough the reference docs can be added to the README. For medium size to larger projects it is important to at least provide a link to where the API reference docs live.

## Tests

Describe and show how to run the tests with code examples.

## Contributors

Let people know how they can dive into the project, include important links to things like issue trackers, irc, twitter accounts if applicable.

## License

A short snippet describing the license (MIT, Apache, etc.)
